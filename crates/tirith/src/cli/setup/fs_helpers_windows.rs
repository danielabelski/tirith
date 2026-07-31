//! Windows filesystem helpers for `tirith setup` — the same public API as
//! `fs_helpers.rs` using held Windows handles and explicit DACL handling.

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

#[path = "fs_helpers_windows_path.rs"]
mod path_rules;

use windows::core::{BOOL, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    MoveFileExW, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_file(self) -> fs::File {
        let raw = self.0 .0 as RawHandle;
        std::mem::forget(self);
        unsafe { fs::File::from_raw_handle(raw) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

struct ValidatedParent {
    path: PathBuf,
    handles: Vec<OwnedHandle>,
    root_final: String,
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn is_win32(error: &windows::core::Error, code: u32) -> bool {
    error.code() == HRESULT::from_win32(code)
}

fn final_path(handle: HANDLE) -> Result<String, String> {
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, Default::default()) };
        if length == 0 {
            return Err(format!(
                "GetFinalPathNameByHandleW: {}",
                std::io::Error::last_os_error()
            ));
        }
        if (length as usize) < buffer.len() {
            return Ok(String::from_utf16_lossy(&buffer[..length as usize]));
        }
        buffer.resize(length as usize + 1, 0);
    }
}

fn open_directory(path: &Path) -> Result<Option<OwnedHandle>, String> {
    let path_wide = wide(path);
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error)
            if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(format!("open directory handle {}: {error}", path.display())),
    };
    let owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|e| format!("inspect directory handle {}: {e}", path.display()))?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, true) {
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(format!(
                "{} is a reparse point — refusing for safety",
                path.display()
            ));
        }
        return Err(format!("{} is not a directory", path.display()));
    }
    Ok(Some(owned))
}

fn open_or_create_directory(
    current: &mut PathBuf,
    component: &OsStr,
    handles: &mut Vec<OwnedHandle>,
    create: bool,
) -> Result<bool, String> {
    current.push(component);
    let component_handle = match open_directory(current)? {
        Some(handle) => handle,
        None if !create => return Ok(false),
        None => {
            let current_wide = wide(current);
            if let Err(error) = unsafe { CreateDirectoryW(PCWSTR(current_wide.as_ptr()), None) } {
                if !is_win32(&error, ERROR_ALREADY_EXISTS.0) {
                    return Err(format!("create directory {}: {error}", current.display()));
                }
            }
            open_directory(current)?.ok_or_else(|| {
                format!("{} disappeared after directory creation", current.display())
            })?
        }
    };
    handles.push(component_handle);
    Ok(true)
}

fn validated_parent(
    path: &Path,
    scope_root: &Path,
    create: bool,
) -> Result<Option<ValidatedParent>, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("current_dir: {e}"))?
            .join(path)
    };
    let root = if scope_root.is_absolute() {
        scope_root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("current_dir: {e}"))?
            .join(scope_root)
    };
    let relative = path.strip_prefix(&root).map_err(|_| {
        format!(
            "{} is outside trusted setup root {}",
            path.display(),
            root.display()
        )
    })?;
    let mut relative_parts: Vec<_> = relative.components().collect();
    if relative_parts.pop().is_none() {
        return Err(format!(
            "{} names the trusted root, not a file",
            path.display()
        ));
    }
    if relative_parts
        .iter()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "{} contains a non-normal path component",
            path.display()
        ));
    }

    let mut anchor = root.clone();
    let mut missing = Vec::new();
    while !anchor.exists() {
        missing.push(
            anchor
                .file_name()
                .ok_or_else(|| format!("cannot resolve {}", root.display()))?
                .to_os_string(),
        );
        if !anchor.pop() {
            return Err(format!("cannot resolve {}", root.display()));
        }
    }
    if !missing.is_empty() && !create {
        return Ok(None);
    }
    let mut current = anchor
        .canonicalize()
        .map_err(|e| format!("canonicalize trusted root {}: {e}", anchor.display()))?;
    let mut handles = vec![open_directory(&current)?
        .ok_or_else(|| format!("trusted root {} disappeared", current.display()))?];

    for component in missing.iter().rev() {
        if !open_or_create_directory(&mut current, component, &mut handles, create)? {
            return Ok(None);
        }
    }
    // Capture the final path of the requested scope root itself, rather than
    // its nearest pre-existing ancestor when the scope had to be created.
    let root_final = final_path(handles.last().expect("root handle exists").0)?;

    for component in relative_parts.iter().filter_map(|part| match part {
        std::path::Component::Normal(name) => Some(*name),
        _ => None,
    }) {
        if !open_or_create_directory(&mut current, component, &mut handles, create)? {
            return Ok(None);
        }
    }

    let parent_final = final_path(handles.last().expect("anchor handle exists").0)?;
    if !path_rules::final_path_within(&root_final, &parent_final) {
        return Err(format!(
            "{} resolves outside trusted setup root",
            current.display()
        ));
    }
    Ok(Some(ValidatedParent {
        path: current,
        handles,
        root_final,
    }))
}

fn open_existing(path: &Path) -> Result<Option<OwnedHandle>, String> {
    let path_wide = wide(path);
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (FILE_GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error)
            if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(format!("open destination {}: {error}", path.display())),
    };
    let owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|e| format!("inspect destination {}: {e}", path.display()))?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, false) {
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(format!(
                "{} is a reparse point — refusing for safety",
                path.display()
            ));
        }
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(Some(owned))
}

/// Read through validated, retained no-reparse parent handles. Missing files or
/// parents return `None` without creating directories, while unsafe components
/// fail even when the caller would otherwise take an idempotent/dry-run return.
pub fn read_to_string_scoped(path: &Path, scope_root: &Path) -> Result<Option<String>, String> {
    let Some(parent) = validated_parent(path, scope_root, false)? else {
        return Ok(None);
    };
    let destination = parent.path.join(
        path.file_name()
            .ok_or_else(|| format!("no file name for {}", path.display()))?,
    );
    let Some(handle) = open_existing(&destination)? else {
        return Ok(None);
    };
    let mut file = handle.into_file();
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("read {} through validated handle: {e}", path.display()))?;
    // Keep the validated parent handles alive through the complete read.
    drop(parent);
    Ok(Some(content))
}

/// Return whether a destination's complete parent chain currently exists and
/// is safe beneath `scope_root`, without creating anything.
pub fn parent_exists_scoped(path: &Path, scope_root: &Path) -> Result<bool, String> {
    validated_parent(path, scope_root, false).map(|parent| parent.is_some())
}

fn owner_only_descriptor() -> Result<LocalSecurityDescriptor, String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::w!("D:P(A;;FA;;;OW)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| format!("build owner-only security descriptor: {e}"))?;
    Ok(LocalSecurityDescriptor(descriptor))
}

/// Write through held, no-reparse directory handles. Existing destination
/// DACLs are copied; new files are owner-only from the instant of creation.
pub fn atomic_write(
    path: &Path,
    scope_root: &Path,
    content: &str,
    _mode: u32,
) -> Result<(), String> {
    atomic_write_with_security(path, scope_root, content, true)
}

fn atomic_write_with_security(
    path: &Path,
    scope_root: &Path,
    content: &str,
    preserve_destination_dacl: bool,
) -> Result<(), String> {
    let parent = validated_parent(path, scope_root, true)?
        .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
    let destination = parent.path.join(
        path.file_name()
            .ok_or_else(|| format!("no file name for {}", path.display()))?,
    );
    let existing = open_existing(&destination)?;
    let acl_source = path_rules::acl_source(existing.is_some(), preserve_destination_dacl);

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let owner_only = owner_only_descriptor()?;
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: owner_only.0 .0,
        bInheritHandle: BOOL(0),
    };

    let (tmp, handle) = (0..4)
        .find_map(|_| {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp = parent
                .path
                .join(format!(".tirith-setup-{}-{n}.tmp", std::process::id()));
            let tmp_wide = wide(&tmp);
            match unsafe {
                CreateFileW(
                    PCWSTR(tmp_wide.as_ptr()),
                    (FILE_GENERIC_WRITE | WRITE_DAC).0,
                    FILE_SHARE_READ,
                    Some(&security_attributes),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            } {
                Ok(handle) => Some(Ok((tmp, handle))),
                Err(error)
                    if is_win32(&error, ERROR_FILE_EXISTS.0)
                        || is_win32(&error, ERROR_ALREADY_EXISTS.0) =>
                {
                    None
                }
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()
        .map_err(|e| format!("create owner-only temporary file: {e}"))?
        .ok_or_else(|| "temporary-name retries exhausted".to_string())?;

    if acl_source == path_rules::AclSource::ExistingDestination {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                existing.as_ref().expect("existing ACL source").0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                Some(&mut descriptor),
            )
        };
        if status.0 != 0 {
            unsafe {
                let _ = CloseHandle(handle);
            }
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "read existing destination DACL: error {}",
                status.0
            ));
        }
        let existing_descriptor = LocalSecurityDescriptor(descriptor);
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        drop(existing_descriptor);
        if status.0 != 0 {
            unsafe {
                let _ = CloseHandle(handle);
            }
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "apply existing destination DACL: error {}",
                status.0
            ));
        }
    }

    let mut file = unsafe { fs::File::from_raw_handle(handle.0 as RawHandle) };
    if let Err(error) = file.write_all(content.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(format!("write temporary file: {error}"));
    }
    drop(file);

    // Revalidate both the held parent containment and final destination type at
    // publication time. Parent handles omit FILE_SHARE_DELETE, preventing a
    // junction swap while this operation is in flight.
    let parent_final = final_path(parent.handles.last().expect("parent handle exists").0)?;
    if !path_rules::final_path_within(&parent.root_final, &parent_final) {
        let _ = fs::remove_file(&tmp);
        return Err("destination parent moved outside trusted setup root".into());
    }
    let final_destination = open_existing(&destination)?;
    // These no-delete handles prevent swaps while validating/copying ACLs;
    // release them only after the final check so MoveFileEx can replace the name.
    drop(final_destination);
    drop(existing);
    let tmp_wide = wide(&tmp);
    let destination_wide = wide(&destination);
    unsafe {
        MoveFileExW(
            PCWSTR(tmp_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("publish {}: {e}", destination.display())
    })?;

    Ok(())
}

/// Write a hook script. No executable bit needed on Windows.
pub fn write_hook_script(
    path: &Path,
    scope_root: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    if let Some(existing) = read_to_string_scoped(path, scope_root)? {
        if existing == content {
            if !dry_run {
                eprintln!("tirith: {} already configured, up to date", path.display());
            } else {
                eprintln!(
                    "[dry-run] would skip {} (already up to date)",
                    path.display()
                );
            }
            return Ok(());
        }

        if !force {
            if dry_run {
                eprintln!(
                    "[dry-run] would error: {} exists but content differs — use --force to update",
                    path.display()
                );
                return Ok(());
            }
            return Err(format!(
                "{} exists but content differs — use --force to update",
                path.display()
            ));
        }
    }

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    atomic_write(path, scope_root, content, 0)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

/// Validate that `dir` stays within `scope_root` after canonicalization.
pub fn validate_target_dir(dir: &Path, scope_root: Option<&Path>) -> Result<(), String> {
    let root = match scope_root {
        Some(r) => r,
        None => return Ok(()),
    };

    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;

    let mut check = dir.to_path_buf();
    loop {
        if check.exists() {
            let canonical = check
                .canonicalize()
                .map_err(|e| format!("canonicalize {}: {e}", check.display()))?;
            if !canonical.starts_with(&root_canonical) {
                return Err(format!(
                    "{} resolves outside project root {} — refusing for safety",
                    dir.display(),
                    root.display()
                ));
            }
            break;
        }
        if !check.pop() {
            return Err(format!(
                "cannot resolve {} — no existing ancestor found",
                dir.display()
            ));
        }
    }

    let mut path_so_far = PathBuf::new();
    for component in dir.components() {
        path_so_far.push(component);
        if path_so_far.exists() {
            if let Ok(meta) = fs::symlink_metadata(&path_so_far) {
                if meta.file_type().is_symlink() && path_so_far.starts_with(&root_canonical) {
                    return Err(format!(
                        "{} is a symlink inside project scope — refusing for safety",
                        path_so_far.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Run a CLI subprocess through the shared trusted, bounded supervisor.
pub fn run_cli(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let executable = tirith_core::trusted_child::resolve_ambient(cmd)
        .map_err(|error| format!("{cmd} not found or untrusted: {error}"))?;
    run_cli_with(
        &executable,
        args,
        tirith_core::trusted_child::ChildLimits::new(
            std::time::Duration::from_secs(30),
            4 * 1024 * 1024,
            4 * 1024 * 1024,
        ),
    )
}

fn run_cli_with(
    executable: &tirith_core::trusted_child::TrustedExecutable,
    args: &[&str],
    limits: tirith_core::trusted_child::ChildLimits,
) -> Result<std::process::Output, String> {
    use tirith_core::trusted_child::{ChildOutcome, ChildSpec};

    let mut spec = ChildSpec::new(args, limits).inherit_env(&[
        "HOME",
        "USER",
        "LOGNAME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "CODEX_HOME",
        "SystemRoot",
        "WINDIR",
    ]);
    if let Some(path) = tirith_core::trusted_child::sanitized_ambient_path() {
        spec = spec.env("PATH", path);
    }
    match tirith_core::trusted_child::run(executable, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        ChildOutcome::SpawnError(reason) => Err(format!("failed to start: {reason}")),
        ChildOutcome::WaitError(reason) => Err(format!("wait failed: {reason}")),
        ChildOutcome::Timeout {
            cleanup_succeeded: true,
        } => Err("timed out after 30s — check installation".into()),
        ChildOutcome::Timeout {
            cleanup_succeeded: false,
        } => Err("timed out and process-tree cleanup failed — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: true,
            ..
        } => Err("output limit exceeded — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: false,
            ..
        } => Err("output limit exceeded and process-tree cleanup failed".into()),
    }
}

/// Create a timestamped backup of `path` when `force` is true and the file exists.
pub fn create_backup(path: &Path, scope_root: &Path, force: bool) -> Result<(), String> {
    if !force {
        return Ok(());
    }
    create_backup_impl(path, scope_root)
}

/// Create a timestamped backup unconditionally.
pub fn create_backup_always(path: &Path, scope_root: &Path) -> Result<(), String> {
    create_backup_impl(path, scope_root)
}

fn create_backup_impl(path: &Path, scope_root: &Path) -> Result<(), String> {
    let Some(content) = read_to_string_scoped(path, scope_root)? else {
        return Ok(());
    };
    let now = chrono::Local::now();
    let timestamp = now.format("%Y%m%d-%H%M%S");
    let backup_name = format!(
        "{}.tirith-backup-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        timestamp
    );
    let backup_path = path
        .parent()
        .ok_or_else(|| format!("no parent for {}", path.display()))?
        .join(&backup_name);

    // Backups are always owner-only, even if an attacker pre-created the
    // timestamped destination with a broader DACL.
    atomic_write_with_security(&backup_path, scope_root, &content, false)?;
    eprintln!("tirith: backup at {}", backup_path.display());

    cleanup_old_backups(path, scope_root)?;
    Ok(())
}

fn cleanup_old_backups(path: &Path, scope_root: &Path) -> Result<(), String> {
    let Some(parent) = validated_parent(path, scope_root, false)? else {
        return Ok(());
    };
    let stem = path
        .file_name()
        .ok_or_else(|| format!("no file name for {}", path.display()))?
        .to_string_lossy();
    let prefix = format!("{stem}.tirith-backup-");

    // The retained component handles omit FILE_SHARE_DELETE, so this path
    // enumeration cannot be redirected by replacing a checked parent.
    let mut backups: Vec<PathBuf> = match fs::read_dir(&parent.path) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .map(|e| e.path())
            .collect(),
        Err(error) => {
            return Err(format!(
                "enumerate backup directory {}: {error}",
                parent.path.display()
            ))
        }
    };

    if backups.len() <= 5 {
        return Ok(());
    }

    backups.sort();
    let to_remove = backups.len() - 5;
    for old in &backups[..to_remove] {
        // Reject a reparse-point or non-file entry immediately before removal.
        // Removing a checked name while all parent handles remain held keeps
        // deletion inside the validated directory chain.
        let checked = match open_existing(old) {
            Ok(Some(handle)) => handle,
            Ok(None) => continue,
            Err(error) => {
                eprintln!(
                    "tirith: could not validate old backup {}: {error}",
                    old.display()
                );
                continue;
            }
        };
        drop(checked);
        if let Err(error) = fs::remove_file(old) {
            eprintln!(
                "tirith: could not clean old backup {}: {error}",
                old.display()
            );
        }
    }
    drop(parent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_directory(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("skipping Windows symlink test: {error}");
                false
            }
        }
    }

    #[test]
    fn up_to_date_hook_refuses_reparse_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("hook.cmd"), "expected").unwrap();
        if !link_directory(outside.path(), &root.path().join("hooks")) {
            return;
        }

        let result = write_hook_script(
            &root.path().join("hooks/hook.cmd"),
            root.path(),
            "expected",
            false,
            true,
        );

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(outside.path().join("hook.cmd")).unwrap(),
            "expected"
        );
    }

    #[test]
    fn backup_and_retention_refuse_reparse_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("config.json"), "outside").unwrap();
        for i in 0..7 {
            fs::write(
                outside
                    .path()
                    .join(format!("config.json.tirith-backup-20260101-00000{i}")),
                "backup",
            )
            .unwrap();
        }
        if !link_directory(outside.path(), &root.path().join("configs")) {
            return;
        }
        let path = root.path().join("configs/config.json");

        assert!(create_backup(&path, root.path(), true).is_err());
        assert!(cleanup_old_backups(&path, root.path()).is_err());
        let backups = fs::read_dir(outside.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(backups, 7);
    }

    #[test]
    fn legitimate_backup_retention_keeps_five() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "data").unwrap();
        for i in 0..7 {
            fs::write(
                root.path()
                    .join(format!("config.json.tirith-backup-20260101-00000{i}")),
                "backup",
            )
            .unwrap();
        }

        cleanup_old_backups(&path, root.path()).unwrap();

        let backups = fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(backups, 5);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn cmd() -> tirith_core::trusted_child::TrustedExecutable {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        tirith_core::trusted_child::TrustedExecutable::from_absolute(
            &PathBuf::from(root).join("System32").join("cmd.exe"),
            &[],
        )
        .expect("trusted system cmd.exe")
    }

    #[test]
    fn windows_setup_runner_preserves_short_legitimate_output() {
        let output = run_cli_with(
            &cmd(),
            &["/D", "/S", "/C", "<nul set /p =setup-ok"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(5), 64, 64),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"setup-ok");
    }

    #[test]
    fn windows_setup_runner_surfaces_output_limit() {
        let error = run_cli_with(
            &cmd(),
            &["/D", "/S", "/C", "<nul set /p =12345"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(5), 4, 64),
        )
        .unwrap_err();
        assert!(error.contains("output limit"));
    }
}
