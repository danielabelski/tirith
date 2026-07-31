//! Windows filesystem helpers for `tirith setup` — the same public API as
//! `fs_helpers.rs` using held Windows handles and explicit DACL handling.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
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
    FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

struct OwnedHandle(HANDLE);

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

fn open_directory(path: &Path) -> Result<OwnedHandle, String> {
    let path_wide = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| format!("open directory handle {}: {e}", path.display()))?;
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
    Ok(owned)
}

fn open_or_create_directory(
    current: &mut PathBuf,
    component: &OsStr,
    handles: &mut Vec<OwnedHandle>,
) -> Result<(), String> {
    current.push(component);
    let component_handle = match open_directory(current) {
        Ok(handle) => handle,
        Err(open_error) if !current.exists() => {
            let current_wide = wide(current);
            unsafe { CreateDirectoryW(PCWSTR(current_wide.as_ptr()), None) }.map_err(|e| {
                format!(
                    "create directory {} after {open_error}: {e}",
                    current.display()
                )
            })?;
            open_directory(current)?
        }
        Err(error) => return Err(error),
    };
    handles.push(component_handle);
    Ok(())
}

fn validated_parent(path: &Path, scope_root: &Path) -> Result<ValidatedParent, String> {
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
    let mut current = anchor
        .canonicalize()
        .map_err(|e| format!("canonicalize trusted root {}: {e}", anchor.display()))?;
    let mut handles = vec![open_directory(&current)?];

    for component in missing.iter().rev() {
        open_or_create_directory(&mut current, component, &mut handles)?;
    }
    // Capture the final path of the requested scope root itself, rather than
    // its nearest pre-existing ancestor when the scope had to be created.
    let root_final = final_path(handles.last().expect("root handle exists").0)?;

    for component in relative_parts.iter().filter_map(|part| match part {
        std::path::Component::Normal(name) => Some(*name),
        _ => None,
    }) {
        open_or_create_directory(&mut current, component, &mut handles)?;
    }

    let parent_final = final_path(handles.last().expect("anchor handle exists").0)?;
    if !path_rules::final_path_within(&root_final, &parent_final) {
        return Err(format!(
            "{} resolves outside trusted setup root",
            current.display()
        ));
    }
    Ok(ValidatedParent {
        path: current,
        handles,
        root_final,
    })
}

fn open_existing(path: &Path) -> Result<Option<OwnedHandle>, String> {
    let path_wide = wide(path);
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (READ_CONTROL | FILE_READ_ATTRIBUTES).0,
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
    let parent = validated_parent(path, scope_root)?;
    let destination = parent.path.join(
        path.file_name()
            .ok_or_else(|| format!("no file name for {}", path.display()))?,
    );
    let existing = open_existing(&destination)?;
    let acl_source = path_rules::acl_source(existing.is_some());

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
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink — refusing to modify for safety",
                path.display()
            ));
        }
    }

    if path.exists() {
        let existing =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
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
pub fn create_backup(path: &Path, force: bool) -> Result<(), String> {
    if !force || !path.exists() {
        return Ok(());
    }
    create_backup_impl(path)
}

/// Create a timestamped backup unconditionally.
pub fn create_backup_always(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    create_backup_impl(path)
}

fn create_backup_impl(path: &Path) -> Result<(), String> {
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

    fs::copy(path, &backup_path).map_err(|e| {
        format!(
            "backup {} -> {}: {e}",
            path.display(),
            backup_path.display()
        )
    })?;
    eprintln!("tirith: backup at {}", backup_path.display());

    cleanup_old_backups(path);
    Ok(())
}

fn cleanup_old_backups(path: &Path) {
    let parent = match path.parent() {
        Some(p) => p,
        None => return,
    };
    let stem = match path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return,
    };
    let prefix = format!("{stem}.tirith-backup-");

    let mut backups: Vec<PathBuf> = match fs::read_dir(parent) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .map(|e| e.path())
            .collect(),
        Err(_) => return,
    };

    if backups.len() <= 5 {
        return;
    }

    backups.sort();
    let to_remove = backups.len() - 5;
    for old in &backups[..to_remove] {
        if let Err(e) = fs::remove_file(old) {
            eprintln!("tirith: could not clean old backup {}: {e}", old.display());
        }
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
