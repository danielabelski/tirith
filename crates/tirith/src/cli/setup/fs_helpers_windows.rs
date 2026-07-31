//! Windows filesystem helpers for `tirith setup` — the same public API as
//! `fs_helpers.rs` using held Windows handles and explicit DACL handling.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use super::fs_transaction::PublicationOutcome;
pub(crate) use super::fs_transaction::{
    transactional_update, transactional_update_checked, FileUpdate, TransactionOutcome,
};

#[path = "fs_helpers_windows_path.rs"]
mod path_rules;

use windows::core::{BOOL, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    ERROR_UNABLE_TO_MOVE_REPLACEMENT, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileAttributeTagInfo, FlushFileBuffers,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    MoveFileExW, ReplaceFileW, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, MOVEFILE_WRITE_THROUGH,
    OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
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

#[cfg(test)]
thread_local! {
    static REPLACE_FILE_TEST_HOOK: std::cell::RefCell<
        Option<Box<dyn FnMut(&Path, &Path, &Path) -> Result<(), u32>>>,
    > = std::cell::RefCell::new(None);
}

fn replace_file_call(
    destination: &Path,
    replacement: &Path,
    displaced: &Path,
) -> Result<(), windows::core::Error> {
    #[cfg(test)]
    if let Some(result) = REPLACE_FILE_TEST_HOOK.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|hook| hook(destination, replacement, displaced))
    }) {
        return result
            .map_err(|code| windows::core::Error::from_hresult(HRESULT::from_win32(code)));
    }

    let destination_wide = wide(destination);
    let replacement_wide = wide(replacement);
    let displaced_wide = wide(displaced);
    unsafe {
        ReplaceFileW(
            PCWSTR(destination_wide.as_ptr()),
            PCWSTR(replacement_wide.as_ptr()),
            PCWSTR(displaced_wide.as_ptr()),
            Default::default(),
            None,
            None,
        )
    }
}

fn unused_displaced_path(destination: &Path) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("no parent for {}", destination.display()))?;
    let stem = destination
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    for _ in 0..3 {
        let candidate = parent.join(format!(
            ".{stem}.tirith-displaced-{}",
            uuid::Uuid::new_v4().simple()
        ));
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(error) => {
                return Err(format!(
                    "inspect displaced-file recovery name {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
    Err("could not reserve an unused displaced-file recovery name".into())
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

fn reparse_tag(handle: HANDLE) -> Result<u32, String> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|error| format!("inspect reparse tag: {error}"))?;
    Ok(info.ReparseTag)
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
            let tag = reparse_tag(handle)?;
            let redirects = path_rules::reparse_tag_redirects_name(tag);
            return Err(format!(
                "{} is a reparse point (tag 0x{tag:08x}, name_redirect={redirects}) — refusing for safety",
                path.display(),
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
            let tag = reparse_tag(handle)?;
            let redirects = path_rules::reparse_tag_redirects_name(tag);
            return Err(format!(
                "{} is a reparse point (tag 0x{tag:08x}, name_redirect={redirects}) — refusing for safety",
                path.display(),
            ));
        }
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(Some(owned))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileGeneration {
    volume_serial: u32,
    file_index: u64,
    size: u64,
    last_write: u64,
}

impl FileGeneration {
    fn from_info(info: &BY_HANDLE_FILE_INFORMATION) -> Self {
        Self {
            volume_serial: info.dwVolumeSerialNumber,
            file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            last_write: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
                | info.ftLastWriteTime.dwLowDateTime as u64,
        }
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.volume_serial == other.volume_serial && self.file_index == other.file_index
    }
}

fn generation_at(path: &Path) -> Option<FileGeneration> {
    let handle = open_existing(path).ok().flatten()?;
    let info = handle_information(handle.0, path).ok()?;
    Some(FileGeneration::from_info(&info))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotGeneration {
    Absent,
    Present(FileGeneration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlatformSnapshot {
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) mode: Option<u32>,
    generation: SnapshotGeneration,
    security_descriptor: Option<Vec<u8>>,
}

impl PlatformSnapshot {
    fn absent() -> Self {
        Self {
            bytes: None,
            mode: None,
            generation: SnapshotGeneration::Absent,
            security_descriptor: None,
        }
    }
}

fn handle_information(handle: HANDLE, path: &Path) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|error| format!("inspect {} through open handle: {error}", path.display()))?;
    Ok(info)
}

fn dacl_descriptor(handle: HANDLE, path: &Path) -> Result<Vec<u8>, String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(format!(
            "read {} DACL security metadata: error {}",
            path.display(),
            status.0
        ));
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let length = unsafe { GetSecurityDescriptorLength(descriptor.0) } as usize;
    if length == 0 {
        return Err(format!("read {} empty security descriptor", path.display()));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(descriptor.0 .0.cast::<u8>(), length).to_vec() };
    Ok(bytes)
}

fn snapshot_destination(
    destination: &Path,
    display_path: &Path,
) -> Result<PlatformSnapshot, String> {
    for _ in 0..3 {
        let Some(handle) = open_existing(destination)? else {
            return Ok(PlatformSnapshot::absent());
        };
        let before = handle_information(handle.0, display_path)?;
        let before_generation = FileGeneration::from_info(&before);
        if before_generation.size > super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 {
            return Err(format!(
                "{} exceeds setup file limit of {} bytes",
                display_path.display(),
                super::fs_transaction::MAX_SETUP_FILE_BYTES
            ));
        }
        let security_before = dacl_descriptor(handle.0, display_path)?;
        let mut file = handle.into_file();
        let raw_handle = HANDLE(file.as_raw_handle());
        let mut bytes = Vec::with_capacity(before_generation.size as usize);
        (&mut file)
            .take(super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                format!(
                    "read {} through validated handle: {error}",
                    display_path.display()
                )
            })?;
        if bytes.len() > super::fs_transaction::MAX_SETUP_FILE_BYTES {
            return Err(format!(
                "{} exceeds setup file limit of {} bytes",
                display_path.display(),
                super::fs_transaction::MAX_SETUP_FILE_BYTES
            ));
        }
        let after = handle_information(raw_handle, display_path)?;
        let after_generation = FileGeneration::from_info(&after);
        let security_after = dacl_descriptor(raw_handle, display_path)?;
        if before_generation == after_generation
            && bytes.len() as u64 == after_generation.size
            && security_before == security_after
        {
            return Ok(PlatformSnapshot {
                bytes: Some(bytes),
                mode: None,
                generation: SnapshotGeneration::Present(after_generation),
                security_descriptor: Some(security_after),
            });
        }
    }
    Err(format!(
        "{} changed repeatedly while being read; retry setup",
        display_path.display()
    ))
}

pub(crate) fn read_snapshot_scoped(
    path: &Path,
    scope_root: &Path,
) -> Result<PlatformSnapshot, String> {
    let Some(parent) = validated_parent(path, scope_root, false)? else {
        return Ok(PlatformSnapshot::absent());
    };
    let destination = parent.path.join(
        path.file_name()
            .ok_or_else(|| format!("no file name for {}", path.display()))?,
    );
    let snapshot = snapshot_destination(&destination, path)?;
    drop(parent);
    Ok(snapshot)
}

/// Read through validated, retained no-reparse parent handles with a strict
/// cap. Missing files or parents return `None` without creating directories.
pub fn read_to_string_scoped(path: &Path, scope_root: &Path) -> Result<Option<String>, String> {
    read_snapshot_scoped(path, scope_root)?
        .bytes
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))
        })
        .transpose()
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

fn stable_lock_path(parent: &ValidatedParent, destination: &Path) -> Result<PathBuf, String> {
    let name = destination
        .file_name()
        .ok_or_else(|| format!("no file name for {}", destination.display()))?;
    let mut hasher = Sha256::new();
    for unit in name.encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    let mut lock_name = String::from(".tirith-setup-lock-");
    for byte in hasher.finalize() {
        let _ = write!(&mut lock_name, "{byte:02x}");
    }
    Ok(parent.path.join(lock_name))
}

fn open_lock_file(parent: &ValidatedParent, destination: &Path) -> Result<fs::File, String> {
    let lock_path = stable_lock_path(parent, destination)?;
    let lock_wide = wide(&lock_path);
    let owner_only = owner_only_descriptor()?;
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: owner_only.0 .0,
        bInheritHandle: BOOL(0),
    };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(lock_wide.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&security_attributes),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| format!("open stable setup lock {}: {error}", lock_path.display()))?;
    let owned = OwnedHandle(handle);
    let info = handle_information(handle, &lock_path)?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, false) {
        return Err(
            "stable setup lock is a reparse point or non-file — refusing for safety".into(),
        );
    }
    let file = owned.into_file();
    Ok(file)
}

fn open_lock(parent: &ValidatedParent, destination: &Path) -> Result<fs::File, String> {
    let file = open_lock_file(parent, destination)?;
    file.lock_exclusive()
        .map_err(|error| format!("lock setup destination: {error}"))?;
    Ok(file)
}

pub(crate) struct PlatformTransaction {
    parent: ValidatedParent,
    destination: PathBuf,
    display_path: PathBuf,
    _lock: fs::File,
    published_generation: std::cell::RefCell<Option<FileGeneration>>,
}

impl PlatformTransaction {
    pub(crate) fn begin(path: &Path, scope_root: &Path) -> Result<Self, String> {
        let parent = validated_parent(path, scope_root, true)?
            .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
        let destination = parent.path.join(
            path.file_name()
                .ok_or_else(|| format!("no file name for {}", path.display()))?,
        );
        let lock = open_lock(&parent, &destination)?;
        Ok(Self {
            parent,
            destination,
            display_path: path.to_path_buf(),
            _lock: lock,
            published_generation: std::cell::RefCell::new(None),
        })
    }

    #[cfg(test)]
    fn lock_is_contended(path: &Path, scope_root: &Path) -> Result<bool, String> {
        let parent = validated_parent(path, scope_root, true)?
            .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
        let destination = parent.path.join(
            path.file_name()
                .ok_or_else(|| format!("no file name for {}", path.display()))?,
        );
        let file = open_lock_file(&parent, &destination)?;
        match file.try_lock_exclusive() {
            Ok(()) => {
                let _ = fs2::FileExt::unlock(&file);
                Ok(false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(format!("probe setup destination lock: {error}")),
        }
    }

    pub(crate) fn read_snapshot(&self) -> Result<PlatformSnapshot, String> {
        snapshot_destination(&self.destination, &self.display_path)
    }

    pub(crate) fn validate_snapshot(&self, expected: &PlatformSnapshot) -> Result<(), String> {
        let parent_final = final_path(
            self.parent
                .handles
                .last()
                .expect("validated parent has a handle")
                .0,
        )?;
        if !path_rules::final_path_within(&self.parent.root_final, &parent_final) {
            return Err("destination parent moved outside trusted setup root".into());
        }
        let live = self.read_snapshot()?;
        if &live != expected {
            return Err(format!(
                "{} changed while setup was preparing the update; no changes were published",
                self.display_path.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_temp<'a>(
        &'a self,
        bytes: &[u8],
        _mode: u32,
        _preserve_existing_mode: bool,
        _snapshot: &PlatformSnapshot,
    ) -> Result<TempGuard<'a>, String> {
        let path = self.parent.path.join(format!(
            ".tirith-setup-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        let path_wide = wide(&path);
        let owner_only = owner_only_descriptor()?;
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: owner_only.0 .0,
            bInheritHandle: BOOL(0),
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ,
                Some(&security_attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| format!("create exclusive owner-only temporary file: {error}"))?;
        let owned = OwnedHandle(handle);
        let generation = FileGeneration::from_info(&handle_information(handle, &path)?);
        let mut guard = TempGuard {
            _transaction: self,
            path,
            file: Some(owned.into_file()),
            generation,
            armed: true,
        };
        let path_for_info = guard.path.clone();
        let synced_generation = {
            let file = guard.file.as_mut().expect("new temp owns file");
            file.write_all(bytes)
                .map_err(|error| format!("write temporary file: {error}"))?;
            unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }
                .map_err(|error| format!("flush temporary file before publication: {error}"))?;
            FileGeneration::from_info(&handle_information(
                HANDLE(file.as_raw_handle()),
                &path_for_info,
            )?)
        };
        guard.generation = synced_generation;
        Ok(guard)
    }

    pub(crate) fn publish(
        &self,
        mut temp: TempGuard<'_>,
        expected: &PlatformSnapshot,
        #[cfg(test)] test_hook: &mut impl FnMut(super::fs_transaction::TestStage) -> Result<(), String>,
    ) -> Result<PublicationOutcome, String> {
        let expected_exists = expected.bytes.is_some();
        // ReplaceFileW documents two failure modes in which it may already
        // have moved one or both names. Keep a private, flushed copy of the
        // locked snapshot until the API has returned so those failures cannot
        // erase both the original and the transaction artifacts.
        let mut recovery = if expected_exists {
            Some(self.create_backup_impl(expected, false)?)
        } else {
            None
        };

        // Keep the write handle non-share-delete while recovery is prepared,
        // then close and verify that the UUID name still identifies the exact
        // flushed file before handing the path to ReplaceFileW/MoveFileExW.
        temp.file.take();
        temp.validate_name()?;

        // Creating the recovery copy can take time, so repeat the no-follow
        // generation/content/DACL check immediately before publication.
        self.validate_snapshot(expected)?;
        #[cfg(test)]
        test_hook(super::fs_transaction::TestStage::PublicationReady)?;

        let temp_wide = wide(&temp.path);
        let destination_wide = wide(&self.destination);
        match path_rules::publication_kind(expected_exists) {
            path_rules::PublicationKind::ReplacePreservingMetadata => {
                let SnapshotGeneration::Present(expected_generation) = &expected.generation else {
                    unreachable!("existing snapshot has a generation")
                };
                let displaced_path = unused_displaced_path(&self.destination)?;
                if let Err(error) =
                    replace_file_call(&self.destination, &temp.path, &displaced_path)
                {
                    let names_may_have_changed =
                        is_win32(&error, ERROR_UNABLE_TO_MOVE_REPLACEMENT.0)
                            || is_win32(&error, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2.0);
                    if names_may_have_changed {
                        let recovery_path = recovery
                            .as_ref()
                            .expect("existing replacement has a recovery snapshot")
                            .path
                            .clone();
                        let destination_generation = generation_at(&self.destination);
                        let replacement_generation = generation_at(&temp.path);
                        let displaced_generation = generation_at(&displaced_path);

                        // With an API backup name, ERROR_UNABLE_TO_MOVE_REPLACEMENT
                        // documents that both original names remain. Prove that
                        // exact identity state before treating it as a clean
                        // failure; otherwise retain every artifact.
                        if is_win32(&error, ERROR_UNABLE_TO_MOVE_REPLACEMENT.0)
                            && destination_generation.as_ref() == Some(expected_generation)
                            && replacement_generation.as_ref() == Some(&temp.generation)
                            && displaced_generation.is_none()
                        {
                            return Err(format!(
                                "replace {} failed before moving either identity: {error}",
                                self.destination.display()
                            ));
                        }

                        let _ = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery();
                        temp.armed = false;
                        return Err(format!(
                            "replace {} entered a partial Windows failure state ({error}); retained the locked original snapshot at {}, destination identity {:?}, replacement identity {:?} at {}, and displaced identity {:?} at {}",
                            self.destination.display(),
                            recovery_path.display(),
                            destination_generation,
                            replacement_generation,
                            temp.path.display(),
                            displaced_generation,
                            displaced_path.display()
                        ));
                    }
                    return Err(format!(
                        "replace {} while preserving its DACL: {error}",
                        self.destination.display()
                    ));
                }

                let installed = generation_at(&self.destination);
                let displaced = generation_at(&displaced_path);
                if installed.as_ref() != Some(&temp.generation)
                    || displaced.as_ref() != Some(expected_generation)
                {
                    // ReplaceFileW's backup captured the exact competing file.
                    // Atomically restore it and keep our attempted replacement
                    // at the original private temp name.
                    let stable = generation_at(&self.destination) == installed
                        && generation_at(&displaced_path) == displaced
                        && generation_at(&temp.path).is_none();
                    if stable
                        && replace_file_call(&self.destination, &displaced_path, &temp.path).is_ok()
                        && generation_at(&self.destination) == displaced
                        && generation_at(&temp.path) == installed
                    {
                        return Err(format!(
                            "{} or its prepared replacement changed at publication; restored the competing destination and published nothing",
                            self.destination.display()
                        ));
                    }

                    let recovery_path = recovery
                        .as_mut()
                        .expect("existing replacement has a recovery snapshot")
                        .retain_for_recovery();
                    temp.armed = false;
                    return Err(format!(
                        "{} or its prepared replacement changed at publication and rollback could not be proven; retained recovery snapshot {}, replacement {}, and displaced identity {}",
                        self.destination.display(),
                        recovery_path.display(),
                        temp.path.display(),
                        displaced_path.display()
                    ));
                }

                // The exact flushed replacement is now installed and the API
                // backup holds the exact displaced generation. Record that
                // before cleanup so a cleanup problem is handled as a
                // post-publication recovery outcome and still receives the
                // mandatory FlushFileBuffers barrier in the shared layer.
                self.published_generation
                    .replace(Some(temp.generation.clone()));

                if generation_at(&displaced_path).as_ref() == Some(expected_generation) {
                    if let Err(error) = fs::remove_file(&displaced_path) {
                        let recovery_path = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery();
                        temp.armed = false;
                        return Ok(PublicationOutcome::RecoveryRequired(format!(
                            "published {} but could not remove displaced identity {} ({error}); retained recovery snapshot {}",
                            self.destination.display(),
                            displaced_path.display(),
                            recovery_path.display()
                        )));
                    }
                } else {
                    let recovery_path = recovery
                        .as_mut()
                        .expect("existing replacement has a recovery snapshot")
                        .retain_for_recovery();
                    temp.armed = false;
                    return Ok(PublicationOutcome::RecoveryRequired(format!(
                        "published {} but displaced identity changed at {}; refusing cleanup and retaining recovery snapshot {}",
                        self.destination.display(),
                        displaced_path.display(),
                        recovery_path.display()
                    )));
                }
            }
            path_rules::PublicationKind::MoveWithoutReplacement => {
                // Omitting REPLACE_EXISTING gives expected-absent publication
                // an atomic never-overwrite guarantee.
                unsafe {
                    MoveFileExW(
                        PCWSTR(temp_wide.as_ptr()),
                        PCWSTR(destination_wide.as_ptr()),
                        MOVEFILE_WRITE_THROUGH,
                    )
                }
                .map_err(|error| {
                    format!(
                        "publish new destination {} without replacement: {error}",
                        self.destination.display()
                    )
                })?;
                self.published_generation
                    .replace(Some(temp.generation.clone()));
            }
        }
        if generation_at(&self.destination).as_ref() != Some(&temp.generation) {
            let recovery_path = recovery.as_mut().map(BackupGuard::retain_for_recovery);
            temp.armed = false;
            return Ok(PublicationOutcome::RecoveryRequired(format!(
                "published destination {} no longer identifies the prepared replacement; retained published state for recovery{}",
                self.destination.display(),
                recovery_path
                    .as_ref()
                    .map(|path| format!(" and original snapshot at {}", path.display()))
                    .unwrap_or_default()
            )));
        }
        temp.armed = false;
        Ok(PublicationOutcome::Clean)
    }

    pub(crate) fn sync_parent(&self) -> Result<(), String> {
        // ReplaceFileW's nominal WRITE_THROUGH flag is explicitly unsupported.
        // Re-open the installed identity with GENERIC_WRITE and use the
        // documented FlushFileBuffers durability barrier, which writes all
        // buffered information for this file to the device. Expected-absent
        // publication additionally uses MoveFileExW(MOVEFILE_WRITE_THROUGH).
        let destination_wide = wide(&self.destination);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(destination_wide.as_ptr()),
                FILE_GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| {
            format!(
                "open published destination {} for durability: {error}",
                self.destination.display()
            )
        })?;
        let owned = OwnedHandle(handle);
        let info = handle_information(handle, &self.destination)?;
        if !path_rules::attributes_are_safe(info.dwFileAttributes, false) {
            return Err(format!(
                "published destination {} changed before durability flush",
                self.destination.display()
            ));
        }
        let expected = self.published_generation.borrow().clone().ok_or_else(|| {
            "no published identity available for durability validation".to_string()
        })?;
        if FileGeneration::from_info(&info) != expected {
            return Err(format!(
                "published destination {} changed before durability flush",
                self.destination.display()
            ));
        }
        unsafe { FlushFileBuffers(handle) }.map_err(|error| {
            format!(
                "flush published destination {} after replacement: {error}",
                self.destination.display()
            )
        })?;
        let after = handle_information(handle, &self.destination)?;
        if FileGeneration::from_info(&after) != expected {
            return Err(format!(
                "published destination {} changed during durability flush",
                self.destination.display()
            ));
        }
        drop(owned);
        Ok(())
    }

    pub(crate) fn create_backup<'a>(
        &'a self,
        snapshot: &PlatformSnapshot,
    ) -> Result<BackupGuard<'a>, String> {
        self.create_backup_impl(snapshot, true)
    }

    fn create_backup_impl<'a>(
        &'a self,
        snapshot: &PlatformSnapshot,
        announce: bool,
    ) -> Result<BackupGuard<'a>, String> {
        let bytes = snapshot
            .bytes
            .as_deref()
            .ok_or_else(|| "cannot back up an absent destination".to_string())?;
        let name = format!(
            "{}.tirith-backup-{}-{}",
            self.destination
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            chrono::Local::now().format("%Y%m%d-%H%M%S"),
            uuid::Uuid::new_v4().simple()
        );
        let path = self.parent.path.join(name);
        let path_wide = wide(&path);
        let owner_only = owner_only_descriptor()?;
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: owner_only.0 .0,
            bInheritHandle: BOOL(0),
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ,
                Some(&security_attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| format!("create exclusive owner-only backup: {error}"))?;
        let owned = OwnedHandle(handle);
        let generation = FileGeneration::from_info(&handle_information(handle, &path)?);
        let mut guard = BackupGuard {
            _transaction: self,
            path,
            file: Some(owned.into_file()),
            generation,
            armed: true,
            announce_on_commit: announce,
        };
        let path_for_info = guard.path.clone();
        let synced_generation = {
            let file = guard.file.as_mut().expect("new backup owns file");
            file.write_all(bytes)
                .map_err(|error| format!("write backup from locked snapshot: {error}"))?;
            unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }
                .map_err(|error| format!("flush backup before update: {error}"))?;
            FileGeneration::from_info(&handle_information(
                HANDLE(file.as_raw_handle()),
                &path_for_info,
            )?)
        };
        guard.generation = synced_generation;
        Ok(guard)
    }

    pub(crate) fn cleanup_old_backups(&self, keep: Option<&BackupGuard<'_>>) -> Result<(), String> {
        let stem = self
            .destination
            .file_name()
            .ok_or_else(|| format!("no file name for {}", self.destination.display()))?
            .to_string_lossy();
        let prefix = format!("{stem}.tirith-backup-");
        let entries = fs::read_dir(&self.parent.path)
            .map_err(|error| {
                format!(
                    "enumerate backup directory {}: {error}",
                    self.parent.path.display()
                )
            })?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        let keep_present = keep.is_some_and(|guard| entries.iter().any(|path| path == &guard.path));
        let mut backups = entries
            .into_iter()
            .filter(|path| keep.is_none_or(|guard| path != &guard.path))
            .collect::<Vec<_>>();
        backups.sort();
        let keep_slots = usize::from(keep_present);
        let remove_count = backups.len().saturating_sub(5 - keep_slots);
        for old in &backups[..remove_count] {
            match open_existing(old) {
                Ok(Some(checked)) => drop(checked),
                Ok(None) => continue,
                Err(error) => {
                    eprintln!(
                        "tirith: could not validate old backup {}: {error}",
                        old.display()
                    );
                    continue;
                }
            }
            if let Err(error) = fs::remove_file(old) {
                eprintln!(
                    "tirith: could not clean old backup {}: {error}",
                    old.display()
                );
            }
        }
        Ok(())
    }
}

pub(crate) struct TempGuard<'a> {
    _transaction: &'a PlatformTransaction,
    path: PathBuf,
    file: Option<fs::File>,
    generation: FileGeneration,
    armed: bool,
}

impl TempGuard<'_> {
    fn validate_name(&self) -> Result<(), String> {
        if generation_at(&self.path).as_ref() != Some(&self.generation) {
            return Err(
                "temporary setup file changed before publication; refusing for safety".into(),
            );
        }
        Ok(())
    }
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        self.file.take();
        if self.armed
            && generation_at(&self.path)
                .as_ref()
                .is_some_and(|live| live.same_identity(&self.generation))
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) struct BackupGuard<'a> {
    _transaction: &'a PlatformTransaction,
    path: PathBuf,
    file: Option<fs::File>,
    generation: FileGeneration,
    armed: bool,
    announce_on_commit: bool,
}

impl BackupGuard<'_> {
    pub(crate) fn commit(&mut self) {
        self.armed = false;
        if self.announce_on_commit {
            eprintln!("tirith: backup at {}", self.path.display());
        }
    }

    pub(crate) fn retain_for_recovery(&mut self) -> PathBuf {
        self.armed = false;
        self.path.clone()
    }
}

impl Drop for BackupGuard<'_> {
    fn drop(&mut self) {
        self.file.take();
        if self.armed
            && generation_at(&self.path)
                .as_ref()
                .is_some_and(|live| live.same_identity(&self.generation))
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Write a hook script. No executable bit needed on Windows.
pub fn write_hook_script(
    path: &Path,
    scope_root: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = transactional_update(path, scope_root, dry_run, |snapshot| {
        if let Some(existing) = snapshot.text(path)? {
            if existing == content {
                if dry_run {
                    eprintln!(
                        "[dry-run] would skip {} (already up to date)",
                        path.display()
                    );
                } else {
                    eprintln!("tirith: {} already configured, up to date", path.display());
                }
                return Ok(FileUpdate::unchanged());
            }
            if !force {
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: {} exists but content differs — use --force to update",
                        path.display()
                    );
                    return Ok(FileUpdate::unchanged());
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
        }
        Ok(FileUpdate::write_text(content.to_string(), 0o644))
    })?;
    if outcome == TransactionOutcome::Written {
        eprintln!("tirith: wrote {}", path.display());
    }
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

#[cfg(all(test, windows))]
mod tests {
    use super::super::fs_transaction::{transactional_update_with_hook, FileUpdate, TestStage};
    use super::*;

    fn symlink_directory_or_explicitly_skip(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => true,
            Err(error) => {
                eprintln!(
                    "SKIP symlink reparse coverage: Windows denied symlink creation ({error})"
                );
                false
            }
        }
    }

    fn symlink_file_or_explicitly_skip(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(error) => {
                eprintln!(
                    "SKIP backup reparse coverage: Windows denied symlink creation ({error})"
                );
                false
            }
        }
    }

    fn backup_paths(root: &Path) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    fn temporary_setup_paths(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                name.starts_with(".tirith-setup-") && name.ends_with(".tmp")
            })
            .collect()
    }

    fn displaced_paths(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .contains("tirith-displaced")
            })
            .collect()
    }

    struct ReplaceHookReset;

    impl Drop for ReplaceHookReset {
        fn drop(&mut self) {
            REPLACE_FILE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn with_replace_hook<T>(
        hook: impl FnMut(&Path, &Path, &Path) -> Result<(), u32> + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        REPLACE_FILE_TEST_HOOK.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        let _reset = ReplaceHookReset;
        run()
    }

    fn update_with_backup(path: &Path, root: &Path, content: &str) -> Result<(), String> {
        transactional_update(path, root, false, |_| {
            Ok(FileUpdate::write_text(content.to_string(), 0o644).with_backup(true))
        })?;
        Ok(())
    }

    fn descriptor_control(descriptor: &mut [u8]) -> u16 {
        use windows::Win32::Security::GetSecurityDescriptorControl;

        let descriptor = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
        control
    }

    fn create_protected_owner_only_file(path: &Path, content: &[u8]) {
        let path_wide = wide(path);
        let owner_only = owner_only_descriptor().unwrap();
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: owner_only.0 .0,
            bInheritHandle: BOOL(0),
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(&security_attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .unwrap();
        let mut file = OwnedHandle(handle).into_file();
        file.write_all(content).unwrap();
        unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }.unwrap();
    }

    #[test]
    fn up_to_date_hook_refuses_symlink_reparse_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("hook.cmd"), "expected").unwrap();
        if !symlink_directory_or_explicitly_skip(outside.path(), &root.path().join("hooks")) {
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
    fn junction_parent_swap_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let junction = root.path().join("junction");
        let command = format!(
            "mklink /J \"{}\" \"{}\"",
            junction.display(),
            outside.path().display()
        );
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/S", "/C", &command])
            .output()
            .expect("cmd.exe is available on Windows");
        assert!(
            output.status.success(),
            "junction coverage setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = junction.join("config.json");
        assert!(update_with_backup(&path, root.path(), "new").is_err());
        assert!(!outside.path().join("config.json").exists());
    }

    #[test]
    fn held_parent_handles_block_concurrent_parent_swap() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("configs");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("config.json");
        fs::write(&path, "before").unwrap();
        let moved = root.path().join("moved-configs");
        let mut swap_was_blocked = false;
        transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    swap_was_blocked = fs::rename(&parent, &moved).is_err();
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(swap_was_blocked);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert!(!moved.exists());
    }

    #[test]
    fn same_second_backups_are_unique_and_retention_keeps_five() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        update_with_backup(&path, root.path(), "one").unwrap();
        update_with_backup(&path, root.path(), "two").unwrap();
        assert_eq!(backup_paths(root.path()).len(), 2);
        for index in 0..6 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }
        let retained = backup_paths(root.path());
        assert_eq!(retained.len(), 5);
        assert!(retained
            .iter()
            .any(|backup| fs::read_to_string(backup).unwrap() == "value-4"));
    }

    #[test]
    fn precreated_regular_and_reparse_backup_names_are_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let regular = root
            .path()
            .join("config.json.tirith-backup-99999999-999999-attacker");
        fs::write(&regular, "attacker-regular").unwrap();
        let target = root.path().join("outside-secret");
        fs::write(&target, "attacker-target").unwrap();
        let link = root
            .path()
            .join("config.json.tirith-backup-99999999-999999-reparse");
        if !symlink_file_or_explicitly_skip(&target, &link) {
            return;
        }
        update_with_backup(&path, root.path(), "updated").unwrap();
        assert_eq!(fs::read_to_string(regular).unwrap(), "attacker-regular");
        assert_eq!(fs::read_to_string(target).unwrap(), "attacker-target");
    }

    #[test]
    fn non_cooperating_generation_change_is_rejected_and_temp_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    fs::write(&path, "editor-change").unwrap();
                }
                Ok(())
            },
        );
        assert!(result.unwrap_err().contains("changed while setup"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "editor-change");
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-")
                    && entry.path() != path
            }));
    }

    #[test]
    fn prepared_temp_handle_blocks_name_swap_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let mut deletion_was_blocked = false;
        transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let temp = fs::read_dir(root.path())
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            let name = entry.file_name();
                            let name = name.to_string_lossy();
                            name.starts_with(".tirith-setup-") && name.ends_with(".tmp")
                        })
                        .unwrap()
                        .path();
                    deletion_was_blocked = fs::remove_file(temp).is_err();
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(deletion_was_blocked);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
    }

    #[test]
    fn destination_swap_after_validation_is_detected_and_competitor_is_restored() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let original_hold = root.path().join("original-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap();
        let mut competitor_generation = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    fs::rename(&path, &original_hold).unwrap();
                    fs::write(&path, "competing-writer").unwrap();
                    competitor_generation = generation_at(&path);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "competing-writer");
        assert_eq!(generation_at(&path), competitor_generation);
        assert_eq!(fs::read_to_string(&original_hold).unwrap(), "original");
        assert_eq!(generation_at(&original_hold), Some(original_generation));
        assert!(temporary_setup_paths(root.path()).is_empty());
        assert!(displaced_paths(root.path()).is_empty());
    }

    #[test]
    fn temp_swap_after_validation_never_publishes_attacker_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let held_prepared = root.path().join("prepared-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap();
        let mut attacker_path = None;
        let mut attacker_generation = None;
        let mut prepared_generation = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    prepared_generation = generation_at(&temp);
                    fs::rename(&temp, &held_prepared).unwrap();
                    fs::write(&temp, "attacker-temp").unwrap();
                    attacker_generation = generation_at(&temp);
                    attacker_path = Some(temp);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(generation_at(&path), Some(original_generation));
        let attacker_path = attacker_path.unwrap();
        assert_eq!(fs::read_to_string(&attacker_path).unwrap(), "attacker-temp");
        assert_eq!(generation_at(&attacker_path), attacker_generation);
        assert_eq!(fs::read_to_string(&held_prepared).unwrap(), "tirith-update");
        assert_eq!(generation_at(&held_prepared), prepared_generation);
    }

    #[test]
    fn unable_to_move_replacement_is_verified_as_clean_failure() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap();

        let error = with_replace_hook(
            |_destination, _replacement, _displaced| Err(ERROR_UNABLE_TO_MOVE_REPLACEMENT.0),
            || {
                transactional_update(&path, root.path(), false, |_| {
                    Ok(FileUpdate::write_text("tirith-update".into(), 0o644))
                })
                .unwrap_err()
            },
        );

        assert!(error.contains("before moving either identity"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(generation_at(&path), Some(original_generation));
        assert!(temporary_setup_paths(root.path()).is_empty());
        assert!(displaced_paths(root.path()).is_empty());
        assert!(backup_paths(root.path()).is_empty());
    }

    #[test]
    fn unable_to_move_replacement_2_retains_exact_identity_recovery() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap();

        let error = with_replace_hook(
            |destination, _replacement, displaced| {
                fs::rename(destination, displaced).unwrap();
                Err(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2.0)
            },
            || {
                transactional_update(&path, root.path(), false, |_| {
                    Ok(FileUpdate::write_text("tirith-update".into(), 0o644))
                })
                .unwrap_err()
            },
        );

        assert!(error.contains("partial Windows failure state"));
        assert!(!path.exists());
        let displaced = displaced_paths(root.path());
        assert_eq!(displaced.len(), 1);
        assert_eq!(fs::read_to_string(&displaced[0]).unwrap(), "original");
        assert_eq!(generation_at(&displaced[0]), Some(original_generation));
        let prepared = temporary_setup_paths(root.path());
        assert_eq!(prepared.len(), 1);
        assert_eq!(fs::read_to_string(&prepared[0]).unwrap(), "tirith-update");
        let recovery = backup_paths(root.path());
        assert_eq!(recovery.len(), 1);
        assert_eq!(fs::read_to_string(&recovery[0]).unwrap(), "original");
    }

    #[test]
    fn publication_failure_rolls_back_only_its_backup_and_temp() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::SnapshotValidated {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(backup_paths(root.path()).is_empty());
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-")
            }));
    }

    fn wait_for_marker(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for subprocess marker {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn subprocess_lock_child() {
        let Some(role) = std::env::var_os("TIRITH_SETUP_LOCK_CHILD_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("TIRITH_SETUP_LOCK_ROOT").unwrap());
        let path = root.join("config.txt");
        match role.to_string_lossy().as_ref() {
            "holder" => {
                let entered = root.join("holder-entered");
                let release = root.join("release-holder");
                transactional_update_with_hook(
                    &path,
                    &root,
                    |snapshot| {
                        let mut content = snapshot.text(&path)?.unwrap().to_string();
                        content.push_str("-holder");
                        Ok(FileUpdate::write_text(content, 0o644))
                    },
                    |stage| {
                        if stage == TestStage::TempSynced {
                            fs::write(&entered, b"locked").unwrap();
                            wait_for_marker(&release);
                        }
                        Ok(())
                    },
                )
                .unwrap();
            }
            "contender" => {
                assert!(PlatformTransaction::lock_is_contended(&path, &root).unwrap());
                fs::write(root.join("contender-observed-lock"), b"contended").unwrap();
                transactional_update(&path, &root, false, |snapshot| {
                    let mut content = snapshot.text(&path)?.unwrap().to_string();
                    content.push_str("-contender");
                    Ok(FileUpdate::write_text(content, 0o644))
                })
                .unwrap();
            }
            other => panic!("unknown setup lock child role {other}"),
        }
    }

    #[test]
    fn cooperative_transactions_overlap_in_distinct_processes_and_recompute() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.txt");
        fs::write(&path, "base").unwrap();
        let test_binary = std::env::current_exe().unwrap();
        let test_name = "cli::setup::fs_helpers::tests::subprocess_lock_child";

        let mut holder = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "holder")
            .env("TIRITH_SETUP_LOCK_ROOT", root.path())
            .spawn()
            .unwrap();
        wait_for_marker(&root.path().join("holder-entered"));

        let mut contender = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "contender")
            .env("TIRITH_SETUP_LOCK_ROOT", root.path())
            .spawn()
            .unwrap();
        wait_for_marker(&root.path().join("contender-observed-lock"));
        assert!(holder.try_wait().unwrap().is_none());
        assert!(contender.try_wait().unwrap().is_none());

        fs::write(root.path().join("release-holder"), b"release").unwrap();
        assert!(holder.wait().unwrap().success());
        assert!(contender.wait().unwrap().success());
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("-holder") && content.contains("-contender"));
    }

    #[test]
    fn cooperative_transactions_serialize_and_recompute() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.txt");
        fs::write(&path, "base").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for suffix in ["-one", "-two"] {
            let path = path.clone();
            let root = root.path().to_path_buf();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                transactional_update(&path, &root, false, |snapshot| {
                    let mut content = snapshot.text(&path)?.unwrap().to_string();
                    content.push_str(suffix);
                    Ok(FileUpdate::write_text(content, 0o644))
                })
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let result = fs::read_to_string(path).unwrap();
        assert!(result.contains("-one") && result.contains("-two"));
    }

    #[test]
    fn oversized_snapshot_is_rejected_at_cap_plus_one() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("huge.json");
        fs::write(
            &path,
            vec![b'x'; super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(read_to_string_scoped(&path, root.path()).is_err());
    }

    #[test]
    fn transformed_payload_cap_is_enforced_before_parent_creation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing").join("too-large.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap_err();
        assert!(error.contains("setup file limit"));
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn transformed_payload_exact_cap_is_accepted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exact-cap.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES);
        transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap();
        assert_eq!(fs::metadata(path).unwrap().len(), payload.len() as u64);
    }

    #[test]
    fn replace_file_preserves_original_dacl_descriptor() {
        use windows::Win32::Security::SE_DACL_PROTECTED;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let before_handle = open_existing(&path).unwrap().unwrap();
        let mut before = dacl_descriptor(before_handle.0, &path).unwrap();
        assert_eq!(
            descriptor_control(&mut before) & SE_DACL_PROTECTED.0,
            0,
            "fixture must exercise an inheriting DACL"
        );
        drop(before_handle);
        transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("after".into(), 0o644))
        })
        .unwrap();
        let after_handle = open_existing(&path).unwrap().unwrap();
        let after = dacl_descriptor(after_handle.0, &path).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn replace_file_preserves_protected_dacl_descriptor() {
        use windows::Win32::Security::SE_DACL_PROTECTED;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        create_protected_owner_only_file(&path, b"before");
        let before_handle = open_existing(&path).unwrap().unwrap();
        let mut before = dacl_descriptor(before_handle.0, &path).unwrap();
        assert_ne!(
            descriptor_control(&mut before) & SE_DACL_PROTECTED.0,
            0,
            "fixture must exercise a protected DACL"
        );
        drop(before_handle);
        transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("after".into(), 0o644))
        })
        .unwrap();
        let after_handle = open_existing(&path).unwrap().unwrap();
        let after = dacl_descriptor(after_handle.0, &path).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn backup_dacl_is_protected_and_owner_only() {
        use windows::Win32::Security::{
            AclSizeInformation, GetAclInformation, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, ACL, ACL_SIZE_INFORMATION, SE_DACL_PROTECTED,
        };

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        update_with_backup(&path, root.path(), "after").unwrap();
        let backup = backup_paths(root.path()).pop().unwrap();
        let handle = open_existing(&backup).unwrap().unwrap();
        let mut descriptor = dacl_descriptor(handle.0, &backup).unwrap();
        let descriptor = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
        assert_ne!(control & SE_DACL_PROTECTED.0, 0);
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .unwrap();
        assert!(present.as_bool() && !dacl.is_null());
        let mut size = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .unwrap();
        assert_eq!(size.AceCount, 1);
    }

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
