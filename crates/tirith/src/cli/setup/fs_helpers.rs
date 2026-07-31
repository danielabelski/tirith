//! Filesystem helpers for `tirith setup` — atomic writes, hook scripts,
//! directory validation, CLI subprocess runner, and backup management.

use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use super::fs_transaction::PublicationOutcome;
pub(crate) use super::fs_transaction::{
    transactional_update, transactional_update_checked, FileUpdate, TransactionOutcome,
};

struct ScopedParent {
    dir: fs::File,
    name: CString,
}

fn c_name(name: &OsStr) -> Result<CString, String> {
    CString::new(name.as_bytes()).map_err(|_| "path component contains NUL".to_string())
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| format!("current_dir: {e}"))
    }
}

fn relative_components<'a>(path: &'a Path, root: &Path) -> Result<Vec<&'a OsStr>, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "{} is outside trusted setup root {}",
            path.display(),
            root.display()
        )
    })?;
    relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(format!(
                "{} contains a non-normal path component",
                path.display()
            )),
        })
        .collect()
}

fn open_dir(path: &Path) -> Result<fs::File, String> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains NUL", path.display()))?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open trusted root {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn open_dir_at(parent: &fs::File, name: &CString) -> std::io::Result<fs::File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

/// Open the destination parent beneath an explicitly trusted root. The root is
/// canonicalized once (allowing normal platform aliases such as macOS `/var`),
/// while every attacker-controlled descendant is traversed with `O_NOFOLLOW`.
fn scoped_parent(
    path: &Path,
    scope_root: &Path,
    create: bool,
) -> Result<Option<ScopedParent>, String> {
    let path = absolute(path)?;
    let root = absolute(scope_root)?;
    let components = relative_components(&path, &root)?;
    let (name, parents) = components
        .split_last()
        .ok_or_else(|| format!("{} names the trusted root, not a file", path.display()))?;

    let mut anchor = root.clone();
    let mut missing_root = Vec::new();
    while !anchor.exists() {
        let component = anchor
            .file_name()
            .ok_or_else(|| format!("cannot resolve trusted root {}", root.display()))?;
        missing_root.push(component.to_os_string());
        if !anchor.pop() {
            return Err(format!("cannot resolve trusted root {}", root.display()));
        }
    }
    let canonical_root = anchor
        .canonicalize()
        .map_err(|e| format!("canonicalize trusted root {}: {e}", anchor.display()))?;
    let mut dir = open_dir(&canonical_root)?;

    for component in missing_root
        .iter()
        .rev()
        .map(|part| part.as_os_str())
        .chain(parents.iter().copied())
    {
        let component = c_name(component)?;
        match open_dir_at(&dir, &component) {
            Ok(next) => dir = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), component.as_ptr(), 0o755) };
                let created = rc == 0;
                if rc < 0 {
                    let mkdir_error = std::io::Error::last_os_error();
                    if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(format!(
                            "create directory component {} below {}: {mkdir_error}",
                            component.to_string_lossy(),
                            canonical_root.display()
                        ));
                    }
                }
                if created {
                    // `mkdirat` only makes the entry visible. Persist the
                    // containing directory before descending so a crash cannot
                    // leave a published file whose newly-created ancestor was
                    // never committed to stable storage.
                    dir.sync_all().map_err(|error| {
                        format!(
                            "sync directory after creating component {} below {}: {error}",
                            component.to_string_lossy(),
                            canonical_root.display()
                        )
                    })?;
                }
                dir = open_dir_at(&dir, &component).map_err(|e| {
                    format!(
                        "open directory component {} below {} without following links: {e}",
                        component.to_string_lossy(),
                        canonical_root.display()
                    )
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "open directory component {} below {} without following links: {error}",
                    component.to_string_lossy(),
                    canonical_root.display()
                ));
            }
        }
    }

    Ok(Some(ScopedParent {
        dir,
        name: c_name(name)?,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableFileState {
    identity: FileIdentity,
    size: u64,
    mode: u32,
    digest: [u8; 32],
}

fn open_stable_file_at(
    parent: &fs::File,
    name: &CStr,
) -> Result<Option<(fs::File, StableFileState)>, String> {
    open_stable_file_at_with_access(parent, name, libc::O_RDONLY)
}

fn open_stable_file_at_with_access(
    parent: &fs::File,
    name: &CStr,
    access: libc::c_int,
) -> Result<Option<(fs::File, StableFileState)>, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "open publication identity without following links: {error}"
        ));
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|error| format!("inspect publication identity: {error}"))?;
    if !before.is_file() || before.len() > super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 {
        return Err("publication identity is not a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read publication identity: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect publication identity: {error}"))?;
    if before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.len() as u64 != after.len()
    {
        return Err("publication identity changed while it was inspected".into());
    }
    let state = StableFileState {
        identity: FileIdentity::from_metadata(&after),
        size: after.len(),
        mode: after.mode() & 0o7777,
        digest: Sha256::digest(&bytes).into(),
    };
    Ok(Some((file, state)))
}

fn stable_state_at(parent: &fs::File, name: &CStr) -> Result<Option<StableFileState>, String> {
    open_stable_file_at(parent, name).map(|opened| opened.map(|(_, state)| state))
}

fn stable_state_from_snapshot(snapshot: &PlatformSnapshot) -> Option<StableFileState> {
    let SnapshotGeneration::Present(generation) = &snapshot.generation else {
        return None;
    };
    let bytes = snapshot.bytes.as_ref()?;
    Some(StableFileState {
        identity: FileIdentity {
            device: generation.device,
            inode: generation.inode,
        },
        size: bytes.len() as u64,
        mode: snapshot.mode.unwrap_or(0) & 0o7777,
        digest: Sha256::digest(bytes).into(),
    })
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileGeneration {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn exchange_names(parent: &fs::File, left: &CStr, right: &CStr) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    return Err("this Unix platform has no atomic pathname-exchange API".into());

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    if result < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn move_no_replace(parent: &fs::File, source: &CStr, destination: &CStr) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    return Err("this Unix platform has no atomic no-replace rename API".into());

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    if result < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

impl FileGeneration {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
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
}

impl PlatformSnapshot {
    fn absent() -> Self {
        Self {
            bytes: None,
            mode: None,
            generation: SnapshotGeneration::Absent,
        }
    }
}

fn snapshot_from_parent(
    parent: &ScopedParent,
    display_path: &Path,
) -> Result<PlatformSnapshot, String> {
    // A non-cooperating writer may mutate while we read. Retry a bounded
    // number of times until the same handle has stable generation metadata
    // before and after the exact, capped read.
    for _ in 0..3 {
        let fd = unsafe {
            libc::openat(
                parent.dir.as_raw_fd(),
                parent.name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(PlatformSnapshot::absent());
            }
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Err(format!(
                    "{} is a symlink — refusing to modify for safety",
                    display_path.display()
                ));
            }
            return Err(format!(
                "open {} without following links: {error}",
                display_path.display()
            ));
        }

        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let before = file.metadata().map_err(|error| {
            format!(
                "stat {} through open handle: {error}",
                display_path.display()
            )
        })?;
        if !before.is_file() {
            return Err(format!(
                "{} is not a regular file — refusing for safety",
                display_path.display()
            ));
        }
        if before.len() > super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 {
            return Err(format!(
                "{} exceeds setup file limit of {} bytes",
                display_path.display(),
                super::fs_transaction::MAX_SETUP_FILE_BYTES
            ));
        }

        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                format!(
                    "read {} through open handle: {error}",
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
        let after = file.metadata().map_err(|error| {
            format!(
                "restat {} through open handle: {error}",
                display_path.display()
            )
        })?;
        let before_generation = FileGeneration::from_metadata(&before);
        let after_generation = FileGeneration::from_metadata(&after);
        if before_generation == after_generation && bytes.len() as u64 == after.len() {
            return Ok(PlatformSnapshot {
                bytes: Some(bytes),
                mode: Some(after.mode() & 0o7777),
                generation: SnapshotGeneration::Present(after_generation),
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
    let Some(parent) = scoped_parent(path, scope_root, false)? else {
        return Ok(PlatformSnapshot::absent());
    };
    snapshot_from_parent(&parent, path)
}

/// Read a setup-managed text file through the same root-confined, no-follow
/// boundary used for writes. Missing files or parents return `None` without
/// creating directories; unsafe components are errors even for dry runs and
/// idempotent early returns.
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
    scoped_parent(path, scope_root, false).map(|parent| parent.is_some())
}

/// Write `content` to `path` atomically via temp+rename.
///
/// Uses `O_EXCL` (`create_new`) to prevent clobbering stale temp files.
/// Retries up to 3 times on collision. If `path` already exists as a
/// regular file, its permissions are preserved; otherwise `mode` is used.
/// Refuses to overwrite a symlink target.
#[cfg(test)]
pub fn atomic_write(
    path: &Path,
    scope_root: &Path,
    content: &str,
    mode: u32,
) -> Result<(), String> {
    transactional_update(path, scope_root, false, |_| {
        Ok(FileUpdate::write_text(content.to_string(), mode))
    })?;
    Ok(())
}

fn open_lock_anchor(scope_root: &Path) -> Result<fs::File, String> {
    let mut anchor = absolute(scope_root)?;
    while !anchor.exists() {
        if !anchor.pop() {
            return Err(format!(
                "cannot find existing setup lock anchor for {}",
                scope_root.display()
            ));
        }
    }
    let canonical = anchor
        .canonicalize()
        .map_err(|error| format!("canonicalize setup lock anchor: {error}"))?;
    open_dir(&canonical)
}

pub(crate) struct PlatformLock {
    _anchor: fs::File,
}

pub(crate) struct PlatformTransaction {
    parent: ScopedParent,
    path: PathBuf,
    _lock: PlatformLock,
}

impl PlatformTransaction {
    pub(crate) fn lock(_path: &Path, scope_root: &Path) -> Result<PlatformLock, String> {
        let anchor = open_lock_anchor(scope_root)?;
        anchor
            .lock_exclusive()
            .map_err(|error| format!("lock setup scope without creating a lock file: {error}"))?;
        Ok(PlatformLock { _anchor: anchor })
    }

    pub(crate) fn begin(
        path: &Path,
        scope_root: &Path,
        lock: PlatformLock,
    ) -> Result<Self, String> {
        let parent = scoped_parent(path, scope_root, true)?
            .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
        Ok(Self {
            parent,
            path: path.to_path_buf(),
            _lock: lock,
        })
    }

    #[cfg(test)]
    fn lock_is_contended(_path: &Path, scope_root: &Path) -> Result<bool, String> {
        let file = open_lock_anchor(scope_root)?;
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
        snapshot_from_parent(&self.parent, &self.path)
    }

    pub(crate) fn validate_snapshot(&self, expected: &PlatformSnapshot) -> Result<(), String> {
        let live = self.read_snapshot()?;
        if &live != expected {
            return Err(format!(
                "{} changed while setup was preparing the update; no changes were published",
                self.path.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_temp<'a>(
        &'a self,
        bytes: &[u8],
        requested_mode: u32,
        preserve_existing_mode: bool,
        snapshot: &PlatformSnapshot,
    ) -> Result<TempGuard<'a>, String> {
        let effective_mode = if preserve_existing_mode {
            snapshot.mode.unwrap_or(requested_mode)
        } else {
            requested_mode
        } & 0o7777;
        let name = CString::new(format!(
            ".tirith-setup-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ))
        .expect("UUID temp name contains no NUL");
        let fd = unsafe {
            libc::openat(
                self.parent.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "create exclusive temporary file below destination: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut guard = TempGuard {
            parent: &self.parent.dir,
            name,
            file: Some(unsafe { fs::File::from_raw_fd(fd) }),
            state: None,
            armed: true,
        };
        let file = guard.file.as_mut().expect("new temp owns file");
        file.write_all(bytes)
            .map_err(|error| format!("write temporary file: {error}"))?;
        if unsafe { libc::fchmod(file.as_raw_fd(), effective_mode as libc::mode_t) } < 0 {
            return Err(format!(
                "set temporary-file permissions: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|error| format!("sync temporary file before publication: {error}"))?;
        let synced_metadata = file
            .metadata()
            .map_err(|error| format!("inspect synced temporary file: {error}"))?;
        guard.state = Some(StableFileState {
            identity: FileIdentity::from_metadata(&synced_metadata),
            size: synced_metadata.len(),
            mode: synced_metadata.mode() & 0o7777,
            digest: Sha256::digest(bytes).into(),
        });
        Ok(guard)
    }

    pub(crate) fn publish(
        &self,
        mut temp: TempGuard<'_>,
        expected: &PlatformSnapshot,
        #[cfg(test)] test_hook: &mut impl FnMut(super::fs_transaction::TestStage) -> Result<(), String>,
    ) -> Result<PublicationGuard<'_>, String> {
        let expected_exists = expected.bytes.is_some();
        let private_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(temp.name.to_bytes()));
        temp.validate_name()?;
        self.validate_snapshot(expected)?;
        let expected_state = stable_state_from_snapshot(expected);
        let held_original = if let Some(expected_state) = expected_state.as_ref() {
            Some(
                match open_stable_file_at_with_access(
                    &self.parent.dir,
                    &self.parent.name,
                    libc::O_RDWR,
                ) {
                    Ok(Some(held)) if &held.1 == expected_state => held,
                    Ok(Some(_)) => {
                        return Err(format!(
                            "{} changed before its recovery identity could be held",
                            self.path.display()
                        ))
                    }
                    Ok(None) => {
                        return Err(format!(
                            "{} disappeared before its recovery identity could be held",
                            self.path.display()
                        ))
                    }
                    Err(write_error) => {
                        // A read-only original can still be retained exactly; it
                        // simply cannot be scrubbed after the durability gate.
                        match open_stable_file_at(&self.parent.dir, &self.parent.name) {
                        Ok(Some(held)) if &held.1 == expected_state => held,
                        observed => {
                            return Err(format!(
                                "hold exact original {} for recovery ({write_error}); read-only fallback was {observed:?}",
                                self.path.display()
                            ))
                        }
                    }
                    }
                },
            )
        } else {
            None
        };
        #[cfg(test)]
        test_hook(super::fs_transaction::TestStage::PublicationReady)?;

        if expected_exists {
            let expected_state = expected_state.expect("existing snapshot has a stable state");
            let held_original = held_original.expect("existing snapshot has a held original");

            // An atomic exchange retains both pathname operands. That lets us
            // prove *after the syscall* that the installed inode is our exact
            // flushed temp and the displaced inode is the exact generation we
            // transformed. A pathname-only rename cannot provide this CAS
            // property because either name can be swapped after validation.
            exchange_names(&self.parent.dir, &temp.name, &self.parent.name).map_err(|error| {
                format!(
                    "publish {} by identity exchange: {error}",
                    self.path.display()
                )
            })?;
            let recovery = RecoveryIdentity {
                parent: &self.parent.dir,
                name: temp.name.clone(),
                display_path: private_path.clone(),
                file: held_original.0,
                state: expected_state.clone(),
            };

            let installed = match stable_state_at(&self.parent.dir, &self.parent.name) {
                Ok(state) => state,
                Err(error) => {
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published {} but could not verify the installed identity ({error}); retained the private entry at {} for manual recovery",
                            self.path.display(),
                            private_path.display()
                        ),
                        Some(recovery),
                    ));
                }
            };
            let displaced = match stable_state_at(&self.parent.dir, &temp.name) {
                Ok(state) => state,
                Err(error) => {
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published {} but could not verify its displaced identity at {} ({error}); retained both names for manual recovery",
                            self.path.display(),
                            private_path.display()
                        ),
                        Some(recovery),
                    ));
                }
            };
            let installed_matches = installed.as_ref() == temp.state.as_ref();
            let displaced_matches = displaced.as_ref() == Some(&expected_state);

            if !installed_matches || !displaced_matches {
                let rollback_safe = matches!(
                    (
                        stable_state_at(&self.parent.dir, &self.parent.name),
                        stable_state_at(&self.parent.dir, &temp.name),
                    ),
                    (Ok(live_installed), Ok(live_displaced))
                        if live_installed == installed && live_displaced == displaced
                );
                if rollback_safe
                    && exchange_names(&self.parent.dir, &temp.name, &self.parent.name).is_ok()
                {
                    let restored = stable_state_at(&self.parent.dir, &self.parent.name);
                    let replacement = stable_state_at(&self.parent.dir, &temp.name);
                    if restored.as_ref().is_ok_and(|state| state == &displaced)
                        && replacement.as_ref().is_ok_and(|state| state == &installed)
                    {
                        return Err(format!(
                            "{} or its prepared replacement changed at publication; restored the competing destination and published nothing",
                            self.path.display()
                        ));
                    }
                }
                temp.armed = false;
                return Ok(PublicationGuard::uncertain(
                    format!(
                        "{} or its prepared replacement changed at publication and rollback could not be proven; retained destination identity {:?} and private identity {:?} at {} for manual recovery",
                        self.path.display(),
                        installed,
                        displaced,
                        private_path.display()
                    ),
                    Some(recovery),
                ));
            }

            // Hold the exact displaced inode through the shared directory
            // fsync. Unix has no pathname-CAS unlink, so cleanup is never a
            // check-then-unlink: the durable commit retains this recovery
            // identity (or materializes it from this handle if its name moves).
            let recovery = match stable_state_at(&self.parent.dir, &temp.name) {
                Ok(Some(state)) if state == expected_state && recovery.state == state => recovery,
                observed => {
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published {} but could not retain the exact displaced identity ({observed:?}); private recovery name is {}",
                            self.path.display(),
                            private_path.display()
                        ),
                        Some(recovery),
                    ));
                }
            };
            let installed = RecoveryIdentity {
                parent: &self.parent.dir,
                name: self.parent.name.clone(),
                display_path: self.path.clone(),
                file: temp.file.take().expect("prepared temp handle remains held"),
                state: temp.state.clone().expect("prepared temp has stable state"),
            };
            temp.armed = false;
            Ok(PublicationGuard::with_recovery(recovery, installed))
        } else {
            // Move the prepared name atomically with no-replace semantics.
            // Unlike link+unlink, this leaves no duplicate name requiring an
            // unsafe check-then-path-delete cleanup.
            move_no_replace(&self.parent.dir, &temp.name, &self.parent.name).map_err(|error| {
                format!(
                    "publish {} atomically without replacement: {error}",
                    self.path.display()
                )
            })?;
            let installed = match stable_state_at(&self.parent.dir, &self.parent.name) {
                Ok(state) => state,
                Err(error) => {
                    let recovery = RecoveryIdentity {
                        parent: &self.parent.dir,
                        name: self.parent.name.clone(),
                        display_path: self.path.clone(),
                        file: temp.file.take().expect("prepared temp handle remains held"),
                        state: temp.state.clone().expect("prepared temp has stable state"),
                    };
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published new destination {} but could not verify its identity ({error}); prepared identity remains held for recovery",
                            self.path.display(),
                        ),
                        Some(recovery),
                    ));
                }
            };
            if installed.as_ref() != temp.state.as_ref() {
                // Roll back with another no-replace rename. No pathname is
                // ever deleted, even when the prepared source was swapped.
                if move_no_replace(&self.parent.dir, &self.parent.name, &temp.name).is_ok()
                    && stable_state_at(&self.parent.dir, &self.parent.name)
                        .as_ref()
                        .is_ok_and(Option::is_none)
                    && stable_state_at(&self.parent.dir, &temp.name)
                        .as_ref()
                        .is_ok_and(|state| state == &installed)
                {
                    return Err(format!(
                        "prepared replacement for {} changed at publication; restored the moved identity and published nothing",
                        self.path.display()
                    ));
                }
                let recovery = RecoveryIdentity {
                    parent: &self.parent.dir,
                    name: self.parent.name.clone(),
                    display_path: self.path.clone(),
                    file: temp.file.take().expect("prepared temp handle remains held"),
                    state: temp.state.clone().expect("prepared temp has stable state"),
                };
                temp.armed = false;
                return Ok(PublicationGuard::uncertain(
                    format!(
                        "prepared replacement for {} changed during publication; rollback could not be proven (destination {:?}); retained both names for manual recovery",
                        self.path.display(),
                        stable_state_at(&self.parent.dir, &self.parent.name)
                    ),
                    Some(recovery),
                ));
            }
            let installed = RecoveryIdentity {
                parent: &self.parent.dir,
                name: self.parent.name.clone(),
                display_path: self.path.clone(),
                file: temp.file.take().expect("prepared temp handle remains held"),
                state: temp.state.clone().expect("prepared temp has stable state"),
            };
            temp.armed = false;
            Ok(PublicationGuard::clean(installed))
        }
    }

    pub(crate) fn sync_parent(&self) -> Result<(), String> {
        self.parent
            .dir
            .sync_all()
            .map_err(|error| format!("sync destination directory after publication: {error}"))
    }

    pub(crate) fn create_backup(&self, snapshot: &PlatformSnapshot) -> Result<BackupGuard, String> {
        let bytes = snapshot
            .bytes
            .as_deref()
            .ok_or_else(|| "cannot back up an absent destination".to_string())?;
        let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let mut name = self.parent.name.to_bytes().to_vec();
        name.extend_from_slice(
            format!(
                ".tirith-backup-{timestamp}-{}",
                uuid::Uuid::new_v4().simple()
            )
            .as_bytes(),
        );
        let name = CString::new(name).map_err(|_| "backup name contains NUL".to_string())?;
        let fd = unsafe {
            libc::openat(
                self.parent.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "create exclusive backup: {}",
                std::io::Error::last_os_error()
            ));
        }
        let display_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(name.to_bytes()));
        let mut guard = BackupGuard {
            display_path,
            file: Some(unsafe { fs::File::from_raw_fd(fd) }),
            armed: true,
        };
        let file = guard.file.as_mut().expect("new backup owns file");
        file.write_all(bytes)
            .map_err(|error| format!("write backup from locked snapshot: {error}"))?;
        if unsafe {
            libc::fchmod(
                file.as_raw_fd(),
                snapshot.mode.unwrap_or(0o600) as libc::mode_t,
            )
        } < 0
        {
            return Err(format!(
                "set backup permissions: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|error| format!("sync backup before update: {error}"))?;
        self.parent
            .dir
            .sync_all()
            .map_err(|error| format!("sync backup directory: {error}"))?;
        Ok(guard)
    }

    pub(crate) fn cleanup_old_backups(&self, _keep: Option<&BackupGuard>) -> Result<(), String> {
        // A previous-run backup pathname has no live capability tying it to
        // the file Tirith originally created. Never turn a pathname check into
        // a later unlink: cleanup is restricted to guards that still hold the
        // exact file handle, and those guards scrub through that handle.
        Ok(())
    }
}

struct RecoveryIdentity<'a> {
    parent: &'a fs::File,
    name: CString,
    display_path: PathBuf,
    file: fs::File,
    state: StableFileState,
}

impl RecoveryIdentity<'_> {
    fn scrub_exact(&mut self) -> Result<(), String> {
        self.file
            .set_len(0)
            .map_err(|error| format!("scrub exact displaced identity: {error}"))?;
        if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o600) } < 0 {
            eprintln!(
                "tirith: could not restrict scrubbed displaced identity: {}",
                std::io::Error::last_os_error()
            );
        }
        if let Err(error) = self.file.sync_all() {
            eprintln!("tirith: could not sync scrubbed displaced identity: {error}");
        }
        Ok(())
    }

    fn materialize_copy(&mut self) -> Result<PathBuf, String> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("seek exact displaced recovery identity: {error}"))?;
        let mut bytes = Vec::with_capacity(self.state.size as usize);
        (&mut self.file)
            .take(super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read exact displaced recovery identity: {error}"))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if bytes.len() as u64 != self.state.size || digest != self.state.digest {
            return Err("exact displaced recovery identity changed while held".into());
        }

        let name = CString::new(format!(
            ".tirith-recovery-{}",
            uuid::Uuid::new_v4().simple()
        ))
        .expect("UUID recovery name contains no NUL");
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "create exclusive recovery copy: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut copy = unsafe { fs::File::from_raw_fd(fd) };
        let write_result = (|| {
            copy.write_all(&bytes)
                .map_err(|error| format!("write exact recovery copy: {error}"))?;
            if unsafe { libc::fchmod(copy.as_raw_fd(), self.state.mode as libc::mode_t) } < 0 {
                return Err(format!(
                    "set exact recovery-copy permissions: {}",
                    std::io::Error::last_os_error()
                ));
            }
            copy.sync_all()
                .map_err(|error| format!("sync exact recovery copy: {error}"))?;
            self.parent
                .sync_all()
                .map_err(|error| format!("sync exact recovery-copy directory entry: {error}"))
        })();
        if let Err(error) = write_result {
            let _ = copy.set_len(0);
            let _ = copy.sync_all();
            return Err(error);
        }
        Ok(self
            .display_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(name.to_bytes())))
    }

    fn ensure_recovery_path(&mut self) -> Result<PathBuf, String> {
        if stable_state_at(self.parent, &self.name)
            .as_ref()
            .is_ok_and(|state| state.as_ref() == Some(&self.state))
        {
            Ok(self.display_path.clone())
        } else {
            self.materialize_copy()
        }
    }
}

pub(crate) struct PublicationGuard<'a> {
    installed: Option<RecoveryIdentity<'a>>,
    recovery: Option<RecoveryIdentity<'a>>,
    terminal_error: Option<String>,
}

impl<'a> PublicationGuard<'a> {
    fn clean(installed: RecoveryIdentity<'a>) -> Self {
        Self {
            installed: Some(installed),
            recovery: None,
            terminal_error: None,
        }
    }

    fn with_recovery(recovery: RecoveryIdentity<'a>, installed: RecoveryIdentity<'a>) -> Self {
        Self {
            installed: Some(installed),
            recovery: Some(recovery),
            terminal_error: None,
        }
    }

    fn uncertain(message: String, recovery: Option<RecoveryIdentity<'a>>) -> Self {
        Self {
            installed: None,
            recovery,
            terminal_error: Some(message),
        }
    }

    pub(crate) fn retain_for_recovery(&mut self) -> String {
        let installed = self.installed.as_mut().map(|identity| {
            identity
                .ensure_recovery_path()
                .map(|path| format!("retained exact installed identity at {}", path.display()))
                .unwrap_or_else(|error| {
                    format!("could not materialize installed recovery: {error}")
                })
        });
        let exact = self.recovery.as_mut().map(|recovery| {
            recovery
                .ensure_recovery_path()
                .map(|path| format!("retained exact displaced recovery at {}", path.display()))
                .unwrap_or_else(|error| {
                    format!("could not materialize displaced recovery: {error}")
                })
        });
        match (&self.terminal_error, exact, installed) {
            (Some(error), Some(recovery), Some(installed)) => {
                format!("{error}; {recovery}; {installed}")
            }
            (Some(error), Some(recovery), None) => format!("{error}; {recovery}"),
            (Some(error), None, Some(installed)) => format!("{error}; {installed}"),
            (Some(error), None, None) => error.clone(),
            (None, Some(recovery), Some(installed)) => format!("{recovery}; {installed}"),
            (None, Some(recovery), None) => recovery,
            (None, None, Some(installed)) => installed,
            (None, None, None) => "new destination has no recovery identity".into(),
        }
    }

    pub(crate) fn finish_after_durability(mut self) -> Result<PublicationOutcome, String> {
        if let Some(error) = self.terminal_error.take() {
            let recovery = self.recovery.as_mut().map(|identity| {
                identity
                    .ensure_recovery_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|copy_error| format!("unavailable ({copy_error})"))
            });
            return Err(match recovery {
                Some(path) => format!("{error}; exact recovery: {path}"),
                None => error,
            });
        }
        if let Some(installed) = self.installed.as_mut() {
            let live = stable_state_at(installed.parent, &installed.name);
            if live.as_ref().is_err()
                || live.as_ref().ok().and_then(Option::as_ref) != Some(&installed.state)
            {
                let installed_recovery = installed
                    .ensure_recovery_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|error| format!("unavailable ({error})"));
                let displaced_recovery = self.recovery.as_mut().map(|identity| {
                    identity
                        .ensure_recovery_path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|error| format!("unavailable ({error})"))
                });
                return Err(match displaced_recovery {
                    Some(displaced) => format!(
                        "installed destination identity changed before transaction completion; installed recovery: {installed_recovery}; displaced recovery: {displaced}"
                    ),
                    None => format!(
                        "installed destination identity changed before transaction completion; installed recovery: {installed_recovery}"
                    ),
                });
            }
        }
        let Some(recovery) = self.recovery.as_mut() else {
            return Ok(PublicationOutcome::Clean);
        };
        if recovery.scrub_exact().is_ok() {
            return Ok(PublicationOutcome::Clean);
        }
        let path = recovery.ensure_recovery_path()?;
        Ok(PublicationOutcome::RecoveryRetained(format!(
            "durable update retained the exact displaced original at {} because Unix has no identity-bound pathname deletion primitive",
            path.display()
        )))
    }
}

pub(crate) struct TempGuard<'a> {
    parent: &'a fs::File,
    name: CString,
    file: Option<fs::File>,
    state: Option<StableFileState>,
    armed: bool,
}

impl TempGuard<'_> {
    fn validate_name(&self) -> Result<(), String> {
        let expected = self
            .state
            .as_ref()
            .expect("prepared temp has a synced state");
        let live = stable_state_at(self.parent, &self.name)?;
        if live.as_ref() != Some(expected) {
            return Err(
                "temporary setup file changed before publication; refusing for safety".into(),
            );
        }
        Ok(())
    }
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Scrub only the inode represented by our held capability. If an
            // attacker swaps the pathname, their file is never selected for
            // cleanup. The zero-length tombstone is intentionally retained.
            if let Some(file) = self.file.as_mut() {
                let _ = file.set_len(0);
                let _ = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
                let _ = file.sync_all();
            }
        }
    }
}

pub(crate) struct BackupGuard {
    display_path: PathBuf,
    file: Option<fs::File>,
    armed: bool,
}

impl BackupGuard {
    pub(crate) fn commit(&mut self) {
        self.armed = false;
        eprintln!("tirith: backup at {}", self.path().display());
    }

    pub(crate) fn retain_for_recovery(&mut self) -> PathBuf {
        self.armed = false;
        self.path()
    }

    fn path(&self) -> PathBuf {
        self.display_path.clone()
    }
}

impl Drop for BackupGuard {
    fn drop(&mut self) {
        if self.armed {
            // As with temporary cleanup, scrub the exact held inode rather
            // than deleting whichever object later occupies the pathname.
            if let Some(file) = self.file.as_mut() {
                let _ = file.set_len(0);
                let _ = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
                let _ = file.sync_all();
            }
        }
    }
}

/// Write a hook script with executable permissions.
///
/// - Hard-errors if `path` is a symlink (even with `--force`).
/// - If file exists with matching content: skip (but verify 0o755 mode).
/// - If file exists with different content: error without `--force`, overwrite with `--force`.
/// - After write, always enforce mode 0o755.
/// - Dry-run: print what would happen, write nothing.
pub fn write_hook_script(
    path: &Path,
    scope_root: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    #[derive(Clone, Copy)]
    enum Action {
        UpToDate,
        FixMode,
        Write,
        WouldError,
    }
    let mut action = Action::Write;
    let outcome = transactional_update(path, scope_root, dry_run, |snapshot| {
        if let Some(existing) = snapshot.text(path)? {
            if existing == content {
                if snapshot.mode().unwrap_or(0) & 0o777 == 0o755 {
                    action = Action::UpToDate;
                    return Ok(FileUpdate::unchanged());
                }
                action = Action::FixMode;
                return Ok(FileUpdate::write_text(content.to_string(), 0o755).with_exact_mode());
            }
            if !force {
                if dry_run {
                    action = Action::WouldError;
                    return Ok(FileUpdate::unchanged());
                }
                return Err(format!(
                    "{} exists but content differs — use --force to update",
                    path.display()
                ));
            }
        }
        action = Action::Write;
        Ok(FileUpdate::write_text(content.to_string(), 0o755).with_exact_mode())
    })?;

    match (action, outcome) {
        (Action::UpToDate, _) if dry_run => eprintln!(
            "[dry-run] would skip {} (already up to date)",
            path.display()
        ),
        (Action::UpToDate, _) => {
            eprintln!("tirith: {} already configured, up to date", path.display())
        }
        (Action::FixMode, TransactionOutcome::DryRunWouldWrite) => eprintln!(
            "[dry-run] would correct {} permissions to mode 0755",
            path.display()
        ),
        (Action::FixMode, outcome) if outcome.was_written() => eprintln!(
            "tirith: {} already configured, fixed permissions",
            path.display()
        ),
        (Action::WouldError, _) => eprintln!(
            "[dry-run] would error: {} exists but content differs — use --force to update",
            path.display()
        ),
        (Action::Write, TransactionOutcome::DryRunWouldWrite) => eprintln!(
            "[dry-run] would write {} ({} bytes, mode 0755)",
            path.display(),
            content.len()
        ),
        (Action::Write, outcome) if outcome.was_written() => {
            eprintln!("tirith: wrote {}", path.display())
        }
        _ => {}
    }
    Ok(())
}

/// Validate that `dir` stays within `scope_root` after canonicalization.
///
/// Walks up from `dir` to find the nearest existing ancestor, canonicalizes
/// it, and verifies it starts with the canonical `scope_root`. Also checks
/// each existing path component for symlinks within the scope.
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

    // Each existing component must not be a symlink pointing back into scope.
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

#[cfg(test)]
mod tests {
    use super::super::fs_transaction::{transactional_update_with_hook, FileUpdate, TestStage};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".tirith-setup-") && name.ends_with(".tmp")
            })
            .map(|entry| entry.path())
            .collect()
    }

    fn nonempty(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
        paths
            .into_iter()
            .filter(|path| fs::metadata(path).is_ok_and(|metadata| metadata.len() != 0))
            .collect()
    }

    fn update_with_backup(path: &Path, root: &Path, content: &str) -> Result<(), String> {
        transactional_update(path, root, false, |_| {
            Ok(FileUpdate::write_text(content.to_string(), 0o644).with_backup(true))
        })?;
        Ok(())
    }

    #[test]
    fn cli_runner_preserves_short_legitimate_output() {
        let shell =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[])
                .unwrap();
        let output = run_cli_with(
            &shell,
            &["-c", "printf setup-ok"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(2), 64, 64),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"setup-ok");
    }

    #[test]
    fn cli_runner_rejects_output_over_its_bound() {
        let shell =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[])
                .unwrap();
        let error = run_cli_with(
            &shell,
            &["-c", "printf 12345"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(2), 4, 64),
        )
        .unwrap_err();
        assert!(error.contains("output limit"));
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        atomic_write(&path, dir.path(), "hello", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn atomic_write_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = atomic_write(&link, dir.path(), "evil", 0o644);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
        // Original untouched
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    #[test]
    fn atomic_write_preserves_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("strict.txt");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        atomic_write(&path, dir.path(), "new", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // Preserved existing 0o600, not overwritten with mode arg 0o644.
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_hook_script_skip_on_same_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "#!/bin/bash\necho hi").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        write_hook_script(&path, dir.path(), "#!/bin/bash\necho hi", false, false).unwrap();
    }

    #[test]
    fn write_hook_script_errors_on_different_content_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "old content").unwrap();

        let result = write_hook_script(&path, dir.path(), "new content", false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("content differs"));
    }

    #[test]
    fn write_hook_script_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "old content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_hook_script(&path, dir.path(), "new content", true, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new content");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn write_hook_script_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sh");
        fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = write_hook_script(&link, dir.path(), "evil", true, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
    }

    #[test]
    fn write_hook_script_refuses_symlinked_parent_even_when_content_matches() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("hook.sh"), "expected").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("hooks")).unwrap();

        let result = write_hook_script(
            &root.path().join("hooks/hook.sh"),
            root.path(),
            "expected",
            false,
            true,
        );

        assert!(result.is_err(), "up-to-date/dry-run must validate parents");
        assert_eq!(
            fs::read_to_string(outside.path().join("hook.sh")).unwrap(),
            "expected"
        );
    }

    #[test]
    fn atomic_write_refuses_symlinked_parent_and_leaves_outside_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked_parent = dir.path().join("hooks");
        std::os::unix::fs::symlink(outside.path(), &linked_parent).unwrap();

        let result = atomic_write(
            &linked_parent.join("config.json"),
            dir.path(),
            "secret",
            0o600,
        );

        assert!(result.is_err());
        assert!(!outside.path().join("config.json").exists());
    }

    #[test]
    fn atomic_write_rejects_destination_outside_scope() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("config.json");

        let result = atomic_write(&path, dir.path(), "secret", 0o600);

        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn atomic_write_creates_nested_components_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one").join("two").join("config.json");

        atomic_write(&path, dir.path(), "secret", 0o600).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "secret");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn validate_target_dir_accepts_normal_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("subdir");
        validate_target_dir(&target, Some(dir.path())).unwrap();
    }

    #[test]
    fn validate_target_dir_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let evil = tempfile::tempdir().unwrap();

        // Symlink inside dir pointing outside the scope must be rejected.
        let link = dir.path().join("escape");
        std::os::unix::fs::symlink(evil.path(), &link).unwrap();

        let target = link.join("subdir");
        let result = validate_target_dir(&target, Some(dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn same_second_backups_are_unique_without_unsafe_path_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        update_with_backup(&path, dir.path(), "one").unwrap();
        update_with_backup(&path, dir.path(), "two").unwrap();
        assert_eq!(backup_paths(dir.path()).len(), 2);
        for index in 0..6 {
            update_with_backup(&path, dir.path(), &format!("value-{index}")).unwrap();
        }
        let retained = backup_paths(dir.path());
        assert_eq!(retained.len(), 8);
        assert!(retained
            .iter()
            .any(|backup| fs::read_to_string(backup).unwrap() == "value-4"));
    }

    #[test]
    fn backup_uses_locked_snapshot_content_and_restrictive_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "secret-data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        update_with_backup(&path, dir.path(), "new-data").unwrap();
        let backup = backup_paths(dir.path()).pop().expect("backup created");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "secret-data");
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn transaction_backup_and_retention_refuse_symlinked_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked = root.path().join("configs");
        std::os::unix::fs::symlink(outside.path(), &linked).unwrap();
        fs::write(outside.path().join("config.json"), "outside-secret").unwrap();
        for i in 0..7 {
            fs::write(
                outside
                    .path()
                    .join(format!("config.json.tirith-backup-20260101-00000{i}")),
                format!("backup-{i}"),
            )
            .unwrap();
        }

        let path = linked.join("config.json");
        assert!(update_with_backup(&path, root.path(), "new").is_err());

        assert_eq!(
            fs::read_to_string(outside.path().join("config.json")).unwrap(),
            "outside-secret"
        );
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
        assert_eq!(backups, 7, "retention must not delete through the link");
    }

    #[test]
    fn dry_run_is_read_only_and_does_not_create_lock_or_parent() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing/config.json");
        let outcome = transactional_update(&path, root.path(), true, |_| {
            Ok(FileUpdate::write_text("planned".into(), 0o644))
        })
        .unwrap();
        assert_eq!(outcome, TransactionOutcome::DryRunWouldWrite);
        assert!(!root.path().join("missing").exists());
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-lock-")
            }));
    }

    #[test]
    fn fifo_snapshot_is_rejected_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("config.json");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        let error = read_to_string_scoped(&fifo, root.path()).unwrap_err();
        assert!(error.contains("not a regular file"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
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
    fn transformed_payload_accepts_exact_cap() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exact-cap.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES);
        let outcome = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap();
        assert_eq!(outcome, TransactionOutcome::Written);
        assert_eq!(fs::metadata(path).unwrap().len(), payload.len() as u64);
    }

    #[test]
    fn transformed_payload_rejects_cap_plus_one_before_live_side_effects() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing").join("too-large.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600).with_backup(true))
        })
        .unwrap_err();
        assert!(error.contains("setup file limit"));
        assert!(!root.path().join("missing").exists());
        assert!(backup_paths(root.path()).is_empty());
    }

    #[test]
    fn drifted_transform_is_recomputed_and_capped_before_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "base").unwrap();
        let oversized = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |snapshot| {
                if snapshot.text(&path)? == Some("base") {
                    Ok(FileUpdate::write_text("small".into(), 0o600).with_backup(true))
                } else {
                    Ok(FileUpdate::write_text(oversized.clone(), 0o600).with_backup(true))
                }
            },
            |stage| {
                if stage == TestStage::PreflightReady {
                    fs::write(&path, "drift").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("setup file limit"));
        assert_eq!(fs::read_to_string(path).unwrap(), "drift");
        assert!(backup_paths(root.path()).is_empty());
        assert!(temporary_setup_paths(root.path()).is_empty());
    }

    #[test]
    fn transformed_payload_rejects_cap_plus_one_in_dry_run_without_side_effects() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing").join("too-large.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update(&path, root.path(), true, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap_err();
        assert!(error.contains("setup file limit"));
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn precreated_regular_and_symlink_backup_names_are_never_overwritten() {
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
            .join("config.json.tirith-backup-99999999-999999-symlink");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        update_with_backup(&path, root.path(), "updated").unwrap();
        assert_eq!(fs::read_to_string(regular).unwrap(), "attacker-regular");
        assert_eq!(fs::read_to_string(target).unwrap(), "attacker-target");
    }

    #[test]
    fn non_cooperating_generation_change_is_rejected_and_temp_is_scrubbed() {
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
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn swapped_temp_is_rejected_without_deleting_the_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let mut attacker_path = None;
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    fs::remove_file(&temp).unwrap();
                    fs::write(&temp, "attacker-replacement").unwrap();
                    attacker_path = Some(temp);
                }
                Ok(())
            },
        );
        assert!(result.unwrap_err().contains("temporary setup file changed"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "before");
        assert_eq!(
            fs::read_to_string(attacker_path.unwrap()).unwrap(),
            "attacker-replacement"
        );
    }

    #[test]
    fn destination_swap_after_validation_is_detected_and_competitor_is_restored() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let original_hold = root.path().join("original-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_identity = FileIdentity::from_metadata(&fs::metadata(&path).unwrap());
        let mut competitor_identity = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    fs::rename(&path, &original_hold).unwrap();
                    fs::write(&path, "competing-writer").unwrap();
                    competitor_identity =
                        Some(FileIdentity::from_metadata(&fs::metadata(&path).unwrap()));
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "competing-writer");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&path).unwrap()),
            competitor_identity.unwrap()
        );
        assert_eq!(fs::read_to_string(&original_hold).unwrap(), "original");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&original_hold).unwrap()),
            original_identity
        );
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn temp_swap_after_validation_never_publishes_attacker_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let held_prepared = root.path().join("prepared-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_identity = FileIdentity::from_metadata(&fs::metadata(&path).unwrap());
        let mut attacker_path = None;
        let mut attacker_identity = None;
        let mut prepared_identity = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    prepared_identity =
                        Some(FileIdentity::from_metadata(&fs::metadata(&temp).unwrap()));
                    fs::rename(&temp, &held_prepared).unwrap();
                    fs::write(&temp, "attacker-temp").unwrap();
                    attacker_identity =
                        Some(FileIdentity::from_metadata(&fs::metadata(&temp).unwrap()));
                    attacker_path = Some(temp);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&path).unwrap()),
            original_identity
        );
        let attacker_path = attacker_path.unwrap();
        assert_eq!(fs::read_to_string(&attacker_path).unwrap(), "attacker-temp");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(attacker_path).unwrap()),
            attacker_identity.unwrap()
        );
        assert_eq!(fs::read_to_string(&held_prepared).unwrap(), "");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(held_prepared).unwrap()),
            prepared_identity.unwrap()
        );
    }

    #[test]
    fn expected_absent_race_never_overwrites_new_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
            |stage| {
                if stage == TestStage::SnapshotValidated {
                    fs::write(&path, "editor-created").unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "editor-created");
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
        assert!(nonempty(backup_paths(root.path())).is_empty());
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn failure_after_temp_sync_scrubs_temp_and_transaction_backup() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    return Err("injected failure after durable temp".into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("injected failure"));
        assert_eq!(fs::read_to_string(path).unwrap(), "before");
        assert!(nonempty(backup_paths(root.path())).is_empty());
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn swapped_backup_cleanup_scrubs_only_the_held_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let held_backup = root.path().join("held-original-backup");
        fs::write(&path, "before-secret").unwrap();
        let mut attacker_backup = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let backup = backup_paths(root.path()).pop().unwrap();
                    fs::rename(&backup, &held_backup).unwrap();
                    fs::write(&backup, "attacker-backup").unwrap();
                    attacker_backup = Some(backup);
                    return Err("injected failure after backup swap".into());
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("injected failure"));
        assert_eq!(
            fs::read_to_string(attacker_backup.unwrap()).unwrap(),
            "attacker-backup"
        );
        assert_eq!(fs::read_to_string(held_backup).unwrap(), "");
        assert_eq!(fs::read_to_string(path).unwrap(), "before-secret");
    }

    #[test]
    fn post_publication_durability_failure_keeps_recovery_backup() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::Published {
                    return Err("injected directory durability failure".into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("durability"));
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert_eq!(backup_paths(root.path()).len(), 1);
    }

    #[test]
    fn installed_name_swap_before_completion_is_detected_without_deleting_attacker() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let moved_install = root.path().join("writer-moved-install");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::Published {
                    fs::rename(&path, &moved_install).unwrap();
                    fs::write(&path, "attacker").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("installed destination identity changed"));
        assert_eq!(fs::read_to_string(path).unwrap(), "attacker");
        assert_eq!(fs::read_to_string(moved_install).unwrap(), "after");
        assert_eq!(backup_paths(root.path()).len(), 1);
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
        assert!(
            holder.try_wait().unwrap().is_none(),
            "holder must still own the lock when the contender proves overlap"
        );
        assert!(
            contender.try_wait().unwrap().is_none(),
            "contender must be blocked until the holder publishes"
        );

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
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("-one") && content.contains("-two"));
    }

    #[test]
    fn same_content_hook_mode_fix_is_atomic_and_dry_run_is_non_mutating() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hook.sh");
        fs::write(&path, "hook").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_hook_script(&path, root.path(), "hook", false, true).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        write_hook_script(&path, root.path(), "hook", false, false).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
