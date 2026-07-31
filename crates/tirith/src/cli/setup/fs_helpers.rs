//! Filesystem helpers for `tirith setup` — atomic writes, hook scripts,
//! directory validation, CLI subprocess runner, and backup management.

use std::ffi::{CStr, CString, OsStr};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use sha2::{Digest, Sha256};

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

fn metadata_at(parent: &fs::File, name: &CStr) -> Option<fs::Metadata> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    file.metadata().ok().filter(|metadata| metadata.is_file())
}

fn name_has_identity(parent: &fs::File, name: &CStr, expected: &FileIdentity) -> bool {
    metadata_at(parent, name)
        .map(|metadata| FileIdentity::from_metadata(&metadata) == *expected)
        .unwrap_or(false)
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

fn stable_lock_name(destination: &CStr) -> CString {
    let digest = Sha256::digest(destination.to_bytes());
    let mut name = String::from(".tirith-setup-lock-");
    for byte in digest {
        let _ = write!(&mut name, "{byte:02x}");
    }
    CString::new(name).expect("hex lock name contains no NUL")
}

fn open_lock(parent: &ScopedParent) -> Result<fs::File, String> {
    let name = stable_lock_name(&parent.name);
    let fd = (0..3)
        .find_map(|attempt| {
            let fd = unsafe {
                libc::openat(
                    parent.dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_NONBLOCK
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd >= 0 {
                return Some(Ok(fd));
            }
            let error = std::io::Error::last_os_error();
            let transient = error.kind() == std::io::ErrorKind::Interrupted
                || error.kind() == std::io::ErrorKind::NotFound;
            if transient && attempt < 2 {
                std::thread::yield_now();
                None
            } else {
                Some(Err(error))
            }
        })
        .expect("bounded lock-open loop returns on its final attempt")
        .map_err(|error| format!("open stable setup lock without following links: {error}"))?;
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect stable setup lock: {error}"))?;
    if !metadata.is_file() {
        return Err("stable setup lock is not a regular file — refusing for safety".into());
    }
    file.lock_exclusive()
        .map_err(|error| format!("lock setup destination: {error}"))?;
    Ok(file)
}

pub(crate) struct PlatformTransaction {
    parent: ScopedParent,
    path: PathBuf,
    _lock: fs::File,
}

impl PlatformTransaction {
    pub(crate) fn begin(path: &Path, scope_root: &Path) -> Result<Self, String> {
        let parent = scoped_parent(path, scope_root, true)?
            .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
        let lock = open_lock(&parent)?;
        Ok(Self {
            parent,
            path: path.to_path_buf(),
            _lock: lock,
        })
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
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
            identity: None,
            generation: None,
            armed: true,
        };
        let created_metadata = guard
            .file
            .as_ref()
            .expect("new temp owns file")
            .metadata()
            .map_err(|error| format!("inspect new temporary file: {error}"))?;
        guard.identity = Some(FileIdentity::from_metadata(&created_metadata));
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
        guard.generation = Some(FileGeneration::from_metadata(&synced_metadata));
        Ok(guard)
    }

    pub(crate) fn publish(
        &self,
        mut temp: TempGuard<'_>,
        expected: &PlatformSnapshot,
    ) -> Result<(), String> {
        let expected_exists = expected.bytes.is_some();
        temp.validate_name()?;
        if expected_exists {
            let result = unsafe {
                libc::renameat(
                    self.parent.dir.as_raw_fd(),
                    temp.name.as_ptr(),
                    self.parent.dir.as_raw_fd(),
                    self.parent.name.as_ptr(),
                )
            };
            if result < 0 {
                return Err(format!(
                    "publish {} atomically: {}",
                    self.path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            temp.armed = false;
        } else {
            // `linkat` is an atomic no-replace publication for an expected-
            // absent destination. It closes the check/rename overwrite race.
            let linked = unsafe {
                libc::linkat(
                    self.parent.dir.as_raw_fd(),
                    temp.name.as_ptr(),
                    self.parent.dir.as_raw_fd(),
                    self.parent.name.as_ptr(),
                    0,
                )
            };
            if linked < 0 {
                return Err(format!(
                    "publish {} atomically without replacement: {}",
                    self.path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            if unsafe { libc::unlinkat(self.parent.dir.as_raw_fd(), temp.name.as_ptr(), 0) } == 0 {
                temp.armed = false;
            } else {
                // The destination is already visible. Keep the guard armed so
                // Drop retries cleanup, but continue to the mandatory parent
                // fsync instead of reporting the completed publication as a
                // failed transaction.
                eprintln!(
                    "tirith: published {} but initial temporary-link cleanup failed: {}",
                    self.path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(())
    }

    pub(crate) fn sync_parent(&self) -> Result<(), String> {
        self.parent
            .dir
            .sync_all()
            .map_err(|error| format!("sync destination directory after publication: {error}"))
    }

    pub(crate) fn create_backup<'a>(
        &'a self,
        snapshot: &PlatformSnapshot,
    ) -> Result<BackupGuard<'a>, String> {
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
        let mut guard = BackupGuard {
            parent: &self.parent.dir,
            name,
            file: Some(unsafe { fs::File::from_raw_fd(fd) }),
            identity: None,
            armed: true,
        };
        let created_metadata = guard
            .file
            .as_ref()
            .expect("new backup owns file")
            .metadata()
            .map_err(|error| format!("inspect new backup: {error}"))?;
        guard.identity = Some(FileIdentity::from_metadata(&created_metadata));
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
        eprintln!(
            "tirith: backup at {}",
            self.path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(OsStr::from_bytes(guard.name.to_bytes()))
                .display()
        );
        Ok(guard)
    }

    pub(crate) fn cleanup_old_backups(&self, keep: Option<&BackupGuard<'_>>) -> Result<(), String> {
        let prefix = [self.parent.name.to_bytes(), b".tirith-backup-"].concat();
        let entries = directory_entries(&self.parent.dir)?;
        let keep_present = keep.is_some_and(|guard| {
            entries
                .iter()
                .any(|name| name.as_c_str() == guard.name.as_c_str())
        });
        let mut backups = entries
            .into_iter()
            .filter(|name| {
                name.to_bytes().starts_with(&prefix)
                    && keep.is_none_or(|guard| name.as_c_str() != guard.name.as_c_str())
            })
            .collect::<Vec<_>>();
        backups.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let keep_slots = usize::from(keep_present);
        let remove_count = backups.len().saturating_sub(5 - keep_slots);
        let mut removed = false;
        for old in &backups[..remove_count] {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let status = unsafe {
                libc::fstatat(
                    self.parent.dir.as_raw_fd(),
                    old.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if status < 0 || unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
                continue;
            }
            if unsafe { libc::unlinkat(self.parent.dir.as_raw_fd(), old.as_ptr(), 0) } == 0 {
                removed = true;
            } else {
                eprintln!(
                    "tirith: could not clean old backup {}: {}",
                    old.to_string_lossy(),
                    std::io::Error::last_os_error()
                );
            }
        }
        if removed {
            self.parent
                .dir
                .sync_all()
                .map_err(|error| format!("sync backup retention changes: {error}"))?;
        }
        Ok(())
    }
}

pub(crate) struct TempGuard<'a> {
    parent: &'a fs::File,
    name: CString,
    file: Option<fs::File>,
    identity: Option<FileIdentity>,
    generation: Option<FileGeneration>,
    armed: bool,
}

impl TempGuard<'_> {
    fn validate_name(&self) -> Result<(), String> {
        let expected = self
            .generation
            .as_ref()
            .expect("prepared temp has a synced generation");
        let live = metadata_at(self.parent, &self.name)
            .map(|metadata| FileGeneration::from_metadata(&metadata));
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
        self.file.take();
        if self.armed
            && self
                .identity
                .as_ref()
                .is_some_and(|identity| name_has_identity(self.parent, &self.name, identity))
        {
            let _ = unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

pub(crate) struct BackupGuard<'a> {
    parent: &'a fs::File,
    name: CString,
    file: Option<fs::File>,
    identity: Option<FileIdentity>,
    armed: bool,
}

impl BackupGuard<'_> {
    pub(crate) fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for BackupGuard<'_> {
    fn drop(&mut self) {
        self.file.take();
        if self.armed
            && self
                .identity
                .as_ref()
                .is_some_and(|identity| name_has_identity(self.parent, &self.name, identity))
        {
            let _ = unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
            let _ = self.parent.sync_all();
        }
    }
}

fn directory_entries(parent: &fs::File) -> Result<Vec<CString>, String> {
    let duplicate = unsafe { libc::dup(parent.as_raw_fd()) };
    if duplicate < 0 {
        return Err(format!(
            "duplicate backup-directory handle: {}",
            std::io::Error::last_os_error()
        ));
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(format!(
            "enumerate backup directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut entries = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if let Ok(name) = CString::new(bytes) {
            entries.push(name);
        }
    }
    unsafe { libc::closedir(directory) };
    Ok(entries)
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
        (Action::FixMode, TransactionOutcome::Written) => eprintln!(
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
        (Action::Write, TransactionOutcome::Written) => {
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
    fn same_second_backups_are_unique_and_retention_keeps_five() {
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
        assert_eq!(retained.len(), 5);
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
                    && !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".tirith-setup-lock-")
            }));
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
        assert!(backup_paths(root.path()).is_empty());
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-")
                    && !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".tirith-setup-lock-")
            }));
    }

    #[test]
    fn failure_after_temp_sync_removes_temp_and_transaction_backup() {
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
        assert!(backup_paths(root.path()).is_empty());
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
