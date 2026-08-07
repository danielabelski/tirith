//! Capability-bound filesystem helpers for security-sensitive directory and
//! repository-contained file creation.
//!
//! The public wrappers deliberately retain an opened parent directory from
//! validation through publication.  Platform implementations must never fall
//! back to a checked pathname for the security-sensitive write itself.

use std::io;
use std::path::Path;

use super::OpenRegularError;

/// A file destination whose parent was traversed beneath an explicit root
/// without following attacker-controlled directory links.  The platform
/// capability remains held until this value is dropped.
#[doc(hidden)]
pub struct ContainedAtomicFile(platform::ContainedAtomicFile);

impl ContainedAtomicFile {
    /// Bind `path` to a retained parent capability beneath `root`.
    ///
    /// When `create_parent` is true, missing directory components are created
    /// relative to already-open parent capabilities. Unix attempts to fsync each
    /// new parent and warns on failure; Windows retains the directory handles but
    /// cannot promise portable directory-entry durability.
    pub fn prepare(root: &Path, path: &Path, create_parent: bool) -> io::Result<Self> {
        platform::ContainedAtomicFile::prepare(root, path, create_parent).map(Self)
    }

    /// Read the currently named regular file through the retained parent
    /// capability, refusing a final symlink and bounding the complete read.
    pub fn read_capped(&self, cap: u64) -> Result<Vec<u8>, OpenRegularError> {
        self.0.read_capped(cap)
    }

    /// Atomically publish `contents` through the retained parent capability.
    /// The prepared tempfile is flushed before publication; publication never
    /// follows a final-component symlink.
    pub fn write_atomic(&self, contents: &[u8], overwrite: bool) -> io::Result<()> {
        self.0.write_atomic(contents, overwrite)
    }
}

/// Create `dir` and any missing ancestors through retained directory
/// capabilities.  Existing attacker-controlled symlink components are refused.
pub(super) fn create_dir_all_durable(dir: &Path) -> io::Result<()> {
    platform::create_dir_all_durable(dir)
}

#[cfg(unix)]
mod platform {
    use std::collections::VecDeque;
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Component, Path, PathBuf};

    use super::OpenRegularError;

    const MAX_TRUSTED_SYMLINKS: usize = 40;
    const MAX_SYMLINK_BYTES: usize = 64 * 1024;

    #[cfg(test)]
    type DirectoryOpenTestHook = Option<Box<dyn FnMut(&OsStr)>>;

    #[cfg(test)]
    thread_local! {
        /// Runs immediately before a descriptor-relative directory open. The
        /// traversal regression replaces the visible parent at this exact seam
        /// and proves the retained fd remains the only authority.
        static DIRECTORY_OPEN_TEST_HOOK: std::cell::RefCell<DirectoryOpenTestHook> =
            std::cell::RefCell::new(None);
    }

    fn invalid_input(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }

    fn permission_denied(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message.into())
    }

    fn absolute(path: &Path) -> io::Result<PathBuf> {
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()?.join(path))
        }
    }

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| invalid_input("path component contains NUL"))
    }

    fn open_root() -> io::Result<File> {
        let root = c"/";
        // SAFETY: `root` is a live NUL-terminated string and the returned fd is
        // uniquely transferred into `File` on success.
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `fd` is a newly owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn open_dir_at(parent: &File, name: &CString) -> io::Result<File> {
        #[cfg(test)]
        DIRECTORY_OPEN_TEST_HOOK.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook(OsStr::from_bytes(name.as_bytes()));
            }
        });
        // SAFETY: both fd and C string stay valid for the duration of `openat`.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `fd` is a newly owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn mkdir_at(parent: &File, name: &CString) -> io::Result<bool> {
        // SAFETY: both fd and C string stay valid for the duration of `mkdirat`.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(error)
        }
    }

    fn parent_can_authorize_system_symlink(parent: &File) -> io::Result<bool> {
        let metadata = parent.metadata()?;
        Ok(metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    }

    fn read_link_at(parent: &File, name: &CString) -> io::Result<OsString> {
        let mut capacity = 256usize;
        loop {
            let mut buffer = vec![0u8; capacity];
            // SAFETY: the fd/name are live and `buffer` is writable for
            // `capacity` bytes. `readlinkat` does not append a NUL.
            let length = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if length < 0 {
                return Err(io::Error::last_os_error());
            }
            let length = length as usize;
            if length < buffer.len() {
                buffer.truncate(length);
                return Ok(OsString::from_vec(buffer));
            }
            if capacity >= MAX_SYMLINK_BYTES {
                return Err(invalid_input("symlink target exceeds traversal limit"));
            }
            capacity = (capacity * 2).min(MAX_SYMLINK_BYTES);
        }
    }

    #[derive(Debug)]
    enum TraversalPart {
        Root,
        Parent,
        Normal(OsString),
    }

    fn parts(path: &Path, allow_parent: bool) -> io::Result<VecDeque<TraversalPart>> {
        let mut out = VecDeque::new();
        for component in path.components() {
            match component {
                Component::RootDir => out.push_back(TraversalPart::Root),
                Component::CurDir => {}
                Component::ParentDir if allow_parent => out.push_back(TraversalPart::Parent),
                Component::ParentDir => {
                    return Err(permission_denied(format!(
                        "refusing parent traversal in {}",
                        path.display()
                    )))
                }
                Component::Normal(name) => {
                    out.push_back(TraversalPart::Normal(name.to_os_string()))
                }
                Component::Prefix(_) => {
                    return Err(invalid_input("Windows path prefix on a Unix platform"))
                }
            }
        }
        Ok(out)
    }

    /// Traverse from the filesystem root.  User-controlled symlinks are never
    /// followed.  A root-owned link in a non-writable root-owned directory is
    /// resolved descriptor-relatively so normal platform aliases such as macOS
    /// `/var -> private/var` remain usable without admitting a planted link in a
    /// user-writable tree.
    fn secure_directory(path: &Path, create: bool) -> io::Result<File> {
        let absolute = absolute(path)?;
        let mut pending = parts(&absolute, false)?;
        if !matches!(pending.front(), Some(TraversalPart::Root)) {
            return Err(invalid_input("secure directory path is not absolute"));
        }
        pending.pop_front();

        let mut stack = vec![open_root()?];
        let mut resolved_links = 0usize;
        while let Some(part) = pending.pop_front() {
            match part {
                TraversalPart::Root => {
                    stack.truncate(1);
                }
                TraversalPart::Parent => {
                    if stack.len() == 1 {
                        return Err(permission_denied(
                            "trusted system symlink target escapes filesystem root",
                        ));
                    }
                    stack.pop();
                }
                TraversalPart::Normal(name) => {
                    let encoded = c_name(&name)?;
                    let parent = stack.last().expect("root directory capability exists");
                    match open_dir_at(parent, &encoded) {
                        Ok(directory) => stack.push(directory),
                        Err(open_error) => {
                            // `readlinkat` succeeds only for a symlink.  Do not
                            // classify errors by one OS-specific ELOOP value.
                            if let Ok(target) = read_link_at(parent, &encoded) {
                                if !parent_can_authorize_system_symlink(parent)? {
                                    return Err(permission_denied(format!(
                                        "refusing symlinked directory component {}",
                                        name.to_string_lossy()
                                    )));
                                }
                                resolved_links += 1;
                                if resolved_links > MAX_TRUSTED_SYMLINKS {
                                    return Err(invalid_input(
                                        "too many trusted system symlinks during traversal",
                                    ));
                                }
                                let target_path = PathBuf::from(target);
                                let mut target_parts = parts(&target_path, true)?;
                                while let Some(target_part) = target_parts.pop_back() {
                                    pending.push_front(target_part);
                                }
                                continue;
                            }

                            if open_error.kind() != io::ErrorKind::NotFound || !create {
                                return Err(open_error);
                            }
                            let created = mkdir_at(parent, &encoded)?;
                            if created {
                                // Persist each new directory entry before
                                // descending so the final file cannot outlive an
                                // uncommitted ancestor after a crash.
                                if let Err(error) = parent.sync_all() {
                                    eprintln!(
                                        "tirith: warning: could not fsync directory after creating {}: {error}; the directory exists but its entry may not be crash-durable",
                                        name.to_string_lossy()
                                    );
                                }
                            }
                            let directory = open_dir_at(parent, &encoded).map_err(|error| {
                                if read_link_at(parent, &encoded).is_ok() {
                                    permission_denied(format!(
                                        "directory component {} became a symlink: {error}",
                                        name.to_string_lossy()
                                    ))
                                } else {
                                    error
                                }
                            })?;
                            stack.push(directory);
                        }
                    }
                }
            }
        }
        stack
            .pop()
            .ok_or_else(|| invalid_input("directory traversal produced no capability"))
    }

    pub(super) fn create_dir_all_durable(dir: &Path) -> io::Result<()> {
        let directory = secure_directory(dir, true)?;
        if let Err(error) = directory.sync_all() {
            eprintln!(
                "tirith: warning: could not fsync newly validated directory {}: {error}; the directory exists but may not be crash-durable",
                dir.display()
            );
        }
        Ok(())
    }

    fn relative_normal_components<'a>(path: &'a Path, root: &Path) -> io::Result<Vec<&'a OsStr>> {
        let relative = path.strip_prefix(root).map_err(|_| {
            permission_denied(format!(
                "{} is outside contained root {}",
                path.display(),
                root.display()
            ))
        })?;
        relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name),
                _ => Err(permission_denied(format!(
                    "{} contains a non-normal component beneath {}",
                    path.display(),
                    root.display()
                ))),
            })
            .collect()
    }

    fn inspect_final(parent: &File, name: &CString) -> io::Result<Option<libc::mode_t>> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd/name are live, `stat` points to writable storage, and
        // AT_SYMLINK_NOFOLLOW ensures the named entry itself is inspected.
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            // SAFETY: successful `fstatat` initialized `stat`.
            return Ok(Some(unsafe { stat.assume_init() }.st_mode));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        }
    }

    fn require_nonsymlink_final(parent: &File, name: &CString, display: &Path) -> io::Result<()> {
        if inspect_final(parent, name)?.is_some_and(|mode| mode & libc::S_IFMT == libc::S_IFLNK) {
            return Err(invalid_input(format!(
                "refusing symlinked contained destination {}",
                display.display()
            )));
        }
        Ok(())
    }

    pub(super) struct ContainedAtomicFile {
        _root: File,
        parent: File,
        name: CString,
        display: PathBuf,
    }

    impl ContainedAtomicFile {
        pub(super) fn prepare(root: &Path, path: &Path, create_parent: bool) -> io::Result<Self> {
            let absolute_root = absolute(root)?;
            let absolute_path = absolute(path)?;
            let components = relative_normal_components(&absolute_path, &absolute_root)?;
            let (name, parents) = components.split_last().ok_or_else(|| {
                invalid_input("contained atomic destination names its root, not a file")
            })?;

            if create_parent {
                create_dir_all_durable(&absolute_root)?;
            }
            let root = secure_directory(&absolute_root, false)?;
            let mut parent = root.try_clone()?;
            for component in parents {
                let component = c_name(component)?;
                match open_dir_at(&parent, &component) {
                    Ok(next) => parent = next,
                    Err(error) if error.kind() == io::ErrorKind::NotFound && create_parent => {
                        let created = mkdir_at(&parent, &component)?;
                        if created {
                            if let Err(error) = parent.sync_all() {
                                eprintln!(
                                    "tirith: warning: could not fsync contained directory after creating {}: {error}; the directory exists but its entry may not be crash-durable",
                                    component.to_string_lossy()
                                );
                            }
                        }
                        parent = open_dir_at(&parent, &component).map_err(|open_error| {
                            if read_link_at(&parent, &component).is_ok() {
                                permission_denied(format!(
                                    "refusing symlinked contained directory component {}",
                                    component.to_string_lossy()
                                ))
                            } else {
                                open_error
                            }
                        })?;
                    }
                    Err(error) => {
                        return Err(if read_link_at(&parent, &component).is_ok() {
                            permission_denied(format!(
                                "refusing symlinked contained directory component {}",
                                component.to_string_lossy()
                            ))
                        } else {
                            error
                        })
                    }
                }
            }

            let name = c_name(name)?;
            require_nonsymlink_final(&parent, &name, &absolute_path)?;
            Ok(Self {
                _root: root,
                parent,
                name,
                display: absolute_path,
            })
        }

        pub(super) fn read_capped(&self, cap: u64) -> Result<Vec<u8>, OpenRegularError> {
            // SAFETY: fd/name are live and the returned descriptor is uniquely
            // transferred to `File` on success.
            let fd = unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Err(OpenRegularError::NotFound);
                }
                if error.raw_os_error() == Some(libc::ELOOP) {
                    return Err(OpenRegularError::NotRegularFile);
                }
                return Err(OpenRegularError::Io(error));
            }
            // SAFETY: `fd` is a newly owned descriptor.
            let mut file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata().map_err(OpenRegularError::Io)?;
            if !metadata.is_file() {
                return Err(OpenRegularError::NotRegularFile);
            }
            if metadata.len() > cap {
                return Err(OpenRegularError::TooLarge);
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take(cap.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(OpenRegularError::Io)?;
            if bytes.len() as u64 > cap {
                return Err(OpenRegularError::TooLarge);
            }
            Ok(bytes)
        }

        pub(super) fn write_atomic(&self, contents: &[u8], overwrite: bool) -> io::Result<()> {
            require_nonsymlink_final(&self.parent, &self.name, &self.display)?;
            if !overwrite && inspect_final(&self.parent, &self.name)?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} already exists", self.display.display()),
                ));
            }

            let temp_name = CString::new(format!(
                ".tirith-contained-{}.tmp",
                uuid::Uuid::new_v4().simple()
            ))
            .expect("UUID temporary name contains no NUL");
            // SAFETY: fd/name are live; O_EXCL gives this call exclusive
            // provenance for the newly created entry.
            let fd = unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    temp_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut temp = TempEntry {
                parent: &self.parent,
                name: temp_name,
                armed: true,
            };
            // SAFETY: `fd` is a newly owned descriptor.
            let mut file = unsafe { File::from_raw_fd(fd) };
            file.write_all(contents)?;
            file.flush()?;
            file.sync_all()?;

            // Recheck the final entry immediately before the atomic namespace
            // operation.  A later swap to a symlink is still safe: renameat
            // replaces the link entry itself and never follows its target.
            require_nonsymlink_final(&self.parent, &self.name, &self.display)?;
            let result = if overwrite {
                // SAFETY: both descriptors and names are live. Same-parent
                // rename is atomic and cannot escape the retained directory.
                unsafe {
                    libc::renameat(
                        self.parent.as_raw_fd(),
                        temp.name.as_ptr(),
                        self.parent.as_raw_fd(),
                        self.name.as_ptr(),
                    )
                }
            } else {
                rename_no_replace(&self.parent, &temp.name, &self.name)
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            temp.armed = false;

            // Publication has succeeded. Preserve the existing contract: a
            // directory-sync failure is visible but does not turn a completed
            // atomic replacement into a reported write failure.
            if let Err(error) = self.parent.sync_all() {
                eprintln!(
                    "tirith: warning: could not fsync parent directory of {} (atomic file write): {error}; the write succeeded but its directory entry may not be crash-durable",
                    self.display.display()
                );
            }
            Ok(())
        }
    }

    fn rename_no_replace(parent: &File, source: &CString, destination: &CString) -> libc::c_int {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: both names are live and relative to the same retained fd.
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    parent.as_raw_fd(),
                    source.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as libc::c_int
            }
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // SAFETY: both names are live and relative to the same retained fd.
            unsafe {
                libc::renameatx_np(
                    parent.as_raw_fd(),
                    source.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_EXCL,
                )
            }
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )))]
        {
            // Portable POSIX fallback: `linkat` is atomic no-clobber because it
            // fails when the destination exists. Remove the private name only
            // after the complete inode is visible under the destination.
            let linked = unsafe {
                libc::linkat(
                    parent.as_raw_fd(),
                    source.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    0,
                )
            };
            if linked < 0 {
                return linked;
            }
            unsafe { libc::unlinkat(parent.as_raw_fd(), source.as_ptr(), 0) }
        }
    }

    struct TempEntry<'a> {
        parent: &'a File,
        name: CString,
        armed: bool,
    }

    impl Drop for TempEntry<'_> {
        fn drop(&mut self) {
            if self.armed {
                // SAFETY: fd/name stay live for this cleanup attempt. We never
                // follow the entry being removed.
                unsafe {
                    let _ = libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::cell::Cell;
        use std::ffi::OsStr;
        use std::rc::Rc;

        use super::*;

        fn clear_directory_open_hook() {
            DIRECTORY_OPEN_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }

        #[test]
        fn atomic_write_stays_under_retained_parent_after_visible_parent_replacement() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let parent = root.join("parent");
            let displaced = root.join("held-parent");
            std::fs::create_dir_all(&parent).unwrap();

            let destination = parent.join("out.bin");
            let writer = ContainedAtomicFile::prepare(&root, &destination, false).unwrap();
            std::fs::rename(&parent, &displaced).unwrap();
            std::fs::create_dir(&parent).unwrap();

            writer.write_atomic(b"held identity", true).unwrap();

            assert_eq!(
                std::fs::read(displaced.join("out.bin")).unwrap(),
                b"held identity"
            );
            assert!(
                !parent.join("out.bin").exists(),
                "publication must not follow the visible replacement parent"
            );
        }

        #[test]
        fn directory_creation_stays_under_retained_parent_after_visible_parent_replacement() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let parent = root.join("parent");
            let displaced = root.join("held-parent");
            std::fs::create_dir_all(&parent).unwrap();

            let fired = Rc::new(Cell::new(false));
            let hook_fired = Rc::clone(&fired);
            let hook_parent = parent.clone();
            let hook_displaced = displaced.clone();
            DIRECTORY_OPEN_TEST_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |name| {
                    if !hook_fired.get() && name == OsStr::new("child") {
                        hook_fired.set(true);
                        std::fs::rename(&hook_parent, &hook_displaced).unwrap();
                        std::fs::create_dir(&hook_parent).unwrap();
                    }
                }));
            });

            let result = create_dir_all_durable(&parent.join("child").join("grandchild"));
            clear_directory_open_hook();
            result.unwrap();

            assert!(fired.get(), "the deterministic replacement seam must run");
            assert!(displaced.join("child").join("grandchild").is_dir());
            assert!(
                !parent.join("child").exists(),
                "child creation must not follow the visible replacement parent"
            );
        }
    }
}

#[cfg(windows)]
mod platform {
    // The Windows implementation follows the same retained-capability model as
    // the repo-trust and setup writers: each no-reparse directory is held,
    // temp identity is verified against that held parent before bytes are
    // written, and SetFileInformationByHandle publishes relative to the held
    // parent handle.
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
    use std::path::{Component, Path, PathBuf};
    use std::ptr::{null, null_mut};

    use super::OpenRegularError;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, RtlNtStatusToDosError, DUPLICATE_SAME_ACCESS,
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileDispositionInfo, FileRenameInfo, GetFileInformationByHandle,
        SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING,
        SYNCHRONIZE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    #[cfg(test)]
    thread_local! {
        /// Runs immediately before a descriptor-relative child open. Windows
        /// regressions use this seam to move the visible parent while its
        /// validated handle remains held and prove the open cannot follow the
        /// replacement path.
        static RELATIVE_OPEN_TEST_HOOK:
            std::cell::RefCell<Option<Box<dyn FnMut(&Path, &OsStr)>>> =
            std::cell::RefCell::new(None);
    }

    fn invalid_input(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }

    fn permission_denied(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message.into())
    }

    /// Name the syscall and its target on the way out. A bare `io::Error` from
    /// one of these handle-relative calls says only "The parameter is
    /// incorrect", which cannot be told apart from a dozen other call sites.
    /// The kind is preserved so `is_not_found` and `is_already_exists` still
    /// classify a wrapped error.
    fn with_context(
        operation: &str,
        target: impl std::fmt::Display,
        error: io::Error,
    ) -> io::Error {
        io::Error::new(error.kind(), format!("{operation} {target}: {error}"))
    }

    fn absolute(path: &Path) -> io::Result<PathBuf> {
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()?.join(path))
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn relative_name(name: &OsStr) -> io::Result<Vec<u16>> {
        let encoded: Vec<u16> = name.encode_wide().collect();
        let byte_len = encoded
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .filter(|length| *length <= u16::MAX as usize)
            .ok_or_else(|| invalid_input("descriptor-relative Windows name is too long"))?;
        if encoded.is_empty()
            || (encoded.len() == 1 && encoded[0] == u16::from(b'.'))
            || (encoded.len() == 2
                && encoded[0] == u16::from(b'.')
                && encoded[1] == u16::from(b'.'))
            || encoded.iter().any(|unit| {
                *unit == 0
                    || *unit == u16::from(b'\\')
                    || *unit == u16::from(b'/')
                    || *unit == u16::from(b':')
            })
        {
            return Err(invalid_input(
                "descriptor-relative Windows name is not one safe path component",
            ));
        }
        debug_assert_eq!(byte_len, encoded.len() * std::mem::size_of::<u16>());
        Ok(encoded)
    }

    fn is_not_found(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound
            || matches!(
                error.raw_os_error().map(|code| code as u32),
                Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PATH_NOT_FOUND)
            )
    }

    fn is_already_exists(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::AlreadyExists
            || matches!(
                error.raw_os_error().map(|code| code as u32),
                Some(ERROR_ALREADY_EXISTS) | Some(ERROR_FILE_EXISTS)
            )
    }

    fn nt_open_relative(
        parent: HANDLE,
        display_parent: &Path,
        name: &OsStr,
        desired_access: u32,
        disposition: u32,
        options: u32,
        attributes: u32,
    ) -> io::Result<OwnedHandle> {
        #[cfg(test)]
        RELATIVE_OPEN_TEST_HOOK.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook(display_parent, name);
            }
        });
        // Keep the caller's `name` in scope: the error path below joins it onto
        // `display_parent` for the diagnostic, and a UTF-16 buffer is not a path.
        let mut encoded_name = relative_name(name)?;
        let byte_len = u16::try_from(encoded_name.len() * std::mem::size_of::<u16>())
            .map_err(|_| invalid_input("descriptor-relative Windows name is too long"))?;
        let unicode_name = UNICODE_STRING {
            Length: byte_len,
            MaximumLength: byte_len,
            Buffer: encoded_name.as_mut_ptr(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent,
            ObjectName: &unicode_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut io_status = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = null_mut();
        // SAFETY: every pointer references live storage for the duration of the
        // call. `RootDirectory` is a retained directory handle, and ObjectName
        // is a validated single relative component with an explicit byte length.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access | SYNCHRONIZE,
                &object_attributes,
                &mut io_status,
                null(),
                attributes,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if status < 0 {
            // NTSTATUS values are not Win32 error codes. Translate before
            // constructing io::Error so NotFound/AlreadyExists classification
            // remains correct at the Rust boundary.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(with_context(
                &format!(
                    "NtCreateFile (status 0x{:08x}, access 0x{:08x}, \
                     disposition {disposition}, options 0x{:08x})",
                    status as u32,
                    desired_access | SYNCHRONIZE,
                    options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ),
                display_parent.join(name).display(),
                io::Error::from_raw_os_error(code as i32),
            ));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "NtCreateFile succeeded without returning a valid handle",
            ));
        }
        Ok(OwnedHandle(handle))
    }

    fn inspect_directory(handle: HANDLE, path: &Path) -> io::Result<()> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: handle is live and `info` is writable.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(with_context(
                "inspect directory handle",
                path.display(),
                io::Error::last_os_error(),
            ));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(permission_denied(format!(
                "refusing reparse or non-directory component {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn open_directory_with_delete(
        path: &Path,
        request_delete: bool,
    ) -> io::Result<Option<OwnedHandle>> {
        let path_wide = wide(path);
        let access = FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | if request_delete { DELETE } else { 0 };
        // SAFETY: pointers are live and the call returns a new owned handle.
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error().map(|code| code as u32),
                Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PATH_NOT_FOUND)
            ) {
                return Ok(None);
            }
            return Err(with_context("open directory", path.display(), error));
        }
        let handle = OwnedHandle(handle);
        inspect_directory(handle.0, path)?;
        Ok(Some(handle))
    }

    fn open_directory(path: &Path) -> io::Result<Option<OwnedHandle>> {
        open_directory_with_delete(path, false)
    }

    fn mark_for_deletion(handle: HANDLE) -> io::Result<()> {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: handle is live and the typed buffer is valid for the call.
        if unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    struct HeldDirectory {
        handle: OwnedHandle,
        path: PathBuf,
    }

    fn root_path(path: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
        let absolute = absolute(path)?;
        let mut components = absolute.components();
        let prefix = match components.next() {
            Some(Component::Prefix(prefix)) => prefix.as_os_str().to_os_string(),
            _ => return Err(invalid_input("Windows path has no absolute prefix")),
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(invalid_input("Windows path is not absolute"));
        }
        let mut root = PathBuf::from(prefix);
        root.push(Path::new(r"\"));
        let mut names = Vec::new();
        for component in components {
            match component {
                Component::Normal(name) => names.push(name.to_os_string()),
                Component::CurDir => {}
                _ => {
                    return Err(permission_denied(format!(
                        "refusing non-normal Windows directory path {}",
                        absolute.display()
                    )))
                }
            }
        }
        Ok((root, names))
    }

    fn open_or_create_child(
        parent: &HeldDirectory,
        name: &OsStr,
        create: bool,
    ) -> io::Result<Option<HeldDirectory>> {
        let path = parent.path.join(name);
        let directory_access = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;
        let child = match nt_open_relative(
            parent.handle.0,
            &parent.path,
            name,
            directory_access,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            FILE_ATTRIBUTE_NORMAL,
        ) {
            Ok(child) => child,
            Err(error) if is_not_found(&error) && !create => return Ok(None),
            Err(error) if is_not_found(&error) => match nt_open_relative(
                parent.handle.0,
                &parent.path,
                name,
                directory_access | DELETE,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
                FILE_ATTRIBUTE_NORMAL,
            ) {
                Ok(child) => child,
                Err(collision) if is_already_exists(&collision) => nt_open_relative(
                    parent.handle.0,
                    &parent.path,
                    name,
                    directory_access,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    FILE_ATTRIBUTE_NORMAL,
                )?,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error),
        };
        inspect_directory(child.0, &path)?;
        Ok(Some(HeldDirectory {
            handle: child,
            path,
        }))
    }

    fn secure_directory(path: &Path, create: bool) -> io::Result<HeldDirectory> {
        let (root_path, names) = root_path(path)?;
        let root = open_directory(&root_path)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Windows root {} does not exist", root_path.display()),
            )
        })?;
        let mut current = HeldDirectory {
            handle: root,
            path: root_path,
        };
        for name in names {
            current = open_or_create_child(&current, &name, create)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "directory component {} does not exist",
                        name.to_string_lossy()
                    ),
                )
            })?;
        }
        Ok(current)
    }

    pub(super) fn create_dir_all_durable(dir: &Path) -> io::Result<()> {
        let directory = secure_directory(dir, true)?;
        // Windows does not provide portable directory fsync semantics. The
        // handle is nevertheless retained until traversal completes.
        drop(directory);
        Ok(())
    }

    fn relative_normal_components(path: &Path, root: &Path) -> io::Result<Vec<OsString>> {
        let relative = path.strip_prefix(root).map_err(|_| {
            permission_denied(format!(
                "{} is outside contained root {}",
                path.display(),
                root.display()
            ))
        })?;
        relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(permission_denied(format!(
                    "{} contains a non-normal component beneath {}",
                    path.display(),
                    root.display()
                ))),
            })
            .collect()
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum RelativeFileDisposition {
        OpenExisting,
        CreateNew,
    }

    fn open_named_file(
        parent: &HeldDirectory,
        name: &OsStr,
        access: u32,
        disposition: RelativeFileDisposition,
    ) -> io::Result<Option<OwnedHandle>> {
        let native_disposition = match disposition {
            RelativeFileDisposition::OpenExisting => FILE_OPEN,
            RelativeFileDisposition::CreateNew => FILE_CREATE,
        };
        match nt_open_relative(
            parent.handle.0,
            &parent.path,
            name,
            access,
            native_disposition,
            FILE_NON_DIRECTORY_FILE,
            FILE_ATTRIBUTE_NORMAL,
        ) {
            Ok(handle) => Ok(Some(handle)),
            Err(error)
                if disposition == RelativeFileDisposition::OpenExisting && is_not_found(&error) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn inspect_regular(handle: HANDLE, display: &Path) -> io::Result<u64> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: handle is live and `info` is writable.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(with_context(
                "inspect file handle",
                display.display(),
                io::Error::last_os_error(),
            ));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            return Err(invalid_input(format!(
                "refusing reparse or non-regular contained destination {}",
                display.display()
            )));
        }
        Ok(((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64)
    }

    fn inspect_destination(
        parent: &HeldDirectory,
        name: &OsStr,
        display: &Path,
    ) -> io::Result<bool> {
        let Some(handle) = open_named_file(
            parent,
            name,
            FILE_READ_ATTRIBUTES,
            RelativeFileDisposition::OpenExisting,
        )?
        else {
            return Ok(false);
        };
        inspect_regular(handle.0, display)?;
        Ok(true)
    }

    pub(super) struct ContainedAtomicFile {
        _root: OwnedHandle,
        parent: HeldDirectory,
        name: OsString,
        display: PathBuf,
    }

    impl ContainedAtomicFile {
        pub(super) fn prepare(root: &Path, path: &Path, create_parent: bool) -> io::Result<Self> {
            let absolute_root = absolute(root)?;
            let absolute_path = absolute(path)?;
            let components = relative_normal_components(&absolute_path, &absolute_root)?;
            let (name, parents) = components.split_last().ok_or_else(|| {
                invalid_input("contained atomic destination names its root, not a file")
            })?;

            if create_parent {
                create_dir_all_durable(&absolute_root)?;
            }
            let root = secure_directory(&absolute_root, false)?;
            let root_handle = root.handle.try_clone()?;
            let mut parent = root;
            for component in parents {
                parent =
                    open_or_create_child(&parent, component, create_parent)?.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "contained parent {} does not exist",
                                component.to_string_lossy()
                            ),
                        )
                    })?;
            }
            inspect_destination(&parent, name, &absolute_path)?;
            Ok(Self {
                _root: root_handle,
                parent,
                name: name.clone(),
                display: absolute_path,
            })
        }

        pub(super) fn read_capped(&self, cap: u64) -> Result<Vec<u8>, OpenRegularError> {
            let handle = match open_named_file(
                &self.parent,
                &self.name,
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES,
                RelativeFileDisposition::OpenExisting,
            ) {
                Ok(Some(handle)) => handle,
                Ok(None) => return Err(OpenRegularError::NotFound),
                Err(error) => return Err(OpenRegularError::Io(error)),
            };
            let size = inspect_regular(handle.0, &self.display).map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidInput {
                    OpenRegularError::NotRegularFile
                } else {
                    OpenRegularError::Io(error)
                }
            })?;
            if size > cap {
                return Err(OpenRegularError::TooLarge);
            }
            let mut file = handle.into_file();
            let mut bytes = Vec::new();
            (&mut file)
                .take(cap.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(OpenRegularError::Io)?;
            if bytes.len() as u64 > cap {
                return Err(OpenRegularError::TooLarge);
            }
            Ok(bytes)
        }

        pub(super) fn write_atomic(&self, contents: &[u8], overwrite: bool) -> io::Result<()> {
            let exists = inspect_destination(&self.parent, &self.name, &self.display)?;
            if exists && !overwrite {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} already exists", self.display.display()),
                ));
            }

            let temp_name = OsString::from(format!(
                ".tirith-contained-{}.tmp",
                uuid::Uuid::new_v4().simple()
            ));
            let handle = open_named_file(
                &self.parent,
                &temp_name,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE,
                RelativeFileDisposition::CreateNew,
            )?
            .ok_or_else(|| io::Error::other("exclusive temporary file creation returned absent"))?;
            let mut temp = TempEntry {
                file: handle.into_file(),
                armed: true,
            };
            inspect_regular(raw_handle(&temp.file), &self.display)?;
            temp.file.write_all(contents)?;
            temp.file.flush()?;
            temp.file.sync_all()?;

            // Revalidate the live destination immediately before a handle-
            // relative rename. A later path swap cannot redirect publication:
            // RootDirectory remains the retained parent handle.
            inspect_destination(&self.parent, &self.name, &self.display)?;
            rename_held_file(
                raw_handle(&temp.file),
                self.parent.handle.0,
                &self.name,
                overwrite,
            )?;
            temp.armed = false;
            Ok(())
        }
    }

    fn raw_handle(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }

    fn rename_held_file(
        file: HANDLE,
        parent: HANDLE,
        name: &OsStr,
        overwrite: bool,
    ) -> io::Result<()> {
        let display_name = name.to_string_lossy().into_owned();
        let name = relative_name(name)?;
        let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let bytes = offset + name.len() * std::mem::size_of::<u16>();
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; words];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: storage is aligned for FILE_RENAME_INFO and sized through the
        // variable filename payload.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = overwrite;
            (*info).RootDirectory = parent;
            (*info).FileNameLength = (name.len() * std::mem::size_of::<u16>()) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            if SetFileInformationByHandle(file, FileRenameInfo, info.cast(), bytes as u32) == 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_ALREADY_EXISTS) | Some(ERROR_FILE_EXISTS)
                ) {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, error));
                }
                return Err(with_context(
                    &format!("publish held temp (replace_if_exists {overwrite}, {bytes} bytes)"),
                    &display_name,
                    error,
                ));
            }
        }
        Ok(())
    }

    struct TempEntry {
        file: File,
        armed: bool,
    }

    impl Drop for TempEntry {
        fn drop(&mut self) {
            if self.armed {
                let _ = mark_for_deletion(raw_handle(&self.file));
            }
        }
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn try_clone(&self) -> io::Result<Self> {
            let process = unsafe { GetCurrentProcess() };
            let mut duplicate = null_mut();
            // SAFETY: source belongs to this process and the returned handle is
            // written into `duplicate` with identical access rights.
            if unsafe {
                DuplicateHandle(
                    process,
                    self.0,
                    process,
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(duplicate))
            }
        }

        fn into_file(self) -> File {
            let handle = self.0;
            std::mem::forget(self);
            // SAFETY: the handle is valid, uniquely owned, and forgotten above.
            unsafe { File::from_raw_handle(handle as RawHandle) }
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this value owns exactly one live handle.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::cell::Cell;
        use std::ffi::OsStr;
        use std::rc::Rc;

        use super::*;

        fn clear_relative_open_hook() {
            RELATIVE_OPEN_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }

        #[test]
        fn atomic_write_stays_under_held_parent_after_visible_parent_replacement() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let parent = root.join("parent");
            let displaced = root.join("held-parent");
            std::fs::create_dir_all(&parent).unwrap();

            let destination = parent.join("out.bin");
            let writer = ContainedAtomicFile::prepare(&root, &destination, false).unwrap();
            let fired = Rc::new(Cell::new(false));
            let hook_fired = Rc::clone(&fired);
            let hook_parent = parent.clone();
            let hook_displaced = displaced.clone();
            RELATIVE_OPEN_TEST_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |opened_parent, name| {
                    if !hook_fired.get()
                        && opened_parent == hook_parent.as_path()
                        && name == OsStr::new("out.bin")
                    {
                        hook_fired.set(true);
                        std::fs::rename(&hook_parent, &hook_displaced).unwrap();
                        std::fs::create_dir(&hook_parent).unwrap();
                    }
                }));
            });

            let result = writer.write_atomic(b"held identity", true);
            clear_relative_open_hook();
            result.unwrap();

            assert!(fired.get(), "the deterministic replacement seam must run");
            assert_eq!(
                std::fs::read(displaced.join("out.bin")).unwrap(),
                b"held identity"
            );
            assert!(
                !parent.join("out.bin").exists(),
                "publication must not follow the visible replacement parent"
            );
        }

        #[test]
        fn directory_creation_stays_under_held_parent_after_visible_parent_replacement() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let parent = root.join("parent");
            let displaced = root.join("held-parent");
            std::fs::create_dir_all(&parent).unwrap();

            let fired = Rc::new(Cell::new(false));
            let hook_fired = Rc::clone(&fired);
            let hook_parent = parent.clone();
            let hook_displaced = displaced.clone();
            RELATIVE_OPEN_TEST_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |opened_parent, name| {
                    if !hook_fired.get()
                        && opened_parent == hook_parent.as_path()
                        && name == OsStr::new("child")
                    {
                        hook_fired.set(true);
                        std::fs::rename(&hook_parent, &hook_displaced).unwrap();
                        std::fs::create_dir(&hook_parent).unwrap();
                    }
                }));
            });

            let result = create_dir_all_durable(&parent.join("child").join("grandchild"));
            clear_relative_open_hook();
            result.unwrap();

            assert!(fired.get(), "the deterministic replacement seam must run");
            assert!(displaced.join("child/grandchild").is_dir());
            assert!(
                !parent.join("child").exists(),
                "child creation must not follow the visible replacement parent"
            );
        }
    }
}

#[cfg(all(not(unix), not(windows)))]
mod platform {
    use std::io;
    use std::path::Path;

    use super::OpenRegularError;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "contained filesystem writes require Unix descriptor-relative or Windows handle-relative operations",
        )
    }

    pub(super) struct ContainedAtomicFile;

    impl ContainedAtomicFile {
        pub(super) fn prepare(
            _root: &Path,
            _path: &Path,
            _create_parent: bool,
        ) -> io::Result<Self> {
            Err(unsupported())
        }

        pub(super) fn read_capped(&self, _cap: u64) -> Result<Vec<u8>, OpenRegularError> {
            Err(OpenRegularError::Io(unsupported()))
        }

        pub(super) fn write_atomic(&self, _contents: &[u8], _overwrite: bool) -> io::Result<()> {
            Err(unsupported())
        }
    }

    pub(super) fn create_dir_all_durable(_dir: &Path) -> io::Result<()> {
        Err(unsupported())
    }
}
