//! Trusted executable selection and bounded child-process supervision.
//!
//! Security-sensitive callers resolve an executable once, validate its absolute
//! identity, clear the ambient environment, and run it with explicit capture
//! limits. On Unix every child owns a process group. On Windows every child is
//! created suspended, assigned to a kill-on-close Job Object, then resumed. A
//! timeout or output flood therefore terminates descendants as well as the direct
//! child on both platform families.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
#[cfg(not(windows))]
use std::time::Instant;

#[cfg(windows)]
mod windows;

#[derive(Debug, Clone)]
pub struct TrustedExecutable {
    path: PathBuf,
    #[cfg(unix)]
    identity: UnixExecutableIdentity,
    #[cfg(not(unix))]
    digest: [u8; 32],
    #[cfg(windows)]
    source: WindowsExecutableSource,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixExecutableIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

/// How an absolute Windows executable was selected. The source is part of the
/// provenance decision: a PATH-discovered program needs installed provenance,
/// while a fixed absolute path/current image is explicit caller authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsExecutableSource {
    /// Caller supplied a fixed absolute path.
    ExplicitAbsolute,
    /// Program was selected from the process PATH.
    PathSearch,
    /// Program is the image already running this process.
    CurrentProcess,
    /// Caller selected from a fixed OS-owned candidate list.
    SystemCandidate,
}

/// Security-relevant owner class returned by the Windows ACL validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsOwnerClass {
    /// Owner SID matches the current process token's user.
    CurrentUser,
    /// Owner SID is LocalSystem.
    LocalSystem,
    /// Owner SID is the built-in Administrators group.
    Administrators,
    /// Owner SID is the Windows Modules Installer service.
    TrustedInstaller,
    /// Owner is present but outside the recognized provenance principals.
    Other,
}

/// Host facts consumed by the pure Windows trust policy. Keeping this decision
/// separate from Win32 collection makes every allow/deny branch host-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsTrustFacts {
    /// A broad low-trust principal can replace the file or an ancestor.
    pub broad_write_access: bool,
    /// Owner of the executable itself.
    pub leaf_owner: WindowsOwnerClass,
    /// Every owner from the executable through its ancestor chain is recognized.
    pub owner_chain_trusted: bool,
    /// ACL and owner evidence establish a protected current-user install tree.
    pub secure_user_install: bool,
    /// Path is under a canonical Windows or Program Files root.
    pub protected_install_root: bool,
    /// Offline WinVerifyTrust policy accepted the image signature.
    pub authenticode_trusted: bool,
}

/// Provenance that authorized a Windows executable after ACL validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsTrustProvenance {
    /// Fixed absolute caller authority plus secure ownership.
    ExplicitAbsolute,
    /// Already-running image plus secure ownership.
    CurrentProcess,
    /// Fixed system candidate under a protected install root.
    SystemCandidate,
    /// Offline Authenticode verification authorized the image.
    Authenticode,
    /// Protected install root and owner chain authorized PATH selection.
    ProtectedInstall,
    /// Secure current-user installation authorized PATH selection.
    SecureUserInstall,
}

/// Decide whether collected Windows ACL/ownership/AuthentiCode evidence is
/// sufficient for the executable-selection source. Broadly writable paths are
/// never trusted, including when a file carries a valid signature: replacement
/// of the path would otherwise bypass the signature checked before launch.
pub fn evaluate_windows_trust(
    source: WindowsExecutableSource,
    facts: WindowsTrustFacts,
) -> Result<WindowsTrustProvenance, &'static str> {
    if facts.broad_write_access {
        return Err("executable or parent path grants broad write access");
    }
    if !facts.owner_chain_trusted || facts.leaf_owner == WindowsOwnerClass::Other {
        return Err("executable has an untrusted owner or ancestor owner");
    }
    match source {
        WindowsExecutableSource::ExplicitAbsolute => Ok(WindowsTrustProvenance::ExplicitAbsolute),
        WindowsExecutableSource::CurrentProcess => Ok(WindowsTrustProvenance::CurrentProcess),
        WindowsExecutableSource::SystemCandidate => {
            if facts.protected_install_root {
                Ok(WindowsTrustProvenance::SystemCandidate)
            } else if facts.authenticode_trusted {
                Ok(WindowsTrustProvenance::Authenticode)
            } else {
                Err("system candidate lacks protected-root or Authenticode provenance")
            }
        }
        WindowsExecutableSource::PathSearch => {
            if facts.authenticode_trusted {
                Ok(WindowsTrustProvenance::Authenticode)
            } else if facts.protected_install_root {
                Ok(WindowsTrustProvenance::ProtectedInstall)
            } else if facts.secure_user_install {
                Ok(WindowsTrustProvenance::SecureUserInstall)
            } else {
                Err("PATH executable lacks Authenticode or trusted install provenance")
            }
        }
    }
}

/// Pure Windows DACL access-mask classifier used by the platform collector.
/// Generic read includes `READ_CONTROL` and `SYNCHRONIZE`; neither is a mutation
/// right, so this intentionally checks only generic write and concrete replace /
/// metadata-write rights instead of intersecting a composite FILE_GENERIC_WRITE.
pub fn windows_access_mask_grants_replacement(mask: u32, leaf: bool) -> bool {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

    let ownership_or_delete = GENERIC_ALL | DELETE | WRITE_DAC | WRITE_OWNER;
    let relevant = if leaf {
        ownership_or_delete
            | GENERIC_WRITE
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_DELETE_CHILD
            | FILE_WRITE_ATTRIBUTES
    } else {
        ownership_or_delete | FILE_DELETE_CHILD
    };
    mask & relevant != 0
}

#[derive(Debug)]
pub enum TrustedExecutableError {
    NotAbsolute(PathBuf),
    NotExecutable(PathBuf),
    NotFound(String),
    Untrusted { path: PathBuf, root: PathBuf },
    InvalidPath { path: PathBuf, reason: String },
}

impl fmt::Display for TrustedExecutableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute(path) => {
                write!(
                    f,
                    "trusted executable path is not absolute: {}",
                    path.display()
                )
            }
            Self::NotExecutable(path) => {
                write!(
                    f,
                    "trusted executable is not an executable file: {}",
                    path.display()
                )
            }
            Self::NotFound(name) => write!(f, "trusted executable not found: {name}"),
            Self::Untrusted { path, root } => write!(
                f,
                "untrusted executable {} is inside denied root {}",
                path.display(),
                root.display()
            ),
            Self::InvalidPath { path, reason } => {
                write!(f, "cannot validate executable {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for TrustedExecutableError {}

fn path_is_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        windows::path_is_within(path, root)
    }
    #[cfg(not(windows))]
    {
        path == root || path.starts_with(root)
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !path.is_absolute() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Return the denied root containing either the lexical selection path or any
/// filesystem-resolved prefix of it. Checking each existing prefix preserves
/// the origin evidence that full canonicalization loses when a symlink/reparse
/// point escapes the denied tree; it also resolves Windows 8.3 aliases.
fn denied_selection_origin(path: &Path, denied_roots: &[PathBuf]) -> Option<PathBuf> {
    let roots = denied_roots
        .iter()
        .map(|root| {
            let lexical = lexical_normalize(root);
            let canonical = root
                .canonicalize()
                .ok()
                .map(|canonical| lexical_normalize(&canonical));
            (root, lexical, canonical)
        })
        .collect::<Vec<_>>();
    let lexical_path = lexical_normalize(path);

    for (original, lexical_root, canonical_root) in &roots {
        if path_is_within(&lexical_path, lexical_root)
            || canonical_root
                .as_ref()
                .is_some_and(|root| path_is_within(&lexical_path, root))
        {
            return Some((*original).clone());
        }
    }

    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if !prefix.is_absolute() {
            continue;
        }
        let Ok(canonical_prefix) = prefix.canonicalize() else {
            continue;
        };
        let canonical_prefix = lexical_normalize(&canonical_prefix);
        for (original, lexical_root, canonical_root) in &roots {
            let resolved_root = canonical_root.as_ref().unwrap_or(lexical_root);
            if path_is_within(&canonical_prefix, resolved_root) {
                return Some((*original).clone());
            }
        }
    }
    None
}

impl TrustedExecutable {
    /// Validate an explicitly selected absolute executable. Symlinks are
    /// canonicalized before the denied-root check and before execution.
    pub fn from_absolute(
        path: &Path,
        denied_roots: &[PathBuf],
    ) -> Result<Self, TrustedExecutableError> {
        Self::from_absolute_with_source(
            path,
            denied_roots,
            WindowsExecutableSource::ExplicitAbsolute,
        )
    }

    fn from_absolute_with_source(
        path: &Path,
        denied_roots: &[PathBuf],
        _source: WindowsExecutableSource,
    ) -> Result<Self, TrustedExecutableError> {
        if !path.is_absolute() {
            return Err(TrustedExecutableError::NotAbsolute(path.to_path_buf()));
        }
        // Reject attacker-controlled selection origin before following symlinks /
        // reparse points. Otherwise `repo/bin/tool -> C:\Windows\...\other.exe`
        // would canonicalize outside the denied root and let the repo substitute
        // an argument-incompatible trusted image for the requested helper name.
        if let Some(root) = denied_selection_origin(path, denied_roots) {
            return Err(TrustedExecutableError::Untrusted {
                path: path.to_path_buf(),
                root,
            });
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| TrustedExecutableError::InvalidPath {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        if !crate::path_audit::is_executable_file(&canonical) {
            return Err(TrustedExecutableError::NotExecutable(canonical));
        }
        for root in denied_roots {
            let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
            if path_is_within(&canonical, &canonical_root) {
                return Err(TrustedExecutableError::Untrusted {
                    path: canonical,
                    root: canonical_root,
                });
            }
        }
        #[cfg(unix)]
        {
            let identity = validate_unix_executable(&canonical)?;
            Ok(Self {
                path: canonical,
                identity,
            })
        }
        #[cfg(windows)]
        {
            windows::validate_executable(&canonical, _source).map_err(|reason| {
                TrustedExecutableError::InvalidPath {
                    path: canonical.clone(),
                    reason,
                }
            })?;
            let digest = executable_digest(&canonical)?;
            Ok(Self {
                path: canonical,
                digest,
                source: _source,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let digest = executable_digest(&canonical)?;
            Ok(Self {
                path: canonical,
                digest,
            })
        }
    }

    /// Resolve `name` in an explicit PATH value. If the first executable hit is
    /// denied, fail closed rather than silently selecting a later binary whose
    /// behavior differs from normal shell resolution.
    pub fn resolve_on_path(
        name: &str,
        path_value: &OsStr,
        denied_roots: &[PathBuf],
    ) -> Result<Self, TrustedExecutableError> {
        for dir in std::env::split_paths(path_value) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let direct = dir.join(name);
            if crate::path_audit::is_executable_file(&direct) {
                return Self::from_absolute_or_canonical(
                    &direct,
                    denied_roots,
                    WindowsExecutableSource::PathSearch,
                );
            }
            #[cfg(windows)]
            for extension in windows_path_extensions() {
                let candidate = dir.join(format!("{name}{extension}"));
                if crate::path_audit::is_executable_file(&candidate) {
                    return Self::from_absolute_or_canonical(
                        &candidate,
                        denied_roots,
                        WindowsExecutableSource::PathSearch,
                    );
                }
            }
        }
        Err(TrustedExecutableError::NotFound(name.to_string()))
    }

    fn from_absolute_or_canonical(
        path: &Path,
        denied_roots: &[PathBuf],
        source: WindowsExecutableSource,
    ) -> Result<Self, TrustedExecutableError> {
        if path.is_absolute() {
            Self::from_absolute_with_source(path, denied_roots, source)
        } else {
            let absolute = std::env::current_dir()
                .map_err(|e| TrustedExecutableError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })?
                .join(path);
            Self::from_absolute_with_source(&absolute, denied_roots, source)
        }
    }

    /// Resolve the first valid executable from fixed absolute candidates.
    pub fn from_system_candidates(candidates: &[&Path]) -> Result<Self, TrustedExecutableError> {
        for candidate in candidates {
            if let Ok(executable) = Self::from_absolute_with_source(
                candidate,
                &[],
                WindowsExecutableSource::SystemCandidate,
            ) {
                return Ok(executable);
            }
        }
        Err(TrustedExecutableError::NotFound(
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" or "),
        ))
    }

    pub fn current() -> Result<Self, TrustedExecutableError> {
        let path = std::env::current_exe().map_err(|e| TrustedExecutableError::InvalidPath {
            path: PathBuf::from("<current executable>"),
            reason: e.to_string(),
        })?;
        Self::from_absolute_with_source(&path, &[], WindowsExecutableSource::CurrentProcess)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-check the canonical executable immediately before a security-sensitive
    /// spawn. This detects replacement, permission/owner drift, and symlink
    /// retargeting between discovery and execution.
    pub fn revalidate(&self) -> Result<(), TrustedExecutableError> {
        let canonical =
            self.path
                .canonicalize()
                .map_err(|e| TrustedExecutableError::InvalidPath {
                    path: self.path.clone(),
                    reason: e.to_string(),
                })?;
        if canonical != self.path {
            return Err(TrustedExecutableError::InvalidPath {
                path: self.path.clone(),
                reason: format!("canonical identity changed to {}", canonical.display()),
            });
        }
        #[cfg(unix)]
        {
            let current = validate_unix_executable(&canonical)?;
            if current != self.identity {
                return Err(TrustedExecutableError::InvalidPath {
                    path: canonical,
                    reason: "executable identity changed after validation".to_string(),
                });
            }
        }
        #[cfg(not(unix))]
        {
            if !crate::path_audit::is_executable_file(&canonical) {
                return Err(TrustedExecutableError::NotExecutable(canonical));
            }
            #[cfg(windows)]
            windows::validate_executable(&canonical, self.source).map_err(|reason| {
                TrustedExecutableError::InvalidPath {
                    path: canonical.clone(),
                    reason,
                }
            })?;
            if executable_digest(&canonical)? != self.digest {
                return Err(TrustedExecutableError::InvalidPath {
                    path: canonical,
                    reason: "executable contents changed after validation".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Windows does not expose the Unix `(dev, ino, ctime, mode, owner)` identity
/// used above through stable `std` APIs. Bind the canonical file's bytes instead
/// so replacement or in-place modification is still detected before spawn.
#[cfg(not(unix))]
fn executable_digest(path: &Path) -> Result<[u8; 32], TrustedExecutableError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    let mut file =
        std::fs::File::open(path).map_err(|error| TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count =
            file.read(&mut buffer)
                .map_err(|error| TrustedExecutableError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
fn validate_unix_executable(
    canonical: &Path,
) -> Result<UnixExecutableIdentity, TrustedExecutableError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        std::fs::metadata(canonical).map_err(|e| TrustedExecutableError::InvalidPath {
            path: canonical.to_path_buf(),
            reason: e.to_string(),
        })?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(TrustedExecutableError::NotExecutable(
            canonical.to_path_buf(),
        ));
    }

    let effective_uid = unsafe { libc::geteuid() };
    validate_unix_owner_and_mode(canonical, &metadata, effective_uid, false)?;

    for parent in canonical.ancestors().skip(1) {
        let parent_metadata =
            std::fs::metadata(parent).map_err(|e| TrustedExecutableError::InvalidPath {
                path: parent.to_path_buf(),
                reason: e.to_string(),
            })?;
        validate_unix_owner_and_mode(parent, &parent_metadata, effective_uid, true)?;
    }

    Ok(UnixExecutableIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn validate_unix_owner_and_mode(
    path: &Path,
    metadata: &std::fs::Metadata,
    effective_uid: u32,
    directory: bool,
) -> Result<(), TrustedExecutableError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "owner uid {} is neither root nor the current uid {}",
                metadata.uid(),
                effective_uid
            ),
        });
    }
    let world_writable = metadata.mode() & 0o002 != 0;
    // Owner identity does not make a group-write bit safe: another member of a
    // shared group can replace an entry in an euid-owned 0770/0775 directory.
    // Only root:root group-write is treated as administrative, since ordinary
    // principals cannot join gid 0. All other group-writable components fail.
    let root_group_writable = metadata.uid() == 0 && metadata.gid() == 0;
    let untrusted_group_writable = metadata.mode() & 0o020 != 0 && !root_group_writable;
    if world_writable || untrusted_group_writable {
        // A root-owned sticky directory (for example /tmp) protects entries
        // owned by another user. The resolver separately denies temp roots, but
        // this exception preserves explicitly selected tools under private temp
        // subdirectories in tests and other non-ambient callers.
        let protected_sticky_directory =
            directory && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !protected_sticky_directory {
            return Err(TrustedExecutableError::InvalidPath {
                path: path.to_path_buf(),
                reason: "path component is writable by an untrusted group or by everyone"
                    .to_string(),
            });
        }
    }
    reject_unix_extended_acl(path, directory).map_err(|reason| {
        TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    Ok(())
}

/// Reject filesystem ACLs that can grant mutation authority independently of
/// Unix owner/group/mode bits. Resolver tools and their trust store use this
/// deliberately conservative rule. Linux rejects any POSIX ACL xattr (including
/// defaults); macOS permits deny-only/read-only entries but rejects every allow
/// entry carrying a mutation right.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn reject_unix_extended_acl(path: &Path, directory: bool) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;

    let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains an interior NUL while checking ACLs".to_string())?;
    let mut names: Vec<&[u8]> = vec![b"system.posix_acl_access\0"];
    if directory {
        names.push(b"system.posix_acl_default\0");
    }
    for name in names {
        // SAFETY: both strings are NUL-terminated; a null/zero output buffer asks
        // getxattr only for the attribute size and does not write memory.
        let size = unsafe {
            libc::getxattr(
                path_bytes.as_ptr(),
                name.as_ptr().cast::<libc::c_char>(),
                std::ptr::null_mut(),
                0,
            )
        };
        if size >= 0 {
            let name = std::str::from_utf8(&name[..name.len() - 1]).unwrap_or("POSIX ACL");
            return Err(format!(
                "path carries extended ACL attribute {name}; trusted paths must be ACL-free"
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENODATA) {
            return Err(format!("cannot verify path ACL attributes: {error}"));
        }
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
pub(crate) fn reject_unix_extended_acl(path: &Path, _directory: bool) -> Result<(), String> {
    use std::ffi::c_void;
    use std::os::unix::ffi::OsStrExt as _;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    const MUTATING_PERMISSIONS: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    unsafe extern "C" {
        fn acl_get_file(path: *const libc::c_char, acl_type: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag_type: *mut libc::c_int) -> libc::c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
        fn acl_free(object: *mut c_void) -> libc::c_int;
    }

    let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains an interior NUL while checking ACLs".to_string())?;
    // SAFETY: path_bytes is NUL-terminated and ACL_TYPE_EXTENDED is the native
    // macOS ACL type. A successful handle is released exactly once below.
    let acl = unsafe { acl_get_file(path_bytes.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        // macOS reports ENOENT when the path exists but has no extended ACL.
        // That is the ordinary ACL-free case; every other lookup failure stays
        // fail-closed because it prevents us from ruling out hidden mutation
        // authority.
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(format!("cannot read path extended ACL: {error}",));
    }
    let inspection = (|| {
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = std::ptr::null_mut();
            // SAFETY: acl is live and entry is a valid out-pointer.
            let status = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
            if status != 0 {
                let error = std::io::Error::last_os_error();
                // Darwin returns zero for an entry and -1/EINVAL after the
                // final entry (unlike Linux's one/zero iterator convention).
                if error.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(());
                } else {
                    return Err(format!("cannot enumerate path extended ACL: {error}"));
                }
            }
            let mut tag_type = 0;
            let mut permissions = 0_u64;
            // SAFETY: entry was returned by acl_get_entry and both output
            // pointers remain valid for the duration of each call.
            if unsafe { acl_get_tag_type(entry, &mut tag_type) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0
            {
                return Err(format!(
                    "cannot inspect path extended ACL entry: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if tag_type == ACL_EXTENDED_ALLOW && permissions & MUTATING_PERMISSIONS != 0 {
                return Err(
                    "path ACL grants mutation rights outside Unix mode bits; trusted paths must not"
                        .to_string(),
                );
            }
            entry_id = ACL_NEXT_ENTRY;
        }
    })();
    // SAFETY: acl was returned by acl_get_file and has not been freed yet.
    unsafe {
        let _ = acl_free(acl);
    }
    inspection
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) fn reject_unix_extended_acl(_path: &Path, _directory: bool) -> Result<(), String> {
    Err("this Unix platform has no extended-ACL verifier; refusing trusted path".to_string())
}

/// Resolve a named installed tool without ever passing its bare name to the OS.
/// Project and temporary-directory candidates are rejected.
pub fn resolve_ambient(name: &str) -> Result<TrustedExecutable, TrustedExecutableError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| TrustedExecutableError::NotFound(format!("{name} (PATH is unset)")))?;
    TrustedExecutable::resolve_on_path(name, &path, &ambient_denied_roots())
}

/// Construct the PATH value a trusted child may inherit. Relative, denied, and
/// world-writable directories are omitted. This is explicit child data, not the
/// ambient PATH used again for selecting the primary executable.
pub fn sanitized_path(path_value: &OsStr, denied_roots: &[PathBuf]) -> OsString {
    let mut directories = Vec::new();
    for directory in std::env::split_paths(path_value) {
        if !directory.is_absolute() {
            continue;
        }
        if denied_selection_origin(&directory, denied_roots).is_some() {
            continue;
        }
        let canonical = match directory.canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        if denied_roots.iter().any(|root| {
            let root = root.canonicalize().unwrap_or_else(|_| root.clone());
            path_is_within(&canonical, &root)
        }) {
            continue;
        }
        #[cfg(unix)]
        {
            let effective_uid = unsafe { libc::geteuid() };
            let trusted_hierarchy = canonical.ancestors().all(|component| {
                std::fs::metadata(component).ok().is_some_and(|metadata| {
                    validate_unix_owner_and_mode(component, &metadata, effective_uid, true).is_ok()
                })
            });
            if !trusted_hierarchy {
                continue;
            }
        }
        #[cfg(windows)]
        if !windows::validate_inherited_path_dir(&canonical) {
            continue;
        }
        directories.push(canonical);
    }
    std::env::join_paths(directories).unwrap_or_default()
}

pub fn sanitized_ambient_path() -> Option<OsString> {
    let path = std::env::var_os("PATH")?;
    Some(sanitized_path(&path, &ambient_denied_roots()))
}

#[cfg(windows)]
fn windows_path_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .ok()
        .map(|value| {
            value
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_else(|| {
            [".com", ".exe", ".bat", ".cmd"]
                .into_iter()
                .map(str::to_string)
                .collect()
        })
}

/// Roots controlled by the current project/environment and therefore invalid
/// executable locations for security-sensitive helpers.
pub fn ambient_denied_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        let mut repository_root = None;
        for ancestor in cwd.ancestors() {
            if ancestor.join(".git").exists() {
                repository_root = Some(ancestor.to_path_buf());
                break;
            }
        }
        roots.push(repository_root.unwrap_or(cwd));
    }
    roots.push(std::env::temp_dir());
    roots
}

#[derive(Debug, Clone, Copy)]
pub struct ChildLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

impl ChildLimits {
    pub const fn new(timeout: Duration, stdout_bytes: usize, stderr_bytes: usize) -> Self {
        Self {
            timeout,
            stdout_bytes,
            stderr_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChildSpec {
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    limits: ChildLimits,
}

impl ChildSpec {
    pub fn new<I, S>(args: I, limits: ChildLimits) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Self {
            args: args
                .into_iter()
                .map(|arg| arg.as_ref().to_os_string())
                .collect(),
            env: Vec::new(),
            cwd: None,
            limits,
        }
    }

    pub fn env(mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((name.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    pub fn inherit_env(mut self, names: &[&str]) -> Self {
        for name in names {
            if let Some(value) = std::env::var_os(name) {
                self.env.push((OsString::from(name), value));
            }
        }
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
pub enum ChildOutcome {
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    SpawnError(String),
    WaitError(String),
    Timeout {
        cleanup_succeeded: bool,
    },
    OutputLimitExceeded {
        stream: CaptureStream,
        cleanup_succeeded: bool,
    },
}

enum ReaderMessage {
    Complete(CaptureStream, Vec<u8>),
    Limit(CaptureStream),
    Error(CaptureStream, String),
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    mut reader: R,
    stream: CaptureStream,
    cap: usize,
    sender: mpsc::Sender<ReaderMessage>,
) {
    std::thread::spawn(move || {
        let mut output = Vec::with_capacity(cap.min(64 * 1024));
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => {
                    let _ = sender.send(ReaderMessage::Complete(stream, output));
                    return;
                }
                Ok(count) if output.len().saturating_add(count) <= cap => {
                    output.extend_from_slice(&chunk[..count]);
                }
                Ok(_) => {
                    let _ = sender.send(ReaderMessage::Limit(stream));
                    return;
                }
                Err(error) => {
                    let _ = sender.send(ReaderMessage::Error(stream, error.to_string()));
                    return;
                }
            }
        }
    });
}

/// Execute a validated absolute program with an empty-by-default environment,
/// bounded output, and a wall-clock deadline.
#[cfg(windows)]
pub fn run(executable: &TrustedExecutable, spec: &ChildSpec) -> ChildOutcome {
    if let Err(error) = executable.revalidate() {
        return ChildOutcome::SpawnError(format!(
            "trusted executable failed pre-spawn revalidation: {error}"
        ));
    }
    windows::run(executable, spec)
}

/// Execute a validated absolute program with an empty-by-default environment,
/// bounded output, and a wall-clock deadline.
#[cfg(not(windows))]
pub fn run(executable: &TrustedExecutable, spec: &ChildSpec) -> ChildOutcome {
    if let Err(error) = executable.revalidate() {
        return ChildOutcome::SpawnError(format!(
            "trusted executable failed pre-spawn revalidation: {error}"
        ));
    }
    let mut command = Command::new(executable.path());
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: setpgid is async-signal-safe and is the only operation in the
        // forked child before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return ChildOutcome::SpawnError(error.to_string()),
    };
    let child_pid = child.id();
    let (sender, receiver) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        spawn_reader(
            stdout,
            CaptureStream::Stdout,
            spec.limits.stdout_bytes,
            sender.clone(),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_reader(
            stderr,
            CaptureStream::Stderr,
            spec.limits.stderr_bytes,
            sender,
        );
    }

    let deadline = Instant::now() + spec.limits.timeout;
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        while let Ok(message) = receiver.try_recv() {
            match message {
                ReaderMessage::Complete(CaptureStream::Stdout, bytes) => stdout = Some(bytes),
                ReaderMessage::Complete(CaptureStream::Stderr, bytes) => stderr = Some(bytes),
                ReaderMessage::Limit(stream) => {
                    let cleanup_succeeded = terminate_tree(&mut child, child_pid, status.is_some());
                    return ChildOutcome::OutputLimitExceeded {
                        stream,
                        cleanup_succeeded,
                    };
                }
                ReaderMessage::Error(stream, reason) => {
                    let _ = terminate_tree(&mut child, child_pid, status.is_some());
                    return ChildOutcome::WaitError(format!("read {stream:?}: {reason}"));
                }
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit)) => status = Some(exit),
                Ok(None) => {}
                Err(error) => {
                    let _ = terminate_tree(&mut child, child_pid, false);
                    return ChildOutcome::WaitError(error.to_string());
                }
            }
        }
        if let Some(exit_status) = status {
            match (stdout.take(), stderr.take()) {
                (Some(stdout_bytes), Some(stderr_bytes)) => {
                    if !terminate_tree(&mut child, child_pid, true) {
                        return ChildOutcome::WaitError(
                            "child exited but descendant process-group cleanup failed".to_string(),
                        );
                    }
                    return ChildOutcome::Completed {
                        status: exit_status,
                        stdout: stdout_bytes,
                        stderr: stderr_bytes,
                    };
                }
                (pending_stdout, pending_stderr) => {
                    stdout = pending_stdout;
                    stderr = pending_stderr;
                }
            }
        }
        if Instant::now() >= deadline {
            let cleanup_succeeded = terminate_tree(&mut child, child_pid, status.is_some());
            return ChildOutcome::Timeout { cleanup_succeeded };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(windows))]
fn terminate_tree(child: &mut std::process::Child, _child_pid: u32, already_reaped: bool) -> bool {
    let mut cleanup_succeeded = true;
    #[cfg(unix)]
    let mut process_group_needs_wait = false;
    #[cfg(unix)]
    {
        let process_group = -(_child_pid as libc::pid_t);
        // ESRCH is success for cleanup purposes: the group is already gone.
        if unsafe { libc::kill(process_group, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                cleanup_succeeded = false;
            }
        } else {
            process_group_needs_wait = true;
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        if !already_reaped && child.kill().is_err() {
            cleanup_succeeded = false;
        }
    }
    if !already_reaped && child.wait().is_err() {
        cleanup_succeeded = false;
    }
    #[cfg(unix)]
    if process_group_needs_wait && !wait_for_process_group_exit(_child_pid) {
        cleanup_succeeded = false;
    }
    cleanup_succeeded
}

#[cfg(unix)]
fn wait_for_process_group_exit(child_pid: u32) -> bool {
    let process_group = -(child_pid as libc::pid_t);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if unsafe { libc::kill(process_group, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            if error.raw_os_error() != Some(libc::EINTR) {
                return false;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
