//! Filesystem helpers for `tirith setup` — atomic writes, hook scripts,
//! directory validation, CLI subprocess runner, and backup management.

use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

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

fn existing_mode(parent: &ScopedParent) -> Result<Option<u32>, String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.dir.as_raw_fd(),
            parent.name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!("stat destination without following links: {error}"));
    }
    let stat = unsafe { stat.assume_init() };
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => Ok(Some(stat.st_mode as u32 & 0o7777)),
        libc::S_IFLNK => Err("destination is a symlink — refusing to overwrite for safety".into()),
        _ => Err("destination is not a regular file — refusing to overwrite for safety".into()),
    }
}

fn read_existing_scoped(path: &Path, scope_root: &Path) -> Result<Option<(String, u32)>, String> {
    let Some(parent) = scoped_parent(path, scope_root, false)? else {
        return Ok(None);
    };
    let fd = unsafe {
        libc::openat(
            parent.dir.as_raw_fd(),
            parent.name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(format!(
                "{} is a symlink — refusing to modify for safety",
                path.display()
            ));
        }
        return Err(format!(
            "open {} without following links: {error}",
            path.display()
        ));
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|e| format!("stat {} through open handle: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{} is not a regular file — refusing for safety",
            path.display()
        ));
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("read {} through open handle: {e}", path.display()))?;
    Ok(Some((content, metadata.permissions().mode() & 0o7777)))
}

/// Read a setup-managed text file through the same root-confined, no-follow
/// boundary used for writes. Missing files or parents return `None` without
/// creating directories; unsafe components are errors even for dry runs and
/// idempotent early returns.
pub fn read_to_string_scoped(path: &Path, scope_root: &Path) -> Result<Option<String>, String> {
    read_existing_scoped(path, scope_root).map(|existing| existing.map(|(content, _mode)| content))
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
pub fn atomic_write(
    path: &Path,
    scope_root: &Path,
    content: &str,
    mode: u32,
) -> Result<(), String> {
    atomic_write_with_security(path, scope_root, content, mode, true)
}

fn atomic_write_with_security(
    path: &Path,
    scope_root: &Path,
    content: &str,
    mode: u32,
    preserve_destination_mode: bool,
) -> Result<(), String> {
    let parent = scoped_parent(path, scope_root, true)?
        .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
    let destination_mode = existing_mode(&parent)?;
    let effective_mode = if preserve_destination_mode {
        destination_mode.unwrap_or(mode)
    } else {
        mode
    } & 0o7777;

    // PID + monotonic counter keeps temp file names unique across concurrent setups.
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let (tmp_name, mut file) = (0..4)
        .find_map(|_| {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let name =
                CString::new(format!(".tirith-setup-{}-{n}.tmp", std::process::id())).unwrap();
            let fd = unsafe {
                libc::openat(
                    parent.dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    effective_mode as libc::c_uint,
                )
            };
            if fd >= 0 {
                Some(Ok((name, unsafe { fs::File::from_raw_fd(fd) })))
            } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                None
            } else {
                Some(Err(std::io::Error::last_os_error()))
            }
        })
        .unwrap_or_else(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "temporary-name retries exhausted",
            ))
        })
        .map_err(|e| format!("create temporary file below {}: {e}", scope_root.display()))?;

    let cleanup = || unsafe {
        libc::unlinkat(parent.dir.as_raw_fd(), tmp_name.as_ptr(), 0);
    };

    // `openat` applies this mode at creation; `fchmod` makes the requested or
    // preserved mode exact before any sensitive bytes are written.
    if unsafe { libc::fchmod(file.as_raw_fd(), effective_mode as libc::mode_t) } < 0 {
        let error = std::io::Error::last_os_error();
        cleanup();
        return Err(format!("set temporary-file permissions: {error}"));
    }
    if let Err(error) = file.write_all(content.as_bytes()) {
        cleanup();
        return Err(format!("write temporary file: {error}"));
    }

    // Re-check the destination through the held parent descriptor immediately
    // before publication, then rename relative to that same descriptor.
    if let Err(error) = existing_mode(&parent) {
        cleanup();
        return Err(error);
    }
    let rc = unsafe {
        libc::renameat(
            parent.dir.as_raw_fd(),
            tmp_name.as_ptr(),
            parent.dir.as_raw_fd(),
            parent.name.as_ptr(),
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        cleanup();
        return Err(format!("publish {}: {error}", path.display()));
    }

    Ok(())
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
    // Resolve through held no-follow handles even in dry-run so a malicious
    // parent link is never treated as an already-configured legitimate file.
    if let Some((existing, existing_mode)) = read_existing_scoped(path, scope_root)? {
        if existing == content {
            if !dry_run {
                if existing_mode & 0o777 != 0o755 {
                    set_mode_scoped(path, scope_root, 0o755)?;
                    eprintln!(
                        "tirith: {} already configured, fixed permissions",
                        path.display()
                    );
                } else {
                    eprintln!("tirith: {} already configured, up to date", path.display());
                }
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
            "[dry-run] would write {} ({} bytes, mode 0755)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    atomic_write(path, scope_root, content, 0o755)?;

    // Always enforce 0o755; atomic_write preserves prior permissions which
    // may be stricter than we need for an executable hook.
    set_mode_scoped(path, scope_root, 0o755)?;

    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

fn set_mode_scoped(path: &Path, scope_root: &Path, mode: u32) -> Result<(), String> {
    let parent = scoped_parent(path, scope_root, false)?
        .ok_or_else(|| format!("{} disappeared before chmod", path.display()))?;
    let fd = unsafe {
        libc::openat(
            parent.dir.as_raw_fd(),
            parent.name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open {} for chmod: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } < 0 {
        return Err(format!(
            "chmod {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
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

/// Create a timestamped backup of `path` when `force` is true and the file exists.
///
/// Format: `{path}.tirith-backup-{YYYYMMDD-HHMMSS}`
/// Retention: keeps the 5 most recent backups, deletes older ones (best-effort).
pub fn create_backup(path: &Path, scope_root: &Path, force: bool) -> Result<(), String> {
    if !force {
        return Ok(());
    }
    create_backup_impl(path, scope_root)
}

/// Create a timestamped backup unconditionally (not gated on `--force`).
///
/// Used for high-value user files like VS Code settings.json where any
/// modification (even first-time insertion) warrants a backup.
pub fn create_backup_always(path: &Path, scope_root: &Path) -> Result<(), String> {
    create_backup_impl(path, scope_root)
}

fn create_backup_impl(path: &Path, scope_root: &Path) -> Result<(), String> {
    let Some((content, mode)) = read_existing_scoped(path, scope_root)? else {
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

    // A colliding attacker-created backup name must not donate a broader mode
    // to sensitive copied content.
    atomic_write_with_security(&backup_path, scope_root, &content, mode, false)?;
    eprintln!("tirith: backup at {}", backup_path.display());

    cleanup_old_backups(path, scope_root)?;

    Ok(())
}

/// Remove old backup files, keeping only the 5 most recent.
fn cleanup_old_backups(path: &Path, scope_root: &Path) -> Result<(), String> {
    let Some(parent) = scoped_parent(path, scope_root, false)? else {
        return Ok(());
    };
    let stem = path
        .file_name()
        .ok_or_else(|| format!("no file name for {}", path.display()))?;
    let prefix = [stem.as_bytes(), b".tirith-backup-"].concat();

    // fdopendir takes ownership of its descriptor, so duplicate the held
    // capability and keep `parent.dir` available for fstatat/unlinkat.
    let duplicate = unsafe { libc::dup(parent.dir.as_raw_fd()) };
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

    let mut backups = Vec::<CString>::new();
    loop {
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name.starts_with(&prefix) {
            if let Ok(name) = CString::new(name) {
                backups.push(name);
            }
        }
    }
    unsafe { libc::closedir(directory) };

    if backups.len() <= 5 {
        return Ok(());
    }

    // Timestamps are embedded, so lexicographic order equals chronological.
    backups.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let to_remove = backups.len() - 5;
    for old in &backups[..to_remove] {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let stat_rc = unsafe {
            libc::fstatat(
                parent.dir.as_raw_fd(),
                old.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_rc < 0 || unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
            continue;
        }
        if unsafe { libc::unlinkat(parent.dir.as_raw_fd(), old.as_ptr(), 0) } < 0 {
            eprintln!(
                "tirith: could not clean old backup {}: {}",
                old.to_string_lossy(),
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn backup_creates_and_retains_five() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "data").unwrap();

        for i in 0..7 {
            let name = format!("config.json.tirith-backup-20260101-00000{i}");
            fs::write(dir.path().join(&name), "backup").unwrap();
        }

        cleanup_old_backups(&path, dir.path()).unwrap();

        let count = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(count, 5);
    }

    #[test]
    fn backup_preserves_content_and_restrictive_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "secret-data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        create_backup(&path, dir.path(), true).unwrap();

        let backup = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .expect("backup created")
            .path();
        assert_eq!(fs::read_to_string(&backup).unwrap(), "secret-data");
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn backup_and_cleanup_refuse_symlinked_parent_without_outside_mutation() {
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
        assert!(create_backup(&path, root.path(), true).is_err());
        assert!(cleanup_old_backups(&path, root.path()).is_err());

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
}
