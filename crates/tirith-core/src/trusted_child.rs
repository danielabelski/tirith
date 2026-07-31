//! Trusted executable selection and bounded child-process supervision.
//!
//! Security-sensitive callers resolve an executable once, validate its absolute
//! identity, clear the ambient environment, and run it with explicit capture
//! limits. On Unix every child owns a process group so a timeout or output flood
//! terminates descendants as well as the direct child.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TrustedExecutable {
    path: PathBuf,
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

impl TrustedExecutable {
    /// Validate an explicitly selected absolute executable. Symlinks are
    /// canonicalized before the denied-root check and before execution.
    pub fn from_absolute(
        path: &Path,
        denied_roots: &[PathBuf],
    ) -> Result<Self, TrustedExecutableError> {
        if !path.is_absolute() {
            return Err(TrustedExecutableError::NotAbsolute(path.to_path_buf()));
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
            if canonical == canonical_root || canonical.starts_with(&canonical_root) {
                return Err(TrustedExecutableError::Untrusted {
                    path: canonical,
                    root: canonical_root,
                });
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata =
                std::fs::metadata(&canonical).map_err(|e| TrustedExecutableError::InvalidPath {
                    path: canonical.clone(),
                    reason: e.to_string(),
                })?;
            if metadata.mode() & 0o002 != 0 {
                return Err(TrustedExecutableError::InvalidPath {
                    path: canonical,
                    reason: "file is world-writable".to_string(),
                });
            }
        }
        Ok(Self { path: canonical })
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
                return Self::from_absolute_or_canonical(&direct, denied_roots);
            }
            #[cfg(windows)]
            for extension in windows_path_extensions() {
                let candidate = dir.join(format!("{name}{extension}"));
                if crate::path_audit::is_executable_file(&candidate) {
                    return Self::from_absolute_or_canonical(&candidate, denied_roots);
                }
            }
        }
        Err(TrustedExecutableError::NotFound(name.to_string()))
    }

    fn from_absolute_or_canonical(
        path: &Path,
        denied_roots: &[PathBuf],
    ) -> Result<Self, TrustedExecutableError> {
        if path.is_absolute() {
            Self::from_absolute(path, denied_roots)
        } else {
            let absolute = std::env::current_dir()
                .map_err(|e| TrustedExecutableError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })?
                .join(path);
            Self::from_absolute(&absolute, denied_roots)
        }
    }

    /// Resolve the first valid executable from fixed absolute candidates.
    pub fn from_system_candidates(candidates: &[&Path]) -> Result<Self, TrustedExecutableError> {
        for candidate in candidates {
            if let Ok(executable) = Self::from_absolute(candidate, &[]) {
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
        Self::from_absolute(&path, &[])
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
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
        let canonical = match directory.canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        if denied_roots.iter().any(|root| {
            let root = root.canonicalize().unwrap_or_else(|_| root.clone());
            canonical == root || canonical.starts_with(root)
        }) {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if std::fs::metadata(&canonical)
                .map(|metadata| metadata.mode() & 0o002 != 0)
                .unwrap_or(true)
            {
                continue;
            }
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
pub fn run(executable: &TrustedExecutable, spec: &ChildSpec) -> ChildOutcome {
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

fn terminate_tree(child: &mut std::process::Child, child_pid: u32, already_reaped: bool) -> bool {
    let mut cleanup_succeeded = true;
    #[cfg(unix)]
    {
        let process_group = -(child_pid as libc::pid_t);
        // ESRCH is success for cleanup purposes: the group is already gone.
        if unsafe { libc::kill(process_group, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                cleanup_succeeded = false;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if child.kill().is_err() {
            cleanup_succeeded = false;
        }
    }
    if !already_reaped && child.wait().is_err() {
        cleanup_succeeded = false;
    }
    cleanup_succeeded
}
