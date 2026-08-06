//! Internal capsule launcher (`tirith __capsule-child`), Stack E, unit E2.
//!
//! This is NOT a user-facing command. It is the re-exec target the capsule
//! machinery (E5 consumers: `runner.rs`, `temp_run.rs`, the package-firewall
//! install, the gateway upstream spawn) invokes to run a program under OS
//! containment. The parent builds a [`CapsuleSpec`], serializes it to JSON, and
//! spawns:
//!
//! ```text
//! tirith __capsule-child <spec-json> -- <prog> <arg>...
//! ```
//!
//! This process then:
//! 1. Parses its own simple argv (the spec JSON, then everything after `--`).
//! 2. On Linux, validates the parent-owned, policy-granted temporary HOME and applies the
//!    full containment sequence via [`tirith_core::capsule::linux::apply_containment`]
//!    (inherited-FD closure -> rlimits -> no-new-privs -> Landlock -> seccomp ->
//!    env cleanup), verifies the achieved coverage is not degraded against the
//!    spec's requirement, and only then forks the target. The original launcher
//!    remains as a contained process-group leader while its child executes the
//!    target (a content-bound launch uses `execveat(AT_EMPTY_PATH)` on its sealed
//!    inherited descriptor).
//! 3. On macOS, builds the native `sandbox-exec` argv, closes unrelated inherited
//!    descriptors, applies supported rlimits, and `execve`s `sandbox-exec`. This
//!    second exec occurs only after Rust's private parent/child exec-status pipe
//!    has closed normally on the first exec.
//!
//! ## Single-threaded invariant
//!
//! seccomp (`apply_to_current_thread`) filters only the calling thread, and
//! Landlock `restrict_self` is incompatible with the thread-sync (TSYNC) path, so
//! containment MUST be applied while the process is single-threaded. `tirith`'s
//! normal `main()` runs the CLI on a dedicated worker thread (for a roomy stack),
//! which would make this process multi-threaded. To avoid that, [`is_invocation`]
//! is checked at the very top of `main()` **before** the worker thread is spawned,
//! and [`run_on_main_thread`] handles the command directly on the genuinely
//! single-threaded main thread. It never returns: the fork child `exec`s the
//! target while the original process waits as its contained guard, then exits
//! with the target status. On any failure it prints to stderr and exits non-zero.
//! It MUST NOT fall through to running the target uncontained (fail-closed).

use std::ffi::{OsStr, OsString};

/// The hidden subcommand name. A double-underscore prefix marks it internal and
/// keeps it clear of any real command.
pub const SUBCOMMAND: &str = "__capsule-child";
#[cfg(target_os = "linux")]
pub const TARGET_EXEC_OBSERVED: u8 = b'O';
#[cfg(target_os = "linux")]
pub const TARGET_ACK_RESUME: u8 = b'A';
#[cfg(target_os = "linux")]
pub const TARGET_LAUNCH_RESUMED: u8 = b'R';
#[cfg(target_os = "linux")]
pub const TARGET_LAUNCH_ERROR: u8 = b'E';

/// Whether `args` (typically `std::env::args().collect()`) is a `__capsule-child`
/// invocation. Checked at the top of `main()` so the launcher runs before the
/// worker-thread spawn (single-threaded invariant). Pure, so it is unit-testable.
pub fn is_invocation(args: &[OsString]) -> bool {
    args.get(1)
        .is_some_and(|arg| arg.as_os_str() == OsStr::new(SUBCOMMAND))
}

/// The parsed launcher argv: the spec JSON and the target program + args (the part
/// after the `--` separator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArgs {
    /// The serialized [`CapsuleSpec`] JSON.
    pub spec_json: String,
    /// The executable path/name passed to `execvp` for an ordinary launch, or a
    /// diagnostic label when `target_fd` selects held-descriptor execution.
    pub program: OsString,
    /// Optional explicit `argv[0]` for alias-sensitive or multicall targets.
    /// When absent, [`Self::program`] is used, preserving the legacy launcher
    /// contract.
    pub target_argv0: Option<OsString>,
    /// Optional inherited, fully sealed Linux executable descriptor. When set,
    /// the launcher executes this descriptor with `execveat(AT_EMPTY_PATH)` and
    /// treats `program` as a diagnostic label only.
    pub target_fd: Option<i32>,
    /// Optional inherited, fully sealed reviewed-script descriptor. It is
    /// carried into the target interpreter and named in argv via /proc/self/fd.
    pub script_fd: Option<i32>,
    /// Guard-owned status descriptor for proving the actual target crossed
    /// exec. Linux only: the guard reports OBSERVED while the tracee is stopped,
    /// then RESUMED only after exact parent authorization and successful detach.
    pub launch_status_fd: Option<i32>,
    /// Guard-owned read endpoint for the parent's one-shot ACK_RESUME. The
    /// tracee remains stopped at PTRACE_EVENT_EXEC until this exact byte and EOF
    /// are observed.
    pub launch_ack_fd: Option<i32>,
    /// Optional parent-owned temporary HOME. The parent keeps the directory
    /// guard alive until the complete child tree has exited and grants this
    /// exact path in the finalized filesystem policy before launch.
    pub temp_home: Option<OsString>,
    /// The target program's arguments.
    pub program_args: Vec<OsString>,
}

/// Parse `tirith __capsule-child <spec-json> [internal options] -- <prog>
/// <arg>...` from the full process argv. Internal options are closed and may
/// appear at most once: `--target-argv0 <value>`, `--target-fd <number>`,
/// `--script-fd <number>`, `--launch-status-fd <number>`,
/// `--launch-ack-fd <number>`, and
/// `--temp-home <absolute>`.
/// Pure and platform-independent, so the argv grammar is unit-testable
/// everywhere.
pub fn parse_args(args: &[OsString]) -> Result<ParsedArgs, String> {
    // args[0] = "tirith", args[1] = SUBCOMMAND.
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new(SUBCOMMAND)) {
        return Err("not a __capsule-child invocation".to_string());
    }
    let spec_json = args
        .get(2)
        .ok_or_else(|| "missing capsule spec JSON".to_string())?
        .clone()
        .into_string()
        .map_err(|_| "capsule spec JSON is not valid UTF-8".to_string())?;
    // Find the `--` separator.
    let sep = args
        .iter()
        .position(|a| a.as_os_str() == OsStr::new("--"))
        .ok_or_else(|| "missing `--` separator before the program".to_string())?;
    // The spec must be BEFORE the separator (index 2 < sep).
    if sep < 3 {
        return Err("the `--` separator must follow the spec JSON".to_string());
    }
    let mut target_argv0 = None;
    let mut target_fd = None;
    let mut script_fd = None;
    let mut launch_status_fd = None;
    let mut launch_ack_fd = None;
    let mut temp_home = None;
    let mut option_index = 3usize;
    while option_index < sep {
        let option = &args[option_index];
        let value = args
            .get(option_index + 1)
            .filter(|_| option_index + 1 < sep)
            .ok_or_else(|| format!("missing value for internal launcher option {option:?}"))?
            .clone();
        if option == "--target-argv0" {
            if target_argv0.replace(value).is_some() {
                return Err("duplicate `--target-argv0` launcher option".to_string());
            }
        } else if option == "--target-fd" {
            if target_fd.is_some() {
                return Err("duplicate `--target-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--target-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--target-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--target-fd` must not overlap standard I/O".to_string());
            }
            target_fd = Some(parsed);
        } else if option == "--launch-status-fd" {
            if launch_status_fd.is_some() {
                return Err("duplicate `--launch-status-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--launch-status-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--launch-status-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--launch-status-fd` must not overlap standard I/O".to_string());
            }
            launch_status_fd = Some(parsed);
        } else if option == "--script-fd" {
            if script_fd.is_some() {
                return Err("duplicate `--script-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--script-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--script-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--script-fd` must not overlap standard I/O".to_string());
            }
            script_fd = Some(parsed);
        } else if option == "--launch-ack-fd" {
            if launch_ack_fd.is_some() {
                return Err("duplicate `--launch-ack-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--launch-ack-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--launch-ack-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--launch-ack-fd` must not overlap standard I/O".to_string());
            }
            launch_ack_fd = Some(parsed);
        } else if option == "--temp-home" {
            if temp_home.replace(value).is_some() {
                return Err("duplicate `--temp-home` launcher option".to_string());
            }
        } else {
            return Err(format!("unknown internal launcher option {option:?}"));
        }
        option_index += 2;
    }
    let internal_fds = [target_fd, script_fd, launch_status_fd, launch_ack_fd];
    for (index, descriptor) in internal_fds.iter().enumerate() {
        if descriptor.is_some() && internal_fds[index + 1..].contains(descriptor) {
            return Err("internal launcher descriptors must be pairwise distinct".to_string());
        }
    }
    if launch_status_fd.is_some() != launch_ack_fd.is_some() {
        return Err(
            "`--launch-status-fd` and `--launch-ack-fd` must be supplied together".to_string(),
        );
    }
    let rest = &args[sep + 1..];
    let program = rest
        .first()
        .ok_or_else(|| "missing program after `--`".to_string())?
        .clone();
    let program_args = rest[1..].to_vec();
    Ok(ParsedArgs {
        spec_json,
        program,
        target_argv0,
        target_fd,
        script_fd,
        launch_status_fd,
        launch_ack_fd,
        temp_home,
        program_args,
    })
}

/// Handle a `__capsule-child` invocation on the main thread and never return. On
/// Linux this process remains the stable contained guard while its fork child
/// executes the target. On macOS it replaces itself with `sandbox-exec` after the
/// trusted second-launch setup. Every failure exits non-zero. Call this at the top
/// of `main()` only when [`is_invocation`] is true and the process is still
/// single-threaded.
///
/// On Windows and other non-Unix hosts this exits non-zero; those platforms use a
/// different containment backend. macOS deliberately uses this re-exec launcher
/// so descriptor closure happens after Rust has finished using its private
/// exec-status pipe, but before `sandbox-exec` and the target run.
pub fn run_on_main_thread(args: &[OsString]) -> ! {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith __capsule-child: {e}");
            std::process::exit(2);
        }
    };
    #[cfg(target_os = "linux")]
    {
        linux_launch(&parsed)
    }
    #[cfg(target_os = "macos")]
    {
        macos_launch(&parsed)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = &parsed;
        eprintln!(
            "tirith __capsule-child: the re-exec launcher is Unix-only; this platform uses a \
             different containment backend"
        );
        std::process::exit(2);
    }
}

/// macOS launch path: construct the native `sandbox-exec` argv, close every
/// inherited descriptor outside the policy allow-list, apply the supported
/// rlimits, and replace this launcher with `sandbox-exec`.
///
/// This function runs after a successful exec of the Tirith binary. Consequently,
/// the `std::process::Command` exec-status pipe used by the original parent has
/// already observed EOF via `FD_CLOEXEC`; descriptor closure here cannot corrupt
/// Rust's spawn protocol. The process is still single-threaded because `main`
/// dispatches this hidden invocation before creating its worker thread.
#[cfg(target_os = "macos")]
fn macos_launch(parsed: &ParsedArgs) -> ! {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use tirith_core::capsule::CapsuleSpec;

    let spec: CapsuleSpec = match serde_json::from_str(&parsed.spec_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith __capsule-child: invalid capsule spec JSON: {e}");
            std::process::exit(2);
        }
    };

    // Build and validate every CString before descriptor closure so no fallible
    // string conversion or allocation is needed after the isolation boundary is
    // applied. `sandbox_exec_argv_os` also refuses unsupported egress profiles
    // while preserving non-UTF-8 Unix argument bytes exactly.
    let sandbox_argv = match tirith_core::capsule::macos::sandbox_exec_argv_os(
        &spec,
        &parsed.program,
        &parsed.program_args,
    ) {
        Ok(argv) => argv,
        Err(e) => {
            eprintln!("tirith __capsule-child: cannot build sandbox-exec invocation: {e}");
            std::process::exit(2);
        }
    };
    let argv: Vec<CString> = match sandbox_argv
        .iter()
        .map(|arg| CString::new(arg.as_os_str().as_bytes()))
        .collect()
    {
        Ok(argv) => argv,
        Err(_) => {
            eprintln!("tirith __capsule-child: sandbox-exec argument contains NUL");
            std::process::exit(2);
        }
    };

    // Order matters: close inherited fds while RLIMIT_NOFILE still reflects the
    // inherited (higher) ceiling. Lowering it first would not close an already-open
    // high fd and would shrink the scan range, allowing that fd to survive.
    crate::cli::capsule::close_extra_fds(&spec.handles);
    if let Err(e) = crate::cli::capsule::apply_macos_rlimits(&spec.resources) {
        eprintln!("tirith __capsule-child: applying macOS resource limits failed: {e}");
        std::process::exit(2);
    }

    let prog_c = argv[0].clone();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `prog_c` and every pointer in `ptrs` are valid, NUL-terminated C
    // strings that outlive the call, and `ptrs` has a final null pointer.
    unsafe {
        libc::execv(prog_c.as_ptr(), ptrs.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    eprintln!("tirith __capsule-child: exec of sandbox-exec failed: {err}");
    std::process::exit(127);
}

/// Linux launch path: deserialize the spec, validate any parent-owned temporary
/// HOME, apply containment, verify coverage is not degraded against the spec's
/// requirement, then fork the target beneath this stable process-group leader.
/// A content-bound launch uses its held, sealed descriptor via
/// `execveat(AT_EMPTY_PATH)`; ordinary launches retain the pathname `execvp`
/// fallback. Every failure path exits non-zero.
#[cfg(target_os = "linux")]
fn linux_launch(parsed: &ParsedArgs) -> ! {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use tirith_core::capsule::linux::{apply_containment, exec_cstrings};
    use tirith_core::capsule::CapsuleSpec;

    let spec: CapsuleSpec = match serde_json::from_str(&parsed.spec_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith __capsule-child: invalid capsule spec JSON: {e}");
            std::process::exit(2);
        }
    };

    // Defense in depth: refuse to apply containment unless we can CONFIRM the
    // process is single-threaded. Applying a per-thread seccomp filter + Landlock
    // in a multi-threaded process is unsound (the filter binds only the calling
    // thread), so this must fail CLOSED: if we cannot read the thread count, we
    // cannot prove single-threadedness and must not proceed. This should never trip
    // because the caller invokes us before the worker-thread spawn, but a hard
    // fail-closed check here means neither a future refactor nor an unreadable
    // `/proc` can silently weaken the guarantee.
    match thread_decision(current_thread_count()) {
        ThreadDecision::Proceed => {}
        ThreadDecision::RefuseMultiThreaded(threads) => {
            eprintln!(
                "tirith __capsule-child: refusing to contain a multi-threaded process \
                 ({threads} threads); this is an internal invariant violation"
            );
            std::process::exit(2);
        }
        ThreadDecision::RefuseUnknown => {
            eprintln!(
                "tirith __capsule-child: refusing to apply containment; could not confirm the \
                 process is single-threaded (unable to read /proc/self/stat). Failing closed \
                 rather than risk an unsound multi-threaded seccomp/Landlock apply."
            );
            std::process::exit(2);
        }
    }

    // Build both the executable C string and argv BEFORE we lock down, so an
    // interior NUL fails early. The executable path is intentionally independent
    // from argv[0]: a bound snapshot of bash/BusyBox must still observe the closed
    // requested name (`sh`/`ash`) to preserve alias and multicall semantics.
    let prog_c = match CString::new(parsed.program.as_os_str().as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("tirith __capsule-child: program path contains NUL");
            std::process::exit(2);
        }
    };
    let target_argv0 = parsed.target_argv0.as_deref().unwrap_or(&parsed.program);
    let argv: Vec<CString> = match exec_cstrings(target_argv0, &parsed.program_args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tirith __capsule-child: {e}");
            std::process::exit(2);
        }
    };

    if let Some(fd) = parsed.target_fd {
        if let Err(error) = validate_sealed_target_fd(&spec, fd) {
            eprintln!("tirith __capsule-child: invalid sealed target descriptor: {error}");
            std::process::exit(2);
        }
    }
    if parsed.launch_status_fd.is_some() != parsed.launch_ack_fd.is_some() {
        eprintln!(
            "tirith __capsule-child: target-exec status and authorization descriptors must be supplied together"
        );
        std::process::exit(2);
    }
    if let Some(fd) = parsed.launch_status_fd {
        if let Err(error) = validate_launch_protocol_fd(&spec, fd, "status") {
            eprintln!("tirith __capsule-child: invalid target-exec status descriptor: {error}");
            std::process::exit(2);
        }
    }
    if let Some(fd) = parsed.launch_ack_fd {
        if let Err(error) = validate_launch_protocol_fd(&spec, fd, "authorization") {
            eprintln!(
                "tirith __capsule-child: invalid target-exec authorization descriptor: {error}"
            );
            std::process::exit(2);
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            eprintln!(
                "tirith __capsule-child: cannot arm close-on-exec for target authorization descriptor: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }
    if let Some(fd) = parsed.script_fd {
        if Some(fd) == parsed.target_fd
            || Some(fd) == parsed.launch_status_fd
            || Some(fd) == parsed.launch_ack_fd
        {
            eprintln!(
                "tirith __capsule-child: reviewed-script descriptor overlaps another internal descriptor"
            );
            std::process::exit(2);
        }
        if let Err(error) = validate_sealed_script_fd(&spec, fd) {
            eprintln!("tirith __capsule-child: invalid reviewed-script descriptor: {error}");
            std::process::exit(2);
        }
        let expected = OsString::from(format!("/proc/self/fd/{fd}"));
        if parsed.program_args.last() != Some(&expected) {
            eprintln!(
                "tirith __capsule-child: reviewed-script argv does not name the validated descriptor"
            );
            std::process::exit(2);
        }
    } else if parsed
        .program_args
        .last()
        .and_then(|arg| arg.to_str())
        .and_then(|arg| arg.strip_prefix("/proc/self/fd/"))
        .and_then(|fd| fd.parse::<i32>().ok())
        .is_some_and(|fd| {
            spec.handles.extra_unix_fds.contains(&fd)
                && Some(fd) != parsed.target_fd
                && Some(fd) != parsed.launch_status_fd
                && Some(fd) != parsed.launch_ack_fd
        })
    {
        eprintln!(
            "tirith __capsule-child: inherited reviewed-script operand requires --script-fd validation"
        );
        std::process::exit(2);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    if let Some(fd) = parsed.launch_status_fd {
        write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
        eprintln!(
            "tirith __capsule-child: kernel target-exec proof is unavailable on this Linux architecture"
        );
        std::process::exit(2);
    }

    // Every temporary-HOME launch supplies a parent-owned directory that was
    // added to the finalized Landlock read/write policy. The parent keeps its
    // TempDir guard alive through complete-tree cleanup. Creating it here would
    // be too late for the serialized policy and would leak it across target exec.
    let temp_home_path = match (spec.environment.temporary_home, parsed.temp_home.as_deref()) {
        (false, Some(_)) => {
            eprintln!(
                "tirith __capsule-child: --temp-home supplied while temporary_home is disabled"
            );
            std::process::exit(2);
        }
        (true, Some(path)) => match validate_parent_temp_home(&spec, path) {
            Ok(path) => Some(path),
            Err(error) => {
                eprintln!("tirith __capsule-child: invalid parent-owned temporary HOME: {error}");
                std::process::exit(2);
            }
        },
        (true, None) => {
            eprintln!(
                "tirith __capsule-child: temporary_home requires a parent-owned, policy-granted --temp-home"
            );
            std::process::exit(2);
        }
        (false, None) => None,
    };

    // Apply the full containment sequence. On ANY error we exit non-zero and never
    // exec the target (fail-closed).
    let coverage = match apply_containment(&spec, temp_home_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith __capsule-child: containment failed: {e}");
            std::process::exit(2);
        }
    };

    // Honesty gate: the coverage we actually achieved must satisfy what the spec
    // requires, or we refuse to run the target. This is the in-launcher half of the
    // fail-closed contract (the parent also checks available_coverage before
    // spawning, but checking the ACHIEVED coverage here closes the gap where the
    // probe over-reported relative to what the apply actually managed).
    let required = spec.required_coverage();
    if coverage.is_degraded_against(&required) {
        eprintln!(
            "tirith __capsule-child: refusing to run uncontained; achieved coverage is \
             degraded against the spec's requirement (fs_read={} fs_write={} exec={} \
             raw_net_denied={} resources={} env={} handles={})",
            coverage.fs_read_enforced,
            coverage.fs_write_enforced,
            coverage.exec_limited,
            coverage.network_raw_denied,
            coverage.resource_limits_enforced,
            coverage.env_isolated,
            coverage.handles_isolated,
        );
        std::process::exit(13);
    }

    // Keep this contained launcher as the stable process-group leader and fork
    // the target beneath it. This parent boundary is security-critical: Linux
    // clone/clone3 permit a child-termination signal (including SIGKILL or
    // SIGSTOP), and CLONE_PARENT directs that signal at the caller's parent. If
    // the target replaced this launcher directly, a hostile descendant could
    // therefore signal Tirith itself. With the launcher retained, every such
    // signal lands on this already-contained guard instead. The outer supervisor
    // owns the complete group and will kill it before reaping this leader.
    let guard_pid = unsafe { libc::getpid() };
    let process_group = unsafe { libc::getpgrp() };
    if guard_pid <= 0 || process_group != guard_pid {
        eprintln!(
            "tirith __capsule-child: refusing target launch because the contained launcher is \
             not its process-group leader"
        );
        std::process::exit(2);
    }
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        eprintln!(
            "tirith __capsule-child: fork contained target failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(127);
    }
    if target_pid > 0 {
        if let (Some(status_fd), Some(ack_fd)) = (parsed.launch_status_fd, parsed.launch_ack_fd) {
            if let Err(error) = confirm_target_exec_event(target_pid, status_fd, ack_fd) {
                unsafe {
                    libc::close(status_fd);
                    libc::close(ack_fd);
                }
                eprintln!(
                    "tirith __capsule-child: target did not cross the kernel exec boundary: {error}"
                );
                // kill(2) is deliberately absent from the seccomp policy. Use
                // the narrowly-filtered PTRACE_KILL relationship to clean and
                // reap a stopped tracee, including failures before EXITKILL is
                // known armed. If it cannot be issued, never block here: exit
                // immediately so an armed EXITKILL fires and let the outer
                // uncontained supervisor finalize the anchored group.
                let _ = terminate_stopped_tracee(target_pid);
                std::process::exit(127);
            }
        }
        match wait_for_contained_target(target_pid) {
            Ok(ContainedTargetExit::Code(code)) => std::process::exit(code),
            Ok(ContainedTargetExit::Signal(signal)) => std::process::exit(128 + signal),
            Err(error) => {
                eprintln!("tirith __capsule-child: wait for contained target failed: {error}");
                std::process::exit(125);
            }
        }
    }
    // The fork child inherits the guard's group, Landlock domain, seccomp filter,
    // rlimits, scrubbed environment, and descriptor policy. Refuse if that group
    // relationship is ever changed by a future refactor before target exec.
    if unsafe { libc::getpgrp() } != guard_pid {
        eprintln!(
            "tirith __capsule-child: contained target did not inherit the launcher's process group"
        );
        std::process::exit(126);
    }

    // Only the stable guard may consume the parent's ACK_RESUME. The target
    // closes its inherited read endpoint before arming tracing, and the guard
    // endpoint itself is CLOEXEC as defense in depth against future flow edits.
    if let Some(fd) = parsed.launch_ack_fd {
        unsafe {
            libc::close(fd);
        }
    }

    // Close the pre-EXITKILL guard-death window. PR_SET_PDEATHSIG is inherited
    // across exec, and the immediate parent recheck closes the race where the
    // guard dies between fork and prctl. Thus an uncommitted target cannot
    // auto-detach and run if its trusted tracer disappears before SETOPTIONS.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } < 0
        || unsafe { libc::getppid() } != guard_pid
    {
        if let Some(fd) = parsed.launch_status_fd {
            write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
        }
        eprintln!("tirith __capsule-child: cannot bind contained target lifetime to its guard");
        std::process::exit(126);
    }

    if let Some(fd) = parsed.launch_status_fd {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
            eprintln!(
                "tirith __capsule-child: cannot arm target-exec status descriptor: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(126);
        }
        let traced = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if traced < 0 {
            write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
            eprintln!(
                "tirith __capsule-child: cannot arm kernel target-exec tracing: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(126);
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // A synchronous breakpoint produces the initial ptrace stop without
            // granting kill/tgkill to code that survives the later exec.
            std::arch::asm!("int3", options(nomem, nostack));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // AArch64's synchronous breakpoint is the architectural equivalent
            // of x86_64 int3 and yields the initial SIGTRAP trace stop without a
            // signal-delivery syscall grant.
            std::arch::asm!("brk #0", options(nomem, nostack));
        }
    }

    // Only the fork child reaches the execution primitives; the group-leader
    // guard above never replaces itself with attacker-controlled target code.
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    if let Some(fd) = parsed.target_fd {
        let empty = b"\0";
        unsafe extern "C" {
            static mut environ: *mut *mut libc::c_char;
        }
        // SAFETY: the descriptor was validated as a fully sealed executable and
        // kept by HandlePolicy; `empty`, argv, and the current environ are all
        // live and NUL-terminated as required by execveat(AT_EMPTY_PATH).
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                empty.as_ptr() as *const libc::c_char,
                ptrs.as_ptr(),
                environ as *const *const libc::c_char,
                libc::AT_EMPTY_PATH,
            );
        }
        let error = std::io::Error::last_os_error();
        if let Some(status_fd) = parsed.launch_status_fd {
            write_target_launch_status(status_fd, TARGET_LAUNCH_ERROR);
        }
        eprintln!(
            "tirith __capsule-child: execveat of sealed target {:?} failed: {error}",
            parsed.program
        );
        std::process::exit(127);
    }

    // Ordinary launcher calls retain pathname/PATH behavior.
    // SAFETY: `prog_c` and every pointer in `ptrs` are valid, NUL-terminated C
    // strings that outlive the call (owned by `argv`/`prog_c`), and `ptrs` is
    // NULL-terminated as execvp requires.
    unsafe {
        libc::execvp(prog_c.as_ptr(), ptrs.as_ptr());
    }
    // execvp only returns on error.
    let err = std::io::Error::last_os_error();
    if let Some(status_fd) = parsed.launch_status_fd {
        write_target_launch_status(status_fd, TARGET_LAUNCH_ERROR);
    }
    eprintln!(
        "tirith __capsule-child: exec of {:?} failed: {err}",
        parsed.program
    );
    std::process::exit(127);
}

#[cfg(target_os = "linux")]
fn write_target_launch_status(fd: i32, status: u8) -> bool {
    let mut written = 0usize;
    let bytes = [status];
    while written < bytes.len() {
        let result = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if result > 0 {
            written += result as usize;
            continue;
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn confirm_target_exec_event(
    target_pid: libc::pid_t,
    status_fd: i32,
    ack_fd: i32,
) -> Result<(), String> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited == target_pid {
            break;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Err(format!("wait for target trace stop: {error}"));
            }
            return refuse_unarmed_stopped_tracee(
                target_pid,
                format!("wait for target trace stop: {error}"),
            );
        }
    }
    if !libc::WIFSTOPPED(status) {
        return Err("target exited or signalled before arming exec tracing".to_string());
    }
    if libc::WSTOPSIG(status) != libc::SIGTRAP {
        return refuse_unarmed_stopped_tracee(
            target_pid,
            format!(
                "target stopped with signal {} before arming exec tracing",
                libc::WSTOPSIG(status)
            ),
        );
    }
    let set_options = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            target_pid,
            std::ptr::null_mut::<libc::c_void>(),
            ((libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize) as *mut libc::c_void,
        )
    };
    if set_options < 0 {
        return refuse_unarmed_stopped_tracee(
            target_pid,
            format!(
                "set PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL: {}",
                std::io::Error::last_os_error()
            ),
        );
    }
    if unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            target_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } < 0
    {
        return Err(format!(
            "continue traced target: {}",
            std::io::Error::last_os_error()
        ));
    }

    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("wait for target exec event: {error}"));
        }
        if waited != target_pid {
            continue;
        }
        if libc::WIFSTOPPED(status)
            && libc::WSTOPSIG(status) == libc::SIGTRAP
            && ((status >> 16) as libc::c_uint) == libc::PTRACE_EVENT_EXEC as libc::c_uint
        {
            let confirmed = authorize_detach_and_report_target_exec(status_fd, ack_fd, || {
                if unsafe {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                } < 0
                {
                    return Err(format!(
                        "detach kernel-confirmed target: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                Ok(())
            });
            if confirmed.is_ok() {
                // confirm_target_exec_event owns both raw protocol endpoints.
                // On error its caller closes them exactly once; on success
                // ownership ends here after terminal RESUMED was published.
                unsafe {
                    libc::close(status_fd);
                    libc::close(ack_fd);
                }
            }
            return confirmed;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err("target exited before the kernel reported exec".to_string());
        }
        return Err(format!(
            "target stopped with signal {} before exec",
            libc::WSTOPSIG(status)
        ));
    }
}

/// Complete the stopped-exec authorization protocol in causal order: OBSERVED,
/// exact ACK+EOF, detach/resume, then terminal RESUMED. The caller owns and
/// closes both protocol descriptors exactly once.
#[cfg(target_os = "linux")]
fn authorize_detach_and_report_target_exec(
    status_fd: i32,
    ack_fd: i32,
    detach: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    // The tracee is still stopped at the kernel's PTRACE_EVENT_EXEC boundary.
    // Publish only that observation, then require the outer trusted parent to
    // authorize resume with one exact byte and close its endpoint.
    if !write_target_launch_status(status_fd, TARGET_EXEC_OBSERVED) {
        return Err("report stopped kernel-confirmed target exec".to_string());
    }
    read_exact_resume_ack(ack_fd)?;
    detach()?;
    if !write_target_launch_status(status_fd, TARGET_LAUNCH_RESUMED) {
        return Err("report detached kernel-confirmed target exec".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_exact_resume_ack(fd: i32) -> Result<(), String> {
    let mut seen = false;
    let mut bytes = [0u8; 16];
    loop {
        let count =
            unsafe { libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len()) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("read target-resume authorization: {error}"));
        }
        if count == 0 {
            return if seen {
                Ok(())
            } else {
                Err("target-resume authorization channel closed without ACK".to_string())
            };
        }
        for byte in &bytes[..count as usize] {
            if *byte != TARGET_ACK_RESUME {
                return Err("target-resume authorization contained an invalid byte".to_string());
            }
            if seen {
                return Err("target-resume authorization was duplicated".to_string());
            }
            seen = true;
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_stopped_tracee(target_pid: libc::pid_t) -> bool {
    let killed = unsafe {
        libc::ptrace(
            libc::PTRACE_KILL,
            target_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if killed < 0 {
        // ESRCH can also mean a live tracee is not currently in ptrace-stop; it
        // is never terminal proof. Only a successful PTRACE_KILL followed by a
        // terminal wait below proves cleanup.
        return false;
    }
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited == target_pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            return true;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return error.raw_os_error() == Some(libc::ECHILD);
        }
    }
}

/// Refuse before PTRACE_O_EXITKILL is known armed. A returned error guarantees
/// the target was either already terminal (handled by the caller before this
/// helper) or was PTRACE_KILLed and reaped here. If that proof cannot be made,
/// keep this tracer alive and the tracee stopped until the outer uncontained
/// supervisor kills the complete process group; exiting could auto-detach and
/// resume an unacknowledged image.
#[cfg(target_os = "linux")]
fn refuse_unarmed_stopped_tracee(target_pid: libc::pid_t, reason: String) -> Result<(), String> {
    if terminate_stopped_tracee(target_pid) {
        return Err(format!("{reason}; unarmed tracee cleanup succeeded=true"));
    }
    eprintln!(
        "tirith __capsule-child: {reason}; cannot prove unarmed tracee cleanup, waiting for outer process-group termination"
    );
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited == target_pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            return Err(format!(
                "{reason}; outer tracee cleanup observed terminal state"
            ));
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Err(format!("{reason}; tracee is no longer a child"));
            }
            // Do not exit on an ambiguous wait failure while EXITKILL is
            // unarmed. Retry until the outer supervisor resolves the group.
        }
    }
}

/// Wait for the direct contained target while this process remains its stable
/// parent and process-group leader. The outer Tirith supervisor observes this
/// guard, not attacker-controlled code, and owns termination of the entire group.
/// A normally exited target preserves its code; a signal death is returned for
/// the caller to represent as conventional non-zero `128 + signal`. If a hostile clone directs
/// SIGKILL at this guard, the kernel terminates it directly and the outer
/// supervisor still sees a signal death and finalizes the anchored group.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainedTargetExit {
    Code(i32),
    Signal(i32),
}

#[cfg(target_os = "linux")]
fn wait_for_contained_target(target_pid: libc::pid_t) -> std::io::Result<ContainedTargetExit> {
    let mut status = 0;
    loop {
        // __WALL is load-bearing: CLONE_PARENT makes target-created processes
        // direct children of this guard, and a clone exit_signal of 0 is not
        // waitable through ordinary SIGCHLD semantics. Reap every such child so
        // a live target cannot accumulate zombies as a process-limit DoS, but
        // return only when the primary target itself has terminated.
        let waited = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if waited > 0 && waited != target_pid {
            continue;
        }
        if waited == target_pid {
            if libc::WIFEXITED(status) {
                return Ok(ContainedTargetExit::Code(libc::WEXITSTATUS(status)));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(ContainedTargetExit::Signal(libc::WTERMSIG(status)));
            }
            continue;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_sealed_target_fd(
    spec: &tirith_core::capsule::CapsuleSpec,
    fd: i32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if fd < 3 || !spec.handles.extra_unix_fds.contains(&fd) {
        return Err("descriptor is not an explicit non-stdio HandlePolicy grant".to_string());
    }
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(format!(
            "descriptor is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 || seals & required != required {
        return Err("descriptor is not sealed against every content mutation".to_string());
    }
    let proc_path = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
    let metadata = std::fs::metadata(&proc_path)
        .map_err(|error| format!("inspect executable descriptor: {error}"))?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err("descriptor is not an executable regular file".to_string());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "arm close-on-success for executable descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_launch_protocol_fd(
    spec: &tirith_core::capsule::CapsuleSpec,
    fd: i32,
    role: &str,
) -> Result<(), String> {
    if fd < 3 || !spec.handles.extra_unix_fds.contains(&fd) {
        return Err(format!(
            "{role} descriptor is not an explicit non-stdio HandlePolicy grant"
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "{role} descriptor is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
        return Err(format!(
            "inspect {role} descriptor type: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat initialized the structure on success.
    let metadata = unsafe { metadata.assume_init() };
    let descriptor_type = metadata.st_mode & libc::S_IFMT;
    match role {
        "status" => {
            let open_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if descriptor_type != libc::S_IFIFO
                || open_flags < 0
                || open_flags & libc::O_ACCMODE != libc::O_WRONLY
            {
                return Err(
                    "status descriptor is not the write-only endpoint of a pipe".to_string()
                );
            }
        }
        "authorization" => {
            let mut socket_type = 0i32;
            let mut socket_type_len = std::mem::size_of::<i32>() as libc::socklen_t;
            let mut socket_domain = 0i32;
            let mut socket_domain_len = std::mem::size_of::<i32>() as libc::socklen_t;
            if descriptor_type != libc::S_IFSOCK
                || unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_TYPE,
                        (&mut socket_type as *mut i32).cast::<libc::c_void>(),
                        &mut socket_type_len,
                    )
                } < 0
                || socket_type != libc::SOCK_STREAM
                || unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_DOMAIN,
                        (&mut socket_domain as *mut i32).cast::<libc::c_void>(),
                        &mut socket_domain_len,
                    )
                } < 0
                || socket_domain != libc::AF_UNIX
            {
                return Err(
                    "authorization descriptor is not an AF_UNIX stream socket endpoint".to_string(),
                );
            }
        }
        _ => return Err("unknown target-exec protocol descriptor role".to_string()),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sealed_script_fd(
    spec: &tirith_core::capsule::CapsuleSpec,
    fd: i32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if fd < 3 || !spec.handles.extra_unix_fds.contains(&fd) {
        return Err("descriptor is not an explicit non-stdio HandlePolicy grant".to_string());
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "descriptor is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 || seals & required != required {
        return Err("descriptor is not sealed against every content mutation".to_string());
    }
    let metadata = std::fs::metadata(format!("/proc/self/fd/{fd}"))
        .map_err(|error| format!("inspect reviewed-script descriptor: {error}"))?;
    if !metadata.is_file() || metadata.mode() & 0o222 != 0 {
        return Err("descriptor is not a read-only regular file".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_parent_temp_home(
    spec: &tirith_core::capsule::CapsuleSpec,
    raw: &std::ffi::OsStr,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;

    let requested = std::path::PathBuf::from(raw);
    if !requested.is_absolute() {
        return Err("path is not absolute".to_string());
    }
    let canonical = requested
        .canonicalize()
        .map_err(|error| format!("canonicalize {}: {error}", requested.display()))?;
    if canonical != requested {
        return Err(format!(
            "path is not canonical ({} resolves to {})",
            requested.display(),
            canonical.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect {}: {error}", canonical.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("path is not a real directory".to_string());
    }
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err("directory is not owned by the launcher uid with mode 0700".to_string());
    }
    let granted_exactly = |roots: &[std::path::PathBuf]| {
        roots
            .iter()
            .any(|root| root.canonicalize().is_ok_and(|root| root == canonical))
    };
    if !granted_exactly(&spec.filesystem.read_roots)
        || !granted_exactly(&spec.filesystem.write_roots)
    {
        return Err(
            "directory is not an exact finalized read/write filesystem-policy root".to_string(),
        );
    }
    Ok(canonical)
}

/// The number of threads in the current process, read from `/proc/self/stat`
/// (field 20). `None` if it cannot be determined; the caller treats `None` as
/// fail-closed (it cannot confirm single-threadedness, so it refuses to apply
/// containment) rather than proceeding on an unverified assumption. Linux-only.
///
/// The `/proc/self/stat` PARSE is factored into [`parse_num_threads_from_stat`] so
/// it is unit-testable without a live `/proc`.
#[cfg(target_os = "linux")]
fn current_thread_count() -> Option<usize> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    parse_num_threads_from_stat(&stat)
}

/// The fail-closed thread-count decision the launcher acts on. Kept as a pure value
/// (not cfg-gated) so the security-critical "refuse unless provably single-threaded"
/// logic is unit-testable on any platform. It is consumed by the launcher only on
/// Linux (the re-exec backend); off Linux it exists solely for those unit tests, so
/// dead-code is allowed there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadDecision {
    /// Exactly one thread was confirmed: safe to apply per-thread seccomp/Landlock.
    Proceed,
    /// More than one thread: refuse (a per-thread filter would not bind the others).
    RefuseMultiThreaded(usize),
    /// The thread count could not be read: refuse, because single-threadedness is
    /// unproven (fail closed rather than assume).
    RefuseUnknown,
}

/// Map a (possibly-unknown) thread count to the fail-closed [`ThreadDecision`].
/// **Pure**, so the refuse-by-default contract is unit-testable: `None` and any
/// count other than exactly 1 must refuse. Applying a per-thread seccomp filter or
/// Landlock `restrict_self` in a multi-threaded process is unsound (it binds only
/// the calling thread), and an unknown count cannot prove single-threadedness, so
/// both are refusals.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn thread_decision(count: Option<usize>) -> ThreadDecision {
    match count {
        Some(1) => ThreadDecision::Proceed,
        Some(threads) => ThreadDecision::RefuseMultiThreaded(threads),
        None => ThreadDecision::RefuseUnknown,
    }
}

/// Parse `num_threads` (field 20) out of the contents of `/proc/self/stat`.
/// **Pure** and platform-independent, so it can be unit-tested without `/proc`.
///
/// `/proc/<pid>/stat` is: `pid (comm) state ppid ...`. The `comm` field is wrapped
/// in parens and may itself contain spaces and `)` characters, so we split after the
/// LAST `") "` to keep the trailing fixed-position fields aligned. Counting from
/// `state` as field 1, `num_threads` is field 18 (the 20th overall field). Returns
/// `None` on any malformed input (a missing closing paren, too few fields, or a
/// non-integer), which the caller treats as fail-closed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_num_threads_from_stat(stat: &str) -> Option<usize> {
    // Split AFTER the closing paren of `comm` (use the LAST one so a `)` inside the
    // command name does not throw off the alignment).
    let after = stat.rsplit_once(") ")?.1;
    // After the ") ", fields are: state(1) ppid(2) ... num_threads is field 18
    // counting from `state` as field 1 (i.e. the 20th overall field).
    let num_threads = after.split_whitespace().nth(17)?;
    num_threads.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn is_invocation_detects_subcommand() {
        assert!(is_invocation(&argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--",
            "ls"
        ])));
        assert!(!is_invocation(&argv(&["tirith", "scan", "."])));
        assert!(!is_invocation(&argv(&["tirith"])));
        assert!(!is_invocation(&argv(&[])));
    }

    #[test]
    fn parse_args_happy_path() {
        let a = argv(&[
            "tirith",
            "__capsule-child",
            "{\"network\":{\"mode\":\"deny_all\"}}",
            "--",
            "/usr/bin/python3",
            "-m",
            "pip",
        ]);
        let p = parse_args(&a).expect("parse");
        assert_eq!(p.spec_json, "{\"network\":{\"mode\":\"deny_all\"}}");
        assert_eq!(p.program, "/usr/bin/python3");
        assert_eq!(
            p.program_args,
            vec![OsString::from("-m"), OsString::from("pip")]
        );
    }

    #[test]
    fn parse_args_program_with_no_args() {
        let a = argv(&["tirith", "__capsule-child", "{}", "--", "ls"]);
        let p = parse_args(&a).expect("parse");
        assert_eq!(p.program, "ls");
        assert!(p.program_args.is_empty());
    }

    #[test]
    fn parse_args_preserves_every_internal_launch_operand() {
        let a = argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--target-argv0",
            "sh",
            "--target-fd",
            "63",
            "--script-fd",
            "62",
            "--launch-status-fd",
            "61",
            "--launch-ack-fd",
            "60",
            "--temp-home",
            "/tmp/tirith-capsule-fixed",
            "--",
            "/tmp/bound/busybox",
            "-s",
        ]);
        let parsed = parse_args(&a).expect("parse internal launch options");
        assert_eq!(parsed.target_argv0.as_deref(), Some(OsStr::new("sh")));
        assert_eq!(parsed.target_fd, Some(63));
        assert_eq!(parsed.script_fd, Some(62));
        assert_eq!(parsed.launch_status_fd, Some(61));
        assert_eq!(parsed.launch_ack_fd, Some(60));
        assert_eq!(
            parsed.temp_home.as_deref(),
            Some(OsStr::new("/tmp/tirith-capsule-fixed"))
        );
        assert_eq!(parsed.program, "/tmp/bound/busybox");
        assert_eq!(parsed.program_args, vec![OsString::from("-s")]);
    }

    #[test]
    fn parse_args_rejects_unknown_or_duplicate_internal_options() {
        for a in [
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--unknown",
                "x",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-argv0",
                "sh",
                "--target-argv0",
                "bash",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "2",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "63",
                "--target-fd",
                "62",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--script-fd",
                "63",
                "--script-fd",
                "62",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--launch-status-fd",
                "63",
                "--launch-status-fd",
                "62",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "63",
                "--script-fd",
                "63",
                "--launch-status-fd",
                "62",
                "--",
                "ls",
            ]),
        ] {
            assert!(parse_args(&a).is_err());
        }
    }

    #[test]
    fn parse_args_requires_separator() {
        let a = argv(&["tirith", "__capsule-child", "{}", "ls"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_args_requires_program_after_separator() {
        let a = argv(&["tirith", "__capsule-child", "{}", "--"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_args_requires_spec_before_separator() {
        // `--` immediately after the subcommand: no spec JSON slot.
        let a = argv(&["tirith", "__capsule-child", "--", "ls"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_args_rejects_non_capsule_invocation() {
        let a = argv(&["tirith", "scan", "{}", "--", "ls"]);
        assert!(parse_args(&a).is_err());
    }

    // ── TG1: /proc/self/stat num_threads parse + fail-closed thread decision ──

    /// Build a `/proc/self/stat`-shaped line with the given `comm` and `num_threads`,
    /// with the surrounding fixed fields in their correct positions (state is field
    /// 3, num_threads is field 20). This mirrors the real kernel format closely
    /// enough to exercise the field-20 alignment, including the `comm`-in-parens
    /// quirk.
    fn stat_line(comm: &str, num_threads: usize) -> String {
        // Fields after comm, with `state` as the first: state ppid pgrp session
        // tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime
        // priority nice num_threads (18 fields = field 3..20). The values are
        // arbitrary placeholders except num_threads (the 18th here).
        let tail = format!(
            "R 5678 1234 1234 34816 1234 4194304 100 0 0 0 1 2 0 0 20 0 {num_threads} \
             0 1 0 0 0 0",
        );
        format!("1234 ({comm}) {tail}")
    }

    #[test]
    fn parse_num_threads_normal_stat_is_one() {
        let stat = stat_line("cat", 1);
        assert_eq!(parse_num_threads_from_stat(&stat), Some(1));
    }

    #[test]
    fn parse_num_threads_handles_comm_with_spaces_and_parens() {
        // The comm field can contain spaces AND parens; the parser splits on the LAST
        // ") " so the trailing fixed fields stay aligned.
        let stat = stat_line("weird )( name", 1);
        assert_eq!(
            parse_num_threads_from_stat(&stat),
            Some(1),
            "comm with spaces/parens must not throw off field-20 alignment"
        );
        // And with a higher count, still aligned.
        let stat3 = stat_line("a (b) c", 3);
        assert_eq!(parse_num_threads_from_stat(&stat3), Some(3));
    }

    #[test]
    fn parse_num_threads_multi_thread_count() {
        let stat = stat_line("server", 3);
        assert_eq!(parse_num_threads_from_stat(&stat), Some(3));
    }

    #[test]
    fn parse_num_threads_garbage_is_none() {
        // No closing paren -> None.
        assert_eq!(parse_num_threads_from_stat("garbage with no parens"), None);
        // Closing paren but too few trailing fields -> None.
        assert_eq!(parse_num_threads_from_stat("1234 (x) R 5 6"), None);
        // Field 20 (num_threads) present but not an integer -> None. After the
        // ") ", `notanumber` must land at 0-indexed token 17 (the num_threads slot:
        // state at index 0 plus 17 more before it).
        let bad = "1234 (x) R 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 notanumber 22";
        // Sanity: confirm the fixture really puts `notanumber` in the num_threads slot.
        assert_eq!(
            bad.rsplit_once(") ").unwrap().1.split_whitespace().nth(17),
            Some("notanumber")
        );
        assert_eq!(parse_num_threads_from_stat(bad), None);
        // Empty -> None.
        assert_eq!(parse_num_threads_from_stat(""), None);
    }

    #[test]
    fn thread_decision_fails_closed_unless_exactly_one() {
        // The dispositive fail-closed contract: only a confirmed single thread
        // proceeds; an unknown count or any multi-thread count refuses.
        assert_eq!(thread_decision(Some(1)), ThreadDecision::Proceed);
        assert_eq!(
            thread_decision(Some(2)),
            ThreadDecision::RefuseMultiThreaded(2)
        );
        assert_eq!(
            thread_decision(Some(64)),
            ThreadDecision::RefuseMultiThreaded(64)
        );
        assert_eq!(thread_decision(None), ThreadDecision::RefuseUnknown);
        // Zero is not "single-threaded" either (impossible, but must not proceed).
        assert_eq!(
            thread_decision(Some(0)),
            ThreadDecision::RefuseMultiThreaded(0)
        );
    }

    /// The spec JSON round-trips into a `CapsuleSpec` so the launcher and the
    /// parent agree on the wire format. Uses the locked-down spec the install
    /// surface will hand it.
    #[test]
    fn spec_json_roundtrips_for_launcher() {
        use tirith_core::capsule::CapsuleSpec;
        let spec = CapsuleSpec::locked_down();
        let json = serde_json::to_string(&spec).unwrap();
        let a = argv(&["tirith", "__capsule-child", &json, "--", "ls"]);
        let p = parse_args(&a).unwrap();
        let back: CapsuleSpec = serde_json::from_str(&p.spec_json).unwrap();
        assert_eq!(back, spec);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    struct TraceProtocolFixture {
        target_pid: libc::pid_t,
        status_reader: i32,
        status_writer: i32,
        ack_guard: i32,
        ack_parent: i32,
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn spawn_trace_protocol_fixture(
        program: &std::ffi::CString,
        arguments: &[std::ffi::CString],
        die_before_trace_stop: bool,
    ) -> TraceProtocolFixture {
        let mut status = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(status.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "status pipe: {}",
            std::io::Error::last_os_error()
        );
        let mut ack = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    ack.as_mut_ptr(),
                )
            },
            0,
            "ACK socketpair: {}",
            std::io::Error::last_os_error()
        );
        let mut argv: Vec<*const libc::c_char> =
            arguments.iter().map(|argument| argument.as_ptr()).collect();
        argv.push(std::ptr::null());
        let target_pid = unsafe { libc::fork() };
        assert!(
            target_pid >= 0,
            "fork traced target: {}",
            std::io::Error::last_os_error()
        );
        if target_pid == 0 {
            // libtest may have other threads. Use only async-signal-safe libc,
            // inline trap instructions, and the already-built pointer vector.
            unsafe {
                libc::close(status[0]);
                libc::close(ack[0]);
                libc::close(ack[1]);
                if die_before_trace_stop {
                    libc::_exit(44);
                }
                let flags = libc::fcntl(status[1], libc::F_GETFD);
                if flags < 0 || libc::fcntl(status[1], libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
                {
                    libc::_exit(45);
                }
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) < 0
                {
                    libc::_exit(46);
                }
                #[cfg(target_arch = "x86_64")]
                std::arch::asm!("int3", options(nomem, nostack));
                #[cfg(target_arch = "aarch64")]
                std::arch::asm!("brk #0", options(nomem, nostack));
                libc::execv(program.as_ptr(), argv.as_ptr());
                let error = [TARGET_LAUNCH_ERROR];
                let _ = libc::write(status[1], error.as_ptr().cast::<libc::c_void>(), 1);
                libc::_exit(127);
            }
        }
        TraceProtocolFixture {
            target_pid,
            status_reader: status[0],
            status_writer: status[1],
            ack_guard: ack[0],
            ack_parent: ack[1],
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn send_test_ack(fd: i32, bytes: &[u8]) {
        let sent = unsafe {
            libc::send(
                fd,
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(sent, bytes.len() as isize);
        unsafe {
            libc::close(fd);
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn read_status_and_close(fd: i32) -> Vec<u8> {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;

        // SAFETY: the fixture transfers unique ownership of its reader here.
        let mut reader = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read status to EOF");
        bytes
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn real_ptrace_exec_event_requires_ack_then_detaches_and_reaps() {
        let program = std::ffi::CString::new("/bin/true").unwrap();
        let argv = [std::ffi::CString::new("true").unwrap()];
        let fixture = spawn_trace_protocol_fixture(&program, &argv, false);
        send_test_ack(fixture.ack_parent, &[TARGET_ACK_RESUME]);
        confirm_target_exec_event(fixture.target_pid, fixture.status_writer, fixture.ack_guard)
            .expect("kernel exec, ACK, detach, and terminal resume");
        assert_eq!(
            read_status_and_close(fixture.status_reader),
            [TARGET_EXEC_OBSERVED, TARGET_LAUNCH_RESUMED]
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(fixture.target_pid, &mut status, 0) },
            fixture.target_pid
        );
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert_ne!(unsafe { libc::kill(fixture.target_pid, 0) }, 0);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn missing_invalid_or_duplicate_ack_cannot_run_execed_script_side_effects() {
        for ack in [Vec::new(), vec![b'X'], vec![TARGET_ACK_RESUME; 2]] {
            let temp = tempfile::tempdir().expect("marker directory");
            let marker = temp.path().join("must-not-exist");
            let command = format!("printf ran > '{}'", marker.display());
            let program = std::ffi::CString::new("/bin/sh").unwrap();
            let argv = [
                std::ffi::CString::new("sh").unwrap(),
                std::ffi::CString::new("-c").unwrap(),
                std::ffi::CString::new(command).unwrap(),
            ];
            let fixture = spawn_trace_protocol_fixture(&program, &argv, false);
            send_test_ack(fixture.ack_parent, &ack);
            let refusal = confirm_target_exec_event(
                fixture.target_pid,
                fixture.status_writer,
                fixture.ack_guard,
            )
            .expect_err("bad ACK must keep the execed image stopped");
            assert!(refusal.contains("authorization"), "{refusal}");
            assert!(terminate_stopped_tracee(fixture.target_pid));
            unsafe {
                libc::close(fixture.status_writer);
                libc::close(fixture.ack_guard);
            }
            assert_eq!(
                read_status_and_close(fixture.status_reader),
                [TARGET_EXEC_OBSERVED]
            );
            assert!(!marker.exists(), "target code ran before an exact ACK");
            assert_ne!(unsafe { libc::kill(fixture.target_pid, 0) }, 0);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn exec_failure_and_death_before_initial_stop_never_report_observed() {
        for (program_path, die_before_stop) in [
            ("/definitely/missing/tirith-target", false),
            ("/bin/true", true),
        ] {
            let program = std::ffi::CString::new(program_path).unwrap();
            let argv = [std::ffi::CString::new("fixture").unwrap()];
            let fixture = spawn_trace_protocol_fixture(&program, &argv, die_before_stop);
            send_test_ack(fixture.ack_parent, &[TARGET_ACK_RESUME]);
            let refusal = confirm_target_exec_event(
                fixture.target_pid,
                fixture.status_writer,
                fixture.ack_guard,
            )
            .expect_err("no successful exec event exists");
            assert!(
                refusal.contains("before") || refusal.contains("signalled"),
                "{refusal}"
            );
            unsafe {
                libc::close(fixture.status_writer);
                libc::close(fixture.ack_guard);
            }
            let statuses = read_status_and_close(fixture.status_reader);
            assert!(!statuses.contains(&TARGET_EXEC_OBSERVED), "{statuses:?}");
            assert!(!statuses.contains(&TARGET_LAUNCH_RESUMED), "{statuses:?}");
            assert_ne!(unsafe { libc::kill(fixture.target_pid, 0) }, 0);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn detach_failure_never_publishes_terminal_resumed() {
        let mut status = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(status.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let mut ack = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    ack.as_mut_ptr(),
                )
            },
            0
        );
        send_test_ack(ack[1], &[TARGET_ACK_RESUME]);
        let refusal = authorize_detach_and_report_target_exec(status[1], ack[0], || {
            Err("injected detach failure".to_string())
        })
        .expect_err("detach failure must not become terminal success");
        assert!(refusal.contains("injected"));
        unsafe {
            libc::close(status[1]);
            libc::close(ack[0]);
        }
        assert_eq!(read_status_and_close(status[0]), [TARGET_EXEC_OBSERVED]);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn unarmed_stopped_tracee_is_ptrace_killed_and_reaped_before_marker() {
        let temp = tempfile::tempdir().expect("pre-option marker directory");
        let marker = temp.path().join("must-not-exist");
        let marker_c =
            std::ffi::CString::new(marker.as_os_str().as_encoded_bytes()).expect("marker C path");
        let target_pid = unsafe { libc::fork() };
        assert!(target_pid >= 0);
        if target_pid == 0 {
            unsafe {
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) < 0
                {
                    libc::_exit(50);
                }
                #[cfg(target_arch = "x86_64")]
                std::arch::asm!("int3", options(nomem, nostack));
                #[cfg(target_arch = "aarch64")]
                std::arch::asm!("brk #0", options(nomem, nostack));
                let byte = *b"x";
                let fd = libc::open(
                    marker_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o600,
                );
                if fd >= 0 {
                    let _ = libc::write(fd, byte.as_ptr().cast::<libc::c_void>(), 1);
                    libc::close(fd);
                }
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) },
            target_pid
        );
        assert!(libc::WIFSTOPPED(status));
        assert!(terminate_stopped_tracee(target_pid));
        assert!(!marker.exists());
        assert_ne!(unsafe { libc::kill(target_pid, 0) }, 0);
    }

    #[cfg(target_os = "linux")]
    fn run_clone_parent_reap_helper() {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;

        let guard_pid = unsafe { libc::getpid() };
        let guard_tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
        assert_eq!(
            unsafe { libc::getpgrp() },
            guard_pid,
            "isolated guard helper must own its process group"
        );

        let mut descriptors = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "create clone-parent receipt pipe: {}",
            std::io::Error::last_os_error()
        );
        let target_pid = unsafe { libc::fork() };
        assert!(
            target_pid >= 0,
            "fork exact contained-target fixture: {}",
            std::io::Error::last_os_error()
        );
        if target_pid == 0 {
            // This child was forked from libtest, which may own runtime locks in
            // other threads. Use only async-signal-safe libc/syscall operations
            // until _exit: the parent guard remains ordinary Rust and exercises
            // the exact production wait loop below.
            unsafe {
                libc::close(descriptors[0]);
                let mut clone_pids = [0 as libc::pid_t; 32];
                for (index, pid_slot) in clone_pids.iter_mut().enumerate() {
                    let exit_signal = if index < 16 { 0 } else { libc::SIGCHLD };
                    let cloned = libc::syscall(
                        libc::SYS_clone,
                        libc::CLONE_PARENT | exit_signal,
                        0,
                        0,
                        0,
                        0,
                    ) as libc::pid_t;
                    if cloned < 0 {
                        libc::_exit(40);
                    }
                    if cloned == 0 {
                        libc::_exit(0);
                    }
                    *pid_slot = cloned;
                }
                let bytes = std::slice::from_raw_parts(
                    clone_pids.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&clone_pids),
                );
                let mut written = 0usize;
                while written < bytes.len() {
                    let count = libc::write(
                        descriptors[1],
                        bytes[written..].as_ptr().cast::<libc::c_void>(),
                        bytes.len() - written,
                    );
                    if count < 0 {
                        if *libc::__errno_location() == libc::EINTR {
                            continue;
                        }
                        libc::_exit(41);
                    }
                    written += count as usize;
                }
                libc::close(descriptors[1]);
                let requested = libc::timespec {
                    tv_sec: 4,
                    tv_nsec: 0,
                };
                let mut remaining = requested;
                while libc::nanosleep(&remaining, &mut remaining) != 0 {
                    if *libc::__errno_location() != libc::EINTR {
                        libc::_exit(42);
                    }
                }
                libc::_exit(0);
            }
        }

        unsafe {
            libc::close(descriptors[1]);
        }
        let mut pipe = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let watcher = std::thread::spawn(move || {
            let mut clone_pids = [0 as libc::pid_t; 32];
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    clone_pids.as_mut_ptr().cast::<u8>(),
                    std::mem::size_of_val(&clone_pids),
                )
            };
            pipe.read_exact(bytes)
                .expect("target publishes every CLONE_PARENT child pid");

            // libtest runs this function on a worker thread, so the forked
            // target is recorded under that thread's task entry. Production is
            // single-threaded and has guard_tid == guard_pid; selecting the
            // actual forking TID keeps this isolated receipt faithful to the
            // kernel's per-task `children` accounting.
            let children_path =
                std::path::PathBuf::from(format!("/proc/{guard_pid}/task/{guard_tid}/children"));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let children = std::fs::read_to_string(&children_path)
                    .expect("inspect exact guard direct children")
                    .split_whitespace()
                    .map(str::parse::<libc::pid_t>)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("numeric exact guard child list");
                let clones_gone = clone_pids
                    .iter()
                    .all(|pid| !std::path::PathBuf::from(format!("/proc/{pid}")).exists());
                if children == [target_pid] && clones_gone {
                    return;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "production __WALL loop retained clone children or zombies while the primary target stayed alive: children={children:?} clone_pids={clone_pids:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        let exit = wait_for_contained_target(target_pid)
            .expect("exact production guard wait must reap the complete direct child set");
        assert_eq!(exit, ContainedTargetExit::Code(0));
        watcher
            .join()
            .expect("clone-parent no-zombie watcher completes");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn contained_guard_reaps_clone_parent_children_with_wall() {
        const HELPER_ENV: &str = "TIRITH_TEST_CLONE_PARENT_REAP_HELPER";
        if std::env::var_os(HELPER_ENV).is_some() {
            run_clone_parent_reap_helper();
            return;
        }

        use std::os::unix::process::CommandExt as _;

        let mut command = std::process::Command::new(
            std::env::current_exe().expect("locate current unit-test executable"),
        );
        command
            .args([
                "--exact",
                "cli::capsule_child::tests::contained_guard_reaps_clone_parent_children_with_wall",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(HELPER_ENV, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let output = command
            .output()
            .expect("spawn isolated exact guard-wait receipt");
        assert!(
            output.status.success(),
            "isolated exact guard-wait receipt failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
