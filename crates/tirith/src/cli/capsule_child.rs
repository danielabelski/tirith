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
//!    spec's requirement, and only then `execve`s the target.
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
//! single-threaded main thread. It never returns on success (`execve` replaces the
//! image); on any failure it prints to stderr and exits non-zero. It MUST NOT
//! fall through to running the target uncontained (fail-closed).

use std::ffi::{OsStr, OsString};

/// The hidden subcommand name. A double-underscore prefix marks it internal and
/// keeps it clear of any real command.
pub const SUBCOMMAND: &str = "__capsule-child";

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
    /// The executable path/name passed to `execvp`.
    pub program: OsString,
    /// Optional explicit `argv[0]` for alias-sensitive or multicall targets.
    /// When absent, [`Self::program`] is used, preserving the legacy launcher
    /// contract.
    pub target_argv0: Option<OsString>,
    /// Optional parent-owned temporary HOME. The parent keeps the directory
    /// guard alive until the complete child tree has exited and grants this
    /// exact path in the finalized filesystem policy before launch.
    pub temp_home: Option<OsString>,
    /// The target program's arguments.
    pub program_args: Vec<OsString>,
}

/// Parse `tirith __capsule-child <spec-json> [internal options] -- <prog>
/// <arg>...` from the full process argv. Internal options are closed and may
/// appear at most once: `--target-argv0 <value>` and `--temp-home <absolute>`.
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
        } else if option == "--temp-home" {
            if temp_home.replace(value).is_some() {
                return Err("duplicate `--temp-home` launcher option".to_string());
            }
        } else {
            return Err(format!("unknown internal launcher option {option:?}"));
        }
        option_index += 2;
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
        temp_home,
        program_args,
    })
}

/// Handle a `__capsule-child` invocation on the main thread and NEVER return on
/// success: it `execve`s the contained target (replacing this image) or exits the
/// process non-zero on any failure. Call this at the top of `main()` only when
/// [`is_invocation`] is true and the process is still single-threaded.
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
/// requirement, then `execve` the target. Diverges (never returns): `execvp`
/// replaces the image on success and every failure path exits non-zero.
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

    // Every temporary-HOME launch supplies a parent-owned directory that was
    // added to the finalized Landlock read/write policy. The parent keeps its
    // TempDir guard alive through complete-tree cleanup. Creating it here would
    // be too late for the serialized policy and would leak it across execvp.
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

    // execvp searches PATH for a bare program name, matching how a user would run
    // it; an absolute/relative path is used as-is. On success this never returns.
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `prog_c` and every pointer in `ptrs` are valid, NUL-terminated C
    // strings that outlive the call (owned by `argv`/`prog_c`), and `ptrs` is
    // NULL-terminated as execvp requires.
    unsafe {
        libc::execvp(prog_c.as_ptr(), ptrs.as_ptr());
    }
    // execvp only returns on error.
    let err = std::io::Error::last_os_error();
    eprintln!(
        "tirith __capsule-child: exec of {:?} failed: {err}",
        parsed.program
    );
    std::process::exit(127);
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
    fn parse_args_preserves_internal_argv0_and_parent_temp_home() {
        let a = argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--target-argv0",
            "sh",
            "--temp-home",
            "/tmp/tirith-capsule-fixed",
            "--",
            "/tmp/bound/busybox",
            "-s",
        ]);
        let parsed = parse_args(&a).expect("parse internal launch options");
        assert_eq!(parsed.target_argv0.as_deref(), Some(OsStr::new("sh")));
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
}
