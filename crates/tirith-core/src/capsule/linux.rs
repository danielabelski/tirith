//! Linux runtime-containment backend (Stack E, unit E2).
//!
//! This module provides the Linux half of the capsule: the
//! [`LandlockSeccompCapsule`] backend (which probes the running kernel and
//! reports honest [`CapsuleCoverage`]) and the [`apply_containment`] primitive
//! that the internal `tirith __capsule-child` launcher calls **inside a freshly
//! `exec`'d, single-threaded child** to lock that child down before it `execve`s
//! the real program.
//!
//! ## Why a launcher, not `pre_exec`
//!
//! seccomp-BPF and Landlock are applied to the *current thread/process*, and a
//! seccomp filter installed in a `Command::pre_exec` closure runs in the forked
//! child between `fork` and `execve`, a context where allocation and most of std
//! are unsafe, and (worse) the parent is multi-threaded so a TSYNC filter cannot
//! be reasoned about. Instead, the CLI re-execs a dedicated subcommand
//! (`tirith __capsule-child <spec-json> -- <prog> <args...>`); that process starts
//! single-threaded, deserializes the [`CapsuleSpec`], calls [`apply_containment`],
//! and only then `execve`s the target. The lockdown therefore happens in a normal
//! (single-threaded, fully-initialized) process, NOT in `pre_exec`.
//!
//! ## Order of operations (must not be reordered)
//!
//! [`apply_containment`] applies, in this exact order:
//!
//! 1. **Inherited-handle closure**: enumerate `/proc/self/fd` before lowering the
//!    descriptor ceiling and close every descriptor outside [`HandlePolicy`].
//! 2. **Resource limits** ([`libc::setrlimit`]): `RLIMIT_CPU`, `RLIMIT_AS`,
//!    `RLIMIT_NPROC`, `RLIMIT_NOFILE` from [`ResourceLimits`].
//! 3. **`PR_SET_NO_NEW_PRIVS`** ([`libc::prctl`]): no `execve` can ever gain
//!    privileges (defeats setuid escalation) and it is a precondition for an
//!    unprivileged seccomp filter. Set explicitly even though seccompiler also sets
//!    it, so that the guarantee holds on a kernel/arch where the seccomp layer is
//!    unavailable.
//! 4. **Landlock** (filesystem confinement): grant only the spec's read/write
//!    roots; everything else (including the sensitive subtrees in
//!    [`crate::capsule::deny_default_paths`] that are not under a grant) is denied
//!    by Landlock's default-deny model.
//! 5. **seccomp** (`extrasafe`): a default-deny syscall policy that allows the
//!    basics + file I/O + thread creation + fork/exec, but grants **no
//!    socket-creation syscalls**, so the child cannot open a raw outbound socket.
//! 6. **Environment cleanup**: drop every variable except the policy's survivors,
//!    strip the known sensitive set, and point HOME/TMPDIR/XDG_* at a temporary
//!    directory so the child cannot read or poison the real user config.
//!
//! After step 5 the launcher `execve`s the target; the seccomp filter and Landlock
//! ruleset are inherited across the `execve`, so they bind the real program.
//!
//! ## Honesty (cross-cutting invariant 2)
//!
//! [`LandlockSeccompCapsule::available_coverage`] probes for Landlock support and
//! checks the architecture for seccomp support, and reports only what it can
//! actually enforce. In particular it **never** claims `domain_proxy_enforced`:
//! E2 has no verified raw-socket-blocking egress path (a complete netns+veth/slirp
//! broker or a proven `srt`/bubblewrap launcher), so an
//! [`CapabilityLevel::AllowListedDomains`] spec is reported as degraded and an
//! enforcing surface fails closed (cross-cutting invariant 3).

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::{
    CapabilityLevel, Capsule, CapsuleCoverage, CapsuleSpec, EnvironmentPolicy, HandlePolicy,
    ResourceLimitSupport, ResourceLimits,
};

/// The stable backend identifier reported in receipts and `tirith doctor`.
pub const BACKEND_ID: &str = "landlock-seccomp";

/// Resource dimensions applied by `apply_rlimits`. Keep this single definition
/// shared by the pure availability probe and the child-side apply receipt so
/// they cannot disagree about aggregate coverage.
const RESOURCE_LIMIT_SUPPORT: ResourceLimitSupport = ResourceLimitSupport {
    cpu_seconds: true,
    memory_bytes: true,
    max_processes: true,
    max_open_files: true,
    max_output_bytes: false,
    wall_clock_seconds: false,
};

/// Whether this build can install a seccomp filter. `extrasafe`/`seccompiler`
/// only support `linux-x86_64`; on any other Linux architecture the seccomp layer
/// is unavailable and must be reported as such (the rest of the containment still
/// applies). Kept as a `const fn` so both the backend and its tests agree.
pub const fn seccomp_supported() -> bool {
    cfg!(target_arch = "x86_64")
}

/// The Linux containment backend. Stateless: it probes the kernel on demand.
#[derive(Debug, Clone, Copy, Default)]
pub struct LandlockSeccompCapsule;

impl Capsule for LandlockSeccompCapsule {
    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }

    fn available_coverage(&self, spec: &CapsuleSpec) -> CapsuleCoverage {
        let fs = landlock_probe();
        let seccomp = seccomp_supported();
        derive_coverage(spec, &fs, seccomp)
    }
}

/// What a Landlock probe found on the running kernel: whether Landlock is usable
/// at all, and at which ABI. `abi` is `Some(n)` when usable. Kept as plain data so
/// [`derive_coverage`] can be unit-tested without a kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LandlockProbe {
    /// Landlock is usable (a ruleset could be created and would restrict access).
    pub usable: bool,
    /// The effective ABI version the kernel + crate agree on, when usable.
    pub abi: Option<u8>,
}

/// Probe the running kernel for Landlock support without restricting this process.
/// A kernel without Landlock (`ENOSYS`) or with it disabled (`EOPNOTSUPP`) yields
/// `usable = false`; the backend then reports the filesystem capabilities as
/// unenforced. It is the honest precondition for claiming `fs_*_enforced`.
///
/// Implemented via [`best_effort_abi`]: a kernel that supports at least ABI v1 can
/// enforce a Landlock ruleset, so `usable` mirrors "an ABI was found". The probe
/// only *creates* throwaway ruleset fds; it never calls `restrict_self`, so it
/// does not lock the calling process.
fn landlock_probe() -> LandlockProbe {
    let abi = best_effort_abi();
    LandlockProbe {
        usable: abi.is_some(),
        abi,
    }
}

/// The effective Landlock ABI the running kernel supports, as a small integer, or
/// `None` when Landlock is unavailable. Implemented by trying to create rulesets
/// at descending ABI levels under `HardRequirement` until one succeeds, a
/// portable stand-in for the crate's private `LandlockStatus::current`. Creating a
/// ruleset (without `restrict_self`) does not restrict the calling process.
fn best_effort_abi() -> Option<u8> {
    use landlock::{Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, ABI};

    for (abi, n) in [(ABI::V4, 4u8), (ABI::V3, 3), (ABI::V2, 2), (ABI::V1, 1)] {
        let ok = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.create())
            .is_ok();
        if ok {
            return Some(n);
        }
    }
    None
}

/// Derive the coverage the backend can honestly claim for `spec`, given the
/// Landlock probe result and whether seccomp is supported on this arch. **Pure**
/// (no syscalls), so every branch of the honesty contract is unit-testable on any
/// platform.
///
/// Rules:
/// - `fs_read_enforced` / `fs_write_enforced`: true only when Landlock is usable.
/// - `exec_limited`: true when EITHER `PR_SET_NO_NEW_PRIVS` (always settable on
///   Linux) or seccomp is in force. We model it as `true` whenever the process can
///   set no-new-privs, which on Linux is always; seccomp tightens it further.
/// - `network_raw_denied`: true only when seccomp is supported (the seccomp policy
///   grants no socket-creation syscall). Without seccomp we cannot block raw
///   sockets, so this is false.
/// - `domain_proxy_enforced`: **always false in E2**. No verified
///   raw-socket-blocking egress backend exists yet, so an allow-list spec is
///   degraded (invariant 3).
/// - `resource_limits_enforced`: true only when every requested dimension is
///   rlimit-able here. Wall-clock and output limits are not applied by this
///   launcher, so either one keeps the aggregate bit false.
/// - `env_isolated` / `handles_isolated`: true (the launcher always scrubs the
///   environment and closes inherited fds down to the policy set).
pub fn derive_coverage(spec: &CapsuleSpec, fs: &LandlockProbe, seccomp: bool) -> CapsuleCoverage {
    CapsuleCoverage {
        fs_read_enforced: fs.usable,
        fs_write_enforced: fs.usable,
        // PR_SET_NO_NEW_PRIVS is always available on Linux; seccomp tightens it.
        exec_limited: true,
        // Raw sockets are denied only by the seccomp policy.
        network_raw_denied: seccomp,
        // E2 ships no verified raw-socket-blocking egress path.
        domain_proxy_enforced: false,
        resource_limits_enforced: spec
            .resources
            .all_requested_enforced_by(RESOURCE_LIMIT_SUPPORT),
        env_isolated: true,
        handles_isolated: true,
    }
}

/// An error from applying containment in the child, before `execve`. The launcher
/// turns this into a non-zero exit and a stderr message; it must NEVER fall
/// through to running the target uncontained.
#[derive(Debug)]
pub enum ContainError {
    /// Inherited descriptors could not be reduced to the policy allow-list.
    Handles(String),
    /// A resource limit could not be set.
    Rlimit(String),
    /// `PR_SET_NO_NEW_PRIVS` failed.
    NoNewPrivs(String),
    /// Building or applying the Landlock ruleset failed.
    Landlock(String),
    /// Building or applying the seccomp filter failed.
    Seccomp(String),
    /// The requested containment level cannot be honored on this host (e.g. an
    /// allow-listed-domains spec, which E2 has no verified egress backend for).
    Unsupported(String),
}

impl std::fmt::Display for ContainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainError::Handles(m) => write!(f, "handle isolation: {m}"),
            ContainError::Rlimit(m) => write!(f, "resource limit: {m}"),
            ContainError::NoNewPrivs(m) => write!(f, "no-new-privs: {m}"),
            ContainError::Landlock(m) => write!(f, "landlock: {m}"),
            ContainError::Seccomp(m) => write!(f, "seccomp: {m}"),
            ContainError::Unsupported(m) => write!(f, "unsupported containment: {m}"),
        }
    }
}

impl std::error::Error for ContainError {}

/// Close every inherited descriptor except the policy's explicit Unix
/// allow-list. This runs while the launcher is confirmed single-threaded and
/// before lowering `RLIMIT_NOFILE`, so enumerating `/proc/self/fd` sees the
/// complete inherited set. Failure is fatal: an already-open file bypasses
/// Landlock and an already-connected socket bypasses syscall-level socket
/// creation denial.
pub fn close_unexpected_fds(policy: &HandlePolicy) -> Result<(), ContainError> {
    let allowed = policy.allowed_unix_fds();
    if let Some(fd) = allowed.iter().find(|fd| **fd < 0) {
        return Err(ContainError::Handles(format!(
            "allowed descriptor must be non-negative: {fd}"
        )));
    }

    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|error| ContainError::Handles(format!("enumerate /proc/self/fd: {error}")))?;
    let mut inherited = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| ContainError::Handles(format!("read /proc/self/fd entry: {error}")))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(ContainError::Handles(
                "non-UTF-8 descriptor name in /proc/self/fd".to_string(),
            ));
        };
        let fd = name.parse::<i32>().map_err(|error| {
            ContainError::Handles(format!("invalid descriptor entry {name:?}: {error}"))
        })?;
        if !allowed.contains(&fd) {
            inherited.push(fd);
        }
    }
    // Drop ReadDir before closing: its own descriptor appeared in the snapshot
    // and is already closed by this point. A later close on that number may
    // therefore report EBADF, which is the desired end state.
    for fd in inherited {
        if unsafe { libc::close(fd) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(ContainError::Handles(format!(
                    "close inherited descriptor {fd}: {error}"
                )));
            }
        }
    }
    Ok(())
}

/// Apply the full containment sequence to the **current** process, then return the
/// coverage actually achieved. Call this from the single-threaded launcher child
/// immediately before `execve`. On `Err`, the caller must abort (exit non-zero)
/// and MUST NOT exec the target.
///
/// `temp_home` is a pre-created temporary directory the launcher owns; the env
/// step points HOME/TMPDIR/XDG_* at it when [`EnvironmentPolicy::temporary_home`]
/// is set. (The parent creates it before serializing the policy, retains the
/// cleanup guard through complete-tree shutdown, and this primitive only reads
/// the path.)
///
/// This refuses an [`CapabilityLevel::AllowListedDomains`] spec with
/// [`ContainError::Unsupported`]: E2 has no backend that blocks raw sockets except
/// a broker, so it must not silently run such a child with no egress containment.
pub fn apply_containment(
    spec: &CapsuleSpec,
    temp_home: Option<&Path>,
) -> Result<CapsuleCoverage, ContainError> {
    // Refuse a level we cannot honestly enforce, BEFORE touching the process.
    if spec.capability_level() == CapabilityLevel::AllowListedDomains {
        return Err(ContainError::Unsupported(
            "allow-listed-domains egress needs a raw-socket-blocking backend not present in E2"
                .to_string(),
        ));
    }
    if spec.environment.temporary_home != temp_home.is_some() {
        return Err(ContainError::Unsupported(
            "temporary_home requires exactly one prevalidated parent-owned directory".to_string(),
        ));
    }

    // 1. Handle isolation. This must precede RLIMIT_NOFILE so the enumeration
    // sees every inherited descriptor, including descriptors above the new cap.
    close_unexpected_fds(&spec.handles)?;

    // 2. Resource limits.
    apply_rlimits(&spec.resources)?;

    // 3. No new privileges.
    set_no_new_privs()?;

    // 4. Landlock filesystem confinement.
    let fs_outcome = apply_landlock(spec)?;
    if fs_outcome == LandlockOutcome::Partially {
        // Honest signal: FS is still confined to the grants (default-deny holds in
        // the safe direction), but the kernel honored only a subset of the
        // requested access set, so we do NOT silently present this as full
        // enforcement. Surfaced to stderr; the coverage flag stays true because the
        // granted roots ARE confined (a partial downgrade narrows, never widens).
        eprintln!(
            "tirith __capsule-child: note: Landlock partially enforced (best-effort kernel \
             downgrade); the granted roots are confined but some requested access restrictions \
             were not applied"
        );
    }

    // 5. seccomp (default-deny syscall policy, no socket creation).
    let seccomp_applied = apply_seccomp()?;

    // 6. Environment scrubbing.
    apply_env(&spec.environment, temp_home);

    Ok(CapsuleCoverage {
        fs_read_enforced: fs_outcome.fs_confined(),
        fs_write_enforced: fs_outcome.fs_confined(),
        exec_limited: true,
        network_raw_denied: seccomp_applied,
        domain_proxy_enforced: false,
        resource_limits_enforced: spec
            .resources
            .all_requested_enforced_by(RESOURCE_LIMIT_SUPPORT),
        env_isolated: true,
        handles_isolated: true,
    })
}

/// Apply the rlimit-able dimensions of [`ResourceLimits`] via `setrlimit`. Each
/// populated dimension is set to a soft==hard limit. `wall_clock_seconds` and
/// `max_output_bytes` are NOT rlimits (the launcher/broker enforce those), so they
/// are ignored here.
fn apply_rlimits(limits: &ResourceLimits) -> Result<(), ContainError> {
    if let Some(cpu) = limits.cpu_seconds {
        set_one_rlimit(libc::RLIMIT_CPU as libc::c_uint, cpu, "RLIMIT_CPU")?;
    }
    if let Some(mem) = limits.memory_bytes {
        set_one_rlimit(libc::RLIMIT_AS as libc::c_uint, mem, "RLIMIT_AS")?;
    }
    if let Some(nproc) = limits.max_processes {
        set_one_rlimit(
            libc::RLIMIT_NPROC as libc::c_uint,
            u64::from(nproc),
            "RLIMIT_NPROC",
        )?;
    }
    if let Some(nofile) = limits.max_open_files {
        set_one_rlimit(
            libc::RLIMIT_NOFILE as libc::c_uint,
            u64::from(nofile),
            "RLIMIT_NOFILE",
        )?;
    }
    Ok(())
}

/// Set one `setrlimit` resource to `value` (soft == hard). `RLIMIT_NOFILE` is a
/// fd *count* and the rest are their natural units; all fit `rlim_t`.
fn set_one_rlimit(resource: libc::c_uint, value: u64, name: &str) -> Result<(), ContainError> {
    let rl = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: `rl` is a valid, fully-initialized rlimit for the duration of the
    // call; `setrlimit` does not retain the pointer.
    // libc exposes the resource argument as an unsigned enum on glibc and as
    // `c_int` on musl. Keep our portable boundary unsigned, then cast to the
    // target-specific signature selected by this build.
    let rc = unsafe { libc::setrlimit(resource as _, &rl) };
    if rc != 0 {
        return Err(ContainError::Rlimit(format!(
            "{name}={value}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Set `PR_SET_NO_NEW_PRIVS`. Idempotent and cheap; a precondition for an
/// unprivileged seccomp filter and a defense against setuid escalation that holds
/// even when the seccomp layer is unavailable (non-x86_64).
fn set_no_new_privs() -> Result<(), ContainError> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args and has no
    // memory-safety implications.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(ContainError::NoNewPrivs(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

/// The outcome of applying the Landlock ruleset, distinguishing full enforcement
/// from a best-effort partial enforcement from no enforcement at all. Kept distinct
/// (rather than collapsed to a `bool`) so [`apply_containment`] never silently
/// claims FULL filesystem enforcement when the kernel only partially honored the
/// requested access set — the "never over-report coverage" invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LandlockOutcome {
    /// Every requested access restriction is enforced.
    Fully,
    /// Landlock is active and the granted roots are confined (default-deny still
    /// holds, in the safe direction), but the kernel honored only a SUBSET of the
    /// requested V1 access rights (best-effort downgrade on an older kernel). FS is
    /// still confined to the grants, so coverage stays `true`, but the partial
    /// status is surfaced rather than masquerading as full enforcement.
    Partially,
    /// Landlock is not in force (kernel lacks it / disabled); FS is NOT confined.
    NotEnforced,
}

impl LandlockOutcome {
    /// Whether the granted roots are actually confined. True for both full and
    /// partial enforcement: in either case Landlock's default-deny means only the
    /// granted roots are reachable (a partial downgrade drops requested access
    /// *types*, never widens reachable paths), so the FS-confinement coverage flag
    /// is honestly `true`. Only [`Self::NotEnforced`] leaves the FS unconfined.
    fn fs_confined(self) -> bool {
        matches!(self, LandlockOutcome::Fully | LandlockOutcome::Partially)
    }
}

/// Build and apply the Landlock ruleset from the spec's read/write roots. Returns
/// the [`LandlockOutcome`] (full / partial / not enforced) so the caller can record
/// the honest status instead of coercing a partial result into a full-enforcement
/// claim.
///
/// Landlock is default-deny: only the granted roots are reachable. Roots in
/// `deny_roots` that are not under any grant are therefore already denied. (v1
/// Landlock cannot carve a denied subtree OUT of a broader grant; a caller that
/// needs that must not grant the parent. The locked-down default grants nothing,
/// so the sensitive subtrees are denied.)
fn apply_landlock(spec: &CapsuleSpec) -> Result<LandlockOutcome, ContainError> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus, ABI,
    };

    // Handle the v1 access set, best-effort so an older kernel downgrades rather
    // than errors. v1 covers read/write/execute, which is what FS confinement for
    // an install hook / MCP server needs; net (v4) is intentionally NOT handled
    // here. Raw-socket denial is the seccomp layer's job.
    let abi = ABI::V1;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| ContainError::Landlock(format!("handle_access: {e}")))?
        .create()
        .map_err(|e| ContainError::Landlock(format!("create: {e}")))?;

    let read_access = AccessFs::from_read(abi);
    let write_access = AccessFs::from_all(abi);

    // Read roots: read access. Write roots imply read, so grant them the full set.
    for root in &spec.filesystem.read_roots {
        ruleset = add_path_rule(ruleset, root, read_access)?;
    }
    for root in &spec.filesystem.write_roots {
        ruleset = add_path_rule(ruleset, root, write_access)?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| ContainError::Landlock(format!("restrict_self: {e}")))?;

    // Map the kernel's enforcement status honestly. A PartiallyEnforced ruleset is
    // a best-effort downgrade (fewer access *types* enforced) but still confines
    // the granted roots in the deny direction; it is NOT collapsed into the same
    // value as FullyEnforced, so the caller can surface the difference.
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => LandlockOutcome::Fully,
        RulesetStatus::PartiallyEnforced => LandlockOutcome::Partially,
        RulesetStatus::NotEnforced => LandlockOutcome::NotEnforced,
    })
}

/// Add one path-beneath rule to the ruleset, ignoring only a path that is already
/// absent. Any other inspection/open failure is fatal: silently dropping an
/// existing temporary-HOME or runtime grant would make the reported filesystem
/// coverage inaccurate. A removal between the metadata check and `PathFd::new`
/// likewise fails closed.
fn add_path_rule<R>(
    ruleset: R,
    path: &Path,
    access: landlock::BitFlags<landlock::AccessFs>,
) -> Result<R, ContainError>
where
    R: landlock::RulesetCreatedAttr,
{
    use landlock::{PathBeneath, PathFd};

    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(ruleset),
        Err(error) => {
            return Err(ContainError::Landlock(format!(
                "inspect grant {}: {error}",
                path.display()
            )))
        }
    }
    let fd = PathFd::new(path).map_err(|error| {
        ContainError::Landlock(format!("open grant {}: {error}", path.display()))
    })?;
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map_err(|e| ContainError::Landlock(format!("add_rule {}: {e}", path.display())))
}

/// Build and apply the default-deny seccomp policy. Returns `true` when a filter
/// was installed (x86_64 only). On a non-x86_64 Linux arch the seccomp layer is
/// unavailable; the function returns `Ok(false)` and the caller reports
/// `network_raw_denied = false`.
///
/// The policy ALLOWS: basic process/memory syscalls, file I/O (read/write/open/
/// metadata/close/stdio), Landlock-confined directory creation, thread creation,
/// and fork/exec (the launcher must `execve` the target and an installer spawns
/// sub-processes). It grants **no** socket-creation syscalls, so the child cannot
/// open a raw outbound socket: the foundation of `network_raw_denied` for a
/// `DenyAll` capsule.
#[cfg(target_arch = "x86_64")]
struct SafeDescriptorControls;

/// Small, non-network process/runtime operations observed while starting a
/// dynamically linked POSIX shell and a child utility. Keep this separate from
/// the broad extrasafe capability sets so additions require an explicit review:
/// in particular, this deliberately excludes socket creation and process-group
/// operations (`setsid`, `setpgid`) that could weaken the supervisor boundary.
#[cfg(target_arch = "x86_64")]
struct PostExecRuntime;

#[cfg(target_arch = "x86_64")]
const SAFE_TERMINAL_IOCTL_REQUESTS: &[u64] = &[
    libc::TCGETS,
    libc::TIOCGWINSZ,
    libc::TIOCGPGRP,
    libc::FIONREAD,
];

#[cfg(target_arch = "x86_64")]
const SAFE_FCNTL_COMMANDS: &[u32] = &[
    libc::F_GETFD as u32,
    libc::F_SETFD as u32,
    libc::F_GETFL as u32,
    libc::F_DUPFD as u32,
    libc::F_DUPFD_CLOEXEC as u32,
];

#[cfg(target_arch = "x86_64")]
impl extrasafe::RuleSet for PostExecRuntime {
    fn simple_rules(&self) -> Vec<extrasafe::syscalls::Sysno> {
        use extrasafe::syscalls::Sysno;

        vec![
            // Required by the x86_64 dynamic loader and libc startup.
            Sysno::arch_prctl,
            Sysno::set_tid_address,
            // Loader access probes and harmless process-identity discovery.
            Sysno::access,
            Sysno::faccessat,
            Sysno::faccessat2,
            Sysno::getuid,
            Sysno::geteuid,
            Sysno::getgid,
            Sysno::getegid,
            Sysno::getppid,
            Sysno::getpgrp,
            Sysno::getrlimit,
            Sysno::sysinfo,
            // POSIX-shell redirection and in-script pipelines. Every inherited
            // descriptor was closed before this filter is installed, and newly
            // opened paths remain constrained by Landlock.
            Sysno::dup,
            Sysno::dup2,
            Sysno::dup3,
            Sysno::pipe,
            Sysno::pipe2,
            // Targets need first-use cache/config trees beneath their writable
            // roots. Landlock is already active before this filter and remains
            // the authority over *where* either syscall may create a directory.
            Sysno::mkdir,
            Sysno::mkdirat,
        ]
    }

    fn conditional_rules(
        &self,
    ) -> std::collections::HashMap<extrasafe::syscalls::Sysno, Vec<extrasafe::SeccompRule>> {
        use extrasafe::syscalls::Sysno;
        use extrasafe::{SeccompArgumentFilter, SeccompRule, SeccompilerComparator};

        // glibc queries this process's stack limit during startup. Do not grant
        // arbitrary prlimit64: a same-UID target could otherwise alter another
        // process's limits. pid=0 binds the call to self and new_limit=NULL makes
        // it read-only.
        let prlimit = SeccompRule::new(Sysno::prlimit64)
            .and_condition(SeccompArgumentFilter::new64(
                0,
                SeccompilerComparator::Eq,
                0,
            ))
            .and_condition(SeccompArgumentFilter::new64(
                2,
                SeccompilerComparator::Eq,
                0,
            ));
        // Bash queries only its own group while deciding whether job control is
        // available. Keep this read-only lookup self-scoped too.
        let getpgid = SeccompRule::new(Sysno::getpgid).and_condition(SeccompArgumentFilter::new64(
            0,
            SeccompilerComparator::Eq,
            0,
        ));
        // The forked target binds its lifetime to the contained guard before
        // TRACEME. This closes the window before PTRACE_O_EXITKILL is installed;
        // no other prctl option or death signal is granted.
        let parent_death_signal = SeccompRule::new(Sysno::prctl)
            .and_condition(SeccompArgumentFilter::new64(
                0,
                SeccompilerComparator::Eq,
                libc::PR_SET_PDEATHSIG as u64,
            ))
            .and_condition(SeccompArgumentFilter::new64(
                1,
                SeccompilerComparator::Eq,
                libc::SIGKILL as u64,
            ))
            .and_condition(SeccompArgumentFilter::new64(
                2,
                SeccompilerComparator::Eq,
                0,
            ))
            .and_condition(SeccompArgumentFilter::new64(
                3,
                SeccompilerComparator::Eq,
                0,
            ))
            .and_condition(SeccompArgumentFilter::new64(
                4,
                SeccompilerComparator::Eq,
                0,
            ));
        let mut rules: std::collections::HashMap<_, Vec<_>> = [
            (Sysno::prlimit64, vec![prlimit]),
            (Sysno::getpgid, vec![getpgid]),
            (Sysno::prctl, vec![parent_death_signal]),
        ]
        .into_iter()
        .collect();
        // The contained guard uses ptrace only as a kernel-authenticated exec
        // boundary. Bind every granted request to its exact argument contract:
        // the child may declare only TRACEME with otherwise-null arguments; the
        // guard may operate only on a positive child pid, may install exactly
        // TRACEEXEC|EXITKILL, may resume/detach without injecting a signal, and
        // may terminate only its already-traced positive-pid child if the proof
        // protocol fails before EXITKILL is known armed.
        // No attach, seize, peek/poke, register, arbitrary option, arbitrary
        // signal, or self/negative-pid request is granted.
        let null_arg = |index| SeccompArgumentFilter::new64(index, SeccompilerComparator::Eq, 0);
        let positive_pid = || SeccompArgumentFilter::new64(1, SeccompilerComparator::Gt, 0);
        // seccomp compares the raw unsigned register value. Without this upper
        // bound, a negative pid_t is sign-extended to a large u64 and would pass
        // the `Gt 0` condition.
        let nonnegative_pid_t =
            || SeccompArgumentFilter::new64(1, SeccompilerComparator::Le, i32::MAX as u64);
        let ptrace_rules = rules.entry(Sysno::ptrace).or_default();
        ptrace_rules.push(
            SeccompRule::new(Sysno::ptrace)
                .and_condition(SeccompArgumentFilter::new64(
                    0,
                    SeccompilerComparator::Eq,
                    libc::PTRACE_TRACEME as u64,
                ))
                .and_condition(null_arg(1))
                .and_condition(null_arg(2))
                .and_condition(null_arg(3)),
        );
        ptrace_rules.push(
            SeccompRule::new(Sysno::ptrace)
                .and_condition(SeccompArgumentFilter::new64(
                    0,
                    SeccompilerComparator::Eq,
                    libc::PTRACE_SETOPTIONS as u64,
                ))
                .and_condition(positive_pid())
                .and_condition(nonnegative_pid_t())
                .and_condition(null_arg(2))
                .and_condition(SeccompArgumentFilter::new64(
                    3,
                    SeccompilerComparator::Eq,
                    (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as u64,
                )),
        );
        for request in [libc::PTRACE_CONT, libc::PTRACE_DETACH, libc::PTRACE_KILL] {
            ptrace_rules.push(
                SeccompRule::new(Sysno::ptrace)
                    .and_condition(SeccompArgumentFilter::new64(
                        0,
                        SeccompilerComparator::Eq,
                        request as u64,
                    ))
                    .and_condition(positive_pid())
                    .and_condition(nonnegative_pid_t())
                    .and_condition(null_arg(2))
                    .and_condition(null_arg(3)),
            );
        }
        rules
    }

    fn name(&self) -> &'static str {
        "PostExecRuntime"
    }
}

#[cfg(target_arch = "x86_64")]
impl extrasafe::RuleSet for SafeDescriptorControls {
    fn simple_rules(&self) -> Vec<extrasafe::syscalls::Sysno> {
        Vec::new()
    }

    fn conditional_rules(
        &self,
    ) -> std::collections::HashMap<extrasafe::syscalls::Sysno, Vec<extrasafe::SeccompRule>> {
        use extrasafe::syscalls::Sysno;
        use extrasafe::{SeccompArgumentFilter, SeccompRule, SeccompilerComparator};

        let mut rules = std::collections::HashMap::new();
        for request in SAFE_TERMINAL_IOCTL_REQUESTS {
            rules.entry(Sysno::ioctl).or_insert_with(Vec::new).push(
                SeccompRule::new(Sysno::ioctl)
                    .and_condition(SeccompArgumentFilter::new32(
                        0,
                        SeccompilerComparator::Le,
                        libc::STDERR_FILENO as u32,
                    ))
                    .and_condition(SeccompArgumentFilter::new64(
                        1,
                        SeccompilerComparator::Eq,
                        *request,
                    )),
            );
        }
        for command in SAFE_FCNTL_COMMANDS {
            rules.entry(Sysno::fcntl).or_insert_with(Vec::new).push(
                SeccompRule::new(Sysno::fcntl).and_condition(SeccompArgumentFilter::new32(
                    1,
                    SeccompilerComparator::Eq,
                    *command,
                )),
            );
        }
        rules
    }

    fn name(&self) -> &'static str {
        "SafeDescriptorControls"
    }
}

#[cfg(target_arch = "x86_64")]
fn apply_seccomp() -> Result<bool, ContainError> {
    use extrasafe::builtins::danger_zone::{ForkAndExec, Threads};
    use extrasafe::builtins::{BasicCapabilities, SystemIO};
    use extrasafe::SafetyContext;

    SafetyContext::new()
        .enable(BasicCapabilities)
        .and_then(|ctx| {
            ctx.enable(
                SystemIO::nothing()
                    .allow_read()
                    .allow_write()
                    .allow_open()
                    .yes_really()
                    .allow_metadata()
                    .allow_close(),
            )
        })
        // Never use SystemIO::allow_ioctl(): it also grants unrestricted ioctl
        // and fcntl. Read-only terminal discovery stays limited to standard
        // streams. Only a reviewed set of descriptor-local fcntl commands is allowed
        // on descriptors the process already holds; TIOCSTI, TIOCLINUX,
        // ownership changes, and arbitrary device controls remain denied with
        // EPERM by the default action.
        .and_then(|ctx| ctx.enable(SafeDescriptorControls))
        .and_then(|ctx| ctx.enable(PostExecRuntime))
        .and_then(|ctx| ctx.enable(Threads::nothing().allow_create()))
        .and_then(|ctx| ctx.enable(ForkAndExec))
        .map_err(|e| ContainError::Seccomp(e.to_string()))?
        .apply_to_current_thread()
        .map_err(|e| ContainError::Seccomp(e.to_string()))?;
    Ok(true)
}

/// Non-x86_64 Linux: the `extrasafe`/`seccompiler` stack only supports
/// `linux-x86_64`, so no seccomp filter can be installed. The rest of the
/// containment (rlimits, no-new-privs, Landlock, env) still applies; the caller
/// reports `network_raw_denied = false` and an enforcing surface that requires it
/// will fail closed.
#[cfg(not(target_arch = "x86_64"))]
fn apply_seccomp() -> Result<bool, ContainError> {
    Ok(false)
}

/// Scrub the child's environment: compute the surviving variable names from the
/// policy, remove everything else, then (when `temporary_home`) point
/// HOME/TMPDIR/XDG_* at `temp_home`. Pure libc/std memory work; safe to run after
/// the seccomp filter (no special syscalls).
fn apply_env(policy: &EnvironmentPolicy, temp_home: Option<&Path>) {
    // The names currently present in this process's environment, as raw `OsString`
    // so a name that is not valid UTF-8 is still considered for removal. We only
    // need the UTF-8-decodable names to compute the survivor set (the allow-list is
    // UTF-8), but the REMOVE pass must iterate every name, including non-UTF-8 ones.
    let present: Vec<OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    let utf8_present: Vec<String> = present
        .iter()
        .filter_map(|k| k.to_str().map(str::to_owned))
        .collect();
    let survivors = env_survivors(policy, &utf8_present);

    // Remove every variable not in the survivor set, operating on the raw name so a
    // non-UTF-8-named variable is removed too. A non-UTF-8 name can never match a
    // UTF-8 allow-list entry, so `env_name_survives` is false for it and it is
    // dropped (the fail-closed direction: deny-by-default with no UTF-8 leak hole).
    for name in &present {
        if !env_name_survives(name, &survivors) {
            std::env::remove_var(name);
        }
    }

    if policy.temporary_home {
        if let Some(home) = temp_home {
            let home: OsString = home.as_os_str().to_owned();
            std::env::set_var("HOME", &home);
            std::env::set_var("TMPDIR", &home);
            std::env::set_var("XDG_CONFIG_HOME", PathBuf::from(&home).join(".config"));
            std::env::set_var("XDG_CACHE_HOME", PathBuf::from(&home).join(".cache"));
            std::env::set_var("XDG_DATA_HOME", PathBuf::from(&home).join(".local/share"));
            std::env::set_var("XDG_STATE_HOME", PathBuf::from(&home).join(".local/state"));
        }
    }
}

/// The set of environment-variable names that survive into the child, as a pure
/// function of the policy and the present names. A thin wrapper over
/// [`EnvironmentPolicy::surviving_vars`] kept here so the env step and its tests
/// share one definition (and so HOME/TMPDIR, which are re-set afterward, are
/// allowed to survive when `temporary_home` will overwrite them anyway).
pub fn env_survivors(policy: &EnvironmentPolicy, present: &[String]) -> BTreeSet<String> {
    policy.surviving_vars(present.iter().map(|s| s.as_str()))
}

/// Whether the environment variable named `name` (a raw `OsStr`, so it may not be
/// valid UTF-8) should survive into the contained child, given the UTF-8 survivor
/// set. A name keeps iff it decodes to UTF-8 AND is in `survivors`; a non-UTF-8
/// name can never match a (UTF-8) allow-list entry, so it is dropped. Pure and
/// unit-testable, and the basis for the fail-closed removal pass in [`apply_env`]:
/// removing a non-UTF-8-named variable is correct because deny-by-default means
/// anything not explicitly allowed (which a non-UTF-8 name can never be) is scrubbed.
fn env_name_survives(name: &std::ffi::OsStr, survivors: &BTreeSet<String>) -> bool {
    match name.to_str() {
        Some(s) => survivors.contains(s),
        // Non-UTF-8 name: cannot be in a UTF-8 allow-list, so never survives.
        None => false,
    }
}

/// Build the argv for `execve`: `prog` followed by `args`, as NUL-terminated
/// C strings. Returns an error if any component contains an interior NUL (which
/// cannot be passed to `execve`). Pure, so it is unit-testable on any platform.
pub fn exec_cstrings(prog: &OsStr, args: &[OsString]) -> Result<Vec<CString>, ContainError> {
    let mut out = Vec::with_capacity(args.len() + 1);
    out.push(
        CString::new(prog.as_bytes())
            .map_err(|_| ContainError::Unsupported("program path contains NUL".to_string()))?,
    );
    for a in args {
        out.push(
            CString::new(a.as_bytes())
                .map_err(|_| ContainError::Unsupported("argument contains NUL".to_string()))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{NetworkPolicy, ResourceLimits};

    #[test]
    fn backend_id_is_stable() {
        assert_eq!(LandlockSeccompCapsule.backend_id(), "landlock-seccomp");
        assert_eq!(BACKEND_ID, "landlock-seccomp");
    }

    #[test]
    fn derive_coverage_denyall_with_full_backend() {
        // Landlock usable + seccomp supported + a locked-down spec -> FS
        // enforced, raw-net denied, NEVER egress, and env + handles set. The
        // aggregate resource bit stays false because locked_down also requests
        // output and wall-clock limits that this launcher does not enforce.
        let spec = CapsuleSpec::locked_down();
        let fs = LandlockProbe {
            usable: true,
            abi: Some(4),
        };
        let cov = derive_coverage(&spec, &fs, true);
        assert!(cov.fs_read_enforced);
        assert!(cov.fs_write_enforced);
        assert!(cov.exec_limited);
        assert!(cov.network_raw_denied);
        // The single most important honesty property of E2's Linux backend.
        assert!(!cov.domain_proxy_enforced);
        assert!(!cov.resource_limits_enforced);
        assert!(cov.env_isolated);
        assert!(cov.handles_isolated);
        // And the coverage is internally coherent (no egress claim w/o raw-deny).
        assert!(cov.egress_claim_is_coherent());
        assert!(cov.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn derive_coverage_without_landlock_does_not_claim_fs() {
        // No Landlock on the kernel -> FS not enforced, even though seccomp is.
        let spec = CapsuleSpec::locked_down();
        let fs = LandlockProbe::default(); // usable = false
        let cov = derive_coverage(&spec, &fs, true);
        assert!(!cov.fs_read_enforced);
        assert!(!cov.fs_write_enforced);
        assert!(cov.network_raw_denied);
    }

    #[test]
    fn derive_coverage_without_seccomp_does_not_claim_raw_net_deny() {
        // A non-x86_64 Linux arch can apply Landlock but not seccomp -> raw sockets
        // are NOT denied, so a DenyAll spec is degraded against its requirement.
        let spec = CapsuleSpec::locked_down();
        let fs = LandlockProbe {
            usable: true,
            abi: Some(2),
        };
        let cov = derive_coverage(&spec, &fs, false);
        assert!(!cov.network_raw_denied);
        // The locked-down spec requires raw-net-deny, so this coverage is degraded.
        assert!(cov.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn derive_coverage_resource_flag_tracks_rlimitable_dimensions() {
        // A spec with NO rlimit-able dimension does not claim resource limits.
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits::default(); // nothing set
        let fs = LandlockProbe {
            usable: true,
            abi: Some(1),
        };
        let cov = derive_coverage(&spec, &fs, true);
        assert!(!cov.resource_limits_enforced);

        // Only a wall-clock / output cap (NOT rlimit-able) -> still not claimed.
        spec.resources = ResourceLimits {
            wall_clock_seconds: Some(60),
            max_output_bytes: Some(1024),
            ..ResourceLimits::default()
        };
        let cov2 = derive_coverage(&spec, &fs, true);
        assert!(!cov2.resource_limits_enforced);

        // A CPU limit IS rlimit-able -> claimed.
        spec.resources = ResourceLimits {
            cpu_seconds: Some(30),
            ..ResourceLimits::default()
        };
        let cov3 = derive_coverage(&spec, &fs, true);
        assert!(cov3.resource_limits_enforced);
    }

    #[test]
    fn mixed_cpu_and_wall_clock_does_not_claim_all_resource_limits() {
        let fs = LandlockProbe {
            usable: true,
            abi: Some(4),
        };
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits {
            cpu_seconds: Some(30),
            wall_clock_seconds: Some(60),
            ..ResourceLimits::default()
        };

        let coverage = derive_coverage(&spec, &fs, true);
        assert!(
            !coverage.resource_limits_enforced,
            "a supported CPU rlimit must not hide the unenforced wall-clock limit"
        );
        assert!(coverage.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn linux_supported_only_resource_limits_are_reported_enforced() {
        let fs = LandlockProbe {
            usable: true,
            abi: Some(4),
        };
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits {
            cpu_seconds: Some(30),
            memory_bytes: Some(512 * 1024 * 1024),
            max_processes: Some(32),
            max_open_files: Some(64),
            ..ResourceLimits::default()
        };

        let coverage = derive_coverage(&spec, &fs, true);
        assert!(coverage.resource_limits_enforced);
        assert!(!coverage.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn seccomp_supported_matches_arch() {
        assert_eq!(seccomp_supported(), cfg!(target_arch = "x86_64"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn descriptor_control_policy_never_grants_unrestricted_or_injecting_ioctl() {
        use extrasafe::syscalls::Sysno;
        use extrasafe::RuleSet as _;

        assert!(SafeDescriptorControls.simple_rules().is_empty());
        let rules = SafeDescriptorControls.conditional_rules();
        let ioctl_rules = rules.get(&Sysno::ioctl).expect("conditional ioctl rules");
        assert_eq!(ioctl_rules.len(), SAFE_TERMINAL_IOCTL_REQUESTS.len());
        assert!(!SAFE_TERMINAL_IOCTL_REQUESTS.contains(&{ libc::TIOCSTI }));
        assert!(!SAFE_TERMINAL_IOCTL_REQUESTS.contains(&{ libc::TIOCLINUX }));
        for rule in ioctl_rules {
            assert_eq!(rule.argument_filters.len(), 2);
            assert!(rule
                .argument_filters
                .iter()
                .any(|filter| filter.arg_idx == 0 && filter.value == libc::STDERR_FILENO as u64));
            let request = rule
                .argument_filters
                .iter()
                .find(|filter| filter.arg_idx == 1)
                .expect("ioctl request filter")
                .value;
            assert!(SAFE_TERMINAL_IOCTL_REQUESTS.contains(&request));
        }

        let fcntl_rules = rules.get(&Sysno::fcntl).expect("conditional fcntl rules");
        assert_eq!(fcntl_rules.len(), SAFE_FCNTL_COMMANDS.len());
        for rule in fcntl_rules {
            assert_eq!(rule.argument_filters.len(), 1);
            let command = rule
                .argument_filters
                .iter()
                .find(|filter| filter.arg_idx == 1)
                .expect("fcntl command filter")
                .value as u32;
            assert!(SAFE_FCNTL_COMMANDS.contains(&command));
        }
        assert!(!SAFE_FCNTL_COMMANDS.contains(&(libc::F_SETOWN as u32)));
        assert!(!SAFE_FCNTL_COMMANDS.contains(&(libc::F_SETLK as u32)));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn post_exec_runtime_allows_landlock_confined_mkdir_and_excludes_escape_syscalls() {
        use extrasafe::syscalls::Sysno;
        use extrasafe::RuleSet as _;

        let rules = PostExecRuntime.simple_rules();
        assert!(rules.contains(&Sysno::mkdir));
        assert!(rules.contains(&Sysno::mkdirat));
        for denied in [
            Sysno::socket,
            Sysno::socketpair,
            Sysno::connect,
            Sysno::setsid,
            Sysno::setpgid,
            Sysno::kill,
            Sysno::tkill,
            Sysno::tgkill,
            Sysno::rt_sigqueueinfo,
            Sysno::rt_tgsigqueueinfo,
            Sysno::pidfd_send_signal,
        ] {
            assert!(
                !rules.contains(&denied),
                "post-exec runtime must not grant {denied:?}"
            );
        }
        let conditional = PostExecRuntime.conditional_rules();
        for denied in [
            Sysno::socket,
            Sysno::socketpair,
            Sysno::connect,
            Sysno::setsid,
            Sysno::setpgid,
            Sysno::kill,
            Sysno::tkill,
            Sysno::tgkill,
            Sysno::rt_sigqueueinfo,
            Sysno::rt_tgsigqueueinfo,
            Sysno::pidfd_send_signal,
        ] {
            assert!(
                !conditional.contains_key(&denied),
                "conditional post-exec runtime must not grant {denied:?}"
            );
        }
        let prlimit = conditional
            .get(&Sysno::prlimit64)
            .expect("self-query-only prlimit64 rule");
        assert_eq!(prlimit.len(), 1);
        assert_eq!(prlimit[0].argument_filters.len(), 2);
        assert!(prlimit[0]
            .argument_filters
            .iter()
            .any(|filter| filter.arg_idx == 0 && filter.value == 0));
        assert!(prlimit[0]
            .argument_filters
            .iter()
            .any(|filter| filter.arg_idx == 2 && filter.value == 0));
        let getpgid = conditional
            .get(&Sysno::getpgid)
            .expect("self-query-only getpgid rule");
        assert_eq!(getpgid.len(), 1);
        assert_eq!(getpgid[0].argument_filters.len(), 1);
        assert_eq!(getpgid[0].argument_filters[0].arg_idx, 0);
        assert_eq!(getpgid[0].argument_filters[0].value, 0);

        let parent_death_signal = conditional
            .get(&Sysno::prctl)
            .expect("exact guard parent-death prctl rule");
        assert_eq!(parent_death_signal.len(), 1);
        assert_eq!(parent_death_signal[0].argument_filters.len(), 5);
        for (index, value) in [libc::PR_SET_PDEATHSIG as u64, libc::SIGKILL as u64, 0, 0, 0]
            .into_iter()
            .enumerate()
        {
            let filter = parent_death_signal[0]
                .argument_filters
                .iter()
                .find(|filter| usize::from(filter.arg_idx) == index)
                .unwrap_or_else(|| panic!("missing prctl argument {index}"));
            assert_eq!(filter.value, value);
            assert!(filter.is_64bit);
        }

        let ptrace = conditional
            .get(&Sysno::ptrace)
            .expect("exact target-exec ptrace rules");
        assert_eq!(
            ptrace.len(),
            5,
            "only the five exec-proof and traced-cleanup requests are granted"
        );
        let expected_requests = [
            libc::PTRACE_TRACEME as u64,
            libc::PTRACE_SETOPTIONS as u64,
            libc::PTRACE_CONT as u64,
            libc::PTRACE_DETACH as u64,
            libc::PTRACE_KILL as u64,
        ];
        for request in expected_requests {
            let rule = ptrace
                .iter()
                .find(|rule| {
                    rule.argument_filters
                        .iter()
                        .any(|filter| filter.arg_idx == 0 && filter.value == request)
                })
                .unwrap_or_else(|| panic!("missing ptrace request {request}"));
            let expected_filter_count = if request == libc::PTRACE_TRACEME as u64 {
                4
            } else {
                5
            };
            assert_eq!(rule.argument_filters.len(), expected_filter_count);
            assert_eq!(
                rule.argument_filters
                    .iter()
                    .filter(|filter| filter.arg_idx == 0)
                    .count(),
                1
            );
            assert_eq!(
                rule.argument_filters
                    .iter()
                    .filter(|filter| filter.arg_idx == 1)
                    .count(),
                if request == libc::PTRACE_TRACEME as u64 {
                    1
                } else {
                    2
                },
                "guard requests must bind pid to 1..=i32::MAX"
            );
            for index in 2..=3 {
                assert_eq!(
                    rule.argument_filters
                        .iter()
                        .filter(|filter| filter.arg_idx == index)
                        .count(),
                    1,
                    "ptrace argument {index} must be constrained exactly once"
                );
            }
            assert!(rule.argument_filters.iter().all(|filter| filter.is_64bit));
            assert_eq!(
                rule.argument_filters
                    .iter()
                    .find(|filter| filter.arg_idx == 2)
                    .expect("ptrace address filter")
                    .value,
                0,
                "ptrace address must always be null"
            );
            if request != libc::PTRACE_TRACEME as u64 {
                let pid_values: Vec<u64> = rule
                    .argument_filters
                    .iter()
                    .filter(|filter| filter.arg_idx == 1)
                    .map(|filter| filter.value)
                    .collect();
                assert!(pid_values.contains(&0));
                assert!(pid_values.contains(&(i32::MAX as u64)));
            }
        }
        let traceme = ptrace
            .iter()
            .find(|rule| rule.argument_filters[0].value == libc::PTRACE_TRACEME as u64)
            .expect("TRACEME rule");
        assert!(traceme
            .argument_filters
            .iter()
            .filter(|filter| filter.arg_idx > 0)
            .all(|filter| filter.value == 0));
        let setoptions = ptrace
            .iter()
            .find(|rule| rule.argument_filters[0].value == libc::PTRACE_SETOPTIONS as u64)
            .expect("SETOPTIONS rule");
        assert_eq!(
            setoptions
                .argument_filters
                .iter()
                .find(|filter| filter.arg_idx == 3)
                .expect("SETOPTIONS data filter")
                .value,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as u64
        );
        for request in [
            libc::PTRACE_CONT as u64,
            libc::PTRACE_DETACH as u64,
            libc::PTRACE_KILL as u64,
        ] {
            let rule = ptrace
                .iter()
                .find(|rule| rule.argument_filters[0].value == request)
                .expect("resume/detach/kill rule");
            assert_eq!(
                rule.argument_filters
                    .iter()
                    .find(|filter| filter.arg_idx == 3)
                    .expect("signal filter")
                    .value,
                0,
                "resume/detach/kill may not carry arbitrary data"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn seccomp_guard_death_subprocess() {
        use std::io::BufRead as _;
        use std::os::unix::ffi::OsStrExt as _;

        const MODE: &str = "TIRITH_SECCOMP_GUARD_DEATH_MODE";
        const MARKER: &str = "TIRITH_SECCOMP_GUARD_DEATH_MARKER";
        match std::env::var(MODE).ok().as_deref() {
            None => (),
            Some("guard") => {
                let marker = std::path::PathBuf::from(
                    std::env::var_os(MARKER).expect("guard-death marker path"),
                );
                let marker_c = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
                let mut lifetime = [0i32; 2];
                assert_eq!(
                    unsafe { libc::pipe2(lifetime.as_mut_ptr(), libc::O_CLOEXEC) },
                    0
                );
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    0
                );
                assert!(apply_seccomp().expect("apply production seccomp in guard helper"));
                let guard_pid = unsafe { libc::getpid() };
                let target_pid = unsafe { libc::fork() };
                assert!(target_pid >= 0);
                if target_pid == 0 {
                    unsafe {
                        libc::close(lifetime[1]);
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
                            || libc::getppid() != guard_pid
                        {
                            libc::_exit(71);
                        }
                        let mut receipt = [0u8; 64];
                        let prefix = b"TARGET_PID:";
                        receipt[..prefix.len()].copy_from_slice(prefix);
                        let mut digits = [0u8; 20];
                        let mut digit_count = 0usize;
                        let mut pid = libc::getpid() as u32;
                        loop {
                            digits[digit_count] = b'0' + (pid % 10) as u8;
                            digit_count += 1;
                            pid /= 10;
                            if pid == 0 {
                                break;
                            }
                        }
                        let mut length = prefix.len();
                        while digit_count > 0 {
                            digit_count -= 1;
                            receipt[length] = digits[digit_count];
                            length += 1;
                        }
                        receipt[length] = b'\n';
                        length += 1;
                        if libc::write(
                            libc::STDOUT_FILENO,
                            receipt.as_ptr().cast::<libc::c_void>(),
                            length,
                        ) != length as isize
                        {
                            libc::_exit(72);
                        }
                        let mut byte = 0u8;
                        // The guard owns the only writer. Parent death closes it;
                        // without PDEATHSIG this read reaches EOF and the marker
                        // proves uncommitted code survived.
                        let _ = libc::read(
                            lifetime[0],
                            (&mut byte as *mut u8).cast::<libc::c_void>(),
                            1,
                        );
                        // A dying parent closes its descriptors BEFORE it sends
                        // the death signal (exit_files runs ahead of
                        // exit_notify), so on another CPU this EOF can win the
                        // race against the pending SIGKILL and the target would
                        // exit normally, flaking the controller's WIFSIGNALED
                        // proof. Grant the signal a bounded grace window: when
                        // PDEATHSIG works the process dies inside this loop,
                        // and only a genuine delivery failure reaches the
                        // marker write.
                        let mut grace = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 40_000_000,
                        };
                        for _ in 0..25 {
                            let _ = libc::nanosleep(&grace, &mut grace as *mut libc::timespec);
                            grace.tv_sec = 0;
                            grace.tv_nsec = 40_000_000;
                        }
                        let fd = libc::open(
                            marker_c.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                            0o600,
                        );
                        if fd >= 0 {
                            let marker_byte = *b"x";
                            let _ = libc::write(fd, marker_byte.as_ptr().cast::<libc::c_void>(), 1);
                            libc::close(fd);
                        }
                        libc::_exit(73);
                    }
                }
                unsafe {
                    libc::close(lifetime[0]);
                }
                let mut status = 0;
                let _ = unsafe { libc::waitpid(target_pid, &mut status, 0) };
            }
            Some("controller") => {
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
                    0
                );
                let executable = std::env::current_exe().expect("current test executable");
                let mut guard = std::process::Command::new(executable)
                    .args(["seccomp_guard_death_subprocess", "--nocapture"])
                    .env(MODE, "guard")
                    .env(MARKER, std::env::var_os(MARKER).expect("controller marker"))
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("spawn seccomp guard helper");
                let mut output = std::io::BufReader::new(guard.stdout.take().unwrap());
                let target_pid = loop {
                    let mut line = String::new();
                    assert_ne!(
                        output.read_line(&mut line).unwrap(),
                        0,
                        "guard exited early"
                    );
                    if let Some(raw) = line.trim().strip_prefix("TARGET_PID:") {
                        break raw.parse::<libc::pid_t>().expect("target pid receipt");
                    }
                };
                assert_eq!(
                    unsafe { libc::kill(guard.id() as libc::pid_t, libc::SIGKILL) },
                    0
                );
                let guard_status = guard.wait().expect("reap killed guard");
                assert!(!guard_status.success());

                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                let mut target_status = 0;
                loop {
                    let waited =
                        unsafe { libc::waitpid(target_pid, &mut target_status, libc::WNOHANG) };
                    if waited == target_pid {
                        break;
                    }
                    assert_eq!(
                        waited,
                        0,
                        "wait adopted target: {}",
                        std::io::Error::last_os_error()
                    );
                    assert!(
                        std::time::Instant::now() < deadline,
                        "PDEATHSIG target survived"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                assert!(libc::WIFSIGNALED(target_status));
                assert_eq!(libc::WTERMSIG(target_status), libc::SIGKILL);
                assert_ne!(unsafe { libc::kill(target_pid, 0) }, 0);
            }
            Some(other) => panic!("unknown guard-death helper mode {other}"),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn production_seccomp_parent_death_signal_kills_and_reaps_target() {
        const MODE: &str = "TIRITH_SECCOMP_GUARD_DEATH_MODE";
        const MARKER: &str = "TIRITH_SECCOMP_GUARD_DEATH_MARKER";
        let marker_dir = tempfile::tempdir().expect("guard-death marker directory");
        let marker = marker_dir.path().join("target-survived");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["seccomp_guard_death_subprocess", "--nocapture"])
            .env(MODE, "controller")
            .env(MARKER, &marker)
            .output()
            .expect("run isolated guard-death controller");
        assert!(
            output.status.success(),
            "guard-death controller failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !marker.exists(),
            "target survived its seccomp-confined guard"
        );
    }

    #[test]
    fn apply_containment_refuses_allowlisted_domains() {
        // E2 has no verified raw-socket-blocking egress backend, so an allow-list
        // spec must be refused BEFORE any process state is changed (it is the
        // first thing apply_containment checks).
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let err = apply_containment(&spec, None).expect_err("must refuse allow-listed egress");
        match err {
            ContainError::Unsupported(m) => assert!(m.contains("raw-socket")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn apply_containment_refuses_missing_parent_temp_home_before_mutation() {
        let spec = CapsuleSpec::locked_down();
        let err = apply_containment(&spec, None).expect_err("missing temp HOME must fail closed");
        match err {
            ContainError::Unsupported(message) => {
                assert!(message.contains("prevalidated parent-owned"))
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn env_survivors_strip_sensitive_and_keep_allowed() {
        let policy = EnvironmentPolicy {
            inherit: false,
            allow: vec![
                "PATH".to_string(),
                "LANG".to_string(),
                "GITHUB_TOKEN".to_string(),
            ],
            deny_sensitive: true,
            temporary_home: true,
        };
        let present = vec![
            "PATH".to_string(),
            "LANG".to_string(),
            "GITHUB_TOKEN".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "HOME".to_string(),
        ];
        let survivors = env_survivors(&policy, &present);
        assert!(survivors.contains("PATH"));
        assert!(survivors.contains("LANG"));
        // Sensitive names never survive, even if allow-listed or present.
        assert!(!survivors.contains("GITHUB_TOKEN"));
        assert!(!survivors.contains("AWS_SECRET_ACCESS_KEY"));
        // Not allow-listed and not inheriting -> dropped.
        assert!(!survivors.contains("HOME"));
    }

    #[test]
    fn env_name_survives_keeps_allowed_utf8_drops_others() {
        // IM6: the keep/remove predicate the scrub pass uses. A UTF-8 name keeps iff
        // it is in the survivor set; anything else is dropped (fail-closed).
        let survivors: BTreeSet<String> = ["PATH".to_string(), "LANG".to_string()]
            .into_iter()
            .collect();
        assert!(env_name_survives(std::ffi::OsStr::new("PATH"), &survivors));
        assert!(!env_name_survives(
            std::ffi::OsStr::new("AWS_SECRET_ACCESS_KEY"),
            &survivors
        ));
        // An empty survivor set drops everything.
        assert!(!env_name_survives(
            std::ffi::OsStr::new("PATH"),
            &BTreeSet::new()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn env_name_survives_drops_non_utf8_name() {
        // IM6 (the actual leak): a variable whose NAME is not valid UTF-8 must be
        // dropped, never silently kept. It cannot decode, so it cannot be in a UTF-8
        // allow-list; `env_name_survives` returns false even if the allow-list is
        // non-empty. Before the fix the scrub pass iterated only the UTF-8-decodable
        // names, so such a variable survived into the deny-by-default child.
        use std::os::unix::ffi::OsStrExt;
        // 0xFF is never valid UTF-8.
        let bad = std::ffi::OsStr::from_bytes(b"BAD\xFFNAME");
        assert!(bad.to_str().is_none(), "test name must be non-UTF-8");
        let survivors: BTreeSet<String> = ["PATH".to_string(), "BAD\u{FFFD}NAME".to_string()]
            .into_iter()
            .collect();
        assert!(
            !env_name_survives(bad, &survivors),
            "a non-UTF-8-named var must never survive (no UTF-8 allow-list can name it)"
        );
    }

    #[test]
    fn exec_cstrings_builds_argv() {
        let v = exec_cstrings(
            OsStr::new("/usr/bin/python3"),
            &[OsString::from("-m"), OsString::from("pip")],
        )
        .unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].to_str().unwrap(), "/usr/bin/python3");
        assert_eq!(v[2].to_str().unwrap(), "pip");
    }

    #[test]
    fn exec_cstrings_rejects_interior_nul() {
        let err = exec_cstrings(OsStr::new("/bin/sh"), &[OsString::from("a\0b")])
            .expect_err("NUL must error");
        assert!(matches!(err, ContainError::Unsupported(_)));
    }

    #[test]
    fn exec_cstrings_preserves_non_utf8_argument_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let raw = b"raw-\xff-argument".to_vec();
        let v = exec_cstrings(OsStr::new("/bin/echo"), &[OsString::from_vec(raw.clone())])
            .expect("non-UTF8 argv is valid on Unix");
        assert_eq!(v[1].as_bytes(), raw);
    }

    #[test]
    fn landlock_probe_does_not_panic() {
        // On the CI Linux runner Landlock may or may not be available; either way
        // the probe returns without panicking and never claims usable with abi None.
        let p = landlock_probe();
        if p.usable {
            assert!(p.abi.is_some());
        }
    }

    #[test]
    fn landlock_outcome_fs_confinement_is_honest() {
        // I6: a PartiallyEnforced ruleset still confines the granted roots (default-
        // deny holds; a partial downgrade narrows access, never widens), so it
        // reports fs_confined = true alongside FullyEnforced. Only NotEnforced
        // leaves the FS unconfined. The point is the two enforced states are kept
        // DISTINCT (so the partial case can be surfaced) without flipping a normal
        // partial result to degraded.
        assert!(LandlockOutcome::Fully.fs_confined());
        assert!(LandlockOutcome::Partially.fs_confined());
        assert!(!LandlockOutcome::NotEnforced.fs_confined());
        // The variants are genuinely distinct (not collapsed to a bool), so a future
        // reader can tell full from partial.
        assert_ne!(LandlockOutcome::Fully, LandlockOutcome::Partially);
    }
}
