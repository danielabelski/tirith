//! `tirith fix` — interactive presenter over
//! `tirith_core::safe_command::suggest_verified`.
//!
//! Thin shim: tokenize → `engine::analyze` → verified suggestion → present.
//! Detection and final-command re-analysis live in `tirith-core`; this module is
//! presentation + one-keystroke acceptance only. Never invents a rewrite — a
//! finding whose `safe_command` is `None` is rendered as honest guidance from
//! its `remediation` field.
//!
//! ## Exit codes (deliberately distinct from `tirith check`)
//!
//! | code | meaning                                                                                  |
//! |------|------------------------------------------------------------------------------------------|
//! | 0    | no fix needed (verdict was Allow) OR user accepted a rewrite                             |
//! | 1    | findings exist but no mechanical rewrite is available                                    |
//! | 2    | user rejected, JSON write failed, stdin/stderr is not a TTY, OR --non-interactive run    |
//! |      | with rewrites present (the JSON IS the deliverable, but it can't be auto-applied)        |
//!
//! `check` uses 0/1/2/3 (allow/block/warn/warn-ack), tied to *verdict
//! severity*; `fix`'s codes are tied to *whether a rewrite was applied*. The two
//! are deliberately different surfaces (documented in `main.rs`'s after-help).
//!
//! ## TTY gating
//!
//! Interactive mode requires BOTH `stdin` and `stderr` to be a TTY. Stdout is
//! reserved for the chosen `safe_command` so users can wrap the call with
//! `$(tirith fix …)` / `eval "$(tirith fix …)"`. A `--non-interactive` flag or a
//! non-TTY stdin/stderr pair forces JSON-emit-and-exit behavior.
//!
//! ## JSON shape (`--json` / `--non-interactive`)
//!
//! Two shapes, distinguished by whether the verdict had findings:
//!
//! - **No findings** (verdict was Allow) → object envelope:
//!   ```text
//!   { "applied": false, "reason": "no_findings", "verdict": "allow",
//!     "command": "<original>" }
//!   ```
//! - **Findings present** → plain JSON array of `SafeSuggestion`:
//!   ```text
//!   [ { "rule_id": "...", "safe_command": "<verified Allow command>",
//!       "rationale": "...", "remediation": "..." }, ... ]
//!   ```
//!   `safe_command` is omitted when a transform is guidance-only.
//!
//! The array shape is the M6 acceptance criterion; the envelope is the honest
//! negative case so a parser doesn't read an empty `[]` as "nothing was wrong".

use std::io::{self, BufRead, Write};

use serde::Serialize;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::safe_command::{self, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

/// Public entry point for the `tirith fix` subcommand.
///
/// `command_parts` are space-joined (mirroring `tirith check`). `shell` accepts
/// the same tokens as `tirith check --shell`; unknown values fall back to
/// `ShellType::Posix` with a stderr warning. `non_interactive`/`json` force
/// JSON-emit behavior even on a TTY. Returns the exit code per the module table.
pub fn run(command_parts: &[String], shell: &str, non_interactive: bool, json: bool) -> i32 {
    // Empty command is a no-op (mirrors `tirith check`).
    let cmd = command_parts.join(" ");
    if cmd.trim().is_empty() {
        if json || non_interactive {
            // A JSON write failure exits 2: a piped consumer must not read
            // truncated output as the `applied:false / no_findings` envelope.
            if !emit_no_findings_envelope(&FixEnvelope {
                applied: false,
                reason: "no_findings",
                verdict: "allow",
                command: "",
            }) {
                return 2;
            }
        } else {
            println!("no fix needed");
        }
        return 0;
    }

    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            let shell = human_single_line(shell);
            eprintln!("tirith fix: warning: unknown shell '{shell}', falling back to posix");
            ShellType::Posix
        }
    };

    // Analyze without honoring the explicit bypass: a bypass may let the user
    // run the original command, but it must never bless an executable fix.
    // Policy discovery still runs normally and is preserved by the verification
    // context below. `fix` remains advisory and does not audit log.
    let ctx = AnalysisContext {
        input: cmd.clone(),
        shell: shell_type,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    let verdict = engine::analyze_without_bypass_returning_policy(&ctx).0;

    // Allow path: nothing to fix.
    if verdict.action == Action::Allow {
        if json || non_interactive {
            if !emit_no_findings_envelope(&FixEnvelope {
                applied: false,
                reason: "no_findings",
                verdict: action_str(verdict.action),
                command: &cmd,
            }) {
                return 2;
            }
        } else {
            println!("no fix needed");
        }
        return 0;
    }

    // Verdict has findings — ask the library for verified suggestions. Only an
    // exact final command that re-analyzes to Allow under this same context can
    // populate `safe_command` and cross stdout/JSON execution contracts.
    let suggestions = safe_command::suggest_verified(&ctx, &verdict);

    // JSON / non-interactive path: emit a plain JSON array, never prompt. Exit
    // 1 if no mechanical rewrite exists (guidance-only); 2 if rewrites are
    // present but we can't get an accept signal.
    if json || non_interactive {
        let has_rewrite = suggestions.iter().any(|s| s.safe_command.is_some());
        if !emit_suggestions_array(&suggestions) {
            return 2;
        }
        return if has_rewrite { 2 } else { 1 };
    }

    // Partition into applyable vs guidance-only.
    let (with_rewrite, guidance_only): (Vec<&SafeSuggestion>, Vec<&SafeSuggestion>) =
        suggestions.iter().partition(|s| s.safe_command.is_some());

    // No mechanical rewrite anywhere — print every remediation and exit 1.
    // Never invent a rewrite (Risk #2 in the spec).
    if with_rewrite.is_empty() {
        let mut stderr = io::stderr().lock();
        if write_guidance_only_to(&mut stderr, verdict.findings.len(), &guidance_only).is_err() {
            return 2;
        }
        return 1;
    }

    // Interactive mode requires BOTH stdin and stderr to be TTYs (see
    // `is_tty_pair` for why stderr, not stdout).
    if !is_tty_pair() {
        let mut stderr = io::stderr().lock();
        if write_non_tty_rewrites_to(&mut stderr, &with_rewrite).is_err() {
            return 2;
        }
        return 2;
    }

    // Interactive presenter. Prompt + suggestion list go to stderr so stdout
    // stays clean for the chosen `safe_command` (the `$(tirith fix …)` contract).
    let mut stderr = io::stderr().lock();
    if write_interactive_intro_to(
        &mut stderr,
        verdict.findings.len(),
        &cmd,
        verdict.action,
        &with_rewrite,
        &guidance_only,
    )
    .is_err()
    {
        return 2;
    }

    let n = with_rewrite.len();
    if write!(stderr, "\nApply (1-{n})? [n] ").is_err() || stderr.flush().is_err() {
        return 2;
    }

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut buf = String::new();
    match handle.read_line(&mut buf) {
        Ok(0) => {
            // EOF before input — treat as reject.
            let _ = writeln!(stderr, "tirith fix: no input (EOF) — declining to apply");
            2
        }
        Err(e) => {
            let _ = writeln!(stderr, "tirith fix: stdin read failed: {e}");
            2
        }
        Ok(_) => {
            let trimmed = buf.trim();
            // `n`/`N`/`no`/empty → reject; any digit → try to apply.
            if trimmed.is_empty() || matches!(trimmed, "n" | "N" | "no" | "No") {
                let _ = writeln!(stderr, "tirith fix: declined");
                return 2;
            }
            match trimmed.parse::<usize>() {
                Ok(choice) if choice >= 1 && choice <= n => {
                    let sc = with_rewrite[choice - 1]
                        .safe_command
                        .as_deref()
                        .expect("partition guarantees safe_command is Some");
                    // The chosen rewrite goes to stdout byte-for-byte unchanged
                    // (the `$(tirith fix …)` contract). Terminal sanitization is
                    // exclusively for the human preview written to stderr.
                    let mut stdout = io::stdout().lock();
                    if write_accepted_command_to(&mut stdout, sc).is_err() {
                        let _ = writeln!(stderr, "tirith fix: failed to write accepted command");
                        2
                    } else {
                        0
                    }
                }
                _ => {
                    let _ = write_invalid_choice_to(&mut stderr, trimmed);
                    2
                }
            }
        }
    }
}

fn human_single_line(value: &str) -> String {
    super::sanitize_for_human_output(value, false)
}

/// Sanitize prose while retaining legitimate newlines. `outer_indent` is added
/// before the CLI helper's own two-space continuation indent so a continuation
/// remains nested beneath the formatted row that introduced it.
fn human_multiline(value: &str, outer_indent: &str) -> String {
    let value = super::sanitize_for_human_output(value, true);
    if outer_indent.is_empty() {
        value
    } else {
        value.replace('\n', &format!("\n{outer_indent}"))
    }
}

fn write_rewrite_rows_to<W: Write>(out: &mut W, suggestions: &[&SafeSuggestion]) -> io::Result<()> {
    for (i, s) in suggestions.iter().enumerate() {
        let rule_id = human_single_line(&s.rule_id);
        let rewrite = human_single_line(s.safe_command.as_deref().unwrap_or(""));
        let rationale = human_multiline(&s.rationale, "  ");
        writeln!(
            out,
            "  [{}] rule={} rewrite={} — {}",
            i + 1,
            rule_id,
            rewrite,
            rationale
        )?;
    }
    Ok(())
}

fn write_guidance_only_to<W: Write>(
    out: &mut W,
    finding_count: usize,
    guidance_only: &[&SafeSuggestion],
) -> io::Result<()> {
    writeln!(
        out,
        "tirith fix: no mechanical rewrite available — see guidance below ({finding_count} finding(s))"
    )?;
    for s in guidance_only {
        let rule_id = human_single_line(&s.rule_id);
        let rationale = human_multiline(&s.rationale, "    ");
        let remediation = human_multiline(&s.remediation, "    ");
        writeln!(out, "  rule={rule_id}")?;
        writeln!(out, "    rationale:   {rationale}")?;
        writeln!(out, "    remediation: {remediation}")?;
    }
    Ok(())
}

fn write_non_tty_rewrites_to<W: Write>(
    out: &mut W,
    with_rewrite: &[&SafeSuggestion],
) -> io::Result<()> {
    // Surface what the user would have seen, then refuse to apply. Exit 2 =
    // "rewrite available but no accept signal", distinct from exit 1.
    writeln!(
        out,
        "tirith fix: stdin/stdout is not a TTY — re-run with --non-interactive --json \
         to capture suggestions, or attach a TTY to apply one."
    )?;
    write_rewrite_rows_to(out, with_rewrite)
}

fn write_interactive_intro_to<W: Write>(
    out: &mut W,
    finding_count: usize,
    cmd: &str,
    action: Action,
    with_rewrite: &[&SafeSuggestion],
    guidance_only: &[&SafeSuggestion],
) -> io::Result<()> {
    let cmd = human_single_line(cmd);
    writeln!(out, "tirith fix: {finding_count} finding(s) in:")?;
    writeln!(out, "  {cmd}")?;
    writeln!(out, "verdict: {}", action_str(action))?;
    writeln!(out)?;
    writeln!(out, "Suggestions:")?;
    write_rewrite_rows_to(out, with_rewrite)?;

    if !guidance_only.is_empty() {
        writeln!(out)?;
        writeln!(out, "Guidance (no mechanical rewrite):")?;
        for s in guidance_only {
            let rule_id = human_single_line(&s.rule_id);
            let remediation = human_multiline(&s.remediation, "  ");
            writeln!(out, "  rule={rule_id} — {remediation}")?;
        }
    }
    Ok(())
}

fn write_invalid_choice_to<W: Write>(out: &mut W, choice: &str) -> io::Result<()> {
    let choice = human_single_line(choice);
    writeln!(out, "tirith fix: invalid choice '{choice}' — declined")
}

/// Preserve the stdout/eval contract: this is intentionally not a human
/// terminal renderer and must not alter the selected executable command.
fn write_accepted_command_to<W: Write>(out: &mut W, command: &str) -> io::Result<()> {
    writeln!(out, "{command}")
}

/// Map `Verdict::action` to the lowercase JSON token used in our envelope.
fn action_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        // WarnAck collapses to "warn" in the JSON view (mirrors lab.rs).
        Action::Warn | Action::WarnAck => "warn",
        Action::Block => "block",
    }
}

/// Interactive mode requires BOTH stdin and STDERR to be a TTY. We gate on
/// stderr, not stdout: the prompt goes to stderr so stdout stays clean for the
/// `$(tirith fix …)` capture contract, so gating on stdout would reject the
/// documented `eval "$(tirith fix ...)"` flow.
fn is_tty_pair() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

/// Stable JSON envelope for the no-findings case only (Allow under `--json` /
/// `--non-interactive`). Findings-present output is a plain JSON array of
/// [`SafeSuggestion`]. `applied` is always `false` here but kept so parsers can
/// branch on it uniformly across both shapes.
#[derive(Serialize)]
struct FixEnvelope<'a> {
    applied: bool,
    reason: &'a str,
    verdict: &'a str,
    command: &'a str,
}

fn emit_no_findings_envelope(envelope: &FixEnvelope<'_>) -> bool {
    let mut out = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, envelope).is_err() || writeln!(out).is_err() {
        eprintln!("tirith fix: failed to write JSON output");
        return false;
    }
    true
}

fn emit_suggestions_array(suggestions: &[SafeSuggestion]) -> bool {
    let mut out = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, suggestions).is_err() || writeln!(out).is_err() {
        eprintln!("tirith fix: failed to write JSON output");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suggestion(
        rule_id: &str,
        safe_command: Option<&str>,
        rationale: &str,
        remediation: &str,
    ) -> SafeSuggestion {
        SafeSuggestion {
            rule_id: rule_id.to_string(),
            safe_command: safe_command.map(str::to_string),
            rationale: rationale.to_string(),
            remediation: remediation.to_string(),
        }
    }

    #[test]
    fn action_str_collapses_warn_ack() {
        assert_eq!(action_str(Action::Allow), "allow");
        assert_eq!(action_str(Action::Warn), "warn");
        assert_eq!(action_str(Action::WarnAck), "warn");
        assert_eq!(action_str(Action::Block), "block");
    }

    #[test]
    fn no_findings_envelope_serializes_with_stable_keys() {
        // Public JSON contract for the no-findings case — pin keys + types so a
        // field rename/reorder trips CI.
        let envelope = FixEnvelope {
            applied: false,
            reason: "no_findings",
            verdict: "allow",
            command: "ls",
        };
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["applied"], serde_json::Value::Bool(false));
        assert_eq!(json["reason"], "no_findings");
        assert_eq!(json["verdict"], "allow");
        assert_eq!(json["command"], "ls");
    }

    #[test]
    fn interactive_renderer_neutralizes_dynamic_fields() {
        let rewrite = suggestion(
            "rule\x1b[2J\u{009b}\nFORGED RULE",
            Some("echo safe\x1b]52;c;aGVsbG8=\x07\nFORGED REWRITE"),
            "why\x1b[31mred\x1b[0m\nFORGED RATIONALE",
            "remedy\u{202e}\nFORGED REMEDIATION",
        );
        let guidance = suggestion(
            "guide\u{200b}",
            None,
            "guidance rationale",
            "manual\x1b[2J fix\nFORGED GUIDANCE",
        );
        let with_rewrite = vec![&rewrite];
        let guidance_only = vec![&guidance];
        let mut out = Vec::new();

        write_interactive_intro_to(
            &mut out,
            2,
            "curl https://例え.テスト/路径\x1b[2J\nFORGED COMMAND",
            Action::Block,
            &with_rewrite,
            &guidance_only,
        )
        .expect("render interactive intro");

        let rendered = String::from_utf8(out).expect("renderer emits UTF-8");
        assert!(!rendered.contains('\x1b'), "ESC must not reach stderr");
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\u{200b}'));
        assert!(!rendered.contains('\u{009b}'));
        assert!(
            !rendered.contains("\nFORGED"),
            "dynamic values must not forge a top-level line: {rendered:?}"
        );
        assert!(rendered.contains("https://例え.テスト/路径FORGED COMMAND"));
        assert!(rendered.contains("whyred\n    FORGED RATIONALE"));
        assert!(rendered.contains("manual fix\n    FORGED GUIDANCE"));
    }

    #[test]
    fn guidance_and_non_tty_renderers_are_terminal_safe() {
        let rewrite = suggestion(
            "rewrite-rule",
            Some("echo ok\x1b[2J\nFORGED"),
            "rationale\nFORGED",
            "unused",
        );
        let guidance = suggestion("guide\x1b[31m-rule", None, "why\x1b[0m", "remedy\nFORGED");

        let mut non_tty = Vec::new();
        write_non_tty_rewrites_to(&mut non_tty, &[&rewrite]).expect("render non-TTY rewrites");
        let non_tty = String::from_utf8(non_tty).unwrap();
        assert!(!non_tty.contains('\x1b'));
        assert!(!non_tty.contains("\nFORGED"));

        let mut guidance_out = Vec::new();
        write_guidance_only_to(&mut guidance_out, 1, &[&guidance]).expect("render guidance");
        let guidance_out = String::from_utf8(guidance_out).unwrap();
        assert!(!guidance_out.contains('\x1b'));
        assert!(!guidance_out.contains("\nFORGED"));
        assert!(guidance_out.contains("remedy\n      FORGED"));
    }

    #[test]
    fn selection_diagnostic_is_safe_but_accepted_command_is_exact() {
        let mut diagnostic = Vec::new();
        write_invalid_choice_to(&mut diagnostic, "9\x1b[2J\u{202e}")
            .expect("render invalid selection");
        let diagnostic = String::from_utf8(diagnostic).unwrap();
        assert!(!diagnostic.contains('\x1b'));
        assert!(!diagnostic.contains('\u{202e}'));

        let candidate = "printf '路径' && printf '\x1b[2J'";
        let mut stdout = Vec::new();
        write_accepted_command_to(&mut stdout, candidate).expect("write accepted command");
        assert_eq!(stdout, format!("{candidate}\n").into_bytes());
    }

    #[test]
    fn suggestion_json_keeps_raw_machine_values() {
        let raw = "echo ok\x1b[2J路径";
        let s = suggestion("test_rule", Some(raw), "why\u{202e}", "remedy\nnext");

        let json = serde_json::to_value(&s).expect("serialize suggestion");

        assert_eq!(json["safe_command"], raw);
        assert_eq!(json["rationale"], "why\u{202e}");
        assert_eq!(json["remediation"], "remedy\nnext");
    }
}
