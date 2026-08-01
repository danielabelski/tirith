//! End-to-end coverage for the public M6 ch5 safe-command contract. Raw
//! transformation shapes live in module unit tests; this suite verifies that
//! public constructors expose only whole-command `Allow` results.

use tirith_core::safe_command::{suggest, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

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

fn typosquat_finding(name: &str, target: &str) -> Finding {
    Finding {
        rule_id: RuleId::ThreatPackageTyposquat,
        severity: Severity::High,
        title: format!("Confirmed typosquat: {name} → {target}"),
        description: format!("Package '{name}' is a confirmed typosquat of '{target}'."),
        evidence: vec![Evidence::Text {
            detail: format!("package={name} typosquat_of={target}"),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn verdict_with(findings: Vec<Finding>) -> Verdict {
    Verdict::from_findings(findings, 3, Timings::default())
}

fn find_by_rule<'a>(out: &'a [SafeSuggestion], rule: &str) -> Option<&'a SafeSuggestion> {
    out.iter().find(|s| s.rule_id == rule)
}

// ── 1. typosquat guidance ─────────────────────────────────────────────────

#[test]
fn typosquat_unambiguous_target_remains_guidance_only() {
    let cmd = "npm install reqeusts";
    let v = verdict_with(vec![typosquat_finding("reqeusts", "requests")]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "threat_package_typosquat").expect("rule entry");
    assert!(entry.safe_command.is_none());
    assert!(!entry.remediation.is_empty());
}

#[test]
fn typosquat_negative_ambiguous_target_no_rewrite() {
    // Finding has no arrow + no typosquat_of= evidence → target is ambiguous.
    let mut f = typosquat_finding("reqeusts", "requests");
    f.title = "Confirmed typosquat".to_string(); // strip the arrow
    f.evidence = vec![Evidence::Text {
        detail: "no_target_field_here".to_string(),
    }];

    let cmd = "npm install reqeusts";
    let v = verdict_with(vec![f]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "threat_package_typosquat").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "ambiguous target must not produce a rewrite"
    );
    assert!(!entry.remediation.is_empty());
}

#[test]
fn typosquat_flags_multiple_packages_and_shell_variants_are_guidance_only() {
    let finding = typosquat_finding("reqeusts", "--global");
    for (cmd, shell) in [
        ("npm install --save reqeusts", ShellType::Posix),
        ("npm install reqeusts lodash", ShellType::Posix),
        ("npm install other", ShellType::Posix),
        ("npm install reqeusts", ShellType::PowerShell),
        ("npm install reqeusts", ShellType::Cmd),
    ] {
        let suggestions = suggest(cmd, shell, &verdict_with(vec![finding.clone()]));
        let entry = find_by_rule(&suggestions, "threat_package_typosquat").unwrap();
        assert!(
            entry.safe_command.is_none(),
            "typosquat rewrite must stay guidance-only for {shell:?}: {cmd}"
        );
    }
}

// ── 2. sudo-narrow (negative tests only in M6) ────────────────────────────

#[test]
fn sudo_narrow_negative_sudo_rm_rf_root_no_rewrite() {
    // Every sudo shape stays visible as guidance, never executable output.
    let cmd = "sudo rm -rf /";
    let v = verdict_with(vec![finding(RuleId::CommandNetworkDeny)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow").expect("sudo guidance");
    assert!(
        entry.safe_command.is_none(),
        "sudo-narrow must remain guidance-only; got {entry:?}"
    );
}

#[test]
fn sudo_narrow_negative_sudo_sh_returns_interactive_shell_remediation() {
    // Stripped leader `sh` is an interactive shell → None-suggestion + remediation.
    let cmd = "sudo sh";
    let v = verdict_with(vec![finding(RuleId::PipeToInterpreter)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow").expect("sudo_narrow entry must be present");
    assert!(
        entry.safe_command.is_none(),
        "sudo sh must yield no rewrite — got {:?}",
        entry.safe_command
    );
    assert!(
        entry
            .rationale
            .contains("No safe mechanical rewrite is available"),
        "rationale should advertise no rewrite: {}",
        entry.rationale
    );
    assert!(
        entry.rationale.contains("Avoid interactive root shells"),
        "rationale should warn about interactive root shells: {}",
        entry.rationale
    );
}

// ── 2a. sudo-narrow guidance-only positive detection ─────────────────────

#[test]
fn sudo_narrow_sudo_apt_update_is_guidance_only() {
    let cmd = "sudo apt update";
    // Any finding triggers the command-shape transforms.
    let v = verdict_with(vec![finding(RuleId::CommandNetworkDeny)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow")
        .expect("sudo_narrow entry must be present for sudo apt update");
    assert!(entry.safe_command.is_none());
    assert!(
        entry.rationale.contains("No safe mechanical rewrite"),
        "public rationale should explain guidance-only behavior: {}",
        entry.rationale
    );
}

// ── 2b. sudo-narrow (M8 ch4 NEGATIVE — interactive shell invariant) ──────
//
// Pins the M6 ch5 invariant — an interactive-shell leader NEVER yields a
// mechanical rewrite — this time driven by the M8 ch4 `SudoShellSpawn` finding
// to confirm the new sudo rules did not loosen it.

#[test]
fn sudo_narrow_negative_sudo_shell_spawn_keeps_no_rewrite() {
    let cmd = "sudo sh";
    let v = verdict_with(vec![finding(RuleId::SudoShellSpawn)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow")
        .expect("sudo_narrow entry must be present for sudo sh + SudoShellSpawn");
    assert!(
        entry.safe_command.is_none(),
        "sudo sh + SudoShellSpawn must NOT mechanically rewrite — got {:?}",
        entry.safe_command
    );
    assert!(
        entry
            .rationale
            .contains("No safe mechanical rewrite is available"),
        "rationale should advertise no rewrite: {}",
        entry.rationale
    );
    assert!(
        entry.rationale.contains("Avoid interactive root shells"),
        "rationale should mention interactive root shells: {}",
        entry.rationale
    );
}

// ── 3. env-scrub ──────────────────────────────────────────────────────────

// env_scrub end-to-end tests were dropped: they need `std::env::set_var`, whose
// libc environ mutation is not thread-safe on macOS/Windows even under our
// `ENV_LOCK`. Coverage is preserved by the `safe_command::tests`
// `is_simple_command_for_env_scrub` and `build_env_scrub_suggestion_*`
// direct-call unit tests, which avoid touching the real environment.

// ── 4. archive-list-before-extract ────────────────────────────────────────

#[test]
fn archive_list_first_candidate_is_guidance_only_for_tar_xzf() {
    let cmd = "tar -xzf foo.tar.gz -C ~/";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "preview-then-extract still re-analyzes to ArchiveExtract and must not be executable"
    );
    assert!(
        entry.rationale.contains("guidance-only"),
        "the rejected partial transform must be labeled guidance-only: {}",
        entry.rationale
    );
}

#[test]
fn public_suggest_never_exposes_partial_archive_command() {
    // Regression for repo-0149's public-API seam: even a caller that uses the
    // compatibility `suggest` constructor cannot receive the raw preview +
    // extraction candidate.
    let cmd = "tar -xzf payload.tar.gz -C ~/";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "every public constructor must uphold the verified-command invariant: {entry:?}"
    );
}

#[test]
fn archive_list_first_negative_non_archive_leader_no_rewrite() {
    // `ls` is not an archive leader, so even a synthetic ArchiveExtract finding
    // must not produce a rewrite.
    let cmd = "ls foo.tar.gz";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "non-archive leader must yield no rewrite"
    );
}

// ── 5. dotfile-redirect ───────────────────────────────────────────────────

// dotfile-redirect end-to-end tests were dropped for the same libc-environ race
// as env_scrub (they had to set `HOME`). Structural correctness is pinned by the
// `dotfile_redirect_target` and `rewrite_dotfile_backup_first` unit tests in
// `safe_command::tests`; only the on-disk existence check loses dedicated coverage.

// ── 6. PR124 — untrusted-token shell-injection neutralization ─────────────
//
// `tirith fix` prints its rewrite to stdout for `eval "$(tirith fix …)"`, so any
// attacker-influenced token (URL / package / archive path) interpolated into a
// generated command MUST be neutralized. The pipe-to-shell URL and archive path
// are single-quoted; the dotfile redirect target is refused when it carries shell
// metacharacters (it must stay unquoted for `~`/`$HOME` expansion).

#[test]
fn pipe_to_shell_public_contract_is_guidance_only_for_a_replaceable_test_binary() {
    // Public suggestion generation may emit an executable command only when the
    // currently-running Tirith is itself a fixed root-managed x86_64 Linux
    // installation. Cargo's integration-test binary lives in a user-writable
    // target directory, so it must remain guidance-only on every CI platform.
    let cmd = "curl -fsSL https://example.com/install.sh | bash";
    let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
    let suggestions = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&suggestions, "curl_pipe_shell").expect("rule entry");
    assert!(entry.safe_command.is_none());
    assert!(entry.rationale.contains("No safe executable rewrite"));
}

#[test]
fn pipe_to_shell_public_contract_requires_curl_fail_and_redirect_semantics() {
    for command in [
        "curl https://example.com/install.sh | bash",
        "curl -f https://example.com/install.sh | bash",
        "curl -L https://example.com/install.sh | bash",
    ] {
        let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let suggestions = suggest(command, ShellType::Posix, &verdict);
        let entry = find_by_rule(&suggestions, "curl_pipe_shell").expect("rule entry");
        assert!(
            entry.safe_command.is_none(),
            "curl semantics that differ from the bounded fetcher must be guidance-only: {command}"
        );
    }
}

#[test]
fn malformed_space_bearing_url_is_guidance_only() {
    let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
    let suggestions = suggest(
        "curl -fsSL 'https://example.com/a;rm -rf ~' | bash",
        ShellType::Posix,
        &v,
    );
    assert!(find_by_rule(&suggestions, "curl_pipe_shell")
        .expect("rule entry")
        .safe_command
        .is_none());
}

#[test]
fn normalizing_backtick_url_is_guidance_only() {
    let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
    let suggestions = suggest(
        "curl -fsSL 'https://example.com/`id`' | bash",
        ShellType::Posix,
        &v,
    );
    assert!(find_by_rule(&suggestions, "curl_pipe_shell")
        .expect("rule entry")
        .safe_command
        .is_none());
}

#[test]
fn pipe_to_shell_wget_is_guidance_only_for_a_replaceable_test_binary() {
    let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
    let s = suggest(
        "wget -qO- 'https://example.com/$(id)' | sh",
        ShellType::Posix,
        &v,
    );
    let entry = find_by_rule(&s, "wget_pipe_shell").expect("wget guidance expected");
    assert!(entry.safe_command.is_none());
    assert!(entry.rationale.contains("No safe executable rewrite"));
}

#[test]
fn archive_list_first_command_substitution_path_remains_guidance_only() {
    let cmd = "tar -xzf '$(id).tar.gz' -C ~/";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("archive guidance expected");
    assert!(
        entry.safe_command.is_none(),
        "hostile archive input must never escape through the public executable field: {entry:?}"
    );
}
