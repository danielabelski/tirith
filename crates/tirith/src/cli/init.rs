#[cfg(unix)]
use libc;
use std::fs;
use std::path::PathBuf;

use crate::assets;

fn posix_single_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

fn powershell_single_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "''"))
}

/// Warn if another `tirith` binary shadows us on PATH.
fn check_path_shadow() -> Option<String> {
    let shadows = super::find_shadow_binaries();
    if shadows.is_empty() {
        return None;
    }
    let our_exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".into());
    Some(format!(
        "tirith: WARNING: '{}' shadows this binary ({})\n\
         tirith: This may be a different package (e.g. pip-installed).\n\
         tirith: Run '{}' to inspect, and remove the conflicting binary.",
        shadows[0],
        our_exe,
        super::tirith_path_lookup_command(),
    ))
}

/// How long to suppress a repeat PATH-shadow warning. `eval "$(tirith init)"`
/// runs on every new shell, so without this the warning would print every time.
const SHADOW_WARN_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// True when the shadow warning hasn't fired in the last 24h (or ever). Cheap
/// marker stat — checked BEFORE the `check_path_shadow` PATH walk.
fn shadow_warn_due() -> bool {
    let Some(marker) = tirith_core::policy::state_dir().map(|d| d.join("shadow-warned")) else {
        return true;
    };
    match std::fs::metadata(&marker).and_then(|m| m.modified()) {
        Ok(modified) => modified
            .elapsed()
            .map(|age| age.as_secs() >= SHADOW_WARN_INTERVAL_SECS)
            .unwrap_or(true),
        Err(_) => true,
    }
}

fn mark_shadow_warned() {
    if let Some(dir) = tirith_core::policy::state_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("shadow-warned"), b"");
    }
}

pub fn run(shell: Option<&str>, prompt_status: bool) -> i32 {
    // Throttled (once/24h) + `--quiet`-gated: a sourced `tirith init` runs on every
    // new shell. The PATH walk is skipped entirely when a warning isn't due.
    if !crate::cli::is_quiet() && shadow_warn_due() {
        if let Some(warning) = check_path_shadow() {
            eprintln!("{warning}");
            mark_shadow_warned();
        }
    }

    let shell = shell.unwrap_or_else(|| detect_shell());

    let prompt_executable = if prompt_status {
        match tirith_core::trusted_child::TrustedExecutable::current() {
            Ok(executable) => Some(executable),
            Err(error) => {
                eprintln!("tirith: cannot bind prompt status to the running executable: {error}");
                return 1;
            }
        }
    } else {
        None
    };

    let hook_dir = find_hook_dir();

    match shell {
        "zsh" => {
            if let Some(dir) = &hook_dir {
                println!(
                    "source {}",
                    posix_single_quote(&dir.join("lib/zsh-hook.zsh").display().to_string())
                );
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for("zsh", prompt_executable.as_ref().unwrap().path())
                );
            }
            0
        }
        "bash" => {
            if let Some(dir) = &hook_dir {
                println!(
                    "source {}",
                    posix_single_quote(&dir.join("lib/bash-hook.bash").display().to_string())
                );
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for("bash", prompt_executable.as_ref().unwrap().path())
                );
            }
            0
        }
        "fish" => {
            if let Some(dir) = &hook_dir {
                println!(
                    "source {}",
                    posix_single_quote(&dir.join("lib/fish-hook.fish").display().to_string())
                );
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for("fish", prompt_executable.as_ref().unwrap().path())
                );
            }
            0
        }
        "powershell" | "pwsh" => {
            if let Some(dir) = &hook_dir {
                println!(
                    ". {}",
                    powershell_single_quote(
                        &dir.join("lib/powershell-hook.ps1").display().to_string()
                    )
                );
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for(
                        "powershell",
                        prompt_executable.as_ref().unwrap().path(),
                    )
                );
            }
            0
        }
        "nushell" | "nu" => {
            if let Some(dir) = &hook_dir {
                println!(
                    "source {}",
                    posix_single_quote(&dir.join("lib/nushell-hook.nu").display().to_string())
                );
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                // Nushell can't be wired via eval; emit a manual-install pointer
                // (the shipped hook does the real wiring).
                println!(
                    "{}",
                    prompt_status_snippet_for(
                        "nushell",
                        prompt_executable.as_ref().unwrap().path(),
                    )
                );
            }
            0
        }
        _ => {
            eprintln!("tirith: unsupported shell '{shell}'");
            eprintln!("Supported: zsh, bash, fish, powershell, nushell");
            eprintln!("  try: tirith init --shell zsh");
            1
        }
    }
}

/// Render the opt-in `--prompt-status` snippet for `shell`. Each snippet is
/// guarded against double-eval (so PS1/PROMPT isn't double-wrapped) and uses
/// single quotes around the command substitution so it defers to prompt-render
/// time (the only quoting that produces a live status).
pub(crate) fn prompt_status_snippet_for(shell: &str, executable: &std::path::Path) -> String {
    let executable = executable.display().to_string();
    let posix_executable = posix_single_quote(&executable);
    let powershell_executable = powershell_single_quote(&executable);
    match shell {
        "zsh" => {
            let substitution = posix_single_quote(&format!(
                "$(TIRITH_STATUS=\"${{TIRITH_STATUS:-}}\" {posix_executable} prompt-status --short) "
            ));
            [
                "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
                "if [[ -z \"${_TIRITH_PROMPT_STATUS_LOADED:-}\" ]]; then".to_string(),
                "  _TIRITH_PROMPT_STATUS_LOADED=1".to_string(),
                "  setopt PROMPT_SUBST".to_string(),
                format!("  PROMPT={substitution}\"$PROMPT\""),
                "fi".to_string(),
                "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
            ]
            .join("\n")
        }
        "bash" => {
            let substitution = posix_single_quote(&format!(
                "$(TIRITH_STATUS=\"${{TIRITH_STATUS:-}}\" {posix_executable} prompt-status --short) "
            ));
            [
                "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
                "if [ -z \"${_TIRITH_PROMPT_STATUS_LOADED:-}\" ]; then".to_string(),
                "  _TIRITH_PROMPT_STATUS_LOADED=1".to_string(),
                format!("  PS1={substitution}\"$PS1\""),
                "fi".to_string(),
                "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
            ]
            .join("\n")
        }
        "fish" => [
            "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
            "if not set -q _TIRITH_PROMPT_STATUS_LOADED".to_string(),
            "    set -g _TIRITH_PROMPT_STATUS_LOADED 1".to_string(),
            "    functions -q fish_right_prompt; and functions -e _tirith_orig_fish_right_prompt".to_string(),
            "    if functions -q fish_right_prompt".to_string(),
            "        functions -c fish_right_prompt _tirith_orig_fish_right_prompt".to_string(),
            "    end".to_string(),
            "    function fish_right_prompt".to_string(),
            format!("        env TIRITH_STATUS=\"$TIRITH_STATUS\" {posix_executable} prompt-status --short"),
            "        if functions -q _tirith_orig_fish_right_prompt".to_string(),
            "            _tirith_orig_fish_right_prompt".to_string(),
            "        end".to_string(),
            "    end".to_string(),
            "end".to_string(),
            "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
        ]
        .join("\n"),
        "powershell" | "pwsh" => [
            "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
            "if (-not $global:_TIRITH_PROMPT_STATUS_LOADED) {".to_string(),
            "    $global:_TIRITH_PROMPT_STATUS_LOADED = $true".to_string(),
            "    if (Test-Path Function:prompt) {".to_string(),
            "        Copy-Item Function:prompt Function:_tirith_orig_prompt -Force".to_string(),
            "    }".to_string(),
            "    function global:prompt {".to_string(),
            "        $_tps = $env:TIRITH_STATUS; $env:TIRITH_STATUS = $global:TIRITH_STATUS".to_string(),
            format!("        try {{ $line = (& {powershell_executable} prompt-status --short) 2>$null }} finally {{ if ($null -eq $_tps) {{ Remove-Item Env:\\TIRITH_STATUS -ErrorAction SilentlyContinue }} else {{ $env:TIRITH_STATUS = $_tps }} }}"),
            "        if (Get-Command _tirith_orig_prompt -ErrorAction SilentlyContinue) {".to_string(),
            "            \"$line $(_tirith_orig_prompt)\"".to_string(),
            "        } else {".to_string(),
            "            \"$line PS $($executionContext.SessionState.Path.CurrentLocation)> \"".to_string(),
            "        }".to_string(),
            "    }".to_string(),
            "}".to_string(),
            "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
        ]
        .join("\n"),
        // Nushell wiring lives in config.nu and can't be spliced via `eval`;
        // print a manual-install pointer instead.
        "nushell" | "nu" => [
            "# >>> tirith prompt-status (M8 ch6) >>>",
            "# Nushell exposes no non-exported TIRITH_STATUS variable, so a live",
            "# status segment would always read `off`. nushell protection is",
            "# warn-only regardless — there is no live prompt status to wire up",
            "# here. See docs/prompt-status.md.",
            "# <<< tirith prompt-status (M8 ch6) <<<",
        ]
        .join("\n"),
        _ => String::new(),
    }
}

pub(crate) fn detect_shell() -> &'static str {
    if let Some(shell) = detect_shell_from_parent() {
        return shell;
    }

    if let Ok(shell) = std::env::var("SHELL") {
        if let Some(shell) = normalize_shell_name(&shell) {
            return shell;
        }
    }

    #[cfg(windows)]
    return "powershell";

    #[cfg(not(windows))]
    "bash"
}

fn normalize_shell_name(name: &str) -> Option<&'static str> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('-')
        .to_ascii_lowercase();

    if base.contains("zsh") {
        Some("zsh")
    } else if base.contains("bash") {
        Some("bash")
    } else if base.contains("fish") {
        Some("fish")
    } else if base.contains("pwsh") {
        Some("pwsh")
    } else if base.contains("powershell") {
        Some("powershell")
    } else if base == "nu" || base == "nu.exe" || base.contains("nushell") {
        Some("nushell")
    } else {
        None
    }
}

#[cfg(unix)]
fn detect_shell_from_parent() -> Option<&'static str> {
    let mut pid = unsafe { libc::getppid() };

    // Walk ancestors: the immediate parent may be a wrapper (timeout/env) or a
    // shell that exec'd into another program.
    for _ in 0..8 {
        if pid <= 1 {
            return None;
        }
        let (name, parent_pid) = read_process(pid)?;
        if let Some(shell) = normalize_shell_name(&name) {
            return Some(shell);
        }
        if parent_pid == pid {
            break;
        }
        pid = parent_pid;
    }

    None
}

#[cfg(unix)]
fn read_process(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
    use tirith_core::trusted_child::{ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable};

    let program = TrustedExecutable::from_system_candidates(&[
        std::path::Path::new("/bin/ps"),
        std::path::Path::new("/usr/bin/ps"),
    ])
    .ok()?;
    let pid = pid.to_string();
    let spec = ChildSpec::new(
        ["-p", pid.as_str(), "-o", "comm=", "-o", "ppid="],
        ChildLimits::new(std::time::Duration::from_secs(1), 16 * 1024, 16 * 1024),
    );
    let ChildOutcome::Completed { status, stdout, .. } =
        tirith_core::trusted_child::run(&program, &spec)
    else {
        return None;
    };
    if !status.success() {
        return None;
    }

    let line = String::from_utf8_lossy(&stdout);
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let ppid = parts.next()?.parse::<libc::pid_t>().ok()?;
    Some((name, ppid))
}

#[cfg(not(unix))]
fn detect_shell_from_parent() -> Option<&'static str> {
    None
}

/// Find the shell hooks directory using the following search order:
/// 1. TIRITH_SHELL_DIR env var (explicit override)
/// 2. ../share/tirith/shell relative to binary (Homebrew layout)
/// 3. /usr/share/tirith/shell (.deb layout)
/// 4. ../shell relative to binary (cargo install / dev layout)
/// 5. ../../shell relative to binary (workspace dev layout)
/// 6. Fallback: materialize embedded hooks to data dir
pub fn find_hook_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("TIRITH_SHELL_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("lib").exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let brew_dir = bin_dir.join("../share/tirith/shell");
            if brew_dir.join("lib").exists() {
                return Some(brew_dir.canonicalize().unwrap_or(brew_dir));
            }

            #[cfg(unix)]
            {
                let sys_dir = PathBuf::from("/usr/share/tirith/shell");
                if sys_dir.join("lib").exists() {
                    return Some(sys_dir);
                }
            }

            let cargo_dir = bin_dir.join("../shell");
            if cargo_dir.join("lib").exists() {
                return Some(cargo_dir.canonicalize().unwrap_or(cargo_dir));
            }

            let dev_dir = bin_dir.join("../../shell");
            if dev_dir.join("lib").exists() {
                return Some(dev_dir.canonicalize().unwrap_or(dev_dir));
            }
        }
    }

    materialize_hooks()
}

/// Find the shell hooks directory without materializing (read-only variant for diagnostics).
pub fn find_hook_dir_readonly() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("TIRITH_SHELL_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("lib").exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let brew_dir = bin_dir.join("../share/tirith/shell");
            if brew_dir.join("lib").exists() {
                return Some(brew_dir.canonicalize().unwrap_or(brew_dir));
            }

            #[cfg(unix)]
            {
                let sys_dir = PathBuf::from("/usr/share/tirith/shell");
                if sys_dir.join("lib").exists() {
                    return Some(sys_dir);
                }
            }

            let cargo_dir = bin_dir.join("../shell");
            if cargo_dir.join("lib").exists() {
                return Some(cargo_dir.canonicalize().unwrap_or(cargo_dir));
            }

            let dev_dir = bin_dir.join("../../shell");
            if dev_dir.join("lib").exists() {
                return Some(dev_dir.canonicalize().unwrap_or(dev_dir));
            }
        }
    }

    // Check if hooks were previously materialized, but do not create them.
    if let Some(data_dir) = tirith_core::policy::data_dir() {
        let shell_dir = data_dir.join("shell");
        if shell_dir.join("lib").exists() {
            return Some(shell_dir);
        }
    }

    None
}

/// Write embedded hook files to the user data dir, returning the shell dir.
fn materialize_hooks() -> Option<PathBuf> {
    let data_dir = tirith_core::policy::data_dir()?;
    let shell_dir = data_dir.join("shell");
    let lib_dir = shell_dir.join("lib");
    let version_path = shell_dir.join(".hooks-version");
    let current_version = env!("CARGO_PKG_VERSION");

    // Re-materialize if required files are missing or the version changed.
    let required_files = [
        shell_dir.join("tirith.sh"),
        lib_dir.join("zsh-hook.zsh"),
        lib_dir.join("bash-hook.bash"),
        lib_dir.join("fish-hook.fish"),
        lib_dir.join("powershell-hook.ps1"),
        lib_dir.join("nushell-hook.nu"),
    ];
    let version_matches = fs::read_to_string(&version_path)
        .ok()
        .map(|v| v.trim() == current_version)
        .unwrap_or(false);
    let needs_write = !required_files.iter().all(|p| p.exists()) || !version_matches;

    if needs_write {
        if let Err(e) = fs::create_dir_all(&lib_dir) {
            eprintln!(
                "tirith: failed to create hook directory {}: {e}",
                lib_dir.display()
            );
            return None;
        }

        let hook_files: Vec<(PathBuf, &str)> = vec![
            (shell_dir.join("tirith.sh"), assets::TIRITH_SH),
            (lib_dir.join("zsh-hook.zsh"), assets::ZSH_HOOK),
            (lib_dir.join("bash-hook.bash"), assets::BASH_HOOK),
            (lib_dir.join("fish-hook.fish"), assets::FISH_HOOK),
            (lib_dir.join("powershell-hook.ps1"), assets::POWERSHELL_HOOK),
            (lib_dir.join("nushell-hook.nu"), assets::NUSHELL_HOOK),
        ];
        for (path, content) in &hook_files {
            if let Err(e) = fs::write(path, content) {
                eprintln!("tirith: failed to write hook {}: {e}", path.display());
                return None;
            }
        }
        if let Err(e) = fs::write(&version_path, format!("{current_version}\n")) {
            eprintln!("tirith: failed to write hook version file: {e}");
            return None;
        }

        eprintln!(
            "tirith: materialized shell hooks to {}",
            shell_dir.display()
        );
    }

    Some(shell_dir)
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_shell_name, posix_single_quote, powershell_single_quote,
        prompt_status_snippet_for,
    };
    use std::path::Path;

    fn prompt_status_snippet(shell: &str) -> String {
        prompt_status_snippet_for(shell, Path::new("/opt/Tirith Bin/tirith"))
    }

    #[test]
    fn normalize_shell_name_from_paths_and_login_shells() {
        assert_eq!(normalize_shell_name("/bin/bash"), Some("bash"));
        assert_eq!(normalize_shell_name("/opt/homebrew/bin/fish"), Some("fish"));
        assert_eq!(normalize_shell_name("-zsh"), Some("zsh"));
    }

    #[test]
    fn normalize_shell_name_supports_case_insensitive_names() {
        assert_eq!(normalize_shell_name("BASH"), Some("bash"));
        assert_eq!(normalize_shell_name("PwSh"), Some("pwsh"));
        assert_eq!(normalize_shell_name("PowerShell"), Some("powershell"));
    }

    #[test]
    fn normalize_shell_name_distinguishes_pwsh_and_windows_powershell() {
        // pwsh (PowerShell 7+) is a distinct label from legacy powershell 5.1;
        // the hook script is the same, only the label differs.
        assert_eq!(normalize_shell_name("/usr/local/bin/pwsh"), Some("pwsh"));
        assert_eq!(
            normalize_shell_name("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            Some("powershell")
        );
        // Non-PowerShell shells are unaffected by the split.
        assert_eq!(normalize_shell_name("/bin/bash"), Some("bash"));
    }

    #[test]
    fn normalize_shell_name_supports_nushell() {
        assert_eq!(normalize_shell_name("nu"), Some("nushell"));
        assert_eq!(normalize_shell_name("nu.exe"), Some("nushell"));
        assert_eq!(normalize_shell_name("nushell"), Some("nushell"));
        assert_eq!(normalize_shell_name("nushell.exe"), Some("nushell"));
        assert_eq!(normalize_shell_name("/usr/bin/nu"), Some("nushell"));
        assert_eq!(
            normalize_shell_name("C:\\Program Files\\nu.exe"),
            Some("nushell")
        );
    }

    #[test]
    fn normalize_shell_name_no_false_positive_on_gnu() {
        // "gnu" contains "nu" but is not nushell — require exact match.
        assert_eq!(normalize_shell_name("gnu"), None);
    }

    #[test]
    fn normalize_shell_name_rejects_unknown_values() {
        assert_eq!(normalize_shell_name(""), None);
        assert_eq!(normalize_shell_name("python"), None);
    }

    #[test]
    fn quote_helpers_escape_shell_metacharacters() {
        assert_eq!(
            posix_single_quote("/tmp/hook' > file"),
            "'/tmp/hook'\\'' > file'"
        );
        assert_eq!(
            powershell_single_quote("C:\\temp\\it's.ps1"),
            "'C:\\temp\\it''s.ps1'"
        );
    }

    /// Each per-shell snippet must carry the BEGIN/END markers (for external
    /// dedupe), reference `tirith prompt-status --short`, guard against double-eval,
    /// and single-quote the substitution so it defers to prompt render.
    #[test]
    fn prompt_status_snippet_zsh_is_marker_wrapped_and_deferred() {
        let s = prompt_status_snippet("zsh");
        assert!(s.contains("# >>> tirith prompt-status (M8 ch6) >>>"));
        assert!(s.contains("# <<< tirith prompt-status (M8 ch6) <<<"));
        assert!(s.contains("setopt PROMPT_SUBST"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
        // Single-quoted so PROMPT re-renders each redraw, AND the non-exported
        // TIRITH_STATUS is forwarded inline so the child can actually read it
        // (a bare `tirith prompt-status` child sees a non-exported var as unset).
        assert!(s.contains("/opt/Tirith Bin/tirith"));
        assert!(!s.contains(" tirith prompt-status --short"));
    }

    #[test]
    fn prompt_status_snippet_bash_uses_ps1_with_single_quoted_subst() {
        let s = prompt_status_snippet("bash");
        assert!(s.contains("/opt/Tirith Bin/tirith"));
        assert!(!s.contains(" tirith prompt-status --short"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
        assert!(s.contains("# >>> tirith prompt-status (M8 ch6) >>>"));
        assert!(s.contains("# <<< tirith prompt-status (M8 ch6) <<<"));
    }

    #[test]
    fn prompt_status_snippet_fish_wraps_right_prompt() {
        let s = prompt_status_snippet("fish");
        assert!(s.contains("function fish_right_prompt"));
        // Forwards the non-exported TIRITH_STATUS via `env` so the child sees it.
        assert!(s.contains("'/opt/Tirith Bin/tirith' prompt-status --short"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
    }

    #[test]
    fn prompt_status_snippet_powershell_forwards_status_env() {
        let s = prompt_status_snippet("powershell");
        // PowerShell stores $global:TIRITH_STATUS (a PS variable, NOT $env:), which
        // a child process cannot see — forward it via $env: for the call, restored
        // in `finally` so it does not leak into the session.
        assert!(s.contains("$env:TIRITH_STATUS = $global:TIRITH_STATUS"));
        assert!(s.contains("finally"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
    }

    #[test]
    fn prompt_status_snippet_powershell_wraps_prompt_function() {
        for shell in ["powershell", "pwsh"] {
            let s = prompt_status_snippet(shell);
            assert!(s.contains("function global:prompt"), "shell={shell}");
            assert!(
                s.contains("'/opt/Tirith Bin/tirith' prompt-status --short"),
                "shell={shell}"
            );
            assert!(s.contains("$global:_TIRITH_PROMPT_STATUS_LOADED"));
        }
    }

    #[test]
    fn prompt_status_snippet_quotes_an_executable_with_a_single_quote() {
        let executable = Path::new("/opt/Tirith's Bin/tirith");
        for shell in ["zsh", "bash", "fish", "powershell"] {
            let snippet = prompt_status_snippet_for(shell, executable);
            assert!(snippet.contains("Tirith"), "shell={shell}: {snippet}");
            assert!(!snippet.contains(" tirith prompt-status --short"));
        }
    }

    #[test]
    fn prompt_status_snippet_nushell_explains_no_live_status() {
        let s = prompt_status_snippet("nushell");
        // Nushell exposes no non-exported TIRITH_STATUS, so the snippet must be an
        // HONEST explanation (warn-only, no live status), NOT a prompt-status
        // command that would always render `off`.
        assert!(s.contains("warn-only"));
        assert!(s.contains("docs/prompt-status.md"));
        // Must NOT hand the user runnable prompt wiring that would render `off`.
        // (The `# >>> tirith prompt-status` MARKER legitimately names the command;
        // we guard against the old `$env.PROMPT_COMMAND` closure instead.)
        assert!(
            !s.contains("PROMPT_COMMAND"),
            "nushell snippet must not suggest a runnable prompt closure (always reads off); got: {s}"
        );
    }
}
