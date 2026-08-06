//! Windows filesystem helpers for `tirith setup` — the same public API as
//! `fs_helpers.rs` without the Unix permission handling (NTFS ACLs default to
//! owner-only, so explicit chmod is unnecessary).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Write `content` to `path` atomically via temp+rename. `mode` is accepted for
/// API compatibility but ignored on Windows.
pub fn atomic_write(path: &Path, content: &str, _mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("no parent directory for {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create dirs {}: {e}", parent.display()))?;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let tmp = {
        let mut tmp_path;
        let mut f_result;

        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        tmp_path = parent.join(format!(".tirith-setup-{}-{}.tmp", std::process::id(), n));
        f_result = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path);

        for _ in 0..3 {
            if f_result.is_ok() {
                break;
            }
            let n2 = COUNTER.fetch_add(1, Ordering::Relaxed);
            tmp_path = parent.join(format!(".tirith-setup-{}-{}.tmp", std::process::id(), n2));
            f_result = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path);
        }

        use std::io::Write;
        let mut f = f_result.map_err(|e| format!("create tmp {}: {e}", tmp_path.display()))?;
        f.write_all(content.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("write tmp: {e}")
        })?;
        tmp_path
    };

    // Refuse to overwrite a symlink target — matches Unix behavior.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "{} is a symlink — refusing to overwrite for safety",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(format!("stat {}: {e}", path.display()));
        }
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;

    Ok(())
}

/// Write a hook script. No executable bit needed on Windows.
pub fn write_hook_script(
    path: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink — refusing to modify for safety",
                path.display()
            ));
        }
    }

    if path.exists() {
        let existing =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if existing == content {
            if !dry_run {
                eprintln!("tirith: {} already configured, up to date", path.display());
            } else {
                eprintln!(
                    "[dry-run] would skip {} (already up to date)",
                    path.display()
                );
            }
            return Ok(());
        }

        if !force {
            if dry_run {
                eprintln!(
                    "[dry-run] would error: {} exists but content differs — use --force to update",
                    path.display()
                );
                return Ok(());
            }
            return Err(format!(
                "{} exists but content differs — use --force to update",
                path.display()
            ));
        }
    }

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    atomic_write(path, content, 0)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

/// Validate that `dir` stays within `scope_root` after canonicalization.
pub fn validate_target_dir(dir: &Path, scope_root: Option<&Path>) -> Result<(), String> {
    let root = match scope_root {
        Some(r) => r,
        None => return Ok(()),
    };

    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;

    let mut check = dir.to_path_buf();
    loop {
        if check.exists() {
            let canonical = check
                .canonicalize()
                .map_err(|e| format!("canonicalize {}: {e}", check.display()))?;
            if !canonical.starts_with(&root_canonical) {
                return Err(format!(
                    "{} resolves outside project root {} — refusing for safety",
                    dir.display(),
                    root.display()
                ));
            }
            break;
        }
        if !check.pop() {
            return Err(format!(
                "cannot resolve {} — no existing ancestor found",
                dir.display()
            ));
        }
    }

    let mut path_so_far = PathBuf::new();
    for component in dir.components() {
        path_so_far.push(component);
        if path_so_far.exists() {
            if let Ok(meta) = fs::symlink_metadata(&path_so_far) {
                if meta.file_type().is_symlink() && path_so_far.starts_with(&root_canonical) {
                    return Err(format!(
                        "{} is a symlink inside project scope — refusing for safety",
                        path_so_far.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Run a CLI subprocess through the shared trusted, bounded supervisor.
pub fn run_cli(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let executable = tirith_core::trusted_child::resolve_ambient(cmd)
        .map_err(|error| format!("{cmd} not found or untrusted: {error}"))?;
    run_cli_with(
        &executable,
        args,
        tirith_core::trusted_child::ChildLimits::new(
            std::time::Duration::from_secs(30),
            4 * 1024 * 1024,
            4 * 1024 * 1024,
        ),
    )
}

fn run_cli_with(
    executable: &tirith_core::trusted_child::TrustedExecutable,
    args: &[&str],
    limits: tirith_core::trusted_child::ChildLimits,
) -> Result<std::process::Output, String> {
    use tirith_core::trusted_child::{ChildOutcome, ChildSpec};

    let mut spec = ChildSpec::new(args, limits).inherit_env(&[
        "HOME",
        "USER",
        "LOGNAME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "CODEX_HOME",
        "SystemRoot",
        "WINDIR",
    ]);
    if let Some(path) = tirith_core::trusted_child::sanitized_ambient_path() {
        spec = spec.env("PATH", path);
    }
    match tirith_core::trusted_child::run(executable, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        ChildOutcome::SpawnError(reason) => Err(format!("failed to start: {reason}")),
        ChildOutcome::WaitError(reason) => Err(format!("wait failed: {reason}")),
        ChildOutcome::Timeout {
            cleanup_succeeded: true,
        } => Err("timed out after 30s — check installation".into()),
        ChildOutcome::Timeout {
            cleanup_succeeded: false,
        } => Err("timed out and process-tree cleanup failed — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: true,
            ..
        } => Err("output limit exceeded — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: false,
            ..
        } => Err("output limit exceeded and process-tree cleanup failed".into()),
    }
}

/// Create a timestamped backup of `path` when `force` is true and the file exists.
pub fn create_backup(path: &Path, force: bool) -> Result<(), String> {
    if !force || !path.exists() {
        return Ok(());
    }
    create_backup_impl(path)
}

/// Create a timestamped backup unconditionally.
pub fn create_backup_always(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    create_backup_impl(path)
}

fn create_backup_impl(path: &Path) -> Result<(), String> {
    let now = chrono::Local::now();
    let timestamp = now.format("%Y%m%d-%H%M%S");
    let backup_name = format!(
        "{}.tirith-backup-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        timestamp
    );
    let backup_path = path
        .parent()
        .ok_or_else(|| format!("no parent for {}", path.display()))?
        .join(&backup_name);

    fs::copy(path, &backup_path).map_err(|e| {
        format!(
            "backup {} -> {}: {e}",
            path.display(),
            backup_path.display()
        )
    })?;
    eprintln!("tirith: backup at {}", backup_path.display());

    cleanup_old_backups(path);
    Ok(())
}

fn cleanup_old_backups(path: &Path) {
    let parent = match path.parent() {
        Some(p) => p,
        None => return,
    };
    let stem = match path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return,
    };
    let prefix = format!("{stem}.tirith-backup-");

    let mut backups: Vec<PathBuf> = match fs::read_dir(parent) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .map(|e| e.path())
            .collect(),
        Err(_) => return,
    };

    if backups.len() <= 5 {
        return;
    }

    backups.sort();
    let to_remove = backups.len() - 5;
    for old in &backups[..to_remove] {
        if let Err(e) = fs::remove_file(old) {
            eprintln!("tirith: could not clean old backup {}: {e}", old.display());
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn cmd() -> tirith_core::trusted_child::TrustedExecutable {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        tirith_core::trusted_child::TrustedExecutable::from_absolute(
            &PathBuf::from(root).join("System32").join("cmd.exe"),
            &[],
        )
        .expect("trusted system cmd.exe")
    }

    #[test]
    fn windows_setup_runner_preserves_short_legitimate_output() {
        // Room to spare on both streams: this case proves legitimate output
        // survives the supervisor, and any host-dependent extra bytes surface
        // in the assertion below instead of as an opaque limit refusal. The
        // limit path itself is covered by the next test.
        let output = run_cli_with(
            &cmd(),
            &["/D", "/S", "/C", "<nul set /p =setup-ok"],
            tirith_core::trusted_child::ChildLimits::new(
                std::time::Duration::from_secs(5),
                4096,
                4096,
            ),
        )
        .unwrap();
        // `set /p` reports errorlevel 1 when its input reaches EOF, which the
        // `<nul` redirect guarantees, so the exit code carries no signal here.
        // What this case proves is that the supervisor hands back the child's
        // exact bytes.
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "setup-ok",
            "status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn windows_setup_runner_surfaces_output_limit() {
        let error = run_cli_with(
            &cmd(),
            &["/D", "/S", "/C", "<nul set /p =12345"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(5), 4, 64),
        )
        .unwrap_err();
        assert!(error.contains("output limit"));
    }
}
