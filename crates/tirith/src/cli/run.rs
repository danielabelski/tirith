use tirith_core::runner::{
    self, RequestedPipeInvocation, RunOptions, ScriptInputMode, ScriptInvocation,
};

pub fn run(
    url: &str,
    no_exec: bool,
    json: bool,
    capsule: bool,
    requested_pipe_invocation: Option<RequestedPipeInvocation>,
    expected_sha256: Option<String>,
) -> i32 {
    let interactive = is_terminal::is_terminal(std::io::stderr());

    // E5: when `--capsule` is set, execute the downloaded script inside the OS
    // containment capsule. `tirith run` is an enforcing surface here, so a host
    // whose backend cannot provide the spec's required coverage fails closed
    // instead of running uncontained. Download/DNS has already occurred under
    // the fetch validator and is not part of interpreter containment.
    let exec_fn: Option<tirith_core::runner::ScriptExecutor> = if capsule {
        Some(Box::new(capsuled_exec))
    } else {
        None
    };

    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256,
        requested_pipe_invocation,
        exec_fn,
    };

    match runner::run(opts) {
        Ok(result) => {
            if json {
                #[derive(serde::Serialize)]
                struct RunOutput<'a> {
                    receipt: &'a tirith_core::receipt::Receipt,
                    verdict: Option<&'a tirith_core::verdict::Verdict>,
                    analysis_complete: bool,
                    refused: bool,
                    executed: bool,
                    exit_code: Option<i32>,
                }
                let out = RunOutput {
                    receipt: &result.receipt,
                    verdict: result.verdict.as_ref(),
                    analysis_complete: result.analysis_complete,
                    refused: result.refused,
                    executed: result.executed,
                    exit_code: result.exit_code,
                };
                if serde_json::to_writer_pretty(std::io::stdout().lock(), &out).is_err() {
                    eprintln!("tirith: failed to write JSON output");
                }
                println!();
            }

            if result.executed || result.refused {
                result.exit_code.unwrap_or(1)
            } else {
                0
            }
        }
        Err(e) => {
            if json {
                let err = serde_json::json!({ "error": e });
                if serde_json::to_writer_pretty(std::io::stdout().lock(), &err).is_err() {
                    eprintln!("tirith: failed to write JSON output");
                }
                println!();
            } else {
                eprintln!("tirith: {e}");
            }
            1
        }
    }
}

/// The contained executor for `tirith run --capsule` (E5). Runs the exact typed
/// interpreter invocation through the locked-down OS capsule, with the private
/// script directory readable when file mode needs it. Enforcing surface: fail
/// closed when the backend cannot provide the spec's required coverage.
fn capsuled_exec(
    invocation: &ScriptInvocation,
    path: &std::path::Path,
    reviewed_bytes: &[u8],
) -> Result<i32, String> {
    use tirith_core::capsule::CapsuleSpec;

    let outcome = match invocation.input_mode {
        ScriptInputMode::File => {
            let mut spec = CapsuleSpec::locked_down();
            if let Some(parent) = path.parent() {
                spec.filesystem.read_roots.push(parent.to_path_buf());
            }
            for root in [
                "/bin",
                "/usr",
                "/lib",
                "/lib64",
                "/etc",
                "/System",
                "/private/var/select",
            ] {
                let root = std::path::PathBuf::from(root);
                if root.exists() {
                    spec.filesystem.read_roots.push(root);
                }
            }
            spec.environment.allow = ["PATH", "LANG", "TERM"]
                .iter()
                .map(|name| name.to_string())
                .collect();
            let mut args = invocation.args.clone();
            args.push(path.to_string_lossy().into_owned());
            crate::cli::capsule::run_to_completion(
                &spec,
                &invocation.interpreter,
                &args,
                None,
                &[],
                crate::cli::capsule::DegradedPolicy::FailClosed,
            )
        }
        ScriptInputMode::Stdin => {
            let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
                "forced stdin execution reached the capsule without a trusted interpreter identity"
                    .to_string()
            })?;
            let mut spec = crate::cli::capsule::supervised_stdin_spec();
            let (read_roots, runtime_path) = validated_stdin_runtime(program)?;
            spec.filesystem.read_roots = read_roots;
            // PATH is supplied as explicit, validated child data. It is not
            // inherited from the ambient lookup that selected the interpreter.
            spec.environment.allow = ["PATH", "LANG", "TERM"]
                .iter()
                .map(|name| name.to_string())
                .collect();
            crate::cli::capsule::run_to_completion_with_stdin(
                &spec,
                program,
                &invocation.args,
                reviewed_bytes,
                // Stdin mode never needs the downloaded file path. A fixed
                // system-owned cwd avoids inheriting an inaccessible or
                // attacker-influenced caller directory into the capsule.
                Some(std::path::Path::new("/")),
                &[("PATH".to_string(), runtime_path)],
            )
        }
    };
    match outcome {
        Ok(outcome) => {
            eprintln!(
                "tirith run: script executed contained via '{}' [{}]",
                outcome.backend_id,
                outcome.coverage_summary()
            );
            Ok(outcome.exit_code)
        }
        Err(refused) => Err(format!(
            "capsule refused to run the script: {}",
            refused.reason
        )),
    }
}

/// Canonicalize and validate the narrow read/runtime roots for a forced stdin
/// interpreter. This deliberately avoids the former broad `/usr`, `/etc`, and
/// `/System` grants. System loader roots, standard executable directories, the
/// exact interpreter directory, and a Homebrew Cellar (only when the selected
/// executable lives there) are the only additions.
fn validated_stdin_runtime(
    program: &tirith_core::trusted_child::TrustedExecutable,
) -> Result<(Vec<std::path::PathBuf>, String), String> {
    let mut read_roots = Vec::new();
    let mut path_dirs = Vec::new();

    let program_dir = program
        .path()
        .parent()
        .ok_or_else(|| "trusted interpreter has no parent directory".to_string())?;
    push_validated_root(&mut read_roots, program_dir)?;
    push_validated_root(&mut path_dirs, program_dir)?;
    if program.launch_path() != program.path() {
        let snapshot_dir = program.launch_path().parent().ok_or_else(|| {
            "bound trusted interpreter snapshot has no parent directory".to_string()
        })?;
        // The snapshot is executable content fixed before network I/O. It is a
        // read root only; it never broadens PATH resolution for child commands.
        push_validated_root(&mut read_roots, snapshot_dir)?;
    }

    for directory in ["/bin", "/usr/bin"] {
        push_existing_validated_root(&mut read_roots, directory)?;
        push_existing_validated_root(&mut path_dirs, directory)?;
    }

    #[cfg(target_os = "linux")]
    for root in [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/share",
        "/etc/ld.so.cache",
    ] {
        push_existing_validated_root(&mut read_roots, root)?;
    }

    #[cfg(target_os = "macos")]
    for root in [
        "/usr/lib",
        "/usr/share",
        "/System/Library",
        "/Library/Frameworks",
    ] {
        push_existing_validated_root(&mut read_roots, root)?;
    }

    for (cellar, bin) in [
        ("/opt/homebrew/Cellar", "/opt/homebrew/bin"),
        ("/usr/local/Cellar", "/usr/local/bin"),
        (
            "/home/linuxbrew/.linuxbrew/Cellar",
            "/home/linuxbrew/.linuxbrew/bin",
        ),
    ] {
        let cellar_path = std::path::Path::new(cellar);
        let canonical_cellar = cellar_path
            .canonicalize()
            .unwrap_or_else(|_| cellar_path.to_path_buf());
        if program.path().starts_with(&canonical_cellar) {
            push_validated_root(&mut read_roots, cellar_path)?;
            push_existing_validated_root(&mut read_roots, bin)?;
            push_existing_validated_root(&mut path_dirs, bin)?;
        }
    }

    let runtime_path = std::env::join_paths(path_dirs.iter()).map_err(|error| {
        format!("cannot construct validated runtime PATH for the interpreter: {error}")
    })?;
    let runtime_path = runtime_path.into_string().map_err(|_| {
        "validated runtime PATH is not valid UTF-8 and cannot enter the capsule environment"
            .to_string()
    })?;
    Ok((read_roots, runtime_path))
}

fn push_existing_validated_root(
    roots: &mut Vec<std::path::PathBuf>,
    candidate: &str,
) -> Result<(), String> {
    let path = std::path::Path::new(candidate);
    if path.exists() {
        push_validated_root(roots, path)?;
    }
    Ok(())
}

fn push_validated_root(
    roots: &mut Vec<std::path::PathBuf>,
    candidate: &std::path::Path,
) -> Result<(), String> {
    if !candidate.is_absolute() {
        return Err(format!(
            "capsule runtime root is not absolute: {}",
            candidate.display()
        ));
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|error| format!("validate runtime root {}: {error}", candidate.display()))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("stat runtime root {}: {error}", canonical.display()))?;
    if !(metadata.is_dir() || metadata.is_file()) {
        return Err(format!(
            "capsule runtime root is neither a file nor directory: {}",
            canonical.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(format!(
                "capsule runtime root is world-writable: {}",
                canonical.display()
            ));
        }
    }
    if !roots.contains(&canonical) {
        roots.push(canonical);
    }
    Ok(())
}
