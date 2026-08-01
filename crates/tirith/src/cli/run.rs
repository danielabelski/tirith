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
    // Structured stdout must contain exactly one trusted envelope. An executed
    // remote script controls its own stdout, so permitting execution in JSON mode
    // would let it prepend forged objects or make the stream unparsable. Refuse
    // before runner setup (and therefore before DNS/download/confirmation).
    if json && !no_exec {
        let error = serde_json::json!({
            "error": "tirith run JSON output is inspection-only; pass --no-exec or omit --json before executing a remote script"
        });
        if serde_json::to_writer(std::io::stdout().lock(), &error).is_err() {
            eprintln!("tirith: failed to write JSON output");
        }
        println!();
        return 1;
    }

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
            let target_argv0 = invocation
                .interpreter
                .parse::<tirith_core::runner::PipeInterpreter>()
                .map_err(|error| {
                    format!("forced stdin execution lost its closed interpreter identity: {error}")
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
                target_argv0,
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
/// exact root-managed interpreter directory are the only additions.
fn validated_stdin_runtime(
    program: &tirith_core::trusted_child::TrustedExecutable,
) -> Result<(Vec<std::path::PathBuf>, String), String> {
    let mut read_roots = Vec::new();
    let mut path_dirs = Vec::new();

    let program_dir = program
        .path()
        .parent()
        .ok_or_else(|| "trusted interpreter has no parent directory".to_string())?;
    push_root_managed_runtime_root(&mut read_roots, program_dir)?;
    push_root_managed_runtime_root(&mut path_dirs, program_dir)?;

    for directory in ["/bin", "/usr/bin"] {
        push_existing_root_managed_runtime_root(&mut read_roots, directory)?;
        push_existing_root_managed_runtime_root(&mut path_dirs, directory)?;
    }

    #[cfg(target_os = "linux")]
    for root in [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/share",
        "/etc/ld.so.cache",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ] {
        push_existing_root_managed_runtime_root(&mut read_roots, root)?;
    }

    #[cfg(target_os = "macos")]
    for root in [
        "/usr/lib",
        "/usr/share",
        "/System/Library",
        "/Library/Frameworks",
    ] {
        push_existing_root_managed_runtime_root(&mut read_roots, root)?;
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

fn push_existing_root_managed_runtime_root(
    roots: &mut Vec<std::path::PathBuf>,
    candidate: &str,
) -> Result<(), String> {
    let path = std::path::Path::new(candidate);
    if path.exists() {
        push_root_managed_runtime_root(roots, path)?;
    }
    Ok(())
}

/// Add a system runtime file/directory only after its canonical target and every
/// ancestor are proven root-owned and non-group/world-writable. The bound
/// interpreter alone is insufficient if a same-UID/group writer can replace its
/// dynamic loader, shared library, PATH child, or data root after review.
fn push_root_managed_runtime_root(
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
    for component in canonical.ancestors() {
        use std::os::unix::fs::MetadataExt as _;
        let component_metadata = std::fs::metadata(component).map_err(|error| {
            format!(
                "stat capsule runtime root ancestor {}: {error}",
                component.display()
            )
        })?;
        if !root_managed_metadata_is_secure(component_metadata.uid(), component_metadata.mode()) {
            return Err(format!(
                "capsule runtime root or ancestor is not root-owned and non-group/world-writable: {}",
                component.display()
            ));
        }
    }
    if !roots.contains(&canonical) {
        roots.push(canonical);
    }
    Ok(())
}

#[cfg(unix)]
fn root_managed_metadata_is_secure(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn root_managed_runtime_metadata_rejects_group_writable_or_non_root_inputs() {
        assert!(super::root_managed_metadata_is_secure(0, 0o040755));
        assert!(!super::root_managed_metadata_is_secure(0, 0o040775));
        assert!(!super::root_managed_metadata_is_secure(0, 0o040757));
        assert!(!super::root_managed_metadata_is_secure(501, 0o040755));
    }

    #[cfg(unix)]
    #[test]
    fn root_managed_runtime_path_rejects_a_same_uid_fixture() {
        let fixture = tempfile::tempdir().expect("runtime-root fixture");
        let mut roots = Vec::new();
        let error = super::push_root_managed_runtime_root(&mut roots, fixture.path())
            .expect_err("same-UID runtime roots must fail closed");
        assert!(
            error.contains("not root-owned"),
            "unexpected error: {error}"
        );
        assert!(roots.is_empty());
    }
}
