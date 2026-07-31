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

    let mut spec = CapsuleSpec::locked_down();
    // The interpreter needs to read the private script and the system roots that
    // hold the interpreter + its runtime. Retain the locked-down spec and let
    // the backend coverage gate decide whether it can be enforced.
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
        let p = std::path::PathBuf::from(root);
        if p.exists() {
            spec.filesystem.read_roots.push(p);
        }
    }
    spec.environment.allow = ["PATH", "LANG", "TERM"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let outcome = match invocation.input_mode {
        ScriptInputMode::File => {
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
        ScriptInputMode::Stdin => crate::cli::capsule::run_to_completion_with_stdin(
            &spec,
            &invocation.interpreter,
            &invocation.args,
            reviewed_bytes,
            &[],
            crate::cli::capsule::DegradedPolicy::FailClosed,
        ),
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
