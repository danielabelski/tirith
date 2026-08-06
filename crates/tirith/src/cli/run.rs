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

    // Every live path now uses the same stopped-target capsule controller. The
    // legacy `--capsule` spelling remains accepted, but omitting it no longer
    // falls back to an ordinary spawn that could run before durable execution
    // state is committed.
    let _capsule_requested = capsule;
    let verified_executor: Option<tirith_core::runner::VerifiedScriptExecutor> =
        Some(Box::new(capsuled_exec));

    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256,
        exec_fn: None,
    };

    let result = match (verified_executor, requested_pipe_invocation) {
        (Some(executor), Some(requested)) => {
            runner::run_with_verified_pipe_executor(opts, requested, executor)
        }
        (Some(executor), None) => runner::run_with_verified_executor(opts, executor),
        (None, Some(_)) => {
            Err("forced stdin execution requires the fail-closed capsule executor".to_string())
        }
        (None, None) => runner::run(opts),
    };
    match result {
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

fn reviewed_file_capsule_spec() -> tirith_core::capsule::CapsuleSpec {
    let spec = tirith_core::capsule::CapsuleSpec::locked_down();
    #[cfg(test)]
    let spec = apply_test_capsule_override(spec);
    spec
}

fn forced_stdin_capsule_spec() -> tirith_core::capsule::CapsuleSpec {
    let spec = crate::cli::capsule::supervised_stdin_spec();
    #[cfg(test)]
    let spec = apply_test_capsule_override(spec);
    spec
}

#[cfg(test)]
#[derive(Clone)]
struct TestCapsuleOverride {
    max_output_bytes: u64,
    wall_clock_seconds: u64,
    write_root: std::path::PathBuf,
}

#[cfg(test)]
std::thread_local! {
    /// Test-only, thread-local tightening of the live `tirith run` capsule.
    /// The executor is synchronous, so this reaches the exact production
    /// `capsuled_exec` function without adding a process environment or CLI
    /// knob that an untrusted script could influence.
    static TEST_CAPSULE_OVERRIDE: std::cell::RefCell<Option<TestCapsuleOverride>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn apply_test_capsule_override(
    mut spec: tirith_core::capsule::CapsuleSpec,
) -> tirith_core::capsule::CapsuleSpec {
    TEST_CAPSULE_OVERRIDE.with(|override_cell| {
        let override_value = override_cell.borrow();
        let Some(override_value) = override_value.as_ref() else {
            return;
        };
        spec.resources.max_output_bytes = Some(override_value.max_output_bytes);
        spec.resources.wall_clock_seconds = Some(override_value.wall_clock_seconds);
        spec.filesystem
            .write_roots
            .push(override_value.write_root.clone());
    });
    spec
}

/// The contained executor for every live `tirith run` (E5). `--capsule` is a
/// legacy compatibility spelling, not an opt-in boundary. Runs the exact typed
/// interpreter invocation through the locked-down OS capsule. File mode receives
/// only the inherited sealed reviewed-script descriptor; no downloaded-script
/// pathname enters argv. Enforcing surface: fail closed when the backend cannot
/// provide the spec's required coverage.
pub(crate) fn capsuled_exec(
    invocation: &ScriptInvocation,
    reviewed_script: tirith_core::runner::ReviewedScript<'_>,
    authorizer: &mut tirith_core::runner::ExecutionAuthorizer,
) -> Result<i32, String> {
    let outcome = match invocation.input_mode {
        ScriptInputMode::File => {
            let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
                "file execution reached the capsule without a trusted interpreter identity"
                    .to_string()
            })?;
            let mut spec = reviewed_file_capsule_spec();
            let (read_roots, runtime_path) = validated_stdin_runtime(program)?;
            spec.filesystem.read_roots = read_roots;
            spec.environment.allow = ["PATH", "LANG", "TERM"]
                .iter()
                .map(|name| name.to_string())
                .collect();
            crate::cli::capsule::run_to_completion_with_reviewed_file(
                &spec,
                program,
                std::ffi::OsStr::new(&invocation.interpreter),
                &invocation.args,
                reviewed_script,
                authorizer,
                Some(std::path::Path::new("/")),
                &[("PATH".to_string(), runtime_path)],
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
            let mut spec = forced_stdin_capsule_spec();
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
                reviewed_script.bytes(),
                authorizer,
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
    #[cfg(target_os = "linux")]
    struct TestCapsuleOverrideGuard(Option<super::TestCapsuleOverride>);

    #[cfg(target_os = "linux")]
    impl TestCapsuleOverrideGuard {
        fn tighten(
            max_output_bytes: u64,
            wall_clock_seconds: u64,
            write_root: &std::path::Path,
        ) -> Self {
            let next = super::TestCapsuleOverride {
                max_output_bytes,
                wall_clock_seconds,
                write_root: write_root.to_path_buf(),
            };
            let previous = super::TEST_CAPSULE_OVERRIDE
                .with(|override_cell| override_cell.replace(Some(next)));
            Self(previous)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestCapsuleOverrideGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            super::TEST_CAPSULE_OVERRIDE.with(|override_cell| {
                override_cell.replace(previous);
            });
        }
    }

    #[cfg(target_os = "linux")]
    struct ScriptServer {
        address: std::net::SocketAddr,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(target_os = "linux")]
    impl ScriptServer {
        fn start(body: &[u8]) -> Self {
            use std::io::{Read as _, Write as _};
            use std::sync::atomic::Ordering;

            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("bind live-run regression server");
            listener
                .set_nonblocking(true)
                .expect("make live-run regression server nonblocking");
            let address = listener.local_addr().expect("read regression address");
            let body = body.to_vec();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_server = std::sync::Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !stop_server.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                                .expect("bound regression request read");
                            let mut request = [0u8; 2048];
                            let _ = stream.read(&mut request);
                            write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .expect("write regression response head");
                            stream
                                .write_all(&body)
                                .expect("write regression response body");
                            stream.flush().expect("flush regression response");
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("live-run regression server failed: {error}"),
                    }
                }
            });
            Self {
                address,
                stop,
                thread: Some(thread),
            }
        }

        fn url(&self) -> String {
            format!("http://{}/script.sh", self.address)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ScriptServer {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;

            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.join().expect("join live-run regression server");
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn sha256_hex(body: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};

        Sha256::digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn execute_live_stdin(body: &[u8]) -> tirith_core::runner::RunResult {
        let server = ScriptServer::start(body);
        let result = tirith_core::runner::run_with_verified_pipe_executor(
            tirith_core::runner::RunOptions {
                url: server.url(),
                no_exec: false,
                interactive: true,
                expected_sha256: Some(sha256_hex(body)),
                exec_fn: None,
            },
            tirith_core::runner::RequestedPipeInvocation {
                interpreter: tirith_core::runner::PipeInterpreter::Bash,
                args: Vec::new(),
            },
            Box::new(super::capsuled_exec),
        );
        drop(server);
        result.expect("live `tirith run` regression transaction")
    }

    #[test]
    fn run_capsule_specs_require_supervised_wall_clock_and_output_limits() {
        for (surface, spec) in [
            ("reviewed file", super::reviewed_file_capsule_spec()),
            ("forced stdin", super::forced_stdin_capsule_spec()),
        ] {
            assert_eq!(
                spec.resources.max_output_bytes,
                Some(16 * 1024 * 1024),
                "{surface} execution must carry a combined output ceiling into the supervised launcher"
            );
            assert_eq!(
                spec.resources.wall_clock_seconds,
                Some(300),
                "{surface} execution must carry a wall-clock deadline into the supervised launcher"
            );
            assert!(
                spec.required_coverage().resource_limits_enforced,
                "{surface} execution must fail closed if the requested resource contract is unavailable"
            );
        }
    }

    /// `repo-0418`: exercise the actual content-bound `tirith run` executor,
    /// including download, policy review, durable authorization, containment,
    /// and target launch. Delayed marker writes prove a killed descendant did
    /// not survive either parent-enforced ceiling; the control proves the same
    /// production entrypoint still permits an ordinary under-limit script.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_run_entrypoint_enforces_wall_output_and_preserves_under_limit_execution() {
        // Live execution requires the operator to confirm on the controlling
        // terminal; a CI job has none, and the confirmation gate is deliberate.
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_err()
        {
            eprintln!("skipping live `tirith run` regression: no controlling terminal");
            return;
        }

        crate::cli::test_harness::with_fake_env(false, |home, _| {
            use crate::cli::test_harness::EnvGuard;

            for directory in ["config", "data", "state", "cache"] {
                std::fs::create_dir_all(home.join(directory))
                    .expect("create isolated live-run state");
            }
            let _config = EnvGuard::set("XDG_CONFIG_HOME", &home.join("config"));
            let _data = EnvGuard::set("XDG_DATA_HOME", &home.join("data"));
            let _state = EnvGuard::set("XDG_STATE_HOME", &home.join("state"));
            let _cache = EnvGuard::set("XDG_CACHE_HOME", &home.join("cache"));
            let _policy = EnvGuard::set("TIRITH_POLICY_ROOT", home);
            let _private = EnvGuard::set(
                "TIRITH_PRIVATE_FETCH_ALLOW",
                std::path::Path::new("127.0.0.1/32"),
            );
            let _no_proxy = EnvGuard::set("NO_PROXY", std::path::Path::new("127.0.0.1,localhost"));
            let _log = EnvGuard::set("TIRITH_LOG", std::path::Path::new("0"));
            let _tirith = EnvGuard::remove("TIRITH");
            let _server_url = EnvGuard::remove("TIRITH_SERVER_URL");
            let _api_key = EnvGuard::remove("TIRITH_API_KEY");
            let _http_proxy = EnvGuard::remove("HTTP_PROXY");
            let _https_proxy = EnvGuard::remove("HTTPS_PROXY");
            let _all_proxy = EnvGuard::remove("ALL_PROXY");
            let _http_proxy_lower = EnvGuard::remove("http_proxy");
            let _https_proxy_lower = EnvGuard::remove("https_proxy");
            let _all_proxy_lower = EnvGuard::remove("all_proxy");

            let marker_root = home.join("markers");
            std::fs::create_dir(&marker_root).expect("create marker root");
            let wall_marker = marker_root.join("wall-survivor");
            let output_marker = marker_root.join("output-survivor");
            let control_marker = marker_root.join("under-limit-ran");

            let _limits = TestCapsuleOverrideGuard::tighten(1024, 1, &marker_root);

            let wall_script = format!(
                "#!/bin/bash\n(sleep 2; printf late > '{}') & wait\n",
                wall_marker.display()
            );
            let wall_started = std::time::Instant::now();
            let wall = execute_live_stdin(wall_script.as_bytes());
            assert!(wall.executed, "the authenticated target reached execution");
            assert_eq!(wall.exit_code, Some(124), "wall overage must be typed");
            assert!(
                wall_started.elapsed() < std::time::Duration::from_secs(5),
                "wall-clock supervision did not terminate promptly"
            );
            std::thread::sleep(std::time::Duration::from_millis(1250));
            assert!(
                !wall_marker.exists(),
                "a wall-clock-terminated descendant survived and wrote a marker"
            );

            let output_script = format!(
                "#!/bin/bash\n(sleep 2; printf late > '{}') & while :; do printf '0123456789abcdef'; done\n",
                output_marker.display()
            );
            let output_started = std::time::Instant::now();
            let output = execute_live_stdin(output_script.as_bytes());
            assert!(
                output.executed,
                "the authenticated target reached execution"
            );
            assert_eq!(output.exit_code, Some(125), "output overage must be typed");
            assert!(
                output_started.elapsed() < std::time::Duration::from_secs(5),
                "combined-output supervision did not terminate promptly"
            );
            std::thread::sleep(std::time::Duration::from_millis(2250));
            assert!(
                !output_marker.exists(),
                "an output-terminated descendant survived and wrote a marker"
            );

            let control_script = format!(
                "#!/bin/bash\nprintf ok\nprintf legitimate > '{}'\n",
                control_marker.display()
            );
            let control = execute_live_stdin(control_script.as_bytes());
            assert!(control.executed);
            assert_eq!(control.exit_code, Some(0));
            assert_eq!(
                std::fs::read(&control_marker).expect("read legitimate marker"),
                b"legitimate"
            );
        });
    }

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
