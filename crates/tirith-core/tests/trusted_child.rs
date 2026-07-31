#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use tirith_core::trusted_child::{
    run, CaptureStream, ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable,
};

fn make_executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
}

fn shell() -> TrustedExecutable {
    TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[]).unwrap()
}

#[test]
fn trusted_lookup_rejects_a_denied_first_path_hit() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    let trusted = temp.path().join("installed-bin");
    std::fs::create_dir(&denied).unwrap();
    std::fs::create_dir(&trusted).unwrap();
    make_executable(&denied.join("probe"), "#!/bin/sh\nexit 0\n");
    make_executable(&trusted.join("probe"), "#!/bin/sh\nexit 0\n");
    let path = std::env::join_paths([&denied, &trusted]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, &[denied]).unwrap_err();
    assert!(error.to_string().contains("untrusted"));
}

#[test]
fn trusted_lookup_preserves_a_legitimate_absolute_tool() {
    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join("installed-bin");
    std::fs::create_dir(&installed).unwrap();
    let probe = installed.join("probe");
    make_executable(&probe, "#!/bin/sh\nprintf legitimate\n");
    let path = std::env::join_paths([&installed]).unwrap();

    let executable = TrustedExecutable::resolve_on_path("probe", &path, &[]).unwrap();
    assert_eq!(executable.path(), probe.canonicalize().unwrap());
}

#[test]
fn supervisor_preserves_short_legitimate_output_and_status() {
    let args = [OsStr::new("-c"), OsStr::new("printf legitimate")];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(2), 64, 64));

    match run(&shell(), &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => {
            assert!(status.success());
            assert_eq!(stdout, b"legitimate");
            assert!(stderr.is_empty());
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn supervisor_enforces_the_capture_cap_before_retaining_excess() {
    let args = [OsStr::new("-c"), OsStr::new("printf 12345")];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(2), 4, 64));

    assert!(matches!(
        run(&shell(), &spec),
        ChildOutcome::OutputLimitExceeded {
            stream: CaptureStream::Stdout,
            ..
        }
    ));
}

#[test]
fn supervisor_deadline_is_not_defeated_by_a_descendant_holding_stdout() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("grandchild.pid");
    let body = format!("sleep 30 & printf '%s' $! > '{}'", pid_file.display());
    let args = [OsStr::new("-c"), OsStr::new(&body)];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_millis(300), 64, 64));

    let started = Instant::now();
    let outcome = run(&shell(), &spec);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(matches!(outcome, ChildOutcome::Timeout { .. }));

    let pid: libc::pid_t = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut alive = true;
    for _ in 0..100 {
        alive = unsafe { libc::kill(pid, 0) } == 0;
        if !alive {
            break;
        }
        // A killed grandchild can remain visible briefly as an orphaned zombie
        // until the platform reaper collects it.
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !alive,
        "the descendant process must be terminated with its group"
    );
}
