#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use tirith_core::trusted_child::{
    run, sanitized_path, CaptureStream, ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable,
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
fn trusted_lookup_rejects_a_denied_symlink_to_a_system_tool() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    symlink("/bin/sh", denied.join("probe")).unwrap();
    let path = std::env::join_paths([&denied]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, &[denied]).unwrap_err();
    assert!(error.to_string().contains("untrusted"));
}

#[test]
fn sanitized_path_rejects_a_denied_symlink_to_a_system_directory() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    let linked = denied.join("system-tools");
    symlink("/usr/bin", &linked).unwrap();
    let path = std::env::join_paths([&linked]).unwrap();

    assert!(sanitized_path(&path, &[denied]).is_empty());
}

#[test]
fn denied_origin_cannot_be_hidden_with_parent_components() {
    let temp = tempfile::tempdir().unwrap();
    let safe = temp.path().join("safe");
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&safe).unwrap();
    std::fs::create_dir(&denied).unwrap();
    make_executable(&denied.join("probe"), "#!/bin/sh\nexit 0\n");
    let traversal = safe.join("..").join("repo-bin");
    let path = std::env::join_paths([&traversal]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, std::slice::from_ref(&denied))
        .unwrap_err();
    assert!(error.to_string().contains("untrusted"));
    assert!(sanitized_path(&path, &[denied]).is_empty());
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
fn trusted_lookup_rejects_symlink_entry_inside_denied_root() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    std::os::unix::fs::symlink("/bin/sh", denied.join("probe")).unwrap();
    let path = std::env::join_paths([&denied]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, &[denied]).unwrap_err();
    assert!(error.to_string().contains("untrusted"), "{error}");
}

#[test]
fn trusted_lookup_rejects_world_writable_directory_hierarchy() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("group-writable-bin");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    let probe = writable.join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");

    let error = TrustedExecutable::from_absolute(&probe, &[]).unwrap_err();
    assert!(
        error.to_string().contains("untrusted group") || error.to_string().contains("everyone"),
        "{error}"
    );
}

#[test]
fn trusted_lookup_rejects_current_owner_group_writable_directory_hierarchy() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("group-writable-bin");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
    let probe = writable.join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");

    let error = TrustedExecutable::from_absolute(&probe, &[]).unwrap_err();
    assert!(error.to_string().contains("untrusted group"), "{error}");
}

#[cfg(target_vendor = "apple")]
#[test]
fn trusted_lookup_rejects_mutating_macos_acl_outside_mode_bits() {
    let temp = tempfile::tempdir().unwrap();
    let probe = temp.path().join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow write"])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(status.success(), "test must install a macOS extended ACL");
    assert_eq!(
        std::fs::metadata(&probe).unwrap().permissions().mode() & 0o022,
        0,
        "the regression must exercise ACL authority invisible to mode bits"
    );

    let error = TrustedExecutable::from_absolute(&probe, &[]).unwrap_err();
    assert!(error.to_string().contains("ACL grants mutation"), "{error}");
}

#[cfg(target_vendor = "apple")]
#[test]
fn trusted_lookup_allows_deny_only_macos_acl() {
    let temp = tempfile::tempdir().unwrap();
    let probe = temp.path().join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone deny delete"])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(status.success(), "test must install a macOS deny-only ACL");

    TrustedExecutable::from_absolute(&probe, &[])
        .expect("a deny-only ACL does not grant hidden mutation authority");
}

#[test]
fn sanitized_child_path_omits_group_writable_directory() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("shared-bin");
    let private = temp.path().join("private-bin");
    std::fs::create_dir(&writable).unwrap();
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::env::join_paths([&writable, &private]).unwrap();

    let sanitized = sanitized_path(&path, &[]);
    let entries = std::env::split_paths(&sanitized).collect::<Vec<_>>();
    assert!(!entries.contains(&writable.canonicalize().unwrap()));
    assert!(entries.contains(&private.canonicalize().unwrap()));
}

#[test]
fn supervisor_refuses_executable_identity_drift_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let probe = temp.path().join("probe");
    let marker = temp.path().join("executed");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");
    let executable = TrustedExecutable::from_absolute(&probe, &[]).unwrap();

    make_executable(
        &probe,
        &format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
    );
    let spec = ChildSpec::new(
        std::iter::empty::<&str>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    let outcome = run(&executable, &spec);
    assert!(
        matches!(outcome, ChildOutcome::SpawnError(_)),
        "{outcome:?}"
    );
    assert!(!marker.exists(), "changed executable must not run");
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

#[test]
fn supervisor_cleans_up_a_descendant_after_the_parent_completed() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("detached-grandchild.pid");
    let body = format!(
        "sleep 30 </dev/null >/dev/null 2>&1 & printf '%s' $! > '{}'",
        pid_file.display()
    );
    let args = [OsStr::new("-c"), OsStr::new(&body)];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(3), 64, 64));

    let outcome = run(&shell(), &spec);
    assert!(
        matches!(outcome, ChildOutcome::Completed { .. }),
        "{outcome:?}"
    );

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
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !alive,
        "a descendant that closed stdio must not survive successful completion"
    );
}
