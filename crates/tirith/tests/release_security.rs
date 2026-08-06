//! Release-profile security controls that must survive the CLI's default
//! feature graph. The release workflow runs this target with `--release` before
//! packaging so a feature-gated security regression cannot ship silently.

use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use tirith_core::artifact::{ArtifactIdentity, ArtifactInspection, InspectionSubject};
use tirith_core::threatdb::{
    Confidence, Ecosystem, ThreatDb, ThreatDbFormat, ThreatDbWriter, ThreatSource,
};
use tirith_core::verdict::{action_from_findings, Action, RuleId, Severity};

#[test]
fn default_cli_feature_graph_blocks_a_known_malicious_artifact_hash() {
    let malicious_sha = [0xA5; 32];
    let signing_key = SigningKey::from_bytes(&[0x17; 32]);
    let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
    writer.add_artifact_sha256(
        malicious_sha,
        ThreatSource::OssfMalicious,
        Confidence::Confirmed,
        true,
        Some("release-regression"),
    );
    let bytes = writer
        .build_format(ThreatDbFormat::V2, &signing_key)
        .expect("build signed v2 test database");
    let db = ThreatDb::from_bytes(bytes, 0).expect("load signed v2 test database");

    let inspection = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
        ecosystem: Ecosystem::PyPI,
        name: "release-regression".to_string(),
        version: Some("1.0.0".to_string()),
        filename: "release_regression-1.0.0-py3-none-any.whl".to_string(),
        sha256: malicious_sha
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }));
    let findings = tirith_core::artifact::correlate::correlate_inspection_findings(
        &inspection,
        &[],
        Some(&db),
    );

    assert!(findings.iter().any(|finding| {
        finding.rule_id == RuleId::ArtifactKnownMalicious && finding.severity == Severity::Critical
    }));
    assert_eq!(action_from_findings(&findings), Action::Block);
}

fn yaml_key<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> &'a serde_yaml::Value {
    mapping
        .get(serde_yaml::Value::String(key.to_string()))
        .unwrap_or_else(|| panic!("release workflow is missing {key:?}"))
}

#[test]
fn release_workflow_keeps_manual_dispatch_non_publishing() {
    let workflow_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".github/workflows/release.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("read release workflow");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&workflow).expect("release workflow must be valid YAML");
    let root = document
        .as_mapping()
        .expect("release workflow root mapping");

    let triggers = yaml_key(root, "on")
        .as_mapping()
        .expect("release workflow trigger mapping");
    let push = yaml_key(triggers, "push")
        .as_mapping()
        .expect("release push trigger mapping");
    let tags = yaml_key(push, "tags")
        .as_sequence()
        .expect("release tag filter");
    assert_eq!(
        tags,
        &[serde_yaml::Value::String("v*".to_string())],
        "release pushes must remain version-tag-only"
    );

    let dispatch = yaml_key(triggers, "workflow_dispatch")
        .as_mapping()
        .expect("manual dispatch mapping");
    let inputs = yaml_key(dispatch, "inputs")
        .as_mapping()
        .expect("manual dispatch inputs");
    let dry_run = yaml_key(inputs, "dry_run")
        .as_mapping()
        .expect("dry-run input mapping");
    assert_eq!(
        yaml_key(dry_run, "default").as_bool(),
        Some(true),
        "manual dispatch must default to a non-publishing dry run"
    );

    // These four jobs only build/test artifacts. Every other current or future
    // job is part of package attestation/publication and must require a real
    // push event as well as a v* ref. This catches a manual dispatch that selects
    // an existing tag: `github.ref` alone is not an adequate publication gate.
    let dry_run_jobs: HashSet<&str> = ["enforcement-check", "completions", "build", "smoke-test"]
        .into_iter()
        .collect();
    let jobs = yaml_key(root, "jobs")
        .as_mapping()
        .expect("release workflow jobs mapping");
    for (job_name, job) in jobs {
        let job_name = job_name.as_str().expect("string release job name");
        if dry_run_jobs.contains(job_name) {
            continue;
        }
        let job = job.as_mapping().expect("release job mapping");
        let condition = yaml_key(job, "if")
            .as_str()
            .expect("publication job condition");
        assert!(
            condition.contains("github.event_name == 'push'")
                && condition.contains("startsWith(github.ref, 'refs/tags/v')"),
            "release job {job_name:?} must be gated to a pushed v* tag, got {condition:?}"
        );
    }
}
