#![no_main]
//! Fuzz target for the untrusted task envelope (`tirith_core::task`).
//!
//! An envelope is an attacker-controlled JSON document that reaches the effect
//! decision. The bytes here are the exact bytes a caller would hand
//! `parse_envelope`.
//!
//! Contract under fuzz:
//!
//!   * never panic, on any input, including deeply nested and truncated JSON;
//!   * a parse failure is a refusal, never a clean decision: a document that
//!     does not parse must not produce an allowed effect anywhere;
//!   * a document's own claim never becomes authority: no assigned source is
//!     ever trusted, so a hostile envelope cannot talk its way past the gate;
//!   * the decision is a subset of what was inferred, which is what makes
//!     "asking never grants" structural rather than a property of one branch;
//!   * assessment is deterministic: the same document twice gives the same
//!     projection.
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

use tirith_core::effects::{BoundaryCapability, CommandEffectKind};
use tirith_core::task::{
    assign_provenance, decide, decision_projection, parse_envelope, validate_envelope,
    IngressAdapter,
};
use tirith_core::web3_policy::{TaskGateMode, TaskGatePolicy, Web3GuardAction};

fn enforcing_gate() -> TaskGatePolicy {
    TaskGatePolicy {
        mode: TaskGateMode::Enforce,
        effects_requiring_verified_provenance: [CommandEffectKind::PackageInstall]
            .into_iter()
            .collect(),
        effects_denied_for_untrusted_sources: [
            CommandEffectKind::PersistenceChange,
            CommandEffectKind::PolicyChange,
            CommandEffectKind::Web3Write,
            CommandEffectKind::Web3SignerUse,
        ]
        .into_iter()
        .collect(),
        action_incomplete_analysis: Web3GuardAction::Block,
    }
}

/// Wrap `data` as attacker-controlled CONTENT inside a well-formed envelope.
///
/// `TaskEnvelopeInput` is `#[serde(default, deny_unknown_fields)]`, so a random
/// byte string deserializes into one about never. With `fuzz/corpus/`
/// gitignored, every CI run starts cold, and a PR-length run only ever reached
/// the four contracts below with the literal document `{}` — an envelope with
/// no sources and no actions, on which all four hold vacuously. Wrapping the
/// same bytes in a valid skeleton puts the fuzzer's output where it decides
/// something: the source content, the locator, and every action arm, which is
/// what `assign_provenance`, `infer_effects` and the denial branches read.
fn wrap_as_envelope_content(data: &str) -> String {
    serde_json::json!({
        "task_id": data,
        "sources": [
            { "claimed_source": "issue_body", "content": data, "locator": data },
            { "claimed_source": "repository_config", "content": data },
            { "claimed_source": "unknown", "content": data },
        ],
        "actions": [
            { "shell": { "command": data } },
            { "config_write": { "path": data } },
            { "package_install": { "ecosystem": data, "package": data } },
            { "narrative": { "text": data } },
        ],
        // Asking for the denied set on every input keeps the "requesting never
        // grants" branch live rather than dependent on the fuzzer guessing it.
        "requested_effects": [
            "package_install",
            "persistence_change",
            "policy_change",
            "secret_read",
            "web3_write",
            "web3_signer_use",
        ],
    })
    .to_string()
}

fn assert_contracts_hold(envelope: &tirith_core::task::TaskEnvelopeInput) {
    let rejections = validate_envelope(envelope);

    for adapter in [
        IngressAdapter::OperatorIngest,
        IngressAdapter::GithubIssue,
        IngressAdapter::GithubPullRequest,
        IngressAdapter::FileRead,
        IngressAdapter::HttpFetch,
        IngressAdapter::Unattributed,
    ] {
        let provenance = envelope
            .sources
            .iter()
            .map(|source| assign_provenance(source, adapter, None, None))
            .collect::<Vec<_>>();

        // No modelled source is trusted. A document that could flip this would
        // have talked its way past the untrusted-source denials.
        for assigned in &provenance {
            assert!(
                !assigned.is_source_trusted(),
                "an untrusted document produced a trusted source assignment"
            );
        }

        for boundary in [
            BoundaryCapability::ObserveOnly,
            BoundaryCapability::BoundaryDependent,
            BoundaryCapability::Enforceable,
        ] {
            let decision = decide(envelope, provenance.clone(), &enforcing_gate(), boundary);

            // Allowed is always a subset of inferred: the decision can narrow
            // what an action does, never widen it.
            assert!(
                decision.allowed_effects.is_subset(&decision.inferred_effects),
                "the decision allowed an effect the action does not have"
            );
            // Requesting an effect never adds it.
            let unrequestable: BTreeSet<_> = decision
                .allowed_effects
                .difference(&decision.inferred_effects)
                .collect();
            assert!(unrequestable.is_empty());

            // Under an enforcing gate, an effect denied for untrusted sources
            // can never be allowed: every source here is untrusted.
            if decision.mode == TaskGateMode::Enforce {
                for kind in [
                    CommandEffectKind::PersistenceChange,
                    CommandEffectKind::PolicyChange,
                    CommandEffectKind::Web3Write,
                    CommandEffectKind::Web3SignerUse,
                ] {
                    assert!(
                        !decision.allowed_effects.contains(&kind),
                        "an enforcing gate allowed an effect denied for untrusted sources"
                    );
                }
            }

            // An envelope that failed validation cannot be reported complete.
            if !rejections.is_empty() {
                assert!(
                    !decision.complete,
                    "a rejected envelope produced a complete decision"
                );
            }

            // Determinism, including the projection every surface renders from.
            let repeat = decide(envelope, provenance.clone(), &enforcing_gate(), boundary);
            assert_eq!(
                decision_projection(&decision, &rejections),
                decision_projection(&repeat, &rejections),
                "task assessment is not deterministic"
            );
        }
    }
}

fuzz_target!(|data: &str| {
    // The exact bytes a caller would hand `parse_envelope`. A refusal is the
    // whole outcome for this half: nothing downstream may run on a document
    // that did not parse.
    if let Ok(envelope) = parse_envelope(data) {
        assert_contracts_hold(&envelope);
    }

    // And the same bytes as content inside a document that does parse, so the
    // decision path runs on every input rather than on the one in ~85,000 that
    // happens to be a deserializable envelope.
    let wrapped = wrap_as_envelope_content(data);
    if let Ok(envelope) = parse_envelope(&wrapped) {
        assert_contracts_hold(&envelope);
    }
});
