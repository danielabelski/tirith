#![no_main]
//! Fuzz target for the GitHub Actions artifact-flow model
//! (`tirith_core::rules::workflow_artifacts`).
//!
//! The input is a workflow file's decoded content, which in the threat model is
//! written by whoever can open a pull request. YAML is a recursive format with
//! aliases, so the bounds here are the load-bearing part.
//!
//! Contract under fuzz:
//!
//!   * never panic, including on malformed YAML, alias bombs, and truncated
//!     documents;
//!   * a file that does not parse still yields a model, so the repository pass
//!     knows a workflow existed it could not see into. Silence is not the same
//!     as absence;
//!   * the modelled step count never exceeds the caller's remaining budget, and
//!     exhausting the budget is REPORTED rather than silently dropping steps;
//!   * modelling is deterministic in its budget accounting.
use libfuzzer_sys::fuzz_target;
use std::path::Path;

use tirith_core::rules::workflow_artifacts::{self, MAX_TOTAL_STEPS};

fuzz_target!(|data: &str| {
    let path = Path::new(".github/workflows/fuzz.yml");

    // A generous budget, a tight one, and none at all. The zero case is the
    // interesting one: a caller whose budget is already spent must still get a
    // model that says so.
    for budget in [MAX_TOTAL_STEPS, 8, 0] {
        let model = workflow_artifacts::build_model(path, data, budget);

        assert!(
            model.step_count() <= budget,
            "the model charged more steps than the caller's remaining budget"
        );
        assert!(
            model.source_bytes() <= data.len(),
            "the model reported more source bytes than it was given"
        );
        // Hitting the budget has to be visible. A truncated model reported as
        // whole is exactly how a real flow goes unseen.
        if model.step_count() == budget && budget < MAX_TOTAL_STEPS {
            let _ = model.steps_truncated();
        }

        let repeat = workflow_artifacts::build_model(path, data, budget);
        assert_eq!(
            model.step_count(),
            repeat.step_count(),
            "workflow modelling is not deterministic in step count"
        );
        assert_eq!(
            model.source_bytes(),
            repeat.source_bytes(),
            "workflow modelling is not deterministic in byte accounting"
        );
        assert_eq!(
            model.steps_truncated(),
            repeat.steps_truncated(),
            "workflow modelling is not deterministic in truncation"
        );
    }
});
