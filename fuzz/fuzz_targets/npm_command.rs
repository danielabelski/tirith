#![no_main]
//! Fuzz target for the npm-family command grammar (`tirith_core::npm_command`).
//!
//! This grammar decides whether a shell line reaches a package registry, and
//! its output feeds the task effect inferrer. Everything it produces must
//! therefore be bounded and stable regardless of what the line looks like.
//!
//! Contract under fuzz:
//!
//!   * never panic, because every shape is a classification, never an abort;
//!   * the package list per invocation stays under
//!     `MAX_PACKAGES_PER_INVOCATION`, so a line naming a million packages
//!     cannot allocate a million entries;
//!   * a truncated parse says so rather than reporting a short list as
//!     complete;
//!   * parsing is deterministic and idempotent: the same bytes twice give the
//!     same invocations, so a decision cannot depend on parse order.
use libfuzzer_sys::fuzz_target;

use tirith_core::npm_command::{self, MAX_PACKAGES_PER_INVOCATION};
use tirith_core::tokenize::ShellType;

fuzz_target!(|data: &str| {
    for shell in [
        ShellType::Posix,
        ShellType::Fish,
        ShellType::PowerShell,
        ShellType::Cmd,
    ] {
        let first = npm_command::parse_input(data, shell);
        let second = npm_command::parse_input(data, shell);
        assert_eq!(
            first.len(),
            second.len(),
            "npm grammar is not deterministic in invocation count"
        );

        for (left, right) in first.iter().zip(second.iter()) {
            assert_eq!(
                left.explicit_packages.len(),
                right.explicit_packages.len(),
                "npm grammar is not deterministic in package count"
            );
            assert_eq!(
                left.operation, right.operation,
                "npm grammar is not deterministic in operation"
            );
            assert!(
                left.explicit_packages.len() <= MAX_PACKAGES_PER_INVOCATION,
                "npm package list exceeded its declared bound"
            );
            // A list that hit the cap must be reported as truncated, or a
            // caller would treat a partial list as the whole dependency set.
            if left.explicit_packages.len() == MAX_PACKAGES_PER_INVOCATION {
                assert!(
                    left.truncated,
                    "a capped npm package list did not report truncation"
                );
            }
        }
    }

    // The package-spec parser takes the same untrusted words.
    let _ = npm_command::parse_npm_package_spec(data);
    let _ = npm_command::is_package_runner_name(data);
});
