# Roadmap

This roadmap separates published behavior, code already merged after the last
release, and capabilities that exist only on the current integration stack.
Presence in the repository or a pull request is not the same as availability
in a package-manager release.

The [capability matrix](capability-matrix.md) is the per-command companion: it
records what each command inspects and whether policy fully governs that
surface. It is generated from the versioned
[`capability-manifest.toml`](capability-manifest.toml) and guarded by a CI test.

## Published: 0.3.3

The latest published release line established the current shell, CLI, policy,
and threat-intelligence foundation:

- interactive zsh, bash, fish, PowerShell, and nushell integrations with
  explicit blocking/warn-only/degraded states;
- command, paste, URL, repository, AI-config, terminal-output, and hidden
  content analysis;
- signed ThreatDB v1 package/domain/IP reputation and optional runtime
  enrichment with a hard offline boundary;
- policy, trust, custom rules, warning accumulation, audit/export, doctor,
  daemon, LSP, GitHub Action, pre-commit, and SARIF surfaces;
- initial agent integrations, MCP server/gateway, configuration locking, caller
  origin, and workstation/persistence guards;
- signed release checksums, package-manager-aware updates, provenance display,
  and self-verification.

See the historical [0.3.3 changelog](../CHANGELOG.md#033---2026-06-19) for the
exact release contents.

## Merged after 0.3.3

These capabilities are on the default branch but have not yet appeared in a
new tagged release:

- **Python artifact pipeline:** typed coverage outcomes, byte/magic
  classification, a hardened streaming wheel reader, RECORD/ownership
  integrity, startup-hook analysis, native ELF/Mach-O/PE triage, execution
  chains, artifact-set correlation, and `package inspect` product wiring.
- **Python package firewall:** quarantine, exact digest binding, enrolled
  resolver identity, native approval authority, contained hash-pinned pip
  installation, environment verification, provenance graphs, release diffs,
  PyPI attestation binding, and receipts. Enforcement is x86_64 Linux only.
- **ThreatDB v2:** artifact/file hashes, malicious URLs, campaign and behavior
  indices, signed dual-format publication, monotonic rollback protection, and a
  staged v1/v2 cutover.
- **Detection expansion:** structural GitHub Actions findings, reverse shells,
  suspicious inline interpreters, additional credential formats, PDF depth and
  compressed-stream guards, and safe terminal rendering.
- **Systemic hardening:** supervised execution, transactional setup/install and
  state publication, no-follow/retained-handle identity checks, bounded
  network/feed/MCP/artifact work, centralized redaction, private audit/receipt
  state, license-event ordering, and immutable release inputs.

## Targeted for 0.4.0

These capabilities are present on the current integration stack and are
planned for 0.4.0 after final integration and release verification:

- bounded Web3 command grammar and `web3_guard` policy for Cast, Forge,
  Hardhat, Solana, and Anchor;
- untrusted task envelopes, `task_gate`, diagnostic `task check`, and the
  preview-gated MCP task tool;
- fail-closed `capsule run --preset untrusted-project` on supported x86_64
  Linux hosts;
- cross-workflow CI artifact-flow analysis, Chromium-family extension audit,
  npm provenance receipts, and build/deployment receipts;
- sensitive wallet/secret/path handling and extended exfiltration correlation;
- bounded MCP structured output, blob, MIME, URI, redaction, descriptor, and
  source/config identity controls;
- 19 named `tirith setup` hosts, including blocking Prime Agent, OMP, Cline,
  and OpenHands hooks, a Windows PowerShell Cline wrapper, and Prime Agent
  IPython execution-vector extraction;
- order-independent package enrichment with typed incomplete outcomes instead
  of timeout-derived malicious-package warnings;
- GLIBC 2.28 Linux release compatibility, canonical Debian/RPM bytes, and
  expanded crates/npm/container/Chocolatey/AUR publication gates.

The [draft 0.4.0 release guide](release-notes-0.4.0.md) is the detailed feature
and upgrade inventory.

## Required before tagging 0.4.0

- Integrate the entire stack onto the final default-branch tip and review the
  resulting tree and conflict resolutions.
- Resolve or explicitly defer every changelog known issue, including the
  nested-shell, `forge create`, inert Web3 policy, command-card authoring,
  task-audit, and full/read-only temporary-directory gaps.
- Run the required Linux, macOS, and Windows matrix on the exact release tree,
  including native Linux containment and real-host-shaped integration checks.
- Complete the Web3/task and ThreatDB v2 rollout playbooks.
- Make the 0.4.0 release commit, package the workspace, and publish only through
  the protected single-use tag workflow.
- Verify every public registry and artifact after publication. Chocolatey and
  Homebrew core may lag the GitHub release and must be described honestly.

## Later

- Broader containment beyond x86_64 Linux without weakening the current
  fail-closed capability contract.
- Kernel/runtime interception for arbitrary Python and notebook process
  creation; source-level IPython extraction cannot provide that guarantee.
- Broader host certification and recurring real-agent end-to-end tests across
  every supported integration and platform.
- Expanded task-effect modelling and complete audit coverage at every owned
  irreversible transition.
- Full Web3 command coverage, live command-card authoring/enforcement, and
  activation or removal of currently inert policy fields.
- Continuous browser/deployment monitoring and reproducible-build workflows,
  if added as explicit products rather than inferred from point-in-time
  receipts.
