# Tirith 0.4.0 release guide

> **Draft, not a release announcement.** Version 0.4.0 is the target for the
> changes merged after 0.3.3 plus the current integration stack. Do not describe
> these capabilities as released until the stack is integrated onto the final
> default-branch tree, all required release gates pass there, and the 0.4.0 tag
> and artifacts exist.

## Why 0.4.0

This is a new minor release rather than a 0.3.4 patch. It adds major public
capabilities, commands, policy sections, document schemas, agent integrations,
and platform-specific enforcement boundaries. `0.4.0` communicates that scope
without skipping an unused 0.4 line. The project remains pre-1.0, so callers
should read the compatibility notes below before upgrading.

## Release highlights

### Python artifact inspection and package firewall

- Version intent preserves exact pins, ranges, compatible constraints,
  exclusions, and unresolved requirements through package threat assessment
  instead of flattening them to a package name.
- `tirith package inspect` analyzes wheel files, sets of wheels, or installed
  environments without downloading them.
- A bounded streaming wheel reader rejects traversal, collisions, encrypted
  entries, conflicting distribution metadata, CRC failures, decompression
  abuse, and ambiguous identities.
- Wheel RECORD and installed-environment RECORD verification detect missing,
  modified, unowned, or multiply owned files.
- Python startup execution through `.pth`, `.start`, `sitecustomize`, and
  `usercustomize` is modelled as an execution chain rather than ordinary data.
- ELF, Mach-O, and PE triage finds native extensions and correlates native
  imports, runtime launches, loaders, and payloads.
- Artifact-set inspection can detect a loader in one distribution that reaches
  a payload shipped by another distribution.
- `tirith pkg approve` and `tirith pkg install` bind resolution, exact artifact
  hashes, inspection results, approval state, contained execution, environment
  verification, and a tamper-evident receipt.
- `tirith pkg graph`, `diff`, `attest`, `attest-npm`, `verify-env`, and
  `receipt` expose ownership, execution, release-delta, provenance, integrity,
  and evidence workflows.

The enforcing installer supports pip on x86_64 Linux only. It refuses before
pip starts on other platforms and never falls back to an uncontained install.
npm and Cargo are evidence surfaces, not package-firewall enforcement.

### Threat intelligence v2

- The signed v2 database adds artifact SHA-256, installed-file hash,
  malicious-URL, campaign, and behavior-tag indices to package, domain, and IP
  reputation.
- The compiler, signed index, updater, and loader support v1 and v2 together so
  older clients can keep using v1 during the staged cutover.
- Monotonic sequence checks prevent rollback, publication is transactional,
  and an invalid update cannot replace the signed last-known-good database.
- OpenSSF malicious-package events retain their actual package and version
  semantics. A bounded affected range is no longer promoted to a whole-package
  block, and a resolution timeout is reported as incomplete verification, not
  evidence that a package is malicious.
- The DigitalSide source is implemented but intentionally inactive until its
  freshness and operating contract are approved.

### Byte-classified file and artifact analysis

- Files are classified by magic bytes read through the retained no-follow
  handle, not merely by name or suffix.
- Misnamed, extensionless, malformed, polyglot, archive, native, and unknown
  binary content receives an explicit route and coverage outcome.
- Typed outcomes distinguish a completed clean analysis from unsupported,
  skipped, rejected, or budget-exhausted work.
- Global finding and output budgets preserve Critical, High, and
  `analysis_incomplete` evidence ahead of lower-value output.

### Web3 and untrusted-task boundaries

- A bounded command grammar models state-changing Cast, Forge, Hardhat,
  Solana, and Anchor operations without reading chain state or simulating a
  transaction.
- `web3_guard` can classify network and signer policy, and new findings cover
  state changes, signer risk, and network-policy violations without echoing
  secrets, private paths, or destinations.
- Command-card schema 2 can bind ordered Web3 operations, network identity,
  signer kind, artifact hashes, and policy identity while keeping schema-1
  signing bytes compatible.
- Untrusted task envelopes retain Tirith-assigned provenance through a bounded
  effect decision. `tirith task check` and the preview-gated
  `tirith_check_task` MCP tool are diagnostic and execute nothing.
- The task gate is wired immediately before Tirith-owned irreversible
  transitions. Defaults are inert; enforcement must be explicitly configured.
- `tirith capsule run --preset untrusted-project` copies a project into a held
  ephemeral tree and executes exact argv under fail-closed containment on
  x86_64 Linux with a usable Landlock ABI. Other platforms refuse before copy
  or spawn.

### AI-agent and MCP protection

- `tirith setup` supports 19 named hosts. The complete enforcement, scope, and
  verification matrix is maintained in
  [Agent integrations](../mcp/clients/mcp-only-agents.md).
- New setup paths cover Grok Build, OMP, OpenCode, Vercel Labs fx, Prime Agent,
  Cline, Roo Code, Continue, and OpenHands in addition to the previously
  supported Claude Code, Codex, GitHub Copilot CLI, Cursor, Gemini CLI, Kiro,
  OpenClaw, Pi CLI, VS Code, and Windsurf integrations.
- Prime Agent, OMP, Cline, and OpenHands now receive blocking pre-execution
  hooks where the host exposes one. Cline receives the platform-native
  `PreToolUse` wrapper on POSIX and `PreToolUse.ps1` on Windows.
- Prime Agent's IPython guard extracts shell escapes, shell magics, and common
  Python process-spawn forms, combines the recovered commands, and delegates
  the decision to the Tirith engine. Dynamic or unrecognised execution forms
  fail closed by default.
- Generated Python-backed hooks pin the validated interpreter and Tirith
  executable selected during setup instead of resolving a repository-influenced
  `PATH` at execution time.
- MCP tool and resource output is sanitized by default with bounded structured
  traversal, leaf preservation, cross-leaf detection, strict blob decoding,
  MIME checks, URI rules, and explicit incomplete-analysis failures.
- MCP configuration locking binds source path, server identity, transport,
  descriptor set, declared tools, and code/config drift without persisting raw
  environment values or URL credentials.

MCP registration alone is cooperative: it gives an agent Tirith tools but does
not force a check. Only a supported, enabled, effective host hook, shell gate,
or gateway boundary can automatically withhold execution. Grok Build, Cline,
and OpenHands can still fail open on their side when a hook process crashes or
times out; run each host's verification step after setup and upgrades.

### CI, browser, and provenance evidence

- Directory scans correlate fork-reachable artifact producers with privileged
  `workflow_run` consumers and execution, PATH, publish, or deployment sinks.
- Structural GitHub Actions rules also cover mutable action references,
  privileged trigger hazards, and expression-to-shell injection.
- `tirith browser audit` provides a one-shot, read-only integrity audit of
  Chrome, Chromium, Brave, and Edge extension source trees with signed
  baselines and typed drift. It does not read browsing history, cookies,
  passwords, extension storage, wallet databases, or `Local State`.
- `tirith pkg attest-npm` binds npm's own supported signature/provenance report
  to the exact lockfile and installed inventory. It does not bind or inspect
  the tarball bytes npm installs.
- Build and deployment attestations are signed, content-addressed,
  point-in-time receipts. They are not reproducible-build claims or continuous
  monitoring.

### Detection expansion

- Reverse-shell and suspicious inline-interpreter command shapes.
- OpenAI, Hugging Face, PyPI, and PGP credential patterns.
- Hidden PDF instructions that account for rendering state, optional content,
  transparency, transforms, and forms, plus preflight nesting and compressed
  stream limits.
- Terminal output controls, deceptive Unicode, prompt injection, and output
  exfiltration across CLI and MCP rendering paths.
- Wallet and sensitive-asset exfiltration through direct uploads, promoted
  operands (`xargs`, `find -exec`, `parallel`), compressors, encoders, and
  staged encryption output.

### Reliability, privacy, and release hardening

- Supervised child execution, checked timeout arithmetic, Unix process-group
  ownership, Windows job ownership, and explicit terminal states.
- Transactional/no-follow setup, install, policy, checkpoint, registry,
  receipt, audit, trust, canary, and ThreatDB publication paths.
- Bounded DNS, redirects, response bodies, feed parsing, MCP work, artifact
  traversal, and output rendering, with incomplete verification kept distinct
  from a clean result or a threat finding.
- Centralized redaction of secrets and reviewed private paths before audit,
  SARIF, webhook, CLI, MCP, gateway, and manual rendering.
- Strict webhook ordering and dead-letter behavior, observable dead-letter and
  internal-server failures, atomic refresh-token handling, and fail-closed
  timestamp parsing in the license service.
- Immutable GitHub Action, container, runner, and release inputs; separated PR
  validation and tag publication; signed checksums and provenance; and
  byte-identical canonical executables in the tarball, Debian, and RPM paths.
- Linux GNU artifacts target a verified GLIBC 2.28 ceiling and are runtime
  smoke-tested on the documented enterprise distributions.

## Upgrade and installation

Do not run these as 0.4.0-specific instructions until the 0.4.0 artifacts are
published. Once released, use the same package manager that owns the current
installation:

```bash
brew upgrade tirith
npm install -g tirith@0.4.0
cargo install tirith --version 0.4.0 --locked
```

```powershell
scoop update tirith
choco upgrade tirith
```

Chocolatey's community-repository moderation can lag the GitHub release. Run
`choco info tirith` to see the approved version; use Scoop or a signed GitHub
release artifact when the newest version is required before moderation
finishes.

After upgrading:

```bash
tirith version --provenance
tirith verify-self
tirith doctor
tirith setup <tool> --update-configs
```

Restart protected shells and agent hosts so they load the new binary and
regenerated hook assets. Re-run the host-specific verification listed in the
agent matrix.

## Compatibility and migrations

- Existing policy files continue to load. `web3_guard` and `task_gate` are
  optional and inert unless configured.
- The default MCP tool list remains frozen. `tirith_check_task` appears only
  when `TIRITH_MCP_PREVIEW=1` is set.
- Command-card schema-1 signing bytes remain unchanged when schema-2 fields are
  absent.
- ThreatDB v1 stays available during the v2 cutover. An old client must not be
  pointed directly at a v2 data file.
- Existing MCP privacy lockfiles require an explicit re-lock when the documented
  schema migration says so; review the diff before committing it.
- Checkpoints created by older builds under `/tmp/tirith/checkpoints` are not
  migrated automatically. Inspect and remove that legacy directory manually;
  0.4.0 uses private per-user state.
- Re-run `tirith setup <tool> --update-configs` after upgrading so generated
  wrappers contain the current validated absolute interpreter and Tirith paths.

## Known limitations that remain

- Broad custom-DLP regexes can currently rewrite protocol-owned string values
  in recursively redacted machine projections, including generated identifiers
  or receipt metadata. Treat this as a release blocker for consumers that need
  stable machine schemas/signatures.
- `tirith install --yes` counts as an unattended approval when task policy says
  `require_approval`; it is not proof that a human used a TTY. Use a blocking
  policy when unattended package-manager execution must be impossible.
- Interpreted MCP exact binding walks and hashes the repository rather than a
  discovered dependency closure, so caps or repository symlinks/special files
  can refuse launch. Revalidation happens before spawn, but interpreter files
  are not executed from sealed reviewed descriptors; concurrent same-user
  mutation remains a verify-to-load gap.
- A full or read-only `TMPDIR` can make zsh and fish fail closed before the
  binary runs; `TIRITH=0` cannot recover that shell. See the troubleshooting
  guide for recovery.
- A sensitive read inside a nested shell body is not yet correlated with a
  sink outside that body.
- `forge create` remains an unmodelled Web3 grammar path on engine surfaces.
- Several declared `web3_guard` fields and schema-2 command-card authoring are
  not yet active enforcement controls; consult the changelog's known-issues
  section before writing policy around them.
- Task-effect inference is intentionally narrow, and most ordinary shell
  commands are incomplete rather than proven safe.
- Prime Agent IPython analysis is source-level extraction, not arbitrary Python
  containment. Earlier-cell wrappers, reflection, and third-party code can
  create process launches that a lexer cannot prove.
- General containment and the Python enforcing installer are x86_64-Linux-only.
- Host hooks and MCP registrations require effective-host verification; config
  presence alone does not prove that a host loaded or honored them.

## Release-owner gates

Before changing `[Unreleased]` to `[0.4.0]`:

1. Integrate the full stack onto the final default-branch tip and review the
   conflict resolutions and resulting tree.
2. Close or explicitly defer every item in the changelog's known-issues list.
3. Run the full required Linux, macOS, and Windows matrices on that exact tree,
   including host-shaped hook fixtures and native Linux containment tests.
4. Complete the Web3/task and ThreatDB v2 rollout playbooks.
5. Set every workspace/package version to `0.4.0`, regenerate locked/generated
   artifacts, and run package assembly before tagging.
6. Verify that 0.4.0 is absent from every destination, then publish through the
   protected tag workflow without replacing any existing artifact.
7. Verify GitHub assets, signatures, provenance, crates.io, npm, Homebrew,
   Scoop, GHCR, Chocolatey submission status, and AUR after publication.

The operational sequence and authority requirements live in the
[release checklist](release-checklist.md).
