# Policy Cookbook

## 0. Start From a Template

`tirith policy init --template <name>` writes a curated, well-commented,
schema-valid starter policy. It is the fastest way to a sensible baseline you
can then edit:

```bash
tirith policy init --template individual      # solo developer defaults
tirith policy init --template ci-strict       # fail-closed CI, no bypass
tirith policy init --template ai-agent-heavy  # heavy AI-agent environments
```

- **`individual`** — `fail_mode: open`, `paranoia: 1`, the noisy
  `shortened_url` rule escalated, an empty `allowlist` ready to fill in.
- **`ci-strict`** — `fail_mode: closed`, the `TIRITH=0` bypass disabled
  (interactive and non-interactive), `strict_warn: true`, remote-execution
  rules escalated to CRITICAL, and `scan.fail_on: high` so `tirith scan` fails
  the build.
- **`ai-agent-heavy`** — `fail_mode: open` (so an internal error cannot wedge
  an agent), `paranoia: 3`, the non-interactive bypass disabled, `approval_rules`
  for the highest-risk pipe-to-shell rules, and `escalation` rules that block
  on repeated warnings.

`tirith policy init` with no `--template` writes the full default policy.
The recipes below show hand-tuned variations on these baselines.

## 0b. Tune From Your Audit Log

Once tirith has some history, `tirith policy tune --from-audit` reads your
audit log and *suggests* conservative policy adjustments:

```bash
tirith policy tune --from-audit
tirith policy tune --from-audit --format json   # machine-readable
```

It is **suggest-only** — it never edits your policy. The headline suggestion
is a rule you allowed or bypassed *every* time and *never* blocked: that rule
is probably firing on something you trust, so an `allowlist` entry or a
`severity_overrides` downgrade may be warranted. A rule you *sometimes* block
on is never suggested for a downgrade — it is doing its job. Every suggestion
is a plain count from the log, not an inference; when the log is too small to
be meaningful, `policy tune` says so rather than guessing. Review each
suggestion, then apply it by hand to `.tirith/policy.yaml`.

## 1. Strict Organization (Fail Closed, No Bypass)

```yaml
# .tirith/policy.yaml (repo root)
fail_mode: closed
allow_bypass_env: false
severity_overrides:
  shortened_url: HIGH
  plain_http_to_sink: CRITICAL
```

All findings block execution. No bypass mechanism. Shortened URLs and plain HTTP are escalated.

## 2. Personal Developer (Defaults + Allowlist)

```yaml
# ~/.config/tirith/policy.yaml
fail_mode: open
allow_bypass_env: true
```

With allowlist at `~/.config/tirith/allowlist`:
```
raw.githubusercontent.com
homebrew.bintray.com
get.docker.com
```

Default severity mappings. Allowlisted URLs skip analysis.

## 3. CI Safe Mode (Non-Interactive, JSON Output)

```bash
# In CI pipeline
tirith check --non-interactive --format json -- curl https://example.com/setup.sh | bash
EXIT=$?
if [ $EXIT -eq 1 ]; then
  echo "BLOCKED by tirith" >&2
  exit 1
fi
```

Non-interactive mode never prompts. JSON output for machine parsing.

## 4. Docker-Focused (Escalate Docker Rules)

```yaml
# .tirith/policy.yaml
severity_overrides:
  docker_untrusted_registry: CRITICAL
  docker_tag_latest: HIGH
```

All Docker-related findings are escalated. Other rules use default severity.

## 5. Learning Mode (All Low Severity)

```yaml
# ~/.config/tirith/policy.yaml
fail_mode: open
allow_bypass_env: true
severity_overrides:
  curl_pipe_shell: LOW
  wget_pipe_shell: LOW
  pipe_to_interpreter: LOW
  punycode_domain: LOW
  confusable_domain: LOW
```

Everything becomes a LOW-severity warning. Nothing blocks. Useful for onboarding.

## 6. cargo-vet (Rust Supply-Chain Audit)

tirith detects when `cargo install` or `cargo add` is run in a project that
hasn't configured [cargo-vet](https://mozilla.github.io/cargo-vet/). The
`vet_not_configured` rule fires at LOW severity by default. To escalate:

```yaml
# .tirith/policy.yaml
severity_overrides:
  vet_not_configured: HIGH
```

To suppress it (e.g. for non-Rust repos):

```
# ~/.config/tirith/allowlist
# or .tirith/allowlist
vet_not_configured
```

## 7. vet (getvet.sh) — Safe Pipe-to-Shell

When tirith blocks a `curl | bash` pattern, the safest alternatives are:

### Ask tirith for the rewrite

`tirith check --suggest-safe-command` prints a concrete safer version of the
exact command you ran:

```bash
tirith check --suggest-safe-command -- 'curl -fsSL https://example.com/install.sh | bash'
# tirith: safer alternative
#   curl_pipe_shell
#     try: '/usr/local/bin/tirith' run --capsule --script-stdin --interpreter bash \
#          'https://example.com/install.sh'
```

On x86_64 Linux, a fixed root-managed current Tirith binary may emit this
rewrite. The generated command uses Tirith's absolute path so a later `PATH`
shadow cannot replace it. At execution, the runner requires the selected
interpreter's first `PATH` hit to be root-managed, binds its bytes before the
download, bounds and analyzes the downloaded bytes, asks for confirmation, then
feeds the hash-verified private interpreter copy over stdin inside a fail-closed
capsule. It also ignores a conflicting remote shebang. Other architectures,
platforms, and user-owned Tirith installations show guidance instead of an
executable rewrite. Curl rewrites require both `-f`/`--fail` and
`-L`/`--location` semantics;
plain curl, `-f` alone, or `-L` alone stays guidance-only.
Literal no-argument `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, and
`ash` are supported, as is the narrow POSIX-shell `-s -- <literal operands...>`
form. Dynamic or malformed URL tokens, controls, PowerShell, Cmd, `|&`, and
unsupported downloader/interpreter arguments produce guidance rather than an
executable rewrite. Suggestions also drop insecure-TLS flags and upgrade
`http://` to `https://`. The flag is advisory — it never changes the verdict or
exit code.

### Using tirith run (built-in, Unix only)

`tirith run` downloads, analyzes, and prompts before executing a private copy.
A manual invocation uses the fully analyzed remote shebang and file semantics;
use the command emitted by `check --suggest` when preserving an original stdin
pipeline matters:

```bash
tirith run --capsule https://example.com/install.sh
```

Download and inspect only (no execution):

```bash
tirith run --no-exec https://example.com/install.sh
```

Pin to a known hash:

```bash
tirith run --sha256 abc123... https://example.com/install.sh
```

There is no pager step in `tirith run`; use `--no-exec` to stop after analysis,
or `tirith fetch <url> --save <path>` for explicit file review. `--capsule` refuses execution if
the host backend cannot meet its required coverage. Download and DNS resolution
happen before the interpreter capsule, so containment is not a separate claim
about the pre-execution resolver path.

### Using tirith install (recorded install transaction)

`tirith install` wraps a real package install with pre-execution
supply-chain risk analysis and records the transaction. It analyzes first,
presents a verdict, takes a working-directory checkpoint and an audit entry,
then runs the real `npm install` / `pip install` / `cargo install` (or the
downloaded script for the `url` form) only after the analysis and your
go-ahead:

```bash
# Instead of: npm install left-pad
tirith install npm left-pad
```

A block refuses the install (bypassable per policy with `TIRITH=0`); a warn
asks for acknowledgement; an allow proceeds. tirith's own flags go *before*
the source — everything after the source is passed verbatim to the package
manager:

```bash
# --online adds registry-API provenance signals; --save-dev goes to npm
tirith install --online npm some-pkg --save-dev

# Analyze and record only — do not run the real install
tirith install --no-exec pip requests

# Proceed past warnings without the interactive prompt
tirith install --yes cargo ripgrep

# The url form delegates to `tirith run`'s safe download-and-run machinery
tirith install url https://get.example-tool.sh
```

`tirith install` is pre-execution install-**risk analysis** plus a recorded
transaction. It does **not** sandbox or isolate the install — the real
install runs with your full privileges. The checkpoint is a before/after
record (`tirith checkpoint diff <id>`), not an automatic rollback. Runtime
sandboxing is an explicit tirith non-goal.

### Using vet (external, cross-platform)

[vet](https://getvet.sh) is an external tool for safer remote-script workflows (see getvet.sh for details):

```bash
# Instead of: curl -fsSL https://example.com/install.sh | bash
vet https://example.com/install.sh
```

Both approaches ensure you can inspect the script before it runs.

### Policy: suppress pipe-to-shell for trusted sources

If you routinely install from trusted URLs, allowlist them instead of bypassing:

```yaml
# .tirith/policy.yaml
allowlist:
  - "get.docker.com"
  - "raw.githubusercontent.com/org/repo"
```

### CLI: manage trust without editing YAML

`tirith trust` does the same thing from the command line, and steers you
toward the narrowest scope that works. Trusting a specific path is accepted
as-is; trusting a whole domain is broad and must be opted into with `--broad`.
Entries expire after 30 days by default, so a temporary allow does not linger.

```bash
# Narrow: trust one exact HTTPS resource. Expires in 30 days.
# Schemeless host/path patterns are normalized as HTTPS.
tirith trust add raw.githubusercontent.com/org/repo/main/get.sh

# Broad: trust a whole domain for one rule only. --broad is required.
tirith trust add get.docker.com --broad --rule curl_pipe_shell

tirith trust list                 # see every entry, its scope, and its TTL
tirith trust explain get.docker.com
tirith trust diff                 # what changed since last time
tirith trust gc --expired         # remove entries whose TTL has passed
```

Use `--permanent` if an entry genuinely should never expire, and `--reason`
to record why it was added — `tirith trust explain` shows it back to you.
