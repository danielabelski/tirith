# Tirith guard for non-interactive zsh command runs (`zsh -lc ...`).
# Skipped when:
#   - TIRITH_ZSHENV_SKIP=1 (explicit disable)
#   - VSCODE_RESOLVING_ENVIRONMENT is set (IDE shell env probe — not a
#     real command; the IDE strips this var from the resolved env so it
#     cannot be abused to bypass the guard for actual commands)
# Uses a single compound condition (no `return`) so later .zshenv lines
# always load — the IDE resolves the full environment (PATH, etc.).
if [[ -n "${ZSH_EXECUTION_STRING:-}" \
   && "${TIRITH_ZSHENV_SKIP:-}" != "1" \
   && -z "${VSCODE_RESOLVING_ENVIRONMENT:-}" ]]; then

  # Setup replaces the assignment below with a zsh-quoted absolute path.
  # Do not honor runtime path overrides: the guard must reach the exact
  # executable that setup verified, independent of an untrusted PATH/env.
  _tirith_bin=__TIRITH_BIN__

  if [[ ! -f "$_tirith_bin" || ! -x "$_tirith_bin" ]]; then
    builtin print -r -- "tirith: configured binary is unavailable — command blocked for safety" >&2
    exit 1
  fi

  # Capture output using zsh-native command substitution. No PATH-resolved
  # utility may execute before Tirith makes the security decision.
  _tirith_output=$("$_tirith_bin" check --non-interactive --shell posix -- "$ZSH_EXECUTION_STRING" 2>&1)
  _tirith_rc=$?

  if [[ $_tirith_rc -eq 1 ]]; then
    [[ -z "$_tirith_output" ]] || builtin print -r -- "$_tirith_output" >&2
    exit 1
  elif [[ $_tirith_rc -eq 2 ]]; then
    [[ -z "$_tirith_output" ]] || builtin print -r -- "$_tirith_output" >&2
  elif [[ $_tirith_rc -ne 0 ]]; then
    [[ -z "$_tirith_output" ]] || builtin print -r -- "$_tirith_output" >&2
    builtin print -r -- "tirith: unexpected exit code $_tirith_rc" >&2
    exit 1
  fi

  builtin unset _tirith_bin _tirith_output _tirith_rc
fi
