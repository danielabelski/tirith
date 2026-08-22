// Pi-family agent extension: intercepts shell tool calls and runs a tirith
// security check before the host executes them.
//
// One file serves Pi CLI, Prime Agent, and OMP. All three expose the same
// `pi.on("tool_call", ...)` pre-execution event and the same
// `{ block: true, reason }` veto, so setup substitutes the two placeholders
// below and writes the same bytes into each host's extension directory.
//
// Like `openclaw-tirith-guard.ts`, this asset deliberately stays valid
// JavaScript even though its extension is `.ts`: the hosts load it through a
// TypeScript-aware runtime, while the conformance test loads the exact shipped
// bytes and needs no transform to do it. Types are documented in JSDoc.
//
// Protocol limitation: the extension API supports only two return values:
//   - undefined (allow, invisible to the agent)
//   - { block: true, reason } (deny with a reason)
// There is no "allow with message". On the warn-allow path findings go to
// process.stderr as a best-effort side channel; the host may or may not surface
// stderr to the user.
//
// Environment:
//   TIRITH_HOOK_WARN_ACTION — "allow" (default) or "deny"
//   TIRITH_FAIL_OPEN        — "1" to allow on error (default: deny)

import { execFile, execFileSync } from "node:child_process";

const TIRITH_BIN = "__TIRITH_BIN__";
const TIRITH_INTEGRATION = "__TIRITH_INTEGRATION__";

/** Tool names that carry a shell command string in `input.command`. */
const SHELL_TOOLS = new Set(["bash", "shell", "run_terminal_command", "terminal"]);
/** Tool names whose `input.code` is an IPython cell. */
const NOTEBOOK_TOOLS = new Set(["ipython", "python", "jupyter"]);

// ---------------------------------------------------------------------------
// IPython cell execution-vector extraction.
//
// A notebook cell can reach a shell through several syntaxes at once, so this
// collects EVERY vector in the cell rather than returning at the first hit. A
// cell whose first line is a harmless `!ls` and whose fifth line calls
// `os.system(...)` must not be waved through on the strength of the first line.
//
// Extraction only. Nothing here decides whether a command is dangerous: the
// recovered commands are handed to `tirith check` as one newline-separated
// script, so every security decision stays in the engine.
// ---------------------------------------------------------------------------

/**
 * @typedef {object} IpythonVectors
 * @property {string[]} commands
 *   Literal shell commands recovered from the cell, in source order.
 * @property {string[]} unresolved
 *   Execution vectors whose command could not be recovered as a literal, such
 *   as `os.system(user_input)`. Reported rather than silently dropped: the cell
 *   reaches a shell in a way this cannot show the engine.
 */

const SHELL_CELL_MAGIC = /^\s*%%(bash|sh|script)\b(.*)$/;
const SHELL_INTERPRETERS = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
]);

/** `!cmd`, `!!cmd`, `x = !cmd`. The `!` opens the line or directly follows `=`. */
const BANG_LINE = /^\s*(?:[A-Za-z_]\w*\s*=\s*)?!{1,2}(.*)$/;
/** `%system cmd`, `%sx cmd`, and their `x = %sx cmd` capture forms. */
const SYSTEM_MAGIC = /^\s*(?:[A-Za-z_]\w*\s*=\s*)?%(?:system|sx)\s+(.*)$/;
/** Any other line magic: not Python, and not a shell vector either. */
const OTHER_MAGIC = /^\s*%{1,2}\w/;

const OS_EXEC = new Set([
  "system", "popen",
  "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
  "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp", "spawnvpe",
  "posix_spawn", "posix_spawnp",
]);
const SUBPROCESS_EXEC = new Set([
  "run", "call", "check_call", "check_output", "Popen",
  "getoutput", "getstatusoutput",
]);
const PTY_EXEC = new Set(["spawn"]);
const EXEC_MODULES = new Set(["os", "subprocess", "pty"]);

const STRING_PREFIXES = new Set([
  "r", "b", "u", "f", "rb", "br", "fr", "rf", "bf", "fb",
]);

function execNamesFor(module) {
  if (module === "os") return OS_EXEC;
  if (module === "subprocess") return SUBPROCESS_EXEC;
  return PTY_EXEC;
}

/**
 * Read one Python string literal starting at `start` (a quote character).
 *
 * @param {string} src
 * @param {number} start
 * @param {boolean} raw
 * @returns {{ value: string, end: number }}
 */
function readString(src, start, raw) {
  const quote = src[start];
  const triple = src.slice(start, start + 3) === quote.repeat(3);
  const delim = triple ? quote.repeat(3) : quote;
  let i = start + delim.length;
  let out = "";
  const n = src.length;

  while (i < n) {
    if (!raw && src[i] === "\\" && i + 1 < n) {
      const esc = src[i + 1];
      if (esc === "n") { out += "\n"; i += 2; continue; }
      if (esc === "t") { out += "\t"; i += 2; continue; }
      if (esc === "r") { out += "\r"; i += 2; continue; }
      if (esc === "\\") { out += "\\"; i += 2; continue; }
      if (esc === "'") { out += "'"; i += 2; continue; }
      if (esc === '"') { out += '"'; i += 2; continue; }
      if (esc === "\n") { i += 2; continue; }
      if (esc === "x") {
        const hex = src.slice(i + 2, i + 4);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          continue;
        }
      }
      if (esc === "u") {
        const hex = src.slice(i + 2, i + 6);
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
      }
      out += esc;
      i += 2;
      continue;
    }
    if (raw && src[i] === "\\" && i + 1 < n) {
      // A raw string keeps its backslash, but the backslash still escapes the
      // quote for the purpose of finding the terminator.
      out += src[i] + src[i + 1];
      i += 2;
      continue;
    }
    if (src.slice(i, i + delim.length) === delim) {
      return { value: out, end: i + delim.length };
    }
    if (!triple && src[i] === "\n") {
      // Unterminated single-quoted string: stop at the newline, as Python does.
      return { value: out, end: i };
    }
    out += src[i];
    i++;
  }
  return { value: out, end: n };
}

/**
 * Lex enough Python to find call sites and their literal arguments.
 *
 * Comments and string bodies are consumed here rather than matched by regex
 * over raw source, so a commented-out `# os.system("rm -rf /")` is correctly
 * ignored and a `#` inside a string does not truncate the line.
 *
 * @param {string} src
 * @returns {Array<{t: string, v: string}>} tokens tagged "name", "str" or "op"
 */
function lexPython(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    const c = src[i];

    if (c === "#") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "\\" && src[i + 1] === "\n") {
      i += 2;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      i++;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      // A string prefix binds to the quote immediately following it.
      if ((src[j] === '"' || src[j] === "'") && STRING_PREFIXES.has(word.toLowerCase())) {
        const lit = readString(src, j, word.toLowerCase().indexOf("r") >= 0);
        tokens.push({ t: "str", v: lit.value });
        i = lit.end;
        continue;
      }
      tokens.push({ t: "name", v: word });
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const lit = readString(src, i, false);
      tokens.push({ t: "str", v: lit.value });
      i = lit.end;
      continue;
    }
    tokens.push({ t: "op", v: c });
    i++;
  }
  return tokens;
}

function tokenName(tok) {
  return tok !== undefined && tok.t === "name" ? tok.v : null;
}

function isOp(tok, value) {
  return tok !== undefined && tok.t === "op" && tok.v === value;
}

/**
 * Track the import forms that let an exec call appear under another name.
 *
 * @param {Array<{t: string, v: string}>} tokens
 * @returns {{ moduleAlias: Map<string, string>, bareExec: Set<string> }}
 */
function collectImports(tokens) {
  const moduleAlias = new Map();
  const bareExec = new Set();

  for (let i = 0; i < tokens.length; i++) {
    const word = tokenName(tokens[i]);
    if (word === null) continue;

    if (word === "import" && tokenName(tokens[i - 1]) !== "from") {
      // `import os`, `import os as o`, `import os, subprocess`
      let j = i + 1;
      while (j < tokens.length) {
        const mod = tokenName(tokens[j]);
        if (mod === null) break;
        let alias = mod;
        let k = j + 1;
        if (tokenName(tokens[k]) === "as" && tokenName(tokens[k + 1]) !== null) {
          alias = tokenName(tokens[k + 1]);
          k += 2;
        }
        if (EXEC_MODULES.has(mod)) moduleAlias.set(alias, mod);
        if (isOp(tokens[k], ",")) {
          j = k + 1;
          continue;
        }
        break;
      }
      continue;
    }

    if (word === "from") {
      const module = tokenName(tokens[i + 1]);
      if (module === null || !EXEC_MODULES.has(module)) continue;
      if (tokenName(tokens[i + 2]) !== "import") continue;
      const allowed = execNamesFor(module);
      let j = i + 3;
      while (j < tokens.length) {
        if (isOp(tokens[j], "(") || isOp(tokens[j], ")")) {
          j++;
          continue;
        }
        const imported = tokenName(tokens[j]);
        if (imported === null) break;
        let local = imported;
        let k = j + 1;
        if (tokenName(tokens[k]) === "as" && tokenName(tokens[k + 1]) !== null) {
          local = tokenName(tokens[k + 1]);
          k += 2;
        }
        if (allowed.has(imported)) bareExec.add(local);
        if (isOp(tokens[k], ",")) {
          j = k + 1;
          continue;
        }
        break;
      }
    }
  }
  return { moduleAlias, bareExec };
}

/**
 * Render the first argument of a call as a command string, if it is literal.
 *
 * @param {Array<{t: string, v: string}>} tokens
 * @param {number} openParen index of the call's `(`
 * @returns {string | null} null when the argument is computed at runtime
 */
function firstArgumentCommand(tokens, openParen) {
  let i = openParen + 1;

  // `subprocess.run(["curl", url])` — a list or tuple of literals renders as argv.
  if (isOp(tokens[i], "[") || isOp(tokens[i], "(")) {
    const close = isOp(tokens[i], "[") ? "]" : ")";
    const parts = [];
    i++;
    while (i < tokens.length && !isOp(tokens[i], close)) {
      const tok = tokens[i];
      if (tok.t === "str") parts.push(tok.v);
      else if (tok.t === "op" && tok.v === ",") { /* element separator */ }
      else return null; // a computed element makes the argv unknowable
      i++;
    }
    return parts.length > 0 ? parts.join(" ") : null;
  }

  // Adjacent string literals concatenate in Python: `"cu" "rl example.test"`.
  const parts = [];
  while (tokens[i] !== undefined && tokens[i].t === "str") {
    parts.push(tokens[i].v);
    i++;
  }
  if (parts.length === 0) return null;
  // Anything other than the end of this argument means the value is computed
  // (`"cmd " + user_input`), so the literal half must not stand in for it.
  if (isOp(tokens[i], ",") || isOp(tokens[i], ")")) return parts.join("");
  return null;
}

/**
 * Extract every shell execution vector an IPython cell carries.
 *
 * @param {string} source
 * @returns {IpythonVectors}
 */
export function extractIpythonVectors(source) {
  const commands = [];
  const unresolved = [];
  if (typeof source !== "string" || source.length === 0) {
    return { commands, unresolved };
  }

  const lines = source.split("\n");

  // A shell cell magic makes the whole remaining cell one shell script, so it
  // is decided first and the Python lexer never runs.
  const magic = lines.length > 0 ? SHELL_CELL_MAGIC.exec(lines[0]) : null;
  if (magic !== null) {
    const kind = magic[1];
    const rest = (magic[2] || "").trim();
    let isShell = kind === "bash" || kind === "sh";
    if (kind === "script") {
      // `%%script --no-raise-error bash` — the interpreter is the last non-flag word.
      const words = rest.split(/\s+/).filter((w) => w.length > 0 && w.charAt(0) !== "-");
      const interpreter = words.length > 0 ? words[words.length - 1] : "";
      const base = interpreter.split("/").pop() || "";
      isShell = SHELL_INTERPRETERS.has(base);
    }
    if (isShell) {
      const body = lines.slice(1).join("\n").trim();
      if (body.length > 0) commands.push(body);
      return { commands, unresolved };
    }
    // A non-shell `%%script python` cell still runs Python, so fall through.
  }

  // Line-oriented pass for the escapes and magics, deliberately run BEFORE the
  // Python lexer and deliberately NOT tracking multi-line string state.
  //
  // A `!rm -rf /` line inside a triple-quoted string is therefore extracted and
  // checked even though Python would treat it as data. That over-extraction is
  // the safe direction: the alternative is tracking `"""` across lines, and a
  // cell can then be written so a stray delimiter in a comment convinces the
  // tracker that a real escape sits inside a string, which turns a usability
  // nicety into an evasion. A spurious check costs a false positive; a skipped
  // line costs a missed command.
  const pythonLines = [];
  for (const line of lines) {
    const bang = BANG_LINE.exec(line);
    if (bang !== null) {
      const cmd = bang[1].trim();
      if (cmd.length > 0) commands.push(cmd);
      pythonLines.push("");
      continue;
    }
    const sys = SYSTEM_MAGIC.exec(line);
    if (sys !== null) {
      const cmd = sys[1].trim();
      if (cmd.length > 0) commands.push(cmd);
      pythonLines.push("");
      continue;
    }
    if (OTHER_MAGIC.test(line)) {
      pythonLines.push("");
      continue;
    }
    pythonLines.push(line);
  }

  const tokens = lexPython(pythonLines.join("\n"));
  const bindings = collectImports(tokens);

  for (let i = 0; i < tokens.length; i++) {
    const word = tokenName(tokens[i]);
    if (word === null) continue;

    let label = null;
    let openParen = -1;

    // `<module>.<call>(` where the module is os/subprocess/pty or an alias.
    const aliased = bindings.moduleAlias.get(word);
    let canonical = null;
    if (aliased !== undefined) canonical = aliased;
    else if (EXEC_MODULES.has(word)) canonical = word;

    if (
      canonical !== null &&
      isOp(tokens[i + 1], ".") &&
      tokenName(tokens[i + 2]) !== null &&
      isOp(tokens[i + 3], "(")
    ) {
      const member = tokenName(tokens[i + 2]);
      if (execNamesFor(canonical).has(member)) {
        label = word + "." + member;
        openParen = i + 3;
      }
    }

    // A bare name bound by `from subprocess import run`.
    if (label === null && bindings.bareExec.has(word) && isOp(tokens[i + 1], "(")) {
      label = word;
      openParen = i + 1;
    }

    if (label === null) continue;

    const command = firstArgumentCommand(tokens, openParen);
    if (command !== null && command.trim().length > 0) commands.push(command);
    else unresolved.push(label);
  }

  return { commands, unresolved };
}

/**
 * Upper bound on the script handed to `tirith check` as a single argument.
 *
 * Comfortably under the smallest `ARG_MAX` any supported platform uses, so a
 * pathological cell fails as a reported truncation rather than as an opaque
 * `E2BIG` spawn error. The engine applies its own budgets below this.
 */
const MAX_CHECK_SCRIPT_BYTES = 128 * 1024;

/**
 * Build the script handed to `tirith check` for one tool call.
 *
 * Every recovered vector is joined with newlines so the engine sees each as its
 * own segment and a single check covers the whole cell.
 *
 * A vector that does not fit within the size bound is DROPPED WHOLE and
 * reported, never truncated: half a command line means something different
 * from the command that would actually run.
 *
 * @param {string} toolName
 * @param {Record<string, unknown> | undefined} input
 * @returns {{ script: string, unresolved: string[] } | null} null when the call
 *   carries nothing executable
 */
export function buildCheckScript(toolName, input) {
  const bag = input === undefined || input === null ? {} : input;
  if (SHELL_TOOLS.has(toolName)) {
    const command = bag.command;
    if (typeof command !== "string" || command.trim().length === 0) return null;
    return { script: command, unresolved: [] };
  }
  if (NOTEBOOK_TOOLS.has(toolName)) {
    let code = bag.code;
    if (code === undefined) code = bag.cell;
    if (code === undefined) code = bag.source;
    if (typeof code !== "string" || code.trim().length === 0) return null;
    const vectors = extractIpythonVectors(code);
    if (vectors.commands.length === 0 && vectors.unresolved.length === 0) return null;

    const kept = [];
    const unresolved = vectors.unresolved.slice();
    let used = 0;
    let dropped = 0;
    for (const command of vectors.commands) {
      const cost = Buffer.byteLength(command, "utf8") + 1;
      if (used + cost > MAX_CHECK_SCRIPT_BYTES) {
        dropped++;
        continue;
      }
      kept.push(command);
      used += cost;
    }
    if (dropped > 0) {
      unresolved.push(`${dropped} oversized command(s) past the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection bound`);
    }
    return { script: kept.join("\n"), unresolved };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Host integration.
// ---------------------------------------------------------------------------

function hookEvent(event, detail) {
  try {
    const args = [
      "hook-event", "--integration", TIRITH_INTEGRATION,
      "--hook-type", "tool_call", "--event", event,
    ];
    if (detail) args.push("--detail", detail);
    execFile(TIRITH_BIN, args, () => {});
  } catch {
    /* telemetry is best effort */
  }
}

function describeFindings(stdout, fallback) {
  if (!stdout || stdout.trim().length === 0) return fallback;
  try {
    const verdict = JSON.parse(stdout);
    const findings = verdict.findings || [];
    if (findings.length === 0) return fallback;
    const parts = findings.map((f) => {
      const title = f.title || f.rule_id || "unknown";
      const severity = f.severity || "";
      return severity ? `[${severity}] ${title}` : title;
    });
    return "Tirith: " + parts.join("; ");
  } catch {
    return stdout.trim().slice(0, 500);
  }
}

function failOpen() {
  return process.env.TIRITH_FAIL_OPEN === "1";
}

export default function (pi) {
  pi.on("tool_call", async (event, _ctx) => {
    const toolName = event && typeof event.toolName === "string" ? event.toolName : "";
    const built = buildCheckScript(toolName, event ? event.input : undefined);
    if (built === null) return undefined;

    const script = built.script;
    const unresolved = built.unresolved;

    // A cell that reaches a shell through a value this cannot recover is not
    // something to wave through silently. It rides the same channel as a
    // warning, so `TIRITH_HOOK_WARN_ACTION=deny` refuses it outright.
    const unresolvedNote = unresolved.length > 0
      ? `tirith: ${unresolved.length} execution vector(s) in this cell (${unresolved.join(", ")}) `
        + "build their command at runtime and could not be inspected"
      : "";

    let warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
    if (warnAction !== "allow" && warnAction !== "deny") {
      process.stderr.write(
        `tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='${warnAction}', defaulting to 'allow'\n`,
      );
      warnAction = "allow";
    }

    if (unresolvedNote && warnAction === "deny") {
      hookEvent("unresolved_vector", unresolved.join(","));
      return { block: true, reason: unresolvedNote };
    }

    if (script.trim().length === 0) {
      if (unresolvedNote) {
        hookEvent("unresolved_vector", unresolved.join(","));
        process.stderr.write(unresolvedNote + "\n");
      }
      return undefined;
    }

    try {
      execFileSync(
        TIRITH_BIN,
        ["check", "--json", "--non-interactive", "--shell", "posix", "--", script],
        {
          timeout: 10000,
          encoding: "utf-8",
          env: { ...process.env, TIRITH_INTEGRATION },
        },
      );
      hookEvent("check_ok");
      if (unresolvedNote) process.stderr.write(unresolvedNote + "\n");
      return undefined;
    } catch (err) {
      // execFileSync throws on a non-zero exit as well as on spawn failure.
      if (err.code === "ENOENT") {
        if (failOpen()) return undefined;
        return {
          block: true,
          reason: `tirith: ${TIRITH_BIN} not found — reinstall the integration or set TIRITH_FAIL_OPEN=1`,
        };
      }
      if (err.killed) {
        hookEvent("timeout");
        if (failOpen()) return undefined;
        return { block: true, reason: "tirith: check timed out — blocked for safety" };
      }

      const exitCode = err.status;
      if (exitCode === null || exitCode === undefined) {
        hookEvent("unexpected_exit", err.message || "unknown");
        if (failOpen()) return undefined;
        return { block: true, reason: `tirith: unexpected error — ${err.message || "unknown"}` };
      }

      const stdout = err.stdout || "";

      if (exitCode !== 1 && exitCode !== 2) {
        hookEvent("unexpected_exit", `exit code ${exitCode}`);
        if (failOpen()) return undefined;
        return {
          block: true,
          reason: `tirith: unexpected exit code ${exitCode} — blocked for safety`,
        };
      }

      if (exitCode === 2 && warnAction !== "deny") {
        hookEvent("warn_allowed");
        const text = describeFindings(stdout, "Tirith: security warnings detected (non-blocking)");
        process.stderr.write(text + "\n");
        if (unresolvedNote) process.stderr.write(unresolvedNote + "\n");
        return undefined;
      }

      hookEvent(exitCode === 1 ? "check_block" : "warn_denied");
      let reason = describeFindings(stdout, "Tirith security check failed");
      if (unresolvedNote) reason += " | " + unresolvedNote;
      return { block: true, reason };
    }
  });
}
