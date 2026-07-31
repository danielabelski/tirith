// OpenClaw plugin: intercepts exec tool calls and runs tirith security check.
//
// Protocol limitation: the OpenClaw plugin API only supports two return shapes:
//   - void/undefined (allow, invisible to the agent)
//   - { block: true, blockReason: string } (deny with reason)
// There is no "allow with message" option. On the warn-allow path, findings are
// written to process.stderr as a best-effort side channel — the host may or may
// not surface stderr to the user.
//
// Environment:
//   TIRITH_BIN              -- path to tirith binary (default: "tirith")
//   TIRITH_SHELL            -- explicit executor-shell assertion: posix, powershell, cmd
//   TIRITH_HOOK_WARN_ACTION -- "allow" (default) or "deny"
//   TIRITH_FAIL_OPEN        -- "1" to allow on error (default: deny)

import { execFile, execFileSync } from "node:child_process";

const VALID_SHELLS = new Set(["posix", "powershell", "cmd"]);
const VALID_EXEC_HOSTS = new Set(["auto", "sandbox", "gateway", "node"]);

function resolvedShell(shell) {
  return { ok: true, shell };
}

function unresolvedShell(reason) {
  return { ok: false, reason };
}

function requireExpectedShell(expected, configuredShell) {
  if (configuredShell !== undefined && configuredShell !== expected) {
    return unresolvedShell(
      `tirith: TIRITH_SHELL does not match OpenClaw's effective ${expected} shell`,
    );
  }
  return resolvedShell(expected);
}

function requireShellAssertion(configuredShell) {
  if (configuredShell === undefined) {
    return unresolvedShell(
      "tirith: cannot determine OpenClaw's effective shell; set TIRITH_SHELL=posix, powershell, or cmd to match the executor",
    );
  }
  return resolvedShell(configuredShell);
}

// OpenClaw's before_tool_call context does not expose the fully resolved exec
// host or remote node OS. Infer only where its public execution contract is
// unambiguous and otherwise require an explicit operator assertion. A bad or
// mismatched assertion is a configuration error and always fails closed; it is
// intentionally not covered by TIRITH_FAIL_OPEN.
export function resolveShellTokenizer(
  toolName,
  params = {},
  configuredShell = process.env.TIRITH_SHELL,
  platform = process.platform,
) {
  if (configuredShell !== undefined && !VALID_SHELLS.has(configuredShell)) {
    return unresolvedShell(
      "tirith: invalid TIRITH_SHELL (expected posix, powershell, or cmd)",
    );
  }

  // OpenClaw's legacy `bash` surface is explicitly POSIX regardless of the
  // gateway platform.
  if (toolName === "bash") {
    return requireExpectedShell("posix", configuredShell);
  }

  const host = params?.host;
  if (host !== undefined && (typeof host !== "string" || !VALID_EXEC_HOSTS.has(host))) {
    return unresolvedShell("tirith: invalid OpenClaw exec host; refusing an ambiguous scan");
  }
  if (params?.elevated !== undefined && typeof params.elevated !== "boolean") {
    return unresolvedShell("tirith: invalid OpenClaw elevated flag; refusing an ambiguous scan");
  }

  // An omitted host can resolve from OpenClaw configuration, including a remote
  // node whose OS is not in hook context. Never guess from the gateway OS.
  if (host === undefined) {
    return requireShellAssertion(configuredShell);
  }

  if (host === "node") {
    return requireShellAssertion(configuredShell);
  }

  // Elevated sandbox/auto calls escape to the gateway (node remains handled
  // above), so the gateway platform decides the grammar.
  if (params?.elevated === true) {
    return requireExpectedShell(platform === "win32" ? "powershell" : "posix", configuredShell);
  }
  // `elevated` can default on in trusted OpenClaw configuration even when the
  // call omits it. That changes sandbox/auto into gateway execution. The two
  // grammars differ on Windows, so an operator assertion is required there.
  if (
    platform === "win32" &&
    params?.elevated === undefined &&
    (host === "sandbox" || host === "auto")
  ) {
    return requireShellAssertion(configuredShell);
  }
  if (host === "sandbox") {
    return requireExpectedShell("posix", configuredShell);
  }
  if (host === "gateway") {
    return requireExpectedShell(platform === "win32" ? "powershell" : "posix", configuredShell);
  }

  // host=auto chooses sandbox or gateway. Both are POSIX on non-Windows. On
  // Windows they differ (sandbox sh vs gateway PowerShell), and hook context
  // exposes no sandbox-resolution bit, so require an assertion.
  if (platform === "win32") {
    return requireShellAssertion(configuredShell);
  }
  return requireExpectedShell("posix", configuredShell);
}

function hookEvent(event, detail) {
  try {
    const tirithBin = process.env.TIRITH_BIN || "tirith";
    execFile(tirithBin, [
      "hook-event", "--integration", "openclaw",
      "--hook-type", "before_tool_call", "--event", event,
      ...(detail ? ["--detail", detail] : []),
    ], () => {});
  } catch {}
}

export default {
  id: "tirith-security",
  name: "tirith Security Scanner",
  description: "Pre-exec command security scanning via tirith",
  register(api) {
    api.on("before_tool_call", (event) => {
      if (event.toolName !== "exec" && event.toolName !== "bash") return;
      const command = event.params?.command;
      if (typeof command !== "string" || !command.trim()) return;

      const tirithBin = process.env.TIRITH_BIN || "tirith";
      const shellResolution = resolveShellTokenizer(event.toolName, event.params);
      if (!shellResolution.ok) {
        hookEvent("shell_resolution_error", shellResolution.reason);
        return { block: true, blockReason: shellResolution.reason };
      }
      const shell = shellResolution.shell;
      try {
        execFileSync(
          tirithBin,
          ["check", "--json", "--non-interactive", "--shell", shell, "--", command],
          { timeout: 10_000, encoding: "utf-8", env: { ...process.env, TIRITH_INTEGRATION: "openclaw" } },
        );
        hookEvent("check_ok");
        return; // Exit 0 = allow
      } catch (err) {
        const execError = /** @type {any} */ (err);
        if (execError.code === "ENOENT") {
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith not found -- install or set TIRITH_FAIL_OPEN=1` };
        }
        // Timeout detection: execFileSync sets killed=true and/or signal="SIGTERM".
        if (execError.killed || execError.signal === "SIGTERM" || execError.code === "ETIMEDOUT") {
          hookEvent("timeout");
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: "tirith: check timed out" };
        }
        const exitCode = execError.status; // execFileSync uses .status
        if (exitCode == null || (exitCode !== 1 && exitCode !== 2)) {
          hookEvent("unexpected_exit", `exit code ${exitCode}`);
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith: unexpected exit ${exitCode}` };
        }
        if (exitCode === 2) {
          let warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
          if (warnAction !== "allow" && warnAction !== "deny") {
            process.stderr.write(`tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='${warnAction}', defaulting to 'allow'\n`);
            warnAction = "allow";
          }
          if (warnAction !== "deny") {
            // Parse findings from stdout for stderr warning
            let warningText = "Tirith: security warnings detected (non-blocking)";
            const stdout = execError.stdout || "";
            if (stdout.trim()) {
              try {
                const verdict = JSON.parse(stdout);
                const findings = verdict.findings || [];
                if (findings.length > 0) {
                  warningText = "Tirith warnings (non-blocking): " + findings.map((f) => {
                    const title = f.title || f.rule_id || "unknown";
                    const sev = f.severity || "";
                    return sev ? `[${sev}] ${title}` : title;
                  }).join("; ");
                }
              } catch { /* ignore parse errors */ }
            }
            hookEvent("warn_allowed");
            process.stderr.write(warningText + "\n");
            return;
          }
        }
        hookEvent(exitCode === 1 ? "check_block" : "warn_denied");
        // Parse findings from stdout
        let reason = "tirith security check failed";
        const stdout = execError.stdout || "";
        if (stdout.trim()) {
          try {
            const verdict = JSON.parse(stdout);
            const findings = verdict.findings || [];
            if (findings.length > 0) {
              reason = "tirith: " + findings.map((f) => {
                const title = f.title || f.rule_id || "unknown";
                const sev = f.severity || "";
                return sev ? `[${sev}] ${title}` : title;
              }).join("; ");
            }
          } catch { reason = stdout.trim().slice(0, 500); }
        }
        return { block: true, blockReason: reason };
      }
    });
  },
};
