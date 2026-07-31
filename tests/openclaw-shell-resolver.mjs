import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// The installed OpenClaw asset deliberately stays JavaScript-compatible even
// though its extension is .ts. Loading the exact shipped bytes through a data
// URL tests the resolver that setup writes, rather than a duplicated fixture.
const assetUrl = new URL(
  "../crates/tirith/assets/hooks/openclaw-tirith-guard.ts",
  import.meta.url,
);
const source = await readFile(assetUrl, "utf8");
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const { default: plugin, resolveShellTokenizer } = await import(moduleUrl);

function expectShell(expected, toolName, params, configured, platform) {
  const result = resolveShellTokenizer(toolName, params, configured, platform);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.shell, expected);
}

function expectBlocked(toolName, params, configured, platform, reasonFragment) {
  const result = resolveShellTokenizer(toolName, params, configured, platform);
  assert.equal(result.ok, false, `unexpectedly resolved ${result.shell}`);
  assert.match(result.reason, reasonFragment);
}

// Explicit execution surfaces have one known grammar.
expectShell("posix", "bash", {}, undefined, "win32");
expectShell("posix", "exec", { host: "sandbox", elevated: false }, undefined, "win32");
expectShell("powershell", "exec", { host: "gateway" }, undefined, "win32");
expectShell("posix", "exec", { host: "gateway" }, undefined, "linux");
expectShell("powershell", "exec", { host: "sandbox", elevated: true }, undefined, "win32");
expectBlocked("exec", { host: "sandbox" }, undefined, "win32", /cannot determine/);
expectShell("posix", "exec", { host: "sandbox" }, undefined, "linux");

// auto is equivalent across POSIX hosts, but ambiguous on Windows because the
// sandbox uses sh and the gateway uses PowerShell.
expectShell("posix", "exec", { host: "auto" }, undefined, "linux");
expectBlocked("exec", { host: "auto" }, undefined, "win32", /cannot determine/);
expectShell("powershell", "exec", { host: "auto" }, "powershell", "win32");

// An omitted host can select any configured target, including a remote node.
// The operator assertion supplies the missing executor identity on every OS.
expectBlocked("exec", {}, undefined, "win32", /cannot determine/);
expectBlocked("exec", {}, undefined, "linux", /cannot determine/);
expectShell("powershell", "exec", {}, "powershell", "win32");
expectShell("posix", "exec", {}, "posix", "linux");

// Remote node OS is not present in before_tool_call context. Exercise every
// supported asserted grammar, including cmd, and refuse a missing assertion.
expectBlocked("exec", { host: "node" }, undefined, "linux", /cannot determine/);
for (const shell of ["posix", "powershell", "cmd"]) {
  expectShell(shell, "exec", { host: "node" }, shell, "linux");
}

// Invalid values and contradictions must not fall through to Tirith's POSIX
// fallback, even when TIRITH_FAIL_OPEN is enabled elsewhere in the plugin.
expectBlocked("exec", { host: "gateway" }, "posix", "win32", /does not match/);
expectBlocked("bash", {}, "powershell", "linux", /does not match/);
expectBlocked("exec", { host: "gateway" }, "", "win32", /invalid TIRITH_SHELL/);
expectBlocked("exec", { host: "mystery" }, undefined, "linux", /invalid OpenClaw exec host/);
expectBlocked("exec", { host: "gateway", elevated: "yes" }, undefined, "linux", /invalid OpenClaw elevated flag/);

// CI runs this on every platform. Verify the real runner maps its gateway to
// the same tokenizer the resolver advertises.
expectShell(
  process.platform === "win32" ? "powershell" : "posix",
  "exec",
  { host: "gateway" },
  undefined,
  process.platform,
);

// Exercise the installed hook boundary as well as the pure resolver: shell
// identity errors must block before Tirith is spawned and cannot be weakened by
// the operational TIRITH_FAIL_OPEN escape hatch.
let beforeToolCall;
plugin.register({
  on(name, handler) {
    if (name === "before_tool_call") beforeToolCall = handler;
  },
});
assert.equal(typeof beforeToolCall, "function");
const originalFailOpen = process.env.TIRITH_FAIL_OPEN;
const originalShell = process.env.TIRITH_SHELL;
try {
  process.env.TIRITH_FAIL_OPEN = "1";
  delete process.env.TIRITH_SHELL;
  const blocked = beforeToolCall({ toolName: "exec", params: { command: "echo safe" } });
  assert.equal(blocked?.block, true);
  assert.match(blocked?.blockReason, /cannot determine/);
} finally {
  if (originalFailOpen === undefined) delete process.env.TIRITH_FAIL_OPEN;
  else process.env.TIRITH_FAIL_OPEN = originalFailOpen;
  if (originalShell === undefined) delete process.env.TIRITH_SHELL;
  else process.env.TIRITH_SHELL = originalShell;
}

console.log("OpenClaw shell resolver: all parser/executor mappings passed");
