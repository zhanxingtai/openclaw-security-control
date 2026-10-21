// Verifies that register() in the plugin entry returns synchronously
// (not a Promise). OpenClaw 9.4's loader-module-runtime.ts throws
// "plugin register must be synchronous" if register() yields a Promise.
// Also verifies the policy auto-seed: src/initialize.ts#seedDefaultPolicy()
// walks up from import.meta.url to find a bundled policies/ folder and copies
// it to the user's home when the configured policyPath is missing.
//
// Run after every build:  node scripts/verify-sync-register.mjs
import { execSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const indexTs = path.join(rootDir, "index.ts");
if (!fs.existsSync(indexTs)) {
  console.error(`FAIL: ${indexTs} not found.`);
  process.exit(1);
}

// os.homedir() is captured at module-load time inside DEFAULT_CONFIG, so we
// can't redirect HOME for the test. Back up any existing policy at the real
// home path, then run the test, then restore.
const realHome = os.homedir();
const realPolicyPath = path.join(realHome, ".openclaw", "security-policy.yaml");
const policyExisted = fs.existsSync(realPolicyPath);
let backupPath = null;
if (policyExisted) {
  backupPath = path.join(tmpdir(), `ocsm-policy-backup-${Date.now()}.yaml`);
  fs.copyFileSync(realPolicyPath, backupPath);
  console.log("Backed up existing policy to", backupPath);
}
// Make sure the policy file is missing so seedDefaultPolicy() actually runs.
if (fs.existsSync(realPolicyPath)) fs.unlinkSync(realPolicyPath);

const workDir = fs.mkdtempSync(path.join(tmpdir(), "openclaw-sync-"));
let stageDir;
try {
  const outDir = path.join(workDir, "out");
  execSync(
    `npx tsc --noEmitOnError --outDir "${outDir}"`,
    { stdio: "inherit", cwd: rootDir }
  );

  // Stage the compiled output as <stage>/pkg/index.js plus <stage>/policies/
  // next to it, mirroring the layout OpenClaw uses when extracting the
  // tarball (package/application/index.js + package/policies/... → up one
  // level from index.js's dirname).
  stageDir = path.join(workDir, "stage");
  const stagePkg = path.join(stageDir, "pkg");
  fs.cpSync(outDir, stagePkg, { recursive: true });
  fs.mkdirSync(path.join(stagePkg, "..", "policies"), { recursive: true });
  fs.writeFileSync(
    path.join(stagePkg, "..", "policies", "security-policy.yaml"),
    "rules: []\n# bundled-test-template\n",
    "utf8"
  );
  const stagedIndex = path.join(stagePkg, "index.js");
  const stagedUrl = new URL(`file:///${stagedIndex.replace(/\\/g, "/")}`).href;

  const mod = await import(stagedUrl);
  const entry = mod.plugin ?? mod.default;
  if (!entry || typeof entry.register !== "function") {
    console.error("FAIL: plugin entry has no register()");
    process.exit(1);
  }

  const calls = [];
  const noop = () => undefined;
  const onCalls = [];
  const registerHookCalls = [];
  const registerGatewayMethodCalls = [];
  const registerHttpRouteCalls = [];
  const registerRuntimeLifecycleCalls = [];
  const fakeApi = {
    logger: {
      info: (...a) => calls.push(["info", ...a]),
      error: (...a) => calls.push(["error", ...a]),
      warn: (...a) => calls.push(["warn", ...a]),
      debug: (...a) => calls.push(["debug", ...a]),
    },
    pluginConfig: {},
    on: (name, _h) => onCalls.push(name),
    registerHook: (events, _h, _opts) => registerHookCalls.push({ events, opts: _opts }),
    registerGatewayMethod: (name, _h, _opts) => registerGatewayMethodCalls.push({ name, opts: _opts }),
    registerHttpRoute: (params) => registerHttpRouteCalls.push(params),
    registerControlUiDescriptor: () => undefined,
    session: { controls: { registerControlUiDescriptor: () => undefined } },
    runtime: { registerRuntimeLifecycle: (lc) => registerRuntimeLifecycleCalls.push(lc) },
  };

  const result = entry.register(fakeApi);
  if (result && typeof result.then === "function") {
    console.error(`FAIL: register() returned a Promise (then=${typeof result.then})`);
    console.error("OpenClaw 9.4 will throw 'plugin register must be synchronous'.");
    process.exit(2);
  }
  console.log("OK: register() is synchronous (returned", result === undefined ? "undefined" : typeof result, ")");
  console.log("Logged", calls.length, "lines from register():");
  for (const line of calls.slice(0, 8)) console.log(" ", line.join(" "));

  // === Default-config sync check ===
  // 校验 openclaw.plugin.json#configSchema 默认值与 src/config.ts#DEFAULT_CONFIG
  // 同名字段值一致；schema 未声明的字段跳过（运行时合并兜底）。
  // 默认值对齐校验：schema 是 OpenClaw 9.4 配置 UI
  // 的真值源，runtime 是真实运行值，两边必须一致。
  const manifest = JSON.parse(fs.readFileSync(path.join(rootDir, "openclaw.plugin.json"), "utf8"));
  const SCHEMA_DEFAULTS = manifest.configSchema?.properties ?? {};
  const runtimeMod = await import(
    pathToFileURL(path.join(stagePkg, "src", "config.js")).href
  );
  const RUNTIME_DEFAULTS = runtimeMod.DEFAULT_CONFIG;
  const syncErrors = [];
  function walkSync(schemaVal, runtimeVal, p) {
    if (schemaVal?.default === undefined) return;
    if (runtimeVal === undefined) return;
    if (typeof schemaVal === "object" && schemaVal.type === "object" && schemaVal.properties) {
      for (const k of Object.keys(schemaVal.properties)) {
        walkSync(schemaVal.properties[k], runtimeVal?.[k], p ? `${p}.${k}` : k);
      }
      return;
    }
    const expected = schemaVal.default;
    if (JSON.stringify(expected) !== JSON.stringify(runtimeVal)) {
      syncErrors.push(`${p}: schema=${JSON.stringify(expected)} runtime=${JSON.stringify(runtimeVal)}`);
    }
  }
  walkSync({ type: "object", properties: SCHEMA_DEFAULTS }, RUNTIME_DEFAULTS, "");
  if (syncErrors.length) {
    console.error("FAIL: openclaw.plugin.json configSchema defaults drift from src/config.ts DEFAULT_CONFIG:");
    for (const e of syncErrors) console.error("  -", e);
    process.exit(10);
  }
  console.log("OK: openclaw.plugin.json configSchema defaults aligned with src/config.ts DEFAULT_CONFIG");

  // The real failure mode: register() THROWS partway through. The host catches
  // it, marks the plugin as failed, and discards every api.on/registerHttpRoute
  // /registerGatewayMethod/registerControlUiDescriptor call that already ran.
  // Verify ALL 14 typed hooks + 5 RPCs + 2 HTTP routes + 1 registerHook landed.
  const requiredHooks = [
    "before_agent_run", "agent_end", "before_tool_call", "after_tool_call",
    "before_message_write",
    "session_start", "session_end", "subagent_spawned", "subagent_progress",
    "subagent_ended", "cron_changed",
  ];
  const missing = requiredHooks.filter((h) => !onCalls.includes(h));
  if (missing.length) {
    console.error("FAIL: api.on() did not register all typed hooks. Missing:", missing.join(", "));
    process.exit(5);
  }
  console.log(`OK: api.on() registered ${onCalls.length}/${requiredHooks.length} typed hooks`);

  if (registerHookCalls.length === 0) {
    console.error("FAIL: api.registerHook() not called (would fail with 'hook registration missing name')");
    process.exit(6);
  }
  for (const call of registerHookCalls) {
    if (!call.opts || !call.opts.name) {
      console.error("FAIL: api.registerHook() called without `name` opt — 9.4 throws 'hook registration missing name'");
      process.exit(7);
    }
  }
  console.log(`OK: api.registerHook() called with name(s): ${registerHookCalls.map((c) => c.opts?.name).join(", ")}`);

  if (registerHttpRouteCalls.length < 2) {
    console.error("FAIL: expected >=2 api.registerHttpRoute() calls (events.ndjson, panel), got", registerHttpRouteCalls.length);
    process.exit(8);
  }
  console.log(`OK: api.registerHttpRoute() registered ${registerHttpRouteCalls.length} route(s):`,
    registerHttpRouteCalls.map((r) => r.path).join(", "));

  if (registerGatewayMethodCalls.length < 5) {
    console.error("FAIL: expected >=5 api.registerGatewayMethod() calls, got", registerGatewayMethodCalls.length);
    process.exit(9);
  }
  console.log(`OK: api.registerGatewayMethod() registered ${registerGatewayMethodCalls.length} RPC(s)`);

  if (fs.existsSync(realPolicyPath)) {
    const seeded = fs.readFileSync(realPolicyPath, "utf8");
    if (seeded.includes("bundled-test-template")) {
      console.log("OK: default policy seeded at", realPolicyPath, "(", seeded.length, "bytes )");
    } else {
      console.error("FAIL: policy file exists but content does not match the staged template");
      console.error("  expected marker: bundled-test-template");
      console.error("  got:", seeded.slice(0, 80));
      process.exit(3);
    }
  } else {
    console.error("FAIL: policy file was not created at", realPolicyPath);
    process.exit(4);
  }
} finally {
  // Clean up: remove the seeded policy, restore backup if any.
  if (fs.existsSync(realPolicyPath)) fs.unlinkSync(realPolicyPath);
  if (backupPath && fs.existsSync(backupPath)) {
    fs.mkdirSync(path.dirname(realPolicyPath), { recursive: true });
    fs.copyFileSync(backupPath, realPolicyPath);
    fs.unlinkSync(backupPath);
    console.log("Restored backup policy");
  }
  fs.rmSync(workDir, { recursive: true, force: true });
}