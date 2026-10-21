import { afterAll, beforeAll, describe, expect, it } from "vitest";
import path from "path";
import { mkdtempSync, rmSync, copyFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import plugin from "../index.js";

/**
 * security.config.diff 危险键识别回归。修复后 diff 与
 * middleware.getConfig() 扁平化后的点路径空间比较，intervention.mode 等
 * 危险键必须被正确标记（修复前 dangerous 恒为空）。
 */

interface GwRec { handler: (params: unknown) => Promise<unknown> | unknown }

function createFakeApi() {
  const gatewayMethods = new Map<string, GwRec>();
  const api = {
    pluginConfig: {},
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    on: () => {},
    registerHook: () => {},
    registerGatewayMethod: (name: string, handler: GwRec["handler"]) =>
      gatewayMethods.set(name, { handler }),
    registerHttpRoute: () => {},
    runtime: { registerRuntimeLifecycle: () => {} },
  };
  return { api, gatewayMethods };
}

describe("security.config.diff dangerous-key detection ", () => {
  let tmpDir: string;
  let gatewayMethods: Map<string, GwRec>;
  const savedEnv: string | undefined = process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;

  beforeAll(() => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "config-diff-"));
    const hostConfigPath = path.join(tmpDir, "openclaw.json");
    writeFileSync(hostConfigPath, "{}", "utf8");
    process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = hostConfigPath;

    const policyPath = path.join(tmpDir, "security-policy.yaml");
    copyFileSync(path.join(process.cwd(), "policies", "security-policy.spl.yaml"), policyPath);

    const { api, gatewayMethods: gw } = createFakeApi();
    gatewayMethods = gw;
    (api as { pluginConfig: Record<string, unknown> }).pluginConfig = {
      collector: { ndjsonPath: path.join(tmpDir, "events.jsonl") },
      application: { enabled: false },
      network: { enabled: false },
      system: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: true, policyPath },
    };
    plugin.register(api as never);
  }, 30000);

  afterAll(() => {
    if (savedEnv === undefined) delete process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
    else process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = savedEnv;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  async function diff(params: Record<string, unknown>) {
    const rec = gatewayMethods.get("security.config.diff");
    expect(rec).toBeDefined();
    return (await rec!.handler(params)) as { changes: Array<{ key: string; from: unknown; to: unknown }>; dangerous: Array<{ key: string; reason: string }> };
  }

  it("flags intervention.mode as dangerous when it changes", async () => {
    // normalized default is mode 'enforce'; proposing 'audit' is a real change.
    const result = await diff({ "intervention.mode": "audit" });
    expect(result.changes).toEqual([
      { key: "intervention.mode", from: "enforce", to: "audit" },
    ]);
    expect(result.dangerous.length).toBeGreaterThanOrEqual(1);
    expect(result.dangerous.some((d) => d.key === "intervention.mode")).toBe(true);
  });

  it("flags intervention.mode but not a benign leaf changed in the same diff", async () => {
    // mode enforce→audit is dangerous; reloadIntervalMs 30000→60000 is not.
    const result = await diff({ "intervention.mode": "audit", "intervention.reloadIntervalMs": 60000 });
    expect(result.changes).toHaveLength(2);
    const dangerousKeys = result.dangerous.map((d) => d.key);
    expect(dangerousKeys).toContain("intervention.mode");
    expect(dangerousKeys).not.toContain("intervention.reloadIntervalMs");
  });

  it("flags other dot-path dangerous keys (collector.ndjsonPath, network.enabled)", async () => {
    const result = await diff({ "collector.ndjsonPath": "/tmp/other.jsonl", "network.enabled": true });
    const dangerousKeys = result.dangerous.map((d) => d.key);
    expect(dangerousKeys).toContain("collector.ndjsonPath");
    expect(dangerousKeys).toContain("network.enabled");
  });

  it("reports no changes when proposed matches the effective config", async () => {
    const result = await diff({ "intervention.mode": "enforce", "intervention.enabled": true });
    expect(result.changes).toEqual([]);
    expect(result.dangerous).toEqual([]);
  });

  it("response keeps the {changes, dangerous} contract", async () => {
    const result = await diff({ "intervention.mode": "audit" });
    expect(Array.isArray(result.changes)).toBe(true);
    expect(Array.isArray(result.dangerous)).toBe(true);
    for (const c of result.changes) {
      expect(typeof c.key).toBe("string");
      expect(c).toHaveProperty("from");
      expect(c).toHaveProperty("to");
    }
    for (const d of result.dangerous) {
      expect(typeof d.key).toBe("string");
      expect(typeof d.reason).toBe("string");
    }
  });
});
