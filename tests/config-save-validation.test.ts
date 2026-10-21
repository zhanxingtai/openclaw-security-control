import { afterAll, beforeAll, describe, expect, it } from "vitest";
import path from "path";
import { mkdtempSync, rmSync, copyFileSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import plugin from "../index.js";

/**
 * 保存链路校验增强（未知键治理）。
 *
 * - string 类型应用 min/max（按字符串长度）：userIdField min:1 / max:64。
 * - schema 之外的未知键：接受保存（不拒绝手改 JSON 的用户），但响应 warnings[]
 *   携带提示，并与 system 空开关 warning 合并进同一数组。
 */

interface GwRec { handler: (params: unknown) => unknown }

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

describe("security.config.save validation hardening", () => {
  let tmpDir: string;
  let gatewayMethods: Map<string, GwRec>;
  let hostConfigPath: string;
  const savedEnv: string | undefined = process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;

  beforeAll(() => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "cfg-save-validate-"));
    hostConfigPath = path.join(tmpDir, "openclaw.json");
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
      intervention: { enabled: false, policyPath },
      environment: { hostId: "cfg-save-validate-test" },
    };
    plugin.register(api as never);
  }, 30000);

  afterAll(() => {
    if (savedEnv === undefined) delete process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
    else process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = savedEnv;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects strings shorter/longer than the schema min/max length", async () => {
    const save = gatewayMethods.get("security.config.save")!;

    const tooShort = (await save.handler({
      patch: { application: { userIdField: "" } },
      confirmDanger: false,
    })) as { ok: boolean; error?: { details?: unknown } };
    expect(tooShort.ok).toBe(false);
    expect(JSON.stringify(tooShort.error?.details)).toContain("application.userIdField");

    const tooLong = (await save.handler({
      patch: { application: { userIdField: "x".repeat(65) } },
      confirmDanger: false,
    })) as { ok: boolean; error?: { details?: unknown } };
    expect(tooLong.ok).toBe(false);
    expect(JSON.stringify(tooLong.error?.details)).toContain("application.userIdField");
  });

  it("accepts in-range string lengths", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    // userIdField is marked danger:true, use token flow
    const first = (await save.handler({
      patch: { application: { userIdField: "openId" } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(first.error?.confirmToken).toBeTruthy();
    const res = (await save.handler({
      patch: { application: { userIdField: "openId" } },
      confirmDanger: true,
      confirmToken: first.error?.confirmToken,
    })) as { ok: boolean };
    expect(res.ok).toBe(true);
  });

  it("accepts unknown keys but flags them in warnings[] and persists them", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    const res = (await save.handler({
      patch: { application: { captureCodeMode: false, nosuchKey: 1 } },
      confirmDanger: false,
    })) as {
      ok: boolean;
      warnings?: Array<{ path: string; message: string }>;
    };
    expect(res.ok).toBe(true);
    expect(res.warnings?.some((w) => w.path === "application.nosuchKey")).toBe(true);

    const persisted = JSON.parse(readFileSync(hostConfigPath, "utf8")) as {
      plugins: { entries: Record<string, { config?: { application?: Record<string, unknown> } }> };
    };
    const appCfg = persisted.plugins.entries["sst-security-control-openclaw"].config?.application;
    expect(appCfg?.captureCodeMode).toBe(false);
    expect(appCfg?.nosuchKey).toBe(1);
  });

  it("merges unknown-key warnings with the system empty-switch warning", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    // system.enabled is a danger field → two-step confirm with the
    // server-issued one-time token.
    const first = (await save.handler({
      patch: { system: { enabled: true }, application: { typoKey: true } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(first.ok).toBe(false);
    const res = (await save.handler({
      patch: { system: { enabled: true }, application: { typoKey: true } },
      confirmDanger: true,
      confirmToken: first.error?.confirmToken,
    })) as { ok: boolean; warnings?: Array<{ path: string }> };
    expect(res.ok).toBe(true);
    const paths = (res.warnings ?? []).map((w) => w.path);
    expect(paths).toContain("system.enabled");
    expect(paths).toContain("application.typoKey");
  });

  it("keeps rejecting null for required fields (server-side semantics unchanged)", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    const res = (await save.handler({
      patch: { application: { userIdField: null } },
      confirmDanger: false,
    })) as { ok: boolean; error?: { details?: unknown } };
    expect(res.ok).toBe(false);
    expect(JSON.stringify(res.error?.details)).toContain("application.userIdField");
  });
});
