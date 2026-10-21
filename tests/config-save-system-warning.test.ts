import { afterAll, beforeAll, describe, expect, it } from "vitest";
import path from "path";
import { mkdtempSync, rmSync, copyFileSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import plugin from "../index.js";

/**
 * system 层空开关治理。
 *
 * - security.config.save 在 system.enabled=true 且 procfs/cgroups 均未开启时，
 *   必须在成功响应里携带 warning（面板展示接线）。
 * - CONFIG_SCHEMA 必须暴露 system.procfs.enabled / system.cgroups.enabled，
 *   且 dependsOn system.enabled。
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

describe("security.config.save system empty-switch warning", () => {
  let tmpDir: string;
  let gatewayMethods: Map<string, GwRec>;
  let hostConfigPath: string;
  const savedEnv: string | undefined = process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;

  beforeAll(() => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "cfg-save-sys-warn-"));
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
      environment: { hostId: "cfg-save-sys-warn-test" },
    };
    plugin.register(api as never);
  }, 30000);

  afterAll(() => {
    if (savedEnv === undefined) delete process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
    else process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = savedEnv;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("warns when system.enabled is saved without procfs/cgroups collectors", async () => {
    const save = gatewayMethods.get("security.config.save");
    expect(save).toBeDefined();
    // danger saves are two-step — the server issues a one-time
    // confirmToken on the first request; the follow-up must carry it.
    const first = (await save!.handler({
      patch: { system: { enabled: true } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(first.ok).toBe(false);
    expect(first.error?.confirmToken).toBeTruthy();
    const res = (await save!.handler({
      patch: { system: { enabled: true } },
      confirmDanger: true,
      confirmToken: first.error?.confirmToken,
    })) as { ok: boolean; warnings?: Array<{ path: string; message: string }> };
    expect(res.ok).toBe(true);
    expect(Array.isArray(res.warnings)).toBe(true);
    expect(res.warnings!.some((w) => w.path === "system.enabled")).toBe(true);
  });

  it("stops warning once a collector toggle is enabled, and persists dotted keys nested", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    const first = (await save.handler({
      patch: { system: { enabled: true, "procfs.enabled": true } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(first.ok).toBe(false);
    const res = (await save.handler({
      patch: { system: { enabled: true, "procfs.enabled": true } },
      confirmDanger: true,
      confirmToken: first.error?.confirmToken,
    })) as { ok: boolean; warnings?: Array<{ path: string; message: string }> };
    expect(res.ok).toBe(true);
    expect(res.warnings ?? []).toHaveLength(0);

    const persisted = JSON.parse(readFileSync(hostConfigPath, "utf8")) as {
      plugins: { entries: Record<string, { config?: { system?: { procfs?: { enabled?: boolean } } } }> };
    };
    const systemCfg = persisted.plugins.entries["sst-security-control-openclaw"].config?.system;
    expect(systemCfg?.procfs?.enabled).toBe(true);
  });

  it("schema exposes procfs/cgroups toggles depending on system.enabled", async () => {
    const get = gatewayMethods.get("security.config.get")!;
    const res = (await get.handler(undefined)) as {
      schema: Array<{
        section: string;
        key: string;
        type: string;
        dependsOn?: { section: string; key: string; value?: unknown };
      }>;
    };
    const procfs = res.schema.find((f) => f.section === "system" && f.key === "procfs.enabled");
    const cgroups = res.schema.find((f) => f.section === "system" && f.key === "cgroups.enabled");
    expect(procfs).toBeDefined();
    expect(procfs!.type).toBe("bool");
    expect(procfs!.dependsOn).toEqual({ section: "system", key: "enabled", value: true });
    expect(cgroups).toBeDefined();
    expect(cgroups!.type).toBe("bool");
    expect(cgroups!.dependsOn).toEqual({ section: "system", key: "enabled", value: true });
  });
});
