import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import http from "http";
import path from "path";
import { mkdtempSync, rmSync, copyFileSync, existsSync } from "fs";
import { tmpdir } from "os";
import type { AddressInfo } from "net";
import plugin from "../index.js";

/**
 * WeChat QR route 404 fallback.
 *
 * The bundled asset ships in assets/, so the happy path is covered by
 * bridge-endpoints.test.ts. This file simulates a broken/missing deployment
 * (asset absent from every search root) by wrapping fs.existsSync, and
 * asserts the route answers 404 instead of crashing.
 */

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    existsSync: (p: Parameters<typeof existsSync>[0]) =>
      String(p).includes("wechat-mp-qr.jpg") ? false : actual.existsSync(p),
  };
});

interface RouteRec { auth: string; handler: (req: unknown, res: unknown) => void }

function createFakeApi() {
  const httpRoutes = new Map<string, RouteRec>();
  const api = {
    pluginConfig: {},
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    on: () => {},
    registerHook: () => {},
    registerGatewayMethod: () => {},
    registerHttpRoute: (route: RouteRec & { path: string }) => httpRoutes.set(route.path, route),
    runtime: { registerRuntimeLifecycle: () => {} },
  };
  return { api, httpRoutes };
}

describe("wechat qr route 404 fallback", () => {
  let tmpDir: string;
  let server: http.Server;
  let base: string;

  beforeAll(async () => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "qr-404-test-"));
    const policyPath = path.join(tmpDir, "security-policy.yaml");
    copyFileSync(path.join(process.cwd(), "policies", "security-policy.spl.yaml"), policyPath);

    const { api, httpRoutes } = createFakeApi();
    (api as { pluginConfig: Record<string, unknown> }).pluginConfig = {
      collector: { ndjsonPath: path.join(tmpDir, "events.jsonl") },
      application: { enabled: false },
      network: { enabled: false },
      system: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: false, policyPath },
      environment: { hostId: "qr-404-test" },
    };
    plugin.register(api as never);

    server = http.createServer((req, res) => {
      const route = httpRoutes.get((req.url ?? "").split("?")[0]);
      if (!route) { res.statusCode = 404; res.end("not found"); return; }
      route.handler(req, res as never);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 30000);

  afterAll(async () => {
    server?.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("answers 404 when the bundled qr image is missing from every search root", async () => {
    const response = await fetch(`${base}/openclaw-security-monitor/wechat-mp-qr.jpg`);
    expect(response.status).toBe(404);
  });

  it("favicon route still resolves (mock only hides the qr asset)", async () => {
    const response = await fetch(`${base}/openclaw-security-monitor/favicon.ico`);
    expect(response.status).toBe(200);
  });
});
