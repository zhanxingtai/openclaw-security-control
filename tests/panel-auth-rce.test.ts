import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "http";
import path from "path";
import vm from "node:vm";
import { mkdtempSync, rmSync, copyFileSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import type { AddressInfo } from "net";
import plugin, { CONFIG_SCHEMA } from "../index.js";
import { isSafePythonPath, probePythonPsutil } from "../src/initialize.js";
import type { SecurityMonitorConfig } from "../src/types.js";

/**
 * 面板 auth/RCE 链加固回归。
 *
 * 覆盖审查发现的八项问题：
 *  1. CSRF guard：host+port 严格同源；Origin: null 仅放行带 panel nonce 的
 *     sandbox iframe 请求；ACAO 不再回显字面 null、移除 ACAC；
 *  2. danger 保存需服务端一次性 confirmToken（confirmDanger 自声明不再够用）；
 *  3. pythonPath RCE：probe 仅执行 python3 命名的安全路径；dry-run 探测当前生效配置；
 *  4. 原型链污染：__proto__/constructor/prototype 的 section/点键段直接拒绝；
 *  5. 面板 XSS：属性上下文 escAttr 转义（vm 驱动真实面板渲染断言）；
 *  6. POST body 1MB 上限 → 413 + 连接销毁；
 *  7. evaluate 参数上限 + matchedPolicies 仅回 rule id；config.get 敏感键混淆；
 *  8. loadEvents/loadBlocks RPC 失败时错误插入 DOM（此前只生成 HTML 丢弃）。
 */

interface RouteRec { auth: string; handler: (req: unknown, res: unknown) => void }
interface GwRec { handler: (params: unknown) => Promise<unknown> | unknown }

function createFakeApi() {
  const httpRoutes = new Map<string, RouteRec>();
  const gatewayMethods = new Map<string, GwRec>();
  const api = {
    pluginConfig: {},
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    on: () => {},
    registerHook: () => {},
    registerGatewayMethod: (name: string, handler: GwRec["handler"]) =>
      gatewayMethods.set(name, { handler }),
    registerHttpRoute: (route: RouteRec & { path: string }) => httpRoutes.set(route.path, route),
    runtime: { registerRuntimeLifecycle: () => {} },
  };
  return { api, httpRoutes, gatewayMethods };
}

function request(base: string, opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string }) {
  return new Promise<{ status: number; headers: http.OutgoingHttpHeaders; body: string }>((resolve, reject) => {
    const u = new URL(base + (opts.path ?? "/openclaw-security-monitor/panel"));
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: opts.method ?? "GET",
        headers: opts.headers ?? {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      }
    );
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

describe("panel auth/RCE hardening", () => {
  let tmpDir: string;
  let server: http.Server;
  let base: string;
  let httpRoutes: Map<string, RouteRec>;
  let gatewayMethods: Map<string, GwRec>;
  const savedEnv: string | undefined = process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;

  beforeAll(async () => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "panel-rce-"));
    const hostConfigPath = path.join(tmpDir, "openclaw.json");
    writeFileSync(hostConfigPath, "{}", "utf8");
    process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = hostConfigPath;

    const policyPath = path.join(tmpDir, "security-policy.yaml");
    copyFileSync(path.join(process.cwd(), "policies", "security-policy.spl.yaml"), policyPath);

    const { api, httpRoutes: routes, gatewayMethods: gw } = createFakeApi();
    httpRoutes = routes;
    gatewayMethods = gw;
    (api as { pluginConfig: Record<string, unknown> }).pluginConfig = {
      collector: { ndjsonPath: path.join(tmpDir, "events.jsonl") },
      application: { enabled: false },
      network: { enabled: false },
      system: { enabled: false },
      assetMonitor: { enabled: false, sensitiveKeyPatterns: ["hostid"] },
      intervention: { enabled: true, policyPath },
      environment: { hostId: "panel-rce-secret-host" },
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
    if (savedEnv === undefined) delete process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
    else process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = savedEnv;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── 1. CSRF guard + CORS ────────────────────────────────────────────

  it("GET panel mints a fresh nonce per load", async () => {
    const a = await request(base, {});
    const b = await request(base, {});
    expect(a.status).toBe(200);
    const nonceA = a.body.match(/ocm-panel-nonce" content="([^"]+)"/)?.[1];
    const nonceB = b.body.match(/ocm-panel-nonce" content="([^"]+)"/)?.[1];
    expect(nonceA).toBeTruthy();
    expect(nonceB).toBeTruthy();
    expect(nonceA).not.toBe(nonceB);
  });

  it("accepts strict same-origin POST (host+port) without a nonce", async () => {
    const res = await request(base, {
      method: "POST",
      headers: { Origin: base, "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.metrics", params: {} }),
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).ok).toBe(true);
  });

  it("rejects same-host-different-port Origin (port is part of the origin)", async () => {
    const res = await request(base, {
      method: "POST",
      headers: { Origin: base.replace(/:\d+$/, ":9999"), "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.metrics", params: {} }),
    });
    expect(res.status).toBe(403);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rejects cross-origin POST and emits no CORS headers", async () => {
    const res = await request(base, {
      method: "POST",
      headers: { Origin: "https://evil.example", "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.metrics", params: {} }),
    });
    expect(res.status).toBe(403);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("rejects Origin: null without a panel nonce — but lets the panel read the 403", async () => {
    const res = await request(base, {
      method: "POST",
      headers: { Origin: "null", "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.metrics", params: {} }),
    });
    expect(res.status).toBe(403);
    // ACAO: null 是**故意**发的，跟上面那条 attacker origin 的 "undefined" 反着来。
    // 不发的话浏览器的 CORS 检查会把 fetch 直接 reject 成 "Failed to fetch"，
    // 面板里的 r.status===401/403 分支（scheduleAuthReload → 自动重载重建会话）
    // 一辈子走不到：用户只看到一个点了没反应、不报错、也换不回别的语言的控件。
    // 让面板读得到自己的拒绝理由，恢复路径才存在。
    //
    // 这里没有放松任何东西：POST 依旧 403；不带 Access-Control-Allow-Credentials
    // （opaque origin 本来也送不到 cookie）；响应体只有一句固定文案。改这条断言
    // 前先读上面两条——attacker origin 必须仍然读不到。
    expect(res.headers["access-control-allow-origin"]).toBe("null");
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
    expect(JSON.parse(res.body).ok).toBe(false);
  });

  it("a stale panel nonce is rejected, and the panel can tell it apart", async () => {
    // 语言切换写入 openclaw.json 会让宿主重载插件，panelNonces 随之清空，
    // 页面手里那个 nonce 就成了 stale 的。此时 POST 必须仍然 403——但要能被
    // 读出来，否则用户看到的只是"点了没反应"。
    const res = await request(base, {
      method: "POST",
      headers: { Origin: "null", "X-Panel-Nonce": "not-a-real-nonce", "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.config.save", params: {} }),
    });
    expect(res.status).toBe(403);
    expect(res.headers["access-control-allow-origin"]).toBe("null");
  });

  it("accepts Origin: null with the minted nonce, ACAO null without credentials", async () => {
    const get = await request(base, {});
    const nonce = get.body.match(/ocm-panel-nonce" content="([^"]+)"/)?.[1]!;
    const res = await request(base, {
      method: "POST",
      headers: { Origin: "null", "X-Panel-Nonce": nonce, "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.metrics", params: {} }),
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).ok).toBe(true);
    expect(res.headers["access-control-allow-origin"]).toBe("null");
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("still accepts POSTs with no Origin header (non-browser clients)", async () => {
    const res = await request(base, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method: "security.metrics", params: {} }),
    });
    expect(res.status).toBe(200);
  });

  it("preflight: rejects cross-origin, approves sandbox null without credentials", async () => {
    const evil = await request(base, { method: "OPTIONS", headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "POST" } });
    expect(evil.status).toBe(403);
    expect(evil.headers["access-control-allow-origin"]).toBeUndefined();

    const sandbox = await request(base, { method: "OPTIONS", headers: { Origin: "null", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type" } });
    expect(sandbox.status).toBe(204);
    expect(sandbox.headers["access-control-allow-origin"]).toBe("null");
    expect(sandbox.headers["access-control-allow-credentials"]).toBeUndefined();
    // The panel's RPC POSTs carry the X-Panel-Nonce custom header; the
    // preflight must allow it or the browser never sends the POST
    // (net::ERR_FAILED), so Allow-Headers must include it alongside
    // Content-Type.
    const allowHeaders = String(sandbox.headers["access-control-allow-headers"] || "").toLowerCase();
    expect(allowHeaders).toContain("content-type");
    expect(allowHeaders).toContain("x-panel-nonce");
  });

  // ── 1b. Long-idle session expiry → auto-reload (panel UX fix) ─────
  //
  // 长挂面板标签页，宿主 session/cookie 过期 → 401/403。浏览器读不到响应体
  // （CORS 拒读），r.text() 抛 "Failed to fetch" 把真正状态吞了。让面板在
  // 401/403 时自动 location.reload() 重建会话，比显示错误信息友好。

  it("401/403 from auto-refresh triggers exactly one window.location.reload()", async () => {
    const { html, nonce } = await extractPanelHtml();
    const panel = await runPanel({
      nonce,
      html,
      respond: (method) => {
        if (method === "security.metrics") return { total: 0 };
        return {};
      },
      statusOverride: (method) => (method === "security.metrics" ? 403 : 200),
    });
    await panel.clickTab("metrics");
    // 50ms scheduleAuthReload 缓冲 + 微任务刷新
    await new Promise((r) => setTimeout(r, 100));
    expect(panel.getReloadCount()).toBe(1);
    // rpc() 在 reload 计划后返回永不 resolve 的 Promise，所以错误条不会被
    // "Failed to fetch" 覆盖（确认错误条仍为初始空状态）。
    expect(panel.els.get("panel").innerHTML).not.toContain("Failed to fetch");
  });

  it("deduplicates reload across parallel RPCs that all hit 403", async () => {
    const { html, nonce } = await extractPanelHtml();
    let inFlight = 0;
    let maxInFlight = 0;
    const panel = await runPanel({
      nonce,
      html,
      respond: async (method) => {
        // security.status 在 boot 时也并行触发一次，所以至少能见到两次 403。
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight--;
        if (method === "security.metrics") return { total: 0 };
        return {};
      },
      statusOverride: () => 401,
    });
    await panel.clickTab("metrics");
    await new Promise((r) => setTimeout(r, 100));
    // 同一 tick 内多 RPC 同时 401 → scheduleAuthReload 去重，reload 仍只 1 次。
    expect(panel.getReloadCount()).toBe(1);
    expect(maxInFlight).toBeGreaterThan(1);
  });

  it("non-auth errors (e.g. 500) do NOT trigger reload — they surface as error bar", async () => {
    const { html, nonce } = await extractPanelHtml();
    const panel = await runPanel({
      nonce,
      html,
      respond: () => ({}),
      statusOverride: () => 500,
    });
    await panel.clickTab("metrics");
    await new Promise((r) => setTimeout(r, 50));
    expect(panel.getReloadCount()).toBe(0);
    expect(panel.els.get("panel").innerHTML).toContain("HTTP 500");
  });

  // ── 1c. 宿主重载窗口 → 读不到响应 ≠ 可以立刻 reload ────────────────
  //
  // Config 页保存写的是宿主的 openclaw.json，宿主随后重载插件配置。
  // 那个窗口里所有插件路由由宿主自己回 500 且**不带** CORS 头，本插件 handler
  // 根本没被调用：浏览器只能报 TypeError("Failed to fetch")，面板读到的是
  // "没有响应"而不是"500"。此刻 location.reload() 正好落进窗口，把用户甩到
  // 一张裸 500 页上（用户报的现象）。所以读不到响应时必须等路由重新给出可读
  // 响应、且连续可读到判据成立，才导航。
  //
  // （header 的语言开关已经不再写宿主配置——见 panel-i18n.test.ts——但它仍然
  // 走同一个 settle 闸门：万一哪天宿主连插件自己的状态文件也 watch，窗口照
  // 旧存在，闸门就是唯一的防线。）

  it("unreadable RPC failures wait for the route to answer again before reloading", async () => {
    const { html, nonce } = await extractPanelHtml();
    let routeReadable = true;
    const panel = await runPanel({
      nonce,
      html,
      respond: (method) => (method === "security.metrics" ? { metrics: { total: 0 } } : {}),
      rejectWhen: () => !routeReadable,
    });
    // boot 时 metrics 成功过一次 → rpcEverOk 为真，后续读不到才值得自愈。
    expect(panel.getReloadCount()).toBe(0);

    routeReadable = false;
    await panel.clickTab("metrics");
    await panel.flush(1500);
    // 窗口里：探针读不到响应，绝不重载（否则就是那张裸 500 页）。
    expect(panel.getReloadCount()).toBe(0);
    expect(panel.calls.filter((c) => c.method === "security.status").length).toBeGreaterThan(0);

    routeReadable = true;
    await panel.flush(7000);
    // 缓过来之后：连续可读够数才导航，且整条链路只导航一次。
    expect(panel.getReloadCount()).toBe(1);
  }, 20000);

  it("the language toggle saves, then navigates only after the reload window closes", async () => {
    const { html, nonce } = await extractPanelHtml();
    let inReloadWindow = true;
    const panel = await runPanel({
      nonce,
      html,
      langSwitch: { current: "en", buttons: ["zh"] },
      respond: (method) => {
        if (method === "security.metrics") return { metrics: { total: 0 } };
        if (method === "security.panel.locale.set") return { ok: true, locale: "zh" };
        return {};
      },
      // 窗口里连探针都读不到：宿主自己的 500 没有 ACAO。除了开关本身那一发
      // （它必须先成功，偏好才谈得上落盘）。
      rejectWhen: (method) => inReloadWindow && method !== "security.panel.locale.set",
    });

    panel.clickLang("zh");
    await panel.flush(1200);
    // 偏好落盘，但此刻路由还读不到 → 不导航。
    expect(panel.calls.some((c) => c.method === "security.panel.locale.set")).toBe(true);
    expect(panel.getReloadCount()).toBe(0);
    // 按钮保持 disabled（用户不该能再点一次）。
    expect(panel.langButtons.find((b) => b.lang === "zh")?.disabled).toBe(true);

    inReloadWindow = false;
    await panel.flush(7000);
    // 路由恢复可读并连续读到判据成立后才导航，一次且仅一次。
    expect(panel.getReloadCount()).toBe(1);
  }, 20000);

  // ── 6. POST body cap ────────────────────────────────────────────────

  it("returns 413 for POST bodies over 1 MiB", async () => {
    await new Promise<void>((resolve, reject) => {
      const u = new URL(base);
      const req = http.request(
        {
          hostname: u.hostname,
          port: u.port,
          path: "/openclaw-security-monitor/panel",
          method: "POST",
          headers: { "Content-Type": "application/json" },
        },
        (res) => {
          expect(res.statusCode).toBe(413);
          res.resume();
          res.on("end", () => resolve());
        }
      );
      req.on("error", reject);
      req.write(JSON.stringify({ method: "security.metrics", params: {} }));
      req.write("x".repeat(1024 * 1024));
      req.end();
    });
  });

  // ── 2. danger save confirm token ────────────────────────────────────

  it("danger save requires the server-issued one-time token; confirmDanger alone no longer works", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    const patch = { system: { enabled: true } };

    // confirmDanger=true without a token: refused, token issued instead.
    const selfDeclared = (await save.handler({ patch, confirmDanger: true })) as {
      ok: boolean;
      error?: { message: string; fields?: string[]; confirmToken?: string };
    };
    expect(selfDeclared.ok).toBe(false);
    expect(selfDeclared.error?.confirmToken).toBeTruthy();
    expect(selfDeclared.error?.fields).toContain("system.enabled");

    // Second request with token + confirmDanger executes.
    const confirmed = (await save.handler({ patch, confirmDanger: true, confirmToken: selfDeclared.error?.confirmToken })) as { ok: boolean };
    expect(confirmed.ok).toBe(true);

    // Token is one-time: reuse is refused.
    const reused = (await save.handler({ patch, confirmDanger: true, confirmToken: selfDeclared.error?.confirmToken })) as {
      ok: boolean;
      error?: { confirmToken?: string };
    };
    expect(reused.ok).toBe(false);
    expect(reused.error?.confirmToken).toBeTruthy(); // a fresh token is issued for the retry
  });

  it("confirm token is bound to the exact patch digest", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    const first = (await save.handler({ patch: { system: { enabled: true } }, confirmDanger: false })) as {
      ok: boolean;
      error?: { confirmToken?: string };
    };
    const token = first.error?.confirmToken!;
    // Same token, different patch → rejected.
    const mismatched = (await save.handler({
      patch: { system: { enabled: true }, application: { typoKey: true } },
      confirmDanger: true,
      confirmToken: token,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(mismatched.ok).toBe(false);
  });

  it("non-danger saves still complete in a single request without a token", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    // userIdField is now marked danger:true, so this requires a token flow.
    const first = (await save.handler({
      patch: { application: { userIdField: "openId2" } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(first.error?.confirmToken).toBeTruthy();
    const res = (await save.handler({
      patch: { application: { userIdField: "openId2" } },
      confirmDanger: true,
      confirmToken: first.error?.confirmToken,
    })) as { ok: boolean };
    expect(res.ok).toBe(true);
  });

  // ── 4. prototype pollution guard ────────────────────────────────────

  it("rejects __proto__/constructor/prototype sections and dotted segments without polluting Object.prototype", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    const protoPatch = JSON.parse('{"__proto__": {"polluted": "yes"}}') as Record<string, Record<string, unknown>>;
    const res = (await save.handler({ patch: protoPatch, confirmDanger: true })) as { ok: boolean; error?: { message: string; details?: unknown } };
    expect(res.ok).toBe(false);
    expect(JSON.stringify(res.error?.details)).toContain("__proto__");
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();

    const dotted = (await save.handler({
      patch: { system: { "__proto__.polluted": 1 } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { details?: unknown } };
    expect(dotted.ok).toBe(false);
    expect(JSON.stringify(dotted.error?.details)).toContain("__proto__");
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();

    const ctor = JSON.parse('{"constructor": {"prototype": {"polluted": "yes"}}}') as Record<string, Record<string, unknown>>;
    const ctorRes = (await save.handler({ patch: ctor, confirmDanger: true })) as { ok: boolean };
    expect(ctorRes.ok).toBe(false);
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
  });

  // ── 3. pythonPath RCE guard ─────────────────────────────────────────

  it("isSafePythonPath accepts only python3-named bare or absolute paths", () => {
    expect(isSafePythonPath("python3")).toBe(true);
    expect(isSafePythonPath("python3.11")).toBe(true);
    expect(isSafePythonPath("/usr/bin/python3")).toBe(true);
    expect(isSafePythonPath("/usr/bin/python3.12")).toBe(true);
    expect(isSafePythonPath("./python3")).toBe(false);
    expect(isSafePythonPath("bin/python3")).toBe(false);
    expect(isSafePythonPath("python")).toBe(false);
    expect(isSafePythonPath("/usr/bin/python")).toBe(false);
    expect(isSafePythonPath("/tmp/evil")).toBe(false);
    expect(isSafePythonPath("python3 -c evil")).toBe(false);
    expect(isSafePythonPath("")).toBe(false);
  });

  it("probePythonPsutil refuses unsafe paths without executing them", () => {
    const mkCfg = (pythonPath: string) =>
      ({ system: { enabled: true, procfs: { enabled: true, pythonPath }, cgroups: { enabled: false } } }) as unknown as SecurityMonitorConfig;
    // Unsafe basename: skipped, treated as psutil-missing (false), never spawned.
    expect(probePythonPsutil(mkCfg("/usr/bin/evil-interpreter"))).toBe(false);
    expect(probePythonPsutil(mkCfg("python3 -c evil"))).toBe(false);
  });

  it("save dry-run probes the CURRENT effective config, never the pending patch's pythonPath", async () => {
    const save = gatewayMethods.get("security.config.save")!;
    // The patch enables system layer with a hostile pythonPath. If the dry-run
    // probed the pending patch, spawn would fail and forcedDisabled would list
    // system.* entries; with the fix the effective config (system off) is
    // probed, so no system.* force-off is reported.
    const first = (await save.handler({
      patch: { system: { enabled: true, "procfs.enabled": true, "procfs.pythonPath": "/usr/bin/evil-interpreter" } },
      confirmDanger: true,
    })) as { ok: boolean; error?: { confirmToken?: string } };
    expect(first.ok).toBe(false);
    const res = (await save.handler({
      patch: { system: { enabled: true, "procfs.enabled": true, "procfs.pythonPath": "/usr/bin/evil-interpreter" } },
      confirmDanger: true,
      confirmToken: first.error?.confirmToken,
    })) as { ok: boolean; bootstrapReport?: { forcedDisabled?: Array<{ path: string }> } };
    expect(res.ok).toBe(true);
    const forced = (res.bootstrapReport?.forcedDisabled ?? []).map((d) => d.path);
    expect(forced.filter((p) => p.startsWith("system."))).toEqual([]);
  });

  // ── 7. evaluate limits + matchedPolicies slim + config.get obfuscation ──

  async function evaluateWhenReady(params: unknown): Promise<Record<string, unknown>> {
    const evaluate = gatewayMethods.get("security.evaluate")!;
    for (let i = 0; i < 100; i++) {
      const res = (await evaluate.handler(params)) as Record<string, unknown>;
      if (!String(res.blockReason ?? "").includes("intervention engine disabled")) return res;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error("intervention engine never became ready");
  }

  it("security.evaluate rejects oversized fields", async () => {
    const res = await evaluateWhenReady({
      actionType: "tool_call",
      toolName: "exec",
      body: "x".repeat(70 * 1024),
    });
    expect(String(res.error ?? "")).toContain("exceeds");
  });

  it("security.evaluate rejects oversized params", async () => {
    const res = await evaluateWhenReady({
      actionType: "tool_call",
      toolName: "exec",
      params: { command: "x".repeat(70 * 1024) },
    });
    expect(String(res.error ?? "")).toContain("exceeds");
  });

  it("security.evaluate returns matchedPolicies as rule ids only", async () => {
    const res = await evaluateWhenReady({
      actionType: "tool_call",
      toolName: "exec",
      params: { command: "cat /etc/shadow" },
    });
    expect(res.decision).toBe("block");
    const matched = res.matchedPolicies as Array<Record<string, unknown>>;
    expect(Array.isArray(matched)).toBe(true);
    expect(matched.length).toBeGreaterThan(0);
    for (const m of matched) {
      expect(Object.keys(m)).toEqual(["policyId"]);
    }
    expect(matched.some((m) => m.policyId === "block-exec-sensitive-file")).toBe(true);
  });

  it("security.config.get obfuscates sensitive-key values (assetMonitor.sensitiveKeyPatterns)", async () => {
    const get = gatewayMethods.get("security.config.get")!;
    const res = (await get.handler(undefined)) as { config: { environment?: { hostId?: string } }; schema: unknown };
    // The test config sets sensitiveKeyPatterns: ["hostid"], so hostId is masked.
    expect(res.config.environment?.hostId).toMatch(/^obf:v1:/);
    expect(res.schema).toBeDefined();
  });

  // ── 5 + 8. panel rendering via vm: attribute escaping + DOM error surfacing ──

  async function extractPanelHtml(): Promise<{ html: string; nonce: string }> {
    const res = await request(base, {});
    const nonce = res.body.match(/ocm-panel-nonce" content="([^"]+)"/)?.[1]!;
    return { html: res.body, nonce };
  }

  function makeEl(id: string, handlers: Map<string, (e: unknown) => void>) {
    return {
      id,
      style: {} as Record<string, string>,
      dataset: {} as Record<string, string>,
      innerHTML: "",
      textContent: "",
      className: "",
      disabled: false,
      checked: false,
      value: "",
      onclick: undefined as unknown,
      addEventListener(type: string, fn: (e: unknown) => void) {
        handlers.set(`${id}:${type}`, fn);
      },
      appendChild(child: { innerHTML: string }) {
        this.innerHTML += child.innerHTML;
      },
      // Append-only mock: collapse "beforeend"/"afterend"/"beforebegin"/"afterbegin"
      // to a plain innerHTML append so the new renderEventsRows / renderHits
      // append path can be observed in tests (the old renderEvents wrote the
      // whole table via innerHTML =, so a no-op here was enough; the new
      // skeleton+rows split needs insertAdjacentHTML to actually land rows).
      insertAdjacentHTML(_pos: string, html: string) {
        this.innerHTML += html;
      },
      setAttribute() {},
      getAttribute() { return null; },
      closest() { return null; },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      focus() {},
    };
  }

  async function runPanel(opts: {
    nonce: string;
    html: string;
    respond: (method: string, params: unknown, callIndex: number) => unknown;
    rejectMethods?: string[];
    /**
     * Model a browser-level failure — the response came back without CORS
     * headers (the host's own 500 while it reloads plugin config), so fetch()
     * rejects with a TypeError and no status ever reaches the panel. Throws a
     * TypeError, unlike rejectMethods' plain Error, because rpc() keys its
     * self-heal off err.name === "TypeError".
     */
    rejectWhen?: (method: string) => boolean;
    /** Header language switcher: data-current plus one button per locale. */
    langSwitch?: { current: string; buttons: string[] };
    /** Force a specific HTTP status for the matching RPC; default 200. */
    statusOverride?: (method: string) => number;
  }) {
    const handlers = new Map<string, (e: unknown) => void>();
    const els = new Map<string, ReturnType<typeof makeEl>>();
    const calls: Array<{ method: string; params: unknown }> = [];
    const getEl = (id: string) => {
      if (!els.has(id)) els.set(id, makeEl(id, handlers));
      return els.get(id)!;
    };
    let reloadCount = 0;
    const langButtons: Array<{ lang: string; disabled: boolean; textContent: string }> = [];
    const sandbox: Record<string, unknown> = {
      console,
      setTimeout,
      clearTimeout,
      setInterval: () => 0,
      clearInterval: () => {},
      fetch: async (_url: string, fetchOpts: { body: string }) => {
        const parsed = JSON.parse(fetchOpts.body) as { method: string; params: unknown };
        calls.push(parsed);
        if (opts.rejectWhen?.(parsed.method)) throw new TypeError("Failed to fetch");
        if (opts.rejectMethods?.includes(parsed.method)) throw new Error("network down");
        const reply = await opts.respond(parsed.method, parsed.params, calls.length - 1);
        const status = opts.statusOverride?.(parsed.method) ?? 200;
        if (status >= 400) {
          return {
            ok: false,
            status,
            json: async () => ({ ok: false, error: { message: "mocked " + status } }),
            text: async () => "mocked " + status,
          };
        }
        return {
          ok: true,
          status,
          json: async () => ({ ok: true, payload: reply }),
          text: async () => "",
        };
      },
      alert: () => {},
      AbortController,
      document: undefined as unknown,
      navigator: {},
      location: {
        reload: () => { reloadCount++; },
        // wireLangButton rewrites the query string before reloading; absent
        // fields would make location.search.indexOf throw inside the click
        // handler and mask whatever the test is actually about.
        search: "",
        pathname: "/openclaw-security-monitor/panel-tab",
        hash: "",
      },
    };
    sandbox.window = sandbox;
    sandbox.top = sandbox;
    sandbox.self = sandbox;
    // Purpose-built (not makeEl): wireLangSwitch reads data-current off the box
    // and data-lang off each button, and makeEl's getAttribute always returns
    // null — with that the switcher silently wires zero buttons.
    if (opts.langSwitch) {
      const current = opts.langSwitch.current;
      for (const lang of opts.langSwitch.buttons) {
        const btn = {
          lang,
          disabled: false,
          textContent: lang,
          getAttribute: (a: string) => (a === "data-lang" ? lang : null),
          addEventListener(type: string, fn: (e: unknown) => void) {
            if (type === "click") handlers.set(`lang:${lang}`, fn);
          },
        };
        langButtons.push(btn);
      }
      getEl("langswitch");
      els.set("langswitch", {
        getAttribute: (a: string) => (a === "data-current" ? current : null),
        querySelectorAll: () => langButtons,
      } as unknown as ReturnType<typeof makeEl>);
    }
    sandbox.document = {
      readyState: "complete",
      body: makeEl("body", handlers),
      getElementById: getEl,
      querySelector: (sel: string) => (sel.includes("ocm-panel-nonce") ? { content: opts.nonce } : null),
      querySelectorAll: () => [],
      addEventListener: (type: string, fn: (e: unknown) => void) => handlers.set(`doc:${type}`, fn),
      createElement: () => makeEl("dyn-" + Math.random(), handlers),
    };
    const context = vm.createContext(sandbox);
    const scriptSrc = opts.html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
    expect(scriptSrc).toBeTruthy();
    vm.runInContext(scriptSrc!, context);
    const flush = async (ms = 40) => { await new Promise((r) => setTimeout(r, ms)); };
    const clickTab = async (tab: string) => {
      handlers.get("tabs:click")!({
        target: {
          closest: (sel: string) =>
            sel === ".tab" ? { classList: { add() {}, remove() {} }, dataset: { tab } } : null,
        },
      });
      await flush();
    };
    return {
      sandbox,
      handlers,
      els: { get: getEl },
      calls,
      flush,
      clickTab,
      langButtons,
      clickLang: (lang: string) => handlers.get(`lang:${lang}`)!({ target: {} }),
      getReloadCount: () => reloadCount,
    };
  }

  it("config string values are quote-escaped in attribute context (no XSS breakout)", async () => {
    const { html, nonce } = await extractPanelHtml();
    const payload = 'x" autofocus onfocus="alert(1)';
    const panel = await runPanel({
      nonce,
      html,
      respond: (method) => {
        if (method === "security.metrics") return { metrics: { total: 0 } };
        if (method === "security.config.get") {
          return { config: { application: { userIdField: payload } }, schema: CONFIG_SCHEMA };
        }
        return {};
      },
    });
    await panel.clickTab("config");
    const htmlOut = panel.els.get("panel").innerHTML;
    expect(htmlOut).toContain(`value="x&quot; autofocus onfocus=&quot;alert(1)"`);
    expect(htmlOut).not.toContain('value="x" autofocus');
  });

  it("appeal tooltip remediation hints are quote-escaped in title attribute", async () => {
    const { html, nonce } = await extractPanelHtml();
    const hint = 'hint" onmouseover="alert(1)';
    const eventRow = {
      ts: Date.now(),
      event_type: "agent_tool_call",
      tool_name: "exec",
      intervention: { decision: "block", appealable: true, remediation_hint: hint, policy_id: "P1", block_reason: "r" },
    };
    const panel = await runPanel({
      nonce,
      html,
      respond: (method) => {
        if (method === "security.metrics") return { metrics: { total: 0 } };
        if (method === "security.events.list") return { events: [eventRow], total: 1, truncated: false };
        if (method === "security.policy.hits") return { hits: [], total: 0 };
        return {};
      },
    });
    await panel.clickTab("events");
    // New append-only pattern: skeleton stays in #events-table; rows land in
    // #events-body (matches Policy Hits #blocks-body separation).
    const htmlOut = panel.els.get("events-body").innerHTML;
    expect(htmlOut).toContain("appeal-tag");
    expect(htmlOut).toContain(`title="hint&quot; onmouseover=&quot;alert(1)"`);
    expect(htmlOut).not.toContain('title="hint" onmouseover');
  });

  it("policy hits tab escapes title attributes and renders rows via DOM", async () => {
    const { html, nonce } = await extractPanelHtml();
    const hint = 'b" onfocus="alert(2)';
    const hit = {
      ts: Date.now(),
      tool_name: "exec",
      decision: "block",
      intervention: { decision: "block", appealable: true, remediation_hint: hint, policy_id: "P2", block_reason: "br" },
    };
    const panel = await runPanel({
      nonce,
      html,
      respond: (method) => {
        if (method === "security.metrics") return { metrics: { total: 0 } };
        if (method === "security.policy.hits") return { hits: [hit], total: 1, byDecision: { block: 1 } };
        return {};
      },
    });
    await panel.clickTab("blocks");
    const body = panel.els.get("blocks-body").innerHTML;
    expect(body).toContain(`title="b&quot; onfocus=&quot;alert(2)"`);
  });

  it("loadEvents/loadBlocks insert an error into the DOM when the RPC fails", async () => {
    const { html, nonce } = await extractPanelHtml();
    const panel = await runPanel({
      nonce,
      html,
      respond: (method) => {
        if (method === "security.metrics") return { metrics: { total: 0 } };
        return {};
      },
      rejectMethods: ["security.events.list", "security.policy.hits"],
    });
    await panel.clickTab("events");
    // Error handler writes to the wrapper #events-table (it replaces the
    // skeleton), not to #events-body — only the success path appends rows
    // to the body. So the error is observable on the wrapper.
    expect(panel.els.get("events-table").innerHTML).toContain('class="error"');
    await panel.clickTab("blocks");
    expect(panel.els.get("blocks-table").innerHTML).toContain('class="error"');
  });

  it("panel save UX keeps the confirm-modal flow using the server token", async () => {
    const { html, nonce } = await extractPanelHtml();
    const saveCalls: Array<{ method: string; params: { confirmDanger?: boolean; confirmToken?: string; patch?: unknown } }> = [];
    const panel = await runPanel({
      nonce,
      html,
      respond: (method, params) => {
        if (method === "security.metrics") return { metrics: { total: 0 } };
        if (method === "security.config.get") {
          return { config: { collector: { ndjsonPath: "/old/events.jsonl" } }, schema: CONFIG_SCHEMA };
        }
        if (method === "security.config.save") {
          saveCalls.push({ method, params: params as never });
          if (saveCalls.length === 1) {
            return { ok: false, error: { message: "danger 字段需要二次确认", fields: ["collector.ndjsonPath"], confirmToken: "TOK-1" } };
          }
          return { ok: true, restartRequired: true, backup: null, applied: (params as { patch: unknown }).patch, warnings: [], bootstrapReport: { forcedDisabled: [] } };
        }
        return {};
      },
    });
    await panel.clickTab("config");

    // Simulate the operator editing the danger field and clicking 保存.
    const input = {
      getAttribute: (n: string) =>
        ({ "data-section": "collector", "data-key": "ndjsonPath", "data-type": "string", "data-danger": "1" })[n] ?? null,
      value: "/tmp/new-events.jsonl",
    };
    // collectPatch reads inputs via document.querySelectorAll — stub the one
    // edited danger input.
    const doc = (panel.sandbox.document as unknown as { querySelectorAll: (sel: string) => unknown[] });
    doc.querySelectorAll = (sel: string) => (sel.includes("data-section") ? [input] : []);
    panel.handlers.get("panel:click")!({ target: { id: "save-config", closest: () => null } });
    await panel.flush();

    // First save went out without a token; the server need-confirm answer opened the modal.
    expect(saveCalls).toHaveLength(1);
    expect(saveCalls[0].params.confirmDanger).toBe(false);
    expect(saveCalls[0].params.confirmToken).toBeUndefined();
    expect((panel.els.get("danger-modal") as unknown as { style: { display: string } }).style.display).toBe("flex");
    expect(panel.els.get("danger-modal-body").innerHTML).toContain("collector.ndjsonPath");

    // Operator ticks the checkbox then clicks 确认保存 → retry carries token + confirmDanger.
    panel.handlers.get("doc:change")!({ target: { id: "danger-confirm", checked: true } });
    panel.handlers.get("panel:click")!({ target: { id: "danger-ok", closest: () => null } });
    await panel.flush();
    expect(saveCalls).toHaveLength(2);
    expect(saveCalls[1].params.confirmDanger).toBe(true);
    expect(saveCalls[1].params.confirmToken).toBe("TOK-1");
  });
});
