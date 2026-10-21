import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, copyFileSync, writeFileSync, readFileSync, existsSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { Writable } from "stream";
import plugin from "../index.js";

/**
 * 宿主集成面覆盖：
 * - index.ts 其余 7 个 RPC（security.evaluate/status/events.list/
 *   events.stats/assets.list/policy.hits/metrics）注册后调用断言；
 * - /events.ndjson 流式路由真实写出 NDJSON；
 * - api.on typed-hook 链路：fakeApi 捕获注册并驱动 before_tool_call
 *   回调，断言事件落盘。
 */

interface GwRec { handler: (params: unknown) => Promise<unknown> | unknown }
interface RouteRec { path: string; handler: (req: unknown, res: unknown) => void | Promise<void> }

let tmpDir: string;
let ndjsonPath: string;
let gatewayMethods: Map<string, GwRec>;
let httpRoutes: Map<string, RouteRec>;
let onHandlers: Map<string, (...args: unknown[]) => unknown>;
let savedEnv: string | undefined;

function createFakeApi() {
  const gatewayMethods = new Map<string, GwRec>();
  const httpRoutes = new Map<string, RouteRec>();
  const onHandlers = new Map<string, (...args: unknown[]) => unknown>();
  const api = {
    pluginConfig: {},
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    on: (name: string, handler: (...args: unknown[]) => unknown) => onHandlers.set(name, handler),
    registerHook: () => {},
    registerGatewayMethod: (name: string, handler: GwRec["handler"]) =>
      gatewayMethods.set(name, { handler }),
    registerHttpRoute: (route: RouteRec) => httpRoutes.set(route.path, route),
    runtime: { registerRuntimeLifecycle: () => {} },
  };
  return { api, gatewayMethods, httpRoutes, onHandlers };
}

function readEvents(): Array<Record<string, unknown>> {
  if (!existsSync(ndjsonPath)) return [];
  return readFileSync(ndjsonPath, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

async function waitForEvents(minCount: number, timeoutMs = 3000): Promise<Array<Record<string, unknown>>> {
  const start = Date.now();
  for (;;) {
    const events = readEvents();
    if (events.length >= minCount) return events;
    if (Date.now() - start > timeoutMs) return events;
    await new Promise((r) => setTimeout(r, 50));
  }
}

beforeAll(() => {
  tmpDir = mkdtempSync(path.join(tmpdir(), "rpc-coverage-"));
  ndjsonPath = path.join(tmpDir, "events.jsonl");
  const hostConfigPath = path.join(tmpDir, "openclaw.json");
  writeFileSync(hostConfigPath, "{}", "utf8");
  savedEnv = process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
  process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = hostConfigPath;

  const policyPath = path.join(tmpDir, "security-policy.yaml");
  copyFileSync(path.join(process.cwd(), "policies", "security-policy.spl.yaml"), policyPath);

  const fake = createFakeApi();
  gatewayMethods = fake.gatewayMethods;
  httpRoutes = fake.httpRoutes;
  onHandlers = fake.onHandlers;
  (fake.api as { pluginConfig: Record<string, unknown> }).pluginConfig = {
    collector: { ndjsonPath },
    application: { enabled: true },
    network: { enabled: false },
    system: { enabled: false },
    assetMonitor: { enabled: false },
    intervention: { enabled: true, policyPath },
  };
  plugin.register(fake.api as never);
}, 30000);

afterAll(() => {
  if (savedEnv === undefined) delete process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
  else process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = savedEnv;
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("7 个 RPC 注册与调用", () => {
  const EXPECTED_RPCS = [
    "security.evaluate",
    "security.status",
    "security.events.list",
    "security.events.stats",
    "security.assets.list",
    "security.policy.hits",
    "security.metrics",
  ];

  it.each(EXPECTED_RPCS)("%s 已注册且调用返回非空结果", async (name) => {
    const rec = gatewayMethods.get(name);
    expect(rec, `RPC ${name} must be registered`).toBeDefined();
    const result = await rec!.handler({});
    expect(result).toBeDefined();
    expect(typeof result).toBe("object");
  });

  it("security.evaluate 对缺参输入返回校验错误而不是抛异常", async () => {
    const rec = gatewayMethods.get("security.evaluate")!;
    const result = (await rec.handler({})) as { error?: string };
    expect(result.error).toContain("actionType and toolName are required");
  });

  it("security.evaluate 对合法输入返回决策对象", async () => {
    const rec = gatewayMethods.get("security.evaluate")!;
    const result = (await rec.handler({
      actionType: "tool_call",
      toolName: "file_read",
      params: { path: "/tmp/benign" },
    })) as { decision?: string; error?: string };
    expect(result.error).toBeUndefined();
    expect(typeof result.decision).toBe("string");
  });

  it("security.status 返回含配置摘要的状态对象", async () => {
    const rec = gatewayMethods.get("security.status")!;
    const result = (await rec.handler({})) as { stats?: { config?: Record<string, unknown> } };
    expect(result.stats?.config).toBeDefined();
    expect(result.stats!.config!["application"]).toBe(true);
  });
});

describe("api.on typed-hook 链路（驱动真实回调）", () => {
  it("before_tool_call 回调驱动后事件落盘到 NDJSON", async () => {
    const handler = onHandlers.get("before_tool_call");
    expect(handler, "before_tool_call must be registered via api.on").toBeDefined();

    const result = await handler!(
      { tool: { name: "exec" }, params: { command: "ls /tmp" } },
      { sessionKey: "sess-rpc-coverage" }
    );
    // ls /tmp 不应被阻断
    expect(result).toBeUndefined();

    const events = await waitForEvents(1);
    const landed = events.find(
      (e) => e["session_id"] === "sess-rpc-coverage" && e["tool_name"] === "exec"
    );
    expect(landed, `expected a landed event for the driven callback, got: ${JSON.stringify(events.map((e) => [e["event_type"], e["session_id"]]))}`).toBeDefined();
  });

  it("before_message_write 同步钩子返回宿主可消费的形状", async () => {
    const handler = onHandlers.get("before_message_write");
    expect(handler).toBeDefined();
    // 普通用户消息不被拦截：返回 undefined（宿主视为放行）
    const result = handler!({ content: "你好，帮我写快排" }, { sessionKey: "s-msg" });
    expect(result).toBeUndefined();
  });
});

describe("/events.ndjson 流式路由", () => {
  it("把 NDJSON 事件流写入响应", async () => {
    const route = httpRoutes.get("/openclaw-security-monitor/events.ndjson");
    expect(route, "events.ndjson route must be registered").toBeDefined();

    const chunks: string[] = [];
    // rs.pipe(res) 要求 res 是真正的 Writable（pipe 依赖 dest.on/write/end）
    const res = new Writable({
      write(chunk, _enc, cb) {
        chunks.push(chunk.toString());
        cb();
      },
    }) as Writable & {
      writeHead: (s: number, h?: unknown) => void;
      setHeader: (n: string, v: unknown) => void;
    };
    res.writeHead = () => {};
    res.setHeader = () => {};
    // 路由监听 req close；用最小 EventEmitter 假 req 即可
    const { EventEmitter } = await import("events");
    const req = new EventEmitter();
    const finished = new Promise<void>((resolve) => res.on("finish", resolve));
    await route!.handler(req, res);
    await Promise.race([finished, new Promise((r) => setTimeout(r, 3000))]);
    res.end();

    // 已有落盘事件（上一个 describe 的 tool_call）应被作为 NDJSON 行写出
    const body = chunks.join("");
    expect(body.length).toBeGreaterThan(0);
    const lines = body.split("\n").filter((l) => l.trim().length > 0);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });
});
