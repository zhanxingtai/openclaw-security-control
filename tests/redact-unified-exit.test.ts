import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { fileURLToPath } from "url";
import { SecurityMonitorStore } from "../src/store.js";
import { normalizeConfig } from "../src/config.js";
import { redactValueContent, SENSITIVE_VALUE_PATTERNS } from "../src/redact.js";

/**
 * 脱敏统一出口。
 *
 * 修复前只有 ApplicationCollector 的 emit helper 调用 redactEventForEmit；
 * asset-collector 等处直接 collector.report(event) 绕过。修复后
 * EventBridgeCollector.report 是 NDJSON 落盘前的唯一出口，任何采集流
 * （application / system / asset）的事件都必须经过同一 redact 口径。
 * hooks/ 侧因零依赖 CJS 保持独立实现，用 source 级断言防两份凭据
 * 规则集合漂移。
 */

const AKIA = "AKIAIOSFODNN7EXAMPLE";
const BEARER = "Bearer abcdef0123456789abcdef0123456789";

let tmpDir: string;
let ndjsonPath: string;
let store: SecurityMonitorStore;
// EventBridgeCollector is private; tests reach it the same way the sub
// collectors do — as the single sink every event flows through.
let sink: { report: (event: unknown) => Promise<void> };

function baseEvent(layer: string, extra: Record<string, unknown>) {
  return {
    event_id: `evt-${Math.random().toString(36).slice(2)}`,
    event_type: "test_emit",
    layer,
    ts: Date.now(),
    schema_version: "1.0.0",
    pid: process.pid,
    session_id: null,
    run_id: null,
    task_id: null,
    turn_id: null,
    agent_id: null,
    host_id: "test-host",
    container_id: null,
    pod_name: null,
    namespace: null,
    source: "openclaw.v1",
    collection_method: "test",
    collector: { hook_name: "test", middleware_name: "test", collector_name: "test" },
    ...extra,
  };
}

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "redact-exit-"));
  ndjsonPath = join(tmpDir, "events.jsonl");
  const config = normalizeConfig({
    collector: { ndjsonPath },
    intervention: { enabled: false },
  });
  store = new SecurityMonitorStore(config);
  sink = (store as unknown as { collector: typeof sink }).collector;
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("EventBridgeCollector 统一脱敏出口", () => {
  it("application 层事件的 content / params 凭据在落盘前被 *** 替换", async () => {
    await sink.report(
      baseEvent("application", {
        content: `use key ${AKIA} and header ${BEARER} here`,
        params: { command: `curl -H "${BEARER}" https://example.com` },
      })
    );
    const line = readFileSync(ndjsonPath, "utf8");
    expect(line).not.toContain(AKIA);
    expect(line).not.toContain("abcdef0123456789abcdef0123456789");
    expect(line).toContain("***");
  });

  it("asset 层事件与 application 层凭据口径一致（绕过路径同样被兜底）", async () => {
    // Mimics asset-collector's direct collector.report() bypass path: before
    // the fix these events reached NDJSON with plaintext credentials.
    await sink.report(
      baseEvent("asset", {
        content: `use key ${AKIA} and header ${BEARER} here`,
        params: { command: `curl -H "${BEARER}" https://example.com` },
      })
    );
    const line = readFileSync(ndjsonPath, "utf8");
    expect(line).not.toContain(AKIA);
    expect(line).not.toContain("abcdef0123456789abcdef0123456789");
    expect(line).toContain("***");
  });

  it("system 层透传事件同样经统一出口", async () => {
    await sink.report(
      baseEvent("system", {
        user_prompt: `token is ${AKIA}`,
        headers: { authorization: BEARER, "content-type": "application/json" },
      })
    );
    const line = readFileSync(ndjsonPath, "utf8");
    expect(line).not.toContain(AKIA);
    // authorization header value must be masked, unrelated headers untouched
    expect(line).not.toContain("abcdef0123456789abcdef0123456789");
    expect(line).toContain('"content-type":"application/json"');
  });

  it("obf:v1 可逆混淆值与事件结构不被统一出口破坏", async () => {
    const obfValue = "obf:v1:Zm9vOmJhcg";
    await sink.report(
      baseEvent("asset", {
        content: "no secrets here",
        params: { asset_path: "/etc/app", sample_value: obfValue },
      })
    );
    const line = readFileSync(ndjsonPath, "utf8");
    expect(line).toContain(obfValue);
    expect(line).toContain('"asset_path":"/etc/app"');
  });

  it("幂等：上游已 redact 的事件再次过出口不产生变化", async () => {
    const once = baseEvent("application", { content: `key ${AKIA}` });
    await sink.report(once);
    const firstLine = readFileSync(ndjsonPath, "utf8").trim();
    const parsed = JSON.parse(firstLine);
    await sink.report(parsed);
    const lines = readFileSync(ndjsonPath, "utf8").trim().split("\n");
    expect(JSON.parse(lines[1])).toEqual(parsed);
  });
});

/**
 * Canonical credential families that MUST be covered on both sides:
 *   - src/redact.ts (TS, masks with ***)
 *   - hooks/runtime.js (zero-dep CJS, risk-flag detection — independent by
 *     design but must not drift from the TS rule set, )
 */
const CANONICAL_PROBES: Array<{ family: string; probe: string }> = [
  { family: "AWS access key id (AKIA)", probe: AKIA },
  { family: "JWT", probe: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.abcDEF123abcDEF123" },
  { family: "Bearer token", probe: BEARER },
  { family: "PEM private key", probe: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----" },
];

// Hooks-side detector signatures, one literal source snippet per canonical
// family. These are deliberately source-level (not behavioral): hooks/runtime.js
// runs inside a hostile preload context and cannot be imported into the test
// process.
const HOOK_DETECTOR_SNIPPETS: Array<{ family: string; snippet: string }> = [
  { family: "AWS access key id (AKIA)", snippet: "AKIA[0-9A-Z]{16}" },
  { family: "JWT", snippet: "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+" },
  { family: "Bearer token", snippet: "Bearer\\s+[A-Za-z0-9_\\-\\.~+\\/=]{8,}" },
  { family: "PEM private key", snippet: "BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY" },
];

describe("TS 与 hooks 凭据规则一致性（防漂移）", () => {
  const runtimeSource = readFileSync(
    fileURLToPath(new URL("../hooks/runtime.js", import.meta.url)),
    "utf8"
  );

  it.each(CANONICAL_PROBES)("TS redact 覆盖 $family", ({ probe }) => {
    expect(redactValueContent(probe)).toBe("***");
  });

  it.each(HOOK_DETECTOR_SNIPPETS)("hooks/runtime.js 覆盖 $family", ({ snippet }) => {
    expect(runtimeSource).toContain(snippet);
  });

  it("AKIA 正则精确等价（防任一侧放宽长度/字符集）", () => {
    const tsAkia = SENSITIVE_VALUE_PATTERNS.map((re) => re.source).find((s) => s.includes("AKIA"));
    expect(tsAkia).toBeDefined();
    expect(tsAkia).toContain("AKIA[0-9A-Z]{16}");
    expect(runtimeSource).toMatch(/AKIA\[0-9A-Z\]\{16\}/);
  });
});
