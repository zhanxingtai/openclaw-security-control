import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { SecurityMonitorStore } from "../src/store.js";
import { normalizeConfig } from "../src/config.js";

/**
 * EventBridgeCollector 落盘失败可见性。
 *
 * 修复前 appendFile 失败被 `catch {}` 完全吞掉——注释自称 warn 但实现
 * 没有。修复后首次失败立即 console.warn 并计数，后续每第 10 次再告警，
 * 且不影响后续事件的上报路径（best-effort 语义不变）。
 */

let tmpDir: string;
let store: SecurityMonitorStore;
let sink: { report: (event: unknown) => Promise<void> };
let warnSpy: ReturnType<typeof vi.spyOn>;

function baseEvent() {
  return {
    event_id: `evt-${Math.random().toString(36).slice(2)}`,
    event_type: "test_emit",
    layer: "application",
    ts: Date.now(),
    schema_version: 1,
    pid: process.pid,
    session_id: null,
    host_id: "test-host",
    source: "openclaw.v1",
    collection_method: "test",
    collector: { hook_name: "test", middleware_name: "test", collector_name: "test" },
  };
}

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "eb-write-err-"));
  // ndjsonPath 的父级是一个普通文件 → appendFile 必然 ENOENT/ENOTDIR
  writeFileSync(join(tmpDir, "blocker"), "not a dir");
  const badPath = join(tmpDir, "blocker", "events.jsonl");
  const config = normalizeConfig({
    collector: { ndjsonPath: badPath },
    intervention: { enabled: false },
  });
  store = new SecurityMonitorStore(config);
  sink = (store as unknown as { collector: typeof sink }).collector;
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("EventBridgeCollector 落盘失败可见性", () => {
  it("appendFile 失败时 warn 且计数，不再静默", async () => {
    await sink.report(baseEvent());
    expect(warnSpy).toHaveBeenCalled();
    const message = warnSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(message).toContain("append");
    expect(message).toContain("failed");
  });

  it("失败后继续上报不抛异常（best-effort 语义保留）", async () => {
    await sink.report(baseEvent());
    warnSpy.mockClear();
    await expect(sink.report(baseEvent())).resolves.toBeUndefined();
    // 第 2 次失败计数未到 10，不重复告警
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
