import { describe, expect, it } from "vitest";
import { ActionHistory } from "../src/intervention/ActionHistory.js";
import type { ActionRecord } from "../src/types.js";

/**
 * ActionHistory 有界性。
 *
 * chain 规则的 previousActions 数据源必须是内存有界的：perSession 50 /
 * global 200 / 500 会话淘汰 / params 单值 4096 截断，防止长跑网关
 * 退化为大对象驻留。
 */

function action(id: string, params?: Record<string, unknown>): ActionRecord {
  return {
    actionId: id,
    actionType: "tool_call",
    toolName: "exec",
    ts: Date.now(),
    decision: "allow",
    params,
  } as ActionRecord;
}

describe("ActionHistory 有界性", () => {
  it("会话内历史最多保留 perSessionCap(50) 条，淘汰最旧", () => {
    const history = new ActionHistory();
    for (let i = 0; i < 60; i++) history.record("sess-1", action(`a-${i}`));
    const recent = history.recent("sess-1");
    expect(recent).toHaveLength(50);
    expect(recent[0].actionId).toBe("a-10");
    expect(recent[recent.length - 1].actionId).toBe("a-59");
  });

  it("全局窗口最多保留 globalCap(200) 条", () => {
    const history = new ActionHistory();
    for (let i = 0; i < 250; i++) history.record(null, action(`g-${i}`));
    const recent = history.recent();
    expect(recent).toHaveLength(200);
    expect(recent[0].actionId).toBe("g-50");
  });

  it("超过 maxSessions(500) 个会话时淘汰最久未新增的会话", () => {
    const history = new ActionHistory();
    for (let i = 0; i < 500; i++) history.record(`sess-${i}`, action(`a-${i}`));
    expect(history.recent("sess-0")).toHaveLength(1);
    // 第 501 个会话触发淘汰：插入序最前的 sess-0 被移除
    history.record("sess-500", action("a-500"));
    const evicted = history.recent("sess-0");
    // 会话已淘汰 → 回退全局窗口；全局仅保留最近 200 条（a-0 早已移出）
    expect(evicted).toHaveLength(200);
    expect(evicted.some((r) => r.actionId === "a-0")).toBe(false);
    expect(evicted.some((r) => r.actionId === "a-301")).toBe(true);
    expect(history.recent("sess-500")).toHaveLength(1);
  });

  it("params 字符串值超 4096 字符截断并加省略标记", () => {
    const history = new ActionHistory();
    const big = "x".repeat(5000);
    history.record("sess-t", action("a-big", { content: big, small: "ok" }));
    const [record] = history.recent("sess-t");
    expect(String(record.params?.content)).toHaveLength(4096 + 3);
    expect(String(record.params?.content).endsWith("...")).toBe(true);
    expect(record.params?.small).toBe("ok");
  });

  it("无会话标识或无会话记录时回退全局窗口", () => {
    const history = new ActionHistory();
    history.record("sess-x", action("a-1"));
    history.record(null, action("g-1"));
    expect(history.recent("unknown-sess").some((r) => r.actionId === "g-1")).toBe(true);
    expect(history.recent(null).some((r) => r.actionId === "g-1")).toBe(true);
  });

  it("clear() 清空会话与全局历史", () => {
    const history = new ActionHistory();
    history.record("sess-c", action("a-1"));
    history.clear();
    expect(history.recent("sess-c").some((r) => r.actionId === "a-1")).toBe(false);
  });
});
