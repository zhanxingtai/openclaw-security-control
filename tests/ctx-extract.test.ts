import { describe, expect, it } from "vitest";
import {
  mergeHookArgs,
  extractRealResult,
  findResultArg,
  extractContentFromLLMResponse,
  extractReasoningFromLLMResponse,
  detectInjectedUserContent,
  extractSessionKey,
  inferAgentIdFromSessionKey,
  normalizeToolContext,
  extractToolParams,
  looksLikeToolContext,
  parseJsonObject,
} from "../src/ctxExtract.js";
import { hookBridge } from "../src/hook-bridge.js";

/**
 * ctxExtract / hook-bridge 行为级用例。
 * 这些是 hook 参数的归一闸门：形状识别错了，下游评估入口就拿不到
 * session / params / 结果内容。
 */

describe("mergeHookArgs（8.2 (event, ctx) 双参合并）", () => {
  it("空参数返回 undefined，单参原样透传", () => {
    expect(mergeHookArgs([])).toBeUndefined();
    const single = { toolName: "exec" };
    expect(mergeHookArgs([single])).toBe(single);
  });

  it("ctx 的 identity 字段覆盖 event 同名字段，undefined 不覆盖", () => {
    const merged = mergeHookArgs([
      { toolName: "old", sessionKey: "s1", extra: 1 },
      { toolName: "new", sessionKey: undefined, runId: "r1" },
    ]) as Record<string, unknown>;
    expect(merged.toolName).toBe("new");
    expect(merged.sessionKey).toBe("s1");
    expect(merged.runId).toBe("r1");
    expect(merged.extra).toBe(1);
  });

  it("第二参非对象时按单参处理", () => {
    expect(mergeHookArgs([{ a: 1 }, "not-object"])).toEqual({ a: 1 });
  });
});

describe("extractRealResult / findResultArg", () => {
  it("无 tool 标记的对象原样返回", () => {
    const result = { content: "done" };
    expect(extractRealResult(result)).toBe(result);
  });

  it("tool 上下文信封挖 output/result 字段", () => {
    expect(extractRealResult({ toolName: "exec", output: "hello" })).toBe("hello");
    expect(extractRealResult({ sessionKey: "s", result: 42 })).toBe(42);
    expect(extractRealResult({ toolCallId: "c" })).toBeUndefined();
  });

  it("findResultArg 优先非上下文参数", () => {
    const ctx = { toolName: "exec" };
    const result = { output: "ok" };
    expect(findResultArg([ctx, result])).toBe(result);
  });
});

describe("LLM 响应内容提取", () => {
  it("choices[0].message.content 与 delta.content 两种形状", () => {
    expect(
      extractContentFromLLMResponse({
        choices: [{ message: { content: "answer" } }],
      })
    ).toBe("answer");
    expect(
      extractContentFromLLMResponse({
        choices: [{ delta: { content: "chunk" } }],
      })
    ).toBe("chunk");
  });

  it("content[0].text 与 response 嵌套包装", () => {
    expect(extractContentFromLLMResponse({ content: [{ text: "block" }] })).toBe("block");
    expect(
      extractContentFromLLMResponse({
        response: { choices: [{ message: { content: "nested" } }] },
      })
    ).toBe("nested");
  });

  it("无任何已知形状返回 undefined", () => {
    expect(extractContentFromLLMResponse({ foo: "bar" })).toBeUndefined();
  });

  it("extractReasoningFromLLMResponse 提取 reasoning_content 与 thinking 块", () => {
    expect(
      extractReasoningFromLLMResponse({
        choices: [{ message: { reasoning_content: "thinking…" } }],
      })
    ).toBe("thinking…");
    expect(
      extractReasoningFromLLMResponse({ content: [{ thinking: "plan" }] })
    ).toBe("plan");
    expect(extractReasoningFromLLMResponse({})).toBeUndefined();
  });
});

describe("detectInjectedUserContent（宿主注入指令标记）", () => {
  it("命中已知注入标记", () => {
    expect(detectInjectedUserContent("Generate a random slug for this conversation")).toBe(true);
    expect(detectInjectedUserContent("The current date and time is …")).toBe(true);
  });

  it("真实用户输入不误标", () => {
    expect(detectInjectedUserContent("帮我写一段快速排序")).toBe(false);
  });
});

describe("会话 / 工具上下文归一", () => {
  it("extractSessionKey 支持嵌套对象（session.id）与多别名", () => {
    expect(extractSessionKey({ sessionKey: "k1" })).toBe("k1");
    expect(extractSessionKey({ session: { id: "k2" } })).toBe("k2");
    expect(extractSessionKey({})).toBeUndefined();
  });

  it("inferAgentIdFromSessionKey 从会话键解析 agent 段", () => {
    expect(inferAgentIdFromSessionKey("agent:main:thread-1")).toBeDefined();
    expect(inferAgentIdFromSessionKey("")).toBeUndefined();
  });

  it("normalizeToolContext 归一 OpenClaw tool 对象形状", () => {
    const ctx = normalizeToolContext({
      tool: { name: "file_read", kind: "builtin" },
      sessionKey: "s1",
      params: { path: "/tmp/x" },
    });
    expect(ctx?.toolName).toBe("file_read");
    expect(ctx?.toolKind).toBe("builtin");
    expect(ctx?.sessionKey).toBe("s1");
    expect(ctx?.params).toEqual({ path: "/tmp/x" });
  });

  it("normalizeToolContext 拒绝非对象输入", () => {
    expect(normalizeToolContext(null)).toBeUndefined();
    expect(normalizeToolContext("string")).toBeUndefined();
  });

  it("extractToolParams 解析 toolCall.function.arguments JSON 字符串", () => {
    expect(
      extractToolParams({
        toolCall: { function: { arguments: JSON.stringify({ command: "ls" }) } },
      })
    ).toEqual({ command: "ls" });
    expect(extractToolParams({})).toEqual({});
  });

  it("looksLikeToolContext 按标记键识别", () => {
    expect(looksLikeToolContext({ toolCallId: "c" })).toBe(true);
    expect(looksLikeToolContext({ random: 1 })).toBe(false);
  });

  it("parseJsonObject 仅接受对象 JSON", () => {
    expect(parseJsonObject('{"a":1}')).toEqual({ a: 1 });
    expect(parseJsonObject("[1,2]")).toBeUndefined();
    expect(parseJsonObject("not json")).toBeUndefined();
  });
});

describe("hookBridge（typed-hook 入口使用的桥接层）", () => {
  it("bridgeToolCall 合并 8.2 (event, ctx) 双参并归一为 MiddlewareContext，同时提取结果", () => {
    const { ctx, result } = hookBridge.bridgeToolCall(
      { tool: { name: "exec" }, params: { command: "ls" }, output: "listing" },
      { sessionKey: "s1", runId: "r1" }
    );
    expect(ctx?.toolName).toBe("exec");
    expect(ctx?.sessionKey).toBe("s1");
    expect(ctx?.runId).toBe("r1");
    expect(ctx?.params).toEqual({ command: "ls" });
    // 工具上下文信封中的结果被一并挖出
    expect(result).toBe("listing");
  });

  it("bridgeToolCall 单参（旧式钩子）同样可用", () => {
    const { ctx } = hookBridge.bridgeToolCall({ toolName: "file_read", sessionKey: "s2" });
    expect(ctx?.toolName).toBe("file_read");
    expect(ctx?.sessionKey).toBe("s2");
  });
});
