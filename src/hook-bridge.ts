// OpenClaw 2026.9.4 typed-hook bridge.
//
// Each typed hook in 9.4 receives `(event, ctx)`. Some events already match
// our ApplicationCollector input shape; others need `mergeHookArgs` + the
// existing normalize helpers in ctxExtract.ts to coerce to the right type.
//
// This module is intentionally small: it owns the "given an arbitrary
// `(event, ctx)` pair, hand back the typed object our collector expects"
// step. Errors are swallowed (logged via console.error) so a malformed
// envelope from a hostile peer cannot break the agent's hook pipeline.

import {
  mergeHookArgs,
  normalizeAgentStartContext,
  normalizeAgentCompleteContext,
  normalizeMessageWriteContext,
  normalizeSessionEndContext,
  normalizeSubagentContext,
  normalizeCronEventContext,
  normalizeToolContext,
  extractRealResult,
} from './ctxExtract.js';
import type {
  AgentStartContext,
  AgentCompleteContext,
  MessageWriteContext,
  MessageWriteResult,
  SessionEndContext,
  SubagentContext,
  CronEventContext,
  MiddlewareContext,
} from './types.js';

function logBridgeFailure(hookName: string, err: unknown): void {
  console.error(`[hook-bridge] ${hookName} normalization failed:`, err);
}

function bridgeAgentStart(event: unknown, ctx: unknown): AgentStartContext | undefined {
  try {
    const merged = mergeHookArgs([event, ctx]);
    return normalizeAgentStartContext(merged);
  } catch (err) {
    logBridgeFailure('before_agent_run / agent_start', err);
    return undefined;
  }
}

function bridgeAgentComplete(event: unknown, ctx: unknown): AgentCompleteContext | undefined {
  try {
    const merged = mergeHookArgs([event, ctx]);
    return normalizeAgentCompleteContext(merged);
  } catch (err) {
    logBridgeFailure('agent_end / agent_complete', err);
    return undefined;
  }
}

/**
 * 归一化一条消息写入上下文。
 *
 * `defaultRole` 是**钩子语义**带来的兜底角色：宿主的 `message.received`
 * 一定是用户输入，`message.sending` 一定是模型输出——即便载荷里没有
 * role 字段，这个信息也在 hook 名字里，丢掉可惜。
 */
function bridgeMessageWrite(
  event: unknown,
  ctx: unknown,
  defaultRole?: MessageWriteContext['role']
): MessageWriteContext | undefined {
  try {
    const merged = mergeHookArgs([event, ctx]);
    return normalizeMessageWriteContext(merged, defaultRole);
  } catch (err) {
    logBridgeFailure('before_message_write / message_received / message_sending', err);
    return undefined;
  }
}

function bridgeToolCall(event: unknown, ctx: unknown): {
  ctx: MiddlewareContext | undefined;
  result: unknown;
} {
  try {
    const merged = mergeHookArgs([event, ctx]);
    const normalized = normalizeToolContext(merged);
    return { ctx: normalized, result: extractRealResult(merged) };
  } catch (err) {
    logBridgeFailure('before_tool_call / after_tool_call', err);
    return { ctx: undefined, result: undefined };
  }
}

function bridgeSessionEnd(event: unknown, ctx: unknown): SessionEndContext | undefined {
  try {
    const merged = mergeHookArgs([event, ctx]);
    return normalizeSessionEndContext(merged);
  } catch (err) {
    logBridgeFailure('session_end', err);
    return undefined;
  }
}

function bridgeSubagent(event: unknown, ctx: unknown): SubagentContext | undefined {
  try {
    const merged = mergeHookArgs([event, ctx]);
    return normalizeSubagentContext(merged);
  } catch (err) {
    logBridgeFailure('subagent_*', err);
    return undefined;
  }
}

function bridgeCron(event: unknown, ctx: unknown): CronEventContext | undefined {
  try {
    const merged = mergeHookArgs([event, ctx]);
    return normalizeCronEventContext(merged);
  } catch (err) {
    logBridgeFailure('cron_reconciled / cron_changed', err);
    return undefined;
  }
}

/**
 * map a MessageWriteResult to the OpenClaw 2026.9.4
 * PluginHookBeforeMessageWriteResult host shape ({ block, message }).
 * Kept as a pure helper (instead of inline in the hook entry) so tests can
 * assert the exact host-consumed shape without standing up a full plugin api.
 */
function toMessageWriteHostResult(
  input: MessageWriteContext,
  result: MessageWriteResult | void
): { block: true; message: { role: string; content: unknown } } | undefined {
  if (result?.content !== undefined) {
    return { block: true, message: { role: input.role, content: result.content } };
  }
  return undefined;
}

export const hookBridge = {
  bridgeAgentStart,
  bridgeAgentComplete,
  bridgeMessageWrite,
  bridgeToolCall,
  bridgeSessionEnd,
  bridgeSubagent,
  bridgeCron,
  toMessageWriteHostResult,
};