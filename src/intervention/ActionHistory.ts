/**
 * OpenClaw Security Monitor - Action History
 *
 * chain 规则的 previousActions 在全部评估入口从未被赋值，导致
 * data-leak-dump-exfil-001 等链式规则运行时永不命中。这里维护一份有界的
 * 会话内动作历史（runtime hook 事件与 tool_call 统一记录），评估入口按
 * "同会话最近 N 步"取值；无会话标识的事件回退到全局最近窗口。
 */

import type { ActionRecord } from '../types.js';

export class ActionHistory {
  private readonly perSession = new Map<string, ActionRecord[]>();
  private readonly global: ActionRecord[] = [];

  constructor(
    private readonly perSessionCap = 50,
    private readonly globalCap = 200,
    private readonly maxSessions = 500
  ) {}

  record(sessionId: string | null | undefined, action: ActionRecord): void {
    // 历史只服务 chain 弱关联匹配，超长字符串值（如 write 工具的大文件内容）
    // 截断即可，避免有界队列退化为大对象驻留。
    const stored: ActionRecord = { ...action };
    if (stored.params) {
      const params: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(stored.params)) {
        params[key] = typeof value === 'string' && value.length > 4096 ? `${value.slice(0, 4096)}...` : value;
      }
      stored.params = params;
    }
    this.global.push(stored);
    if (this.global.length > this.globalCap) this.global.shift();

    const key = sessionId?.trim();
    if (!key) return;
    let list = this.perSession.get(key);
    if (!list) {
      if (this.perSession.size >= this.maxSessions) {
        // 会话数有界，防止长跑网关内存增长；Map 迭代序即插入序，
        // 淘汰最久未新增会话的条目（近似 LRU，够用即可）。
        const oldest = this.perSession.keys().next().value;
        if (oldest !== undefined) this.perSession.delete(oldest);
      }
      list = [];
      this.perSession.set(key, list);
    }
    list.push(stored);
    if (list.length > this.perSessionCap) list.shift();
  }

  /** 同会话历史优先；无会话或会话无记录时回退全局最近窗口。 */
  recent(sessionId?: string | null): ActionRecord[] {
    const key = sessionId?.trim();
    if (key) {
      const list = this.perSession.get(key);
      if (list && list.length > 0) return list.slice();
    }
    return this.global.slice();
  }

  clear(): void {
    this.perSession.clear();
    this.global.length = 0;
  }
}
