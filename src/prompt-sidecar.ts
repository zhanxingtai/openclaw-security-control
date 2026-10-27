/**
 * PromptSidecar —— 系统提示词全文的内容寻址 sidecar 存储。
 *
 * 采样实测 system_prompt 全文占事件流约 54% 的体积：每个会话的第一条消息
 * 驮一份，多会话之间同一份提示词反复内嵌。改造后事件流里 system_prompt
 * 字段彻底移除，所有事件一律只带 16 位指纹 `system_prompt_ref`；全文全局
 * 只落一份到与 security-events.jsonl 同目录的 security-prompts.jsonl，
 * 按 prompt_hash（全文 sha256）内容寻址——同一 hash 无论跨多少事件、
 * 跨多少会话、跨多少次重启都只追加一次。
 *
 * 降级契约：sidecar 写失败绝不阻断事件主流程。事件照常带 ref 落盘，
 * 只记 console.warn；该 hash 不进入已见集合，下一次同内容事件到来时会
 * 重试追加（瞬时故障自愈）。
 */

import { appendFileSync, readFileSync } from 'fs';
import { sha256Hex } from './asset-hash.js';

export interface PromptSidecarRecord {
  prompt_hash: string;
  prompt_ref: string;
  prompt: string;
  first_seen_ts: number;
  session_id: string | null;
  host_id: string | null;
}

export class PromptSidecar {
  /** 已见过的全文 hash 集合。懒加载：首次写入前扫描 sidecar 文件填充。 */
  private readonly seenHashes = new Set<string>();
  private loaded = false;

  constructor(private readonly sidecarPath?: string) {}

  /**
   * 记录一份系统提示词全文：首次见到的 hash 追加进 sidecar，已见过则
   * 直接返回指纹。始终返回 { hash, ref }，调用方据此给事件打 ref。
   */
  recordPrompt(
    prompt: string,
    sessionId?: string | null,
    hostId?: string | null
  ): { hash: string; ref: string } {
    const hash = sha256Hex(prompt);
    const ref = hash.slice(0, 16);
    this.loadSeenHashes();
    if (this.seenHashes.has(hash) || !this.sidecarPath) {
      return { hash, ref };
    }
    const record: PromptSidecarRecord = {
      prompt_hash: hash,
      prompt_ref: ref,
      prompt,
      first_seen_ts: Date.now(),
      session_id: sessionId ?? null,
      host_id: hostId ?? null,
    };
    try {
      appendFileSync(this.sidecarPath, JSON.stringify(record) + '\n', 'utf8');
      // 落盘成功才登记：写失败的 hash 留在集合外，后续事件会重试。
      this.seenHashes.add(hash);
    } catch (err) {
      console.warn(
        `[PromptSidecar] 追加 ${this.sidecarPath} 失败（事件不受影响，同内容事件将重试）: ` +
          (err instanceof Error ? err.message : String(err))
      );
    }
    return { hash, ref };
  }

  /** 当前已见过的 hash 数（观测/测试用）。 */
  get seenCount(): number {
    this.loadSeenHashes();
    return this.seenHashes.size;
  }

  /**
   * 扫描已有 sidecar 文件，把见过的 prompt_hash 填进内存集合。
   *
   * 为什么需要这一步：已见集合是进程内存，重启即失。没有它，每个进程
   * 重启后都会把 sidecar 里已有的提示词再追加一遍。sidecar 文件本身是
   * 唯一跨重启共享的状态，与 store 的 event_id 幂等同一个思路。
   */
  private loadSeenHashes(): void {
    if (this.loaded) return;
    this.loaded = true;
    if (!this.sidecarPath) return;
    let raw: string;
    try {
      raw = readFileSync(this.sidecarPath, 'utf8');
    } catch {
      // 文件还不存在（本机第一个进程）或读失败：按空集合开始。
      return;
    }
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line) as Partial<PromptSidecarRecord>;
        if (typeof rec.prompt_hash === 'string' && rec.prompt_hash.length > 0) {
          this.seenHashes.add(rec.prompt_hash);
        }
      } catch {
        // 跳过损坏行（崩溃撕裂写 / 人为编辑），不阻断启动。
      }
    }
  }
}
