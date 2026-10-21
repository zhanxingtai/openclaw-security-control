/**
 * PidBindingStore — spawn 派生的子进程 PID 反查父 agent session。
 *
 * 缺失原因：runtime hook 阻断 `bash -c 'curl ...'` 时，curl 派生进程对 host 是
 * 独立进程，network event 关联不到父 agent session。OpenRASP 等外部方案
 * 用此能力回溯；openclaw 1.0 补齐。
 *
 * 设计：5000 上限 LRU-by-ts（按 ts 淘汰最老）；invalid-pid guard
 * （NaN / ≤1 / 非整数一律拒收）；cascade eviction（session 失效时
 * 联动清理）。
 */

const MAX_BINDINGS = 5000;

export interface PidBinding {
  pid: number;
  sessionId: string;
  runId: string;
  agentId: string;
  ts: number;
}

class PidBindingStore {
  private readonly map = new Map<number, PidBinding>();

  /**
   * 绑定一个 spawn 派生的子进程 PID 到父 agent session。
   * @returns true 成功；false 失败（pid 非法或 session 字段缺失）
   */
  bind(pid: number, info: Omit<PidBinding, 'pid' | 'ts'>, ts = Date.now()): boolean {
    if (!Number.isInteger(pid) || pid <= 1) return false;
    if (!info.sessionId || !info.runId) return false;
    this.map.set(pid, { pid, ...info, ts });
    this.evictIfNeeded();
    return true;
  }

  /**
   * 按 PID 反查父 agent session。
   */
  lookup(pid: number): PidBinding | undefined {
    return this.map.get(pid);
  }

  /**
   * session 失效时联动清理（避免 PID 残留误导后续回溯）。
   * @returns 被清理的 binding 数
   */
  evictBySession(sessionId: string): number {
    if (!sessionId) return 0;
    let n = 0;
    for (const [pid, b] of this.map) {
      if (b.sessionId === sessionId) {
        this.map.delete(pid);
        n += 1;
      }
    }
    return n;
  }

  stats(): { size: number; max: number } {
    return { size: this.map.size, max: MAX_BINDINGS };
  }

  private evictIfNeeded(): void {
    if (this.map.size <= MAX_BINDINGS) return;
    const overflow = this.map.size - MAX_BINDINGS;
    const ordered = [...this.map.entries()].sort((a, b) => a[1].ts - b[1].ts);
    for (let i = 0; i < overflow; i++) {
      this.map.delete(ordered[i][0]);
    }
  }
}

export const pidBindingStore = new PidBindingStore();
