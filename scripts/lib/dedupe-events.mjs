/**
 * dedupe-events.mjs —— 存量事件文件的去重判定（纯函数，无 IO）
 *
 * 落盘去重只管今后写入；已经写坏的存量文件需要一条可选修复路径。
 * 本模块只判定、不写盘：写盘由 CLI 负责（备份 + 原子替换 + 默认 dry-run），
 * 因此误跑一次不会永久丢审计数据。没有 `event_id` 的行、解析不了的
 * 坏行（读侧本来就容忍坏行）都保留。
 *
 * 与 sink（`src/store.ts` 的 `EventBridgeCollector.report`）口径一致：
 * 同 id + 内容相同 ⇒ 丢后来者；同 id + 内容不同 ⇒ 冲突，默认也丢后来者
 * （保持"行数 == 唯一 id 数"的验收口径），单独计数并要求 `--keep-conflicts` 才保留。
 */

/**
 * 行内容指纹（与 `src/store.ts` 的 `canonicalFingerprint` 同口径）。
 * 顶层 key 排序后再算 ⇒ key 顺序不同不会被误判成"冲突"。
 */
export function canonicalFingerprint(obj) {
  const keys = Object.keys(obj).sort();
  const parts = [];
  for (const key of keys) {
    const value = obj[key];
    const rendered =
      value !== null && typeof value === 'object' ? JSON.stringify(value) ?? '' : String(value);
    parts.push(`${key}=${rendered}`);
  }
  return parts.join(';');
}

/**
 * 对一批 NDJSON 行做去重判定。
 *
 * @param {string[]} lines 原始行（**不含**换行符）
 * @param {{ keepConflicts?: boolean }} [options]
 * @returns {{ kept: string[], duplicates: number, conflicts: number, withoutId: number, unparsable: number, keptConflicts: string[] }}
 */
export function dedupeEventLines(lines, options = {}) {
  const keepConflicts = options.keepConflicts === true;

  const kept = [];
  const keptConflicts = [];
  /** @type {Map<string, string>} */
  const seen = new Map();
  let duplicates = 0;
  let conflicts = 0;
  let withoutId = 0;
  let unparsable = 0;

  for (const line of lines) {
    if (!line || !line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      // 坏行：读侧本来就容忍 ⇒ 保留（绝不静默丢数据）
      unparsable += 1;
      kept.push(line);
      continue;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      unparsable += 1;
      kept.push(line);
      continue;
    }

    const id = typeof parsed.event_id === 'string' && parsed.event_id ? parsed.event_id : undefined;
    if (!id) {
      // 没有 id ⇒ 无从判重 ⇒ 不猜，保留
      withoutId += 1;
      kept.push(line);
      continue;
    }

    const fingerprint = canonicalFingerprint(parsed);
    const previous = seen.get(id);
    if (previous === undefined) {
      seen.set(id, fingerprint);
      kept.push(line);
      continue;
    }

    if (previous === fingerprint) {
      // 同 id + 同内容 ⇒ 真重复 ⇒ 丢后来者
      duplicates += 1;
      continue;
    }

    // 同 id + 不同内容 ⇒ 冲突
    conflicts += 1;
    if (keepConflicts) {
      kept.push(line);
      keptConflicts.push(id);
    }
    // 默认：丢后来者（与 sink 一致）
  }

  return { kept, duplicates, conflicts, withoutId, unparsable, keptConflicts };
}
