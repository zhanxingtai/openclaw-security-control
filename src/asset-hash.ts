/**
 * Content normalization + SHA-256 fingerprinting for asset files.
 *
 * The AssetCollector decides whether to report purely on these hashes: a file is only re-hashed when its
 * mtime/size changes, and an event is only emitted when the normalized
 * content hash actually differs. Normalization removes formatting jitter
 * (trailing whitespace, JSON key order) so cosmetically-rewritten but
 * semantically identical configs do not produce change events.
 */

import { createHash } from 'crypto';

export function sha256Hex(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * JSON.stringify with object keys sorted recursively. Array order is
 * preserved (arrays are semantically ordered). `undefined` object values are
 * skipped, matching JSON.stringify behavior.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'null';
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => stableStringify(item)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return (
    '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}'
  );
}

/**
 * Normalize raw file content before hashing: trim surrounding whitespace and,
 * when the content parses as JSON, re-serialize with sorted keys so key
 * reordering does not register as a change.
 */
export function normalizeContent(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return stableStringify(JSON.parse(trimmed));
    } catch {
      // Not valid JSON after all — fall through to the trimmed raw text.
    }
  }
  return trimmed;
}

export function contentHash(raw: string): string {
  return sha256Hex(normalizeContent(raw));
}
