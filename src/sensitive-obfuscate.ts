/**
 * obf:v1 — unified obfuscation for sensitive asset fields (tokens, api keys,
 * env values) collected by the AssetCollector.
 *
 * This is obfuscation, NOT cryptographic encryption: the algorithm is public
 * and keyless, so anyone who knows it can reverse the payload. Its purpose is
 * to keep credential plaintext out of logs, queues, local NDJSON files and
 * screenshots, while staying trivially decodable by any consumer (one fixed
 * decode function, no key management).
 *
 * Envelope format: `obf:v1:<base64>` where the base64 payload is produced by:
 *   1. UTF-8 encode the plaintext
 *   2. t[i] = (b[i] + (i % 251)) & 0xff        (position-dependent shift)
 *   3. x[i] = t[i] XOR MAGIC[i % 16]           (fixed substitution table)
 *   4. reverse the byte array
 *   5. standard base64
 *
 * The transform is deterministic: identical plaintext always yields the same
 * obfuscated string, so consumers can detect credential reuse across agents
 * without decoding.
 */

const PREFIX = 'obf:v1:';
const SHIFT_MOD = 251;
// Fixed 16-byte substitution table. Part of the public algorithm, not a key.
const MAGIC = Buffer.from('5A3C91E70B62D48F27C156AA09FE73B8', 'hex');

export function obfEncode(plain: string): string {
  const b = Buffer.from(plain, 'utf8');
  const x = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) {
    x[i] = ((b[i] + (i % SHIFT_MOD)) & 0xff) ^ MAGIC[i % 16];
  }
  return PREFIX + Buffer.from([...x].reverse()).toString('base64');
}

export function obfDecode(payload: string): string {
  if (!payload.startsWith(PREFIX)) {
    throw new Error(`[obf] payload does not start with ${PREFIX}`);
  }
  // Cap decoded payload length to 1 MiB to prevent OOM from a hostile or
  // runaway base64 blob. Plugin-internal consumers never exceed a few KB;
  // anything larger is rejected as malformed.
  const MAX_DECODED = 1 << 20;
  const body = payload.slice(PREFIX.length);
  if (body.length > MAX_DECODED * 4 / 3) {
    throw new Error(`[obf] payload exceeds ${MAX_DECODED} bytes after base64 decode`);
  }
  const raw = Buffer.from(body, 'base64');
  const x = Buffer.from([...raw].reverse());
  const b = Buffer.alloc(x.length);
  for (let i = 0; i < x.length; i++) {
    b[i] = (((x[i] ^ MAGIC[i % 16]) - (i % SHIFT_MOD)) + 256) & 0xff;
  }
  return b.toString('utf8');
}

export function isObfuscated(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(PREFIX);
}

/**
 * Case-insensitive substring match of a key against the configured sensitive
 * patterns (e.g. token, key, secret, password, credential).
 */
export function isSensitiveKey(key: string, patterns: readonly string[]): boolean {
  const lower = key.toLowerCase();
  return patterns.some((p) => p.length > 0 && lower.includes(p.toLowerCase()));
}

/**
 * Return a copy of `obj` where string values whose key matches `patterns` are
 * replaced by their obf:v1 envelope. Non-string values are left untouched.
 */
export function obfuscateSensitiveValues(
  obj: Record<string, unknown> | undefined,
  patterns: readonly string[]
): Record<string, unknown> | undefined {
  if (!obj) return obj;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = typeof v === 'string' && isSensitiveKey(k, patterns) ? obfEncode(v) : v;
  }
  return out;
}

/**
 * Recursive variant of obfuscateSensitiveValues: walks objects/arrays of any
 * depth and obfuscates every string value whose key matches `patterns`.
 * Used when raw config file content is included in an event payload.
 */
export function obfuscateDeep(value: unknown, patterns: readonly string[]): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => obfuscateDeep(item, patterns));
  }
  if (typeof value === 'object' && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = typeof v === 'string' && isSensitiveKey(k, patterns) ? obfEncode(v) : obfuscateDeep(v, patterns);
    }
    return out;
  }
  return value;
}
