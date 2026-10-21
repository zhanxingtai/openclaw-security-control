export const DEFAULT_SENSITIVE_BODY_KEYS = [
  // snake_case + camelCase (lowercase substring match below)
  'api_key', 'apikey',
  'api-key', 'apiKey',
  'password', 'passwd', 'pass-word', 'passWord',
  'token', 'access_token', 'accessToken', 'refresh_token', 'refreshToken',
  'id_token', 'idToken', 'session_token', 'sessionToken',
  'jwt', 'bearer', 'cookie', 'set-cookie',
  'authorization', 'auth', 'auth_token', 'authToken',
  'proxy-authorization', 'proxyAuthorization',
  'x-api-key', 'xApiKey', 'x-auth-token', 'xAuthToken',
  'x-amz-security-token', 'x-amz-credential',
  'private_key', 'privateKey',
  'access_key', 'accessKey', 'secret_access_key', 'secretAccessKey',
  'secret', 'secret_key', 'secretKey',
  'client_id', 'clientId', 'client_secret', 'clientSecret',
  'credential', 'credentials',
  'openai-api-key', 'anthropic-api-key', 'github-token', 'slack-token',
];

// Content patterns (regex) for credential-shaped values, applied on top of
// the key-based redaction. Each match is replaced with `***` regardless of
// which key (or no key) the value rides under.
export const SENSITIVE_VALUE_PATTERNS: RegExp[] = [
  // JWT
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // AWS access key id
  /\bAKIA[0-9A-Z]{16}\b/g,
  // AWS secret access key (40 char base64-ish after the prefix tag)
  /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)=([A-Za-z0-9/+=]{40})\b/g,
  // GCP API key
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  // Slack tokens (xoxb / xoxp / xoxa / xoxr / xoxs)
  /\bxox[bpars]-[A-Za-z0-9-]{10,}\b/g,
  // GitHub PAT (ghp_/gho_/ghu_/ghs_/ghr_ + 36 chars)
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  // PEM private key blocks — the begin/end markers delimit the secret; the
  // base64 body between them is what leaks. Redact the whole block so a key
  // pasted into a prompt or param never reaches NDJSON (parity with the
  // hooks-side secret_in_content detector).
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  // Anthropic / OpenAI / Stripe / GitLab PAT shapes. Each is matched
  // standalone (no surrounding key required) so the value-only path catches
  // secrets pinned in prompts.
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bsk_live_[A-Za-z0-9]{16,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{16,}\b/g,
  // Generic bearer prefix in header values (case-insensitive)
  /\bBearer\s+[A-Za-z0-9._\-+/=]{16,}\b/gi,
  // Basic auth in header value (the prefix is public; the base64 token is
  // what carries a credential). Redact `Basic <base64>` rather than trying
  // to decode — decoding is hostile to ndjson durability and not worth the
  // false-negative risk.
  /\bBasic\s+[A-Za-z0-9._\-+/=]{16,}\b/gi,
  // URL-embedded credentials (`http://user:pass@host`)
  /\bhttps?:\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+/g,
  // URL-encoded bearer / basic — some toolchains URL-encode the header
  // before inlining into the body, missing the patterns above.
  /(?:Authorization|Bearer)=[A-Za-z0-9._\-+/=]{16,}/gi,
];

export function redactValueContent(value: string): string {
  let out = value;
  for (const re of SENSITIVE_VALUE_PATTERNS) {
    out = out.replace(re, '***');
  }
  return out;
}

export function redactSensitiveHeaders(
  headers: Record<string, string>,
  sensitiveKeys: string[] = ['authorization', 'cookie', 'x-api-key']
): Record<string, string> {
  const redacted: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    redacted[key] = sensitiveKeys.includes(lowerKey) ? '***' : value;
  }
  return redacted;
}

export function redactSensitiveBody(
  body: unknown,
  sensitiveKeys: string[] = DEFAULT_SENSITIVE_BODY_KEYS
): unknown {
  if (body === null || body === undefined) return body;

  if (Array.isArray(body)) {
    return body.map((item) => redactSensitiveBody(item, sensitiveKeys));
  }

  // Map: redact every entry value recursively.
  if (body instanceof Map) {
    const out = new Map();
    for (const [k, v] of body.entries()) {
      out.set(k, redactSensitiveBody(v, sensitiveKeys));
    }
    return out;
  }

  // Set: redact every member recursively.
  if (body instanceof Set) {
    const out = new Set();
    for (const v of body.values()) {
      out.add(redactSensitiveBody(v, sensitiveKeys));
    }
    return out;
  }

  if (typeof body !== 'object') {
    // Plain string — apply content-pattern redaction for credential-shaped
    // values (JWTs, AKIA, AIza, Slack tokens, URL-embedded creds). This
    // catches the case where a secret rides under a non-sensitive key like
    // {description: "Use AKIAIOSFODNN7EXAMPLE for ..."} or comes from a
    // prompt like "my key is ghp_abc...".
    return typeof body === 'string' ? redactValueContent(body) : body;
  }

  // Buffer / TypedArray / DataView: byte content may carry secrets; replace
  // with a marker so it never reaches NDJSON in plaintext. Object.entries on
  // a TypedArray would yield ['0', byte0], ['1', byte1], … which leaks bytes.
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(body)) {
    return `[Buffer:${body.length}bytes]`;
  }
  if (ArrayBuffer.isView(body)) {
    const view = body as unknown as { length: number; constructor: { name: string } };
    return `[${view.constructor.name || 'TypedArray'}:${view.length}]`;
  }
  if (body instanceof ArrayBuffer) {
    return `[ArrayBuffer:${body.byteLength}]`;
  }

  const result: Record<string, unknown> = {};
  // Normalise sensitive key list once: lowercased, dedup'd, sorted by length
  // descending so longer keys (e.g. 'access-token') match before their
  // shorter substrings ('access-token' before 'access' before 'token').
  const normalisedKeys = sensitiveKeys.map((k) => k.toLowerCase()).sort((a, b) => b.length - a.length);
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    // Exact match (not substring): a key like `tokens` (containing the
    // substring `token`) must NOT trigger redaction at this level — the
    // array should recurse so its elements' own keys are evaluated. The
    // sensitive-keys list already enumerates both `token` and `access_token`
    // etc. so exact match is sufficient.
    const isSensitive = normalisedKeys.some((p) => p === lowerKey);
    if (isSensitive) {
      result[key] = '***';
    } else if (typeof value === 'object' && value !== null) {
      result[key] = redactSensitiveBody(value, sensitiveKeys);
    } else if (typeof value === 'string') {
      result[key] = redactValueContent(value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Redact well-known PII fields on a SecurityEvent before it is written to the
 * NDJSON sink. The application collector emits `user_prompt`, `system_prompt`,
 * `content`, and `code_content` directly from the runtime hook context — these
 * can carry API keys, JWTs, AWS access keys, etc. that the param/header
 * redaction path never touches. This function is the single entry point every
 * `collector.report(event)` site must call before emitting.
 *
 * We also walk `headers` / `header` / `raw_headers` / `cookies` /
 * `request_headers` because the runtime hook writes the full HTTP request
 * header line into these fields. Subkey redaction uses redactSensitiveBody
 * which already does case-insensitive key matching and value-pattern
 * redaction.
 */
export function redactEventForEmit<T extends Record<string, unknown>>(event: T): T {
  const fields = ['user_prompt', 'system_prompt', 'content', 'code_content'] as const;
  const out: Record<string, unknown> = { ...event };
  for (const f of fields) {
    const v = out[f];
    if (typeof v === 'string' && v.length > 0) {
      const wrapped = { [f]: v } as Record<string, string>;
      out[f] = (redactSensitiveBody(wrapped) as Record<string, unknown>)[f];
    }
  }
  // Headers / cookies — same recursive redaction as params. The runtime hook
  // emits the literal header line under `header` (singular) and the full
  // request header set under `headers` / `raw_headers` / `request_headers`.
  for (const k of [
    'params',
    'raw_params',
    'tool_params',
    'headers',
    'header',
    'raw_headers',
    'request_headers',
    'cookies',
  ] as const) {
    if (out[k] && typeof out[k] === 'object') {
      out[k] = redactSensitiveBody(out[k]);
    }
  }
  return out as T;
}
