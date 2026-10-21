import { describe, it, expect } from 'vitest';
import {
  obfEncode,
  obfDecode,
  isObfuscated,
  isSensitiveKey,
  obfuscateSensitiveValues,
  obfuscateDeep,
} from './sensitive-obfuscate.js';

describe('obf:v1 encode/decode', () => {
  it('round-trips ASCII strings', () => {
    expect(obfDecode(obfEncode('ghp_secret_token_12345'))).toBe('ghp_secret_token_12345');
  });

  it('round-trips multi-byte UTF-8 (Chinese, emoji)', () => {
    const value = '密钥-中文-🔑-テスト';
    expect(obfDecode(obfEncode(value))).toBe(value);
  });

  it('round-trips the empty string', () => {
    expect(obfDecode(obfEncode(''))).toBe('');
  });

  it('is deterministic (same plaintext → same envelope)', () => {
    expect(obfEncode('same-input')).toBe(obfEncode('same-input'));
  });

  it('produces the obf:v1: prefix followed by valid base64', () => {
    const encoded = obfEncode('hello');
    expect(encoded.startsWith('obf:v1:')).toBe(true);
    const b64 = encoded.slice('obf:v1:'.length);
    expect(Buffer.from(b64, 'base64').toString('base64')).toBe(b64);
  });

  it('does not leak recognizable plaintext into the envelope', () => {
    const encoded = obfEncode('super-secret-password');
    expect(encoded).not.toContain('super-secret-password');
    expect(encoded).not.toContain('c3VwZXItc2VjcmV0LXBhc3N3b3Jk'); // plain base64 of it
  });

  it('throws when decoding a payload without the prefix', () => {
    expect(() => obfDecode('not-an-envelope')).toThrow();
  });

  it('isObfuscated detects envelopes', () => {
    expect(isObfuscated(obfEncode('x'))).toBe(true);
    expect(isObfuscated('plain')).toBe(false);
    expect(isObfuscated(42)).toBe(false);
  });
});

describe('isSensitiveKey', () => {
  const patterns = ['token', 'key', 'secret', 'password', 'credential'];

  it('matches case-insensitively', () => {
    expect(isSensitiveKey('GITHUB_TOKEN', patterns)).toBe(true);
    expect(isSensitiveKey('x-api-key', patterns)).toBe(true);
    expect(isSensitiveKey('Password', patterns)).toBe(true);
    expect(isSensitiveKey('AWS_SECRET_ACCESS_KEY', patterns)).toBe(true);
  });

  it('does not match non-sensitive keys', () => {
    expect(isSensitiveKey('LOG_LEVEL', patterns)).toBe(false);
    expect(isSensitiveKey('timeout', patterns)).toBe(false);
  });

  it('ignores empty patterns', () => {
    expect(isSensitiveKey('token', [''])).toBe(false);
  });
});

describe('obfuscateSensitiveValues', () => {
  it('obfuscates only matching string values', () => {
    const out = obfuscateSensitiveValues(
      { GITHUB_TOKEN: 'abc', LOG_LEVEL: 'info', retries: 3 },
      ['token']
    );
    expect(out!.GITHUB_TOKEN).toMatch(/^obf:v1:/);
    expect(obfDecode(out!.GITHUB_TOKEN as string)).toBe('abc');
    expect(out!.LOG_LEVEL).toBe('info');
    expect(out!.retries).toBe(3);
  });

  it('returns undefined for undefined input', () => {
    expect(obfuscateSensitiveValues(undefined, ['token'])).toBeUndefined();
  });
});

describe('obfuscateDeep', () => {
  it('obfuscates nested objects and arrays', () => {
    const input = {
      mcpServers: {
        github: { env: { GITHUB_TOKEN: 'abc' } },
        list: [{ apiKey: 'k1' }, { note: 'plain' }],
      },
    };
    const out = obfuscateDeep(input, ['token', 'key']) as typeof input;
    const servers = out.mcpServers as Record<string, Record<string, Record<string, string>>>;
    expect(obfDecode(servers.github.env.GITHUB_TOKEN)).toBe('abc');
    const list = out.mcpServers.list as unknown as Array<Record<string, string>>;
    expect(obfDecode(list[0].apiKey)).toBe('k1');
    expect(list[1].note).toBe('plain');
  });
});
