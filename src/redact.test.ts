import { describe, it, expect } from 'vitest';
import { redactSensitiveBody, redactSensitiveHeaders } from './redact.js';

describe('redactSensitiveBody', () => {
  it('redacts top-level sensitive keys', () => {
    const body = { api_key: 'secret123', name: 'test' };
    expect(redactSensitiveBody(body)).toEqual({ api_key: '***', name: 'test' });
  });

  it('recursively redacts nested sensitive keys', () => {
    const body = {
      user: { password: 'hunter2' },
      tokens: [{ access_token: 'tok' }],
      ok: 'value',
    };
    const redacted = redactSensitiveBody(body) as Record<string, unknown>;
    expect((redacted.user as Record<string, unknown>).password).toBe('***');
    expect(((redacted.tokens as unknown[])[0] as Record<string, unknown>).access_token).toBe('***');
    expect(redacted.ok).toBe('value');
  });

  it('returns primitives as-is', () => {
    expect(redactSensitiveBody('string')).toBe('string');
    expect(redactSensitiveBody(123)).toBe(123);
    expect(redactSensitiveBody(null)).toBe(null);
  });
});

describe('redactSensitiveHeaders', () => {
  it('redacts configured headers case-insensitively', () => {
    const headers = { Authorization: 'Bearer x', 'X-Request-Id': 'y' };
    expect(redactSensitiveHeaders(headers)).toEqual({
      Authorization: '***',
      'X-Request-Id': 'y',
    });
  });
});
