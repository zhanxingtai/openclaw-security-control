import { describe, it, expect } from 'vitest';
import {
  redactSensitiveBody,
  redactSensitiveBodyWithKeys,
  redactSensitiveHeaders,
  redactEventForEmit,
} from './redact.js';

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

describe('redactSensitiveBodyWithKeys', () => {
  it('收集最外层被替换的键名（去重）', () => {
    const { value, redactedKeys } = redactSensitiveBodyWithKeys({
      api_key: 'secret',
      token: 't',
      name: 'test',
    });
    expect(value).toEqual({ api_key: '***', token: '***', name: 'test' });
    expect(redactedKeys.sort()).toEqual(['api_key', 'token']);
  });

  it('嵌套对象里的命中不收集（规范 redacted_keys 只要一级键名）', () => {
    const { redactedKeys } = redactSensitiveBodyWithKeys({
      user: { password: 'hunter2' },
      ok: 'value',
    });
    expect(redactedKeys).toEqual([]);
  });

  it('干净载荷返回空键名列表（调用方据此省略字段）', () => {
    const { value, redactedKeys } = redactSensitiveBodyWithKeys({ path: '/tmp/a' });
    expect(value).toEqual({ path: '/tmp/a' });
    expect(redactedKeys).toEqual([]);
  });

  it('值内容模式命中不算键被替换', () => {
    // api_key 键被替换要收；description 只是值里带了 JWT 形态，键名不收。
    const gh = 'ghp_' + 'a'.repeat(36);
    const { redactedKeys } = redactSensitiveBodyWithKeys({
      description: `用 ${gh} 登录`,
      api_key: 'x',
    });
    expect(redactedKeys).toEqual(['api_key']);
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

describe('redactEventForEmit', () => {
  it('redacts credential-shaped values in session_title', () => {
    const gh = 'ghp_' + 'a'.repeat(36);
    const out = redactEventForEmit({ session_title: `用 ${gh} 登录` });
    expect(out.session_title).not.toContain('ghp_');
    expect(out.session_title).toContain('***');
  });

  it('leaves a clean session_title untouched', () => {
    const out = redactEventForEmit({ session_title: '帮我修复登录接口' });
    expect(out.session_title).toBe('帮我修复登录接口');
  });

  it('does not mutate the input event', () => {
    const gh = 'ghp_' + 'a'.repeat(36);
    const event = { session_title: `用 ${gh} 登录` };
    redactEventForEmit(event);
    expect(event.session_title).toContain('ghp_');
  });
});
