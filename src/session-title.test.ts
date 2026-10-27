import { describe, it, expect } from 'vitest';

import { deriveSessionTitle, truncateByCodePoint, DEFAULT_SESSION_TITLE_LENGTH } from './session-title.js';

const cpLength = (s: string) => Array.from(s).length;

describe('deriveSessionTitle', () => {
  it('从普通用户消息派生标题', () => {
    expect(deriveSessionTitle('帮我修复登录接口的 500 错误')).toBe('帮我修复登录接口的 500 错误');
  });

  it('取首个非空行，忽略其后的行', () => {
    const content = '\n\n  帮我看看这个报错  \nTypeError: x is not a function\nat foo.js:1';
    expect(deriveSessionTitle(content)).toBe('帮我看看这个报错');
  });

  it('压掉行内多余空白', () => {
    expect(deriveSessionTitle('  帮我   看下   这个错  ')).toBe('帮我 看下 这个错');
  });

  it('超长消息截断到 30 字且以省略号收尾', () => {
    const title = deriveSessionTitle('x'.repeat(80));
    expect(title).toBeDefined();
    expect(cpLength(title!)).toBe(DEFAULT_SESSION_TITLE_LENGTH);
    expect(title!.endsWith('…')).toBe(true);
  });

  it('按 code point 截断，不劈开 emoji 的代理对', () => {
    // 20 个 emoji = 40 个 UTF-16 code unit，但只有 20 个 code point：按 code unit
    // 截会在第 30 个 unit 处把一个代理对劈成半个乱码字符。
    const short = deriveSessionTitle('😀'.repeat(20));
    expect(short).toBeDefined();
    expect(cpLength(short!)).toBe(20);
    expect(short).not.toContain('…');

    const title = deriveSessionTitle('😀'.repeat(40));
    expect(title).toBeDefined();
    expect(cpLength(title!)).toBe(DEFAULT_SESSION_TITLE_LENGTH);
    expect(title!.endsWith('…')).toBe(true);
    // 截断后不能出现半个代理对（孤立的高代理项 / 孤立的低代理项）
    expect((title!.match(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g) ?? [])).toEqual([]);
    expect((title!.match(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g) ?? [])).toEqual([]);
  });

  it('纯斜杠命令不作为标题来源', () => {
    expect(deriveSessionTitle('/new')).toBeUndefined();
    expect(deriveSessionTitle('/clear')).toBeUndefined();
    expect(deriveSessionTitle('/model gpt-4')).toBeUndefined();
    expect(deriveSessionTitle('  /help  ')).toBeUndefined();
  });

  it('正文里的斜杠不算斜杠命令', () => {
    expect(deriveSessionTitle('看下 /api/users 这个接口')).toBe('看下 /api/users 这个接口');
    expect(deriveSessionTitle('/api/users 这个路径有问题')).toBe('/api/users 这个路径有问题');
  });

  it('空白消息不产生标题', () => {
    expect(deriveSessionTitle('')).toBeUndefined();
    expect(deriveSessionTitle('   \n\t  ')).toBeUndefined();
  });

  it('非字符串输入不产生标题', () => {
    expect(deriveSessionTitle(undefined)).toBeUndefined();
    expect(deriveSessionTitle(null)).toBeUndefined();
    expect(deriveSessionTitle(42)).toBeUndefined();
    expect(deriveSessionTitle({ text: 'hi' })).toBeUndefined();
  });

  it('脱敏先于截断：跨边界的凭据不留前缀', () => {
    const secret = 'sk-ant-' + 'x'.repeat(25);
    const content = 'A'.repeat(28) + ' ' + secret;
    const title = deriveSessionTitle(content);
    expect(title).toBeDefined();
    expect(title).not.toContain('sk-ant');
    expect(cpLength(title!)).toBeLessThanOrEqual(DEFAULT_SESSION_TITLE_LENGTH);
  });

  it('凭据形态的内容被脱敏', () => {
    const gh = 'ghp_' + 'a'.repeat(36);
    const title = deriveSessionTitle(`我的 token 是 ${gh} 请收好`);
    expect(title).toBeDefined();
    expect(title).not.toContain('ghp_');
    expect(title).toContain('***');
  });
});

describe('truncateByCodePoint', () => {
  it('长度未超时不加省略号', () => {
    expect(truncateByCodePoint('abc', 5)).toBe('abc');
    expect(truncateByCodePoint('abcde', 5)).toBe('abcde');
  });

  it('超长时省略号计入总长', () => {
    expect(truncateByCodePoint('abcdef', 5)).toBe('abcd…');
    expect(cpLength(truncateByCodePoint('abcdef', 5))).toBe(5);
  });

  it('maxLength 为 1 时只留一个字符', () => {
    expect(truncateByCodePoint('abc', 1)).toBe('a');
  });

  it('非法 maxLength 退化为空串', () => {
    expect(truncateByCodePoint('abc', 0)).toBe('');
    expect(truncateByCodePoint('abc', -1)).toBe('');
    expect(truncateByCodePoint('abc', NaN)).toBe('');
  });
});
