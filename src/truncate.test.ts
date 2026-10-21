import { describe, it, expect } from 'vitest';
import { truncateString, computeContentLength } from './truncate.js';

describe('truncateString', () => {
  it('truncates content longer than maxLen with an ellipsis', () => {
    expect(truncateString('hello world', 5)).toBe('hello...');
    expect(truncateString('hi', 5)).toBe('hi');
  });

  it('serializes non-string content before truncating', () => {
    expect(truncateString({ a: 1, b: 2 }, 7)).toBe('{"a":1,...');
  });

  it('returns empty string for null / undefined', () => {
    expect(truncateString(null, 10)).toBe('');
    expect(truncateString(undefined, 10)).toBe('');
  });

  // NaN maxLen makes `s.length > NaN` always false, so truncation silently
  // never happens and poisoned config could leak full content into events.
  // Non-finite limits fall back to 0 (truncate).
  it('does not silently disable truncation when maxLen is NaN or non-finite', () => {
    expect(truncateString('hello world', NaN)).toBe('...');
    expect(truncateString('hello world', Infinity)).toBe('...');
    expect(truncateString('', NaN)).toBe('');
  });
});

describe('computeContentLength', () => {
  it('computes length for strings and serializable objects', () => {
    expect(computeContentLength('abc')).toBe(3);
    expect(computeContentLength({ a: 1 })).toBe(7);
  });
});
