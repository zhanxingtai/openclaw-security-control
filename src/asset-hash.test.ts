import { describe, it, expect } from 'vitest';
import { contentHash, normalizeContent, stableStringify } from './asset-hash.js';

describe('stableStringify', () => {
  it('is invariant to JSON key order', () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe(stableStringify({ a: 2, b: 1 }));
  });

  it('preserves array order', () => {
    expect(stableStringify([2, 1])).not.toBe(stableStringify([1, 2]));
  });

  it('handles nested structures', () => {
    const a = { x: { d: [1, { e: 2 }], c: 's' } };
    const b = { x: { c: 's', d: [1, { e: 2 }] } };
    expect(stableStringify(a)).toBe(stableStringify(b));
  });
});

describe('contentHash', () => {
  it('is stable across JSON key reordering (no format jitter)', () => {
    const h1 = contentHash('{"a":1,"b":2}');
    const h2 = contentHash('{ "b": 2, "a": 1 }');
    expect(h1).toBe(h2);
  });

  it('changes when a value changes', () => {
    expect(contentHash('{"a":1}')).not.toBe(contentHash('{"a":2}'));
  });

  it('ignores surrounding whitespace for non-JSON content', () => {
    expect(contentHash('# Title\n')).toBe(contentHash('# Title'));
  });

  it('falls back to raw text for invalid JSON', () => {
    expect(normalizeContent('{not json}')).toBe('{not json}');
  });
});
