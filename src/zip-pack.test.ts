import { describe, it, expect } from 'vitest';
import { inflateRawSync } from 'zlib';
import { buildZip, crc32 } from './zip-pack.js';

/** Minimal ZIP reader: walks local file headers sequentially. */
function readZip(buf: Buffer): Array<{ name: string; method: number; crc: number; data: Buffer }> {
  const out: Array<{ name: string; method: number; crc: number; data: Buffer }> = [];
  let off = 0;
  while (off + 30 <= buf.length && buf.readUInt32LE(off) === 0x04034b50) {
    const method = buf.readUInt16LE(off + 8);
    const crc = buf.readUInt32LE(off + 14);
    const csize = buf.readUInt32LE(off + 18);
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8');
    const payloadStart = off + 30 + nameLen + extraLen;
    const payload = buf.subarray(payloadStart, payloadStart + csize);
    const data = method === 8 ? inflateRawSync(payload) : Buffer.from(payload);
    out.push({ name, method, crc, data });
    off = payloadStart + csize;
  }
  return out;
}

describe('buildZip', () => {
  it('round-trips entries (deflate + store, utf-8 names)', () => {
    const text = 'line\n'.repeat(500); // highly compressible
    const binary = Buffer.from([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]);
    const zip = buildZip([
      { name: 'SKILL.md', data: Buffer.from('# demo\n') },
      { name: '脚本/工具.py', data: Buffer.from(text) },
      { name: 'bin/raw.dat', data: binary },
    ]);

    // ZIP magic + EOCD at the end.
    expect(zip.readUInt32LE(0)).toBe(0x04034b50);
    expect(zip.readUInt32LE(zip.length - 22)).toBe(0x06054b50);

    const entries = readZip(zip);
    expect(entries.map((e) => e.name)).toEqual(['SKILL.md', '脚本/工具.py', 'bin/raw.dat']);

    for (const entry of entries) {
      expect(crc32(entry.data)).toBe(entry.crc);
    }
    expect(entries[0].data.toString('utf8')).toBe('# demo\n');
    expect(entries[1].data.toString('utf8')).toBe(text);
    expect(entries[1].method).toBe(8); // compressed
    expect(entries[2].data.equals(binary)).toBe(true);
  });

  it('stores incompressible data (method 0) instead of growing it', () => {
    // xorshift32 pseudo-random bytes: no pattern for deflate to exploit.
    let seed = 42;
    const random = Buffer.alloc(2048);
    for (let i = 0; i < random.length; i++) {
      seed ^= seed << 13;
      seed >>>= 0;
      seed ^= seed >> 17;
      seed ^= seed << 5;
      seed >>>= 0;
      random[i] = seed & 0xff;
    }
    const zip = buildZip([{ name: 'rand.bin', data: random }]);
    const [entry] = readZip(zip);
    expect(entry.method).toBe(0);
    expect(entry.data.equals(random)).toBe(true);
  });

  it('builds a valid empty archive', () => {
    const zip = buildZip([]);
    expect(zip.length).toBe(22);
    expect(zip.readUInt32LE(0)).toBe(0x06054b50);
  });
});
