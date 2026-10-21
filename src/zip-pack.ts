/**
 * Dependency-free ZIP builder for skill package collection.
 *
 * The install bundle ships no node_modules (js-yaml lesson), so this builds
 * the ZIP container by hand: local file headers + per-entry deflate (Node
 * built-in zlib) + central directory + EOCD. Each entry carries its own
 * CRC32, so consumers can list entries without inflating and a corrupt
 * entry does not affect the others.
 *
 * Entries fall back to STORE (method 0) when deflate would not shrink them
 * (already-compressed binaries), matching standard archiver behavior.
 */

import { deflateRawSync } from 'zlib';

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export interface ZipEntryInput {
  /** Entry path inside the archive (forward slashes, UTF-8). */
  name: string;
  data: Buffer;
  mtime?: Date | number;
}

function dosDateTime(d: Date): { time: number; date: number } {
  const year = Math.max(1980, d.getFullYear());
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = (((year - 1980) & 0x7f) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

export function buildZip(entries: ZipEntryInput[]): Buffer {
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name.replace(/\\/g, '/'), 'utf8');
    const crc = crc32(entry.data);
    const deflated = deflateRawSync(entry.data);
    const useStore = deflated.length >= entry.data.length;
    const payload = useStore ? entry.data : deflated;
    const method = useStore ? 0 : 8;
    const { time, date } = dosDateTime(entry.mtime ? new Date(entry.mtime) : new Date());

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // flag: UTF-8 entry names
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    chunks.push(local, nameBuf, payload);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); // central directory header signature
    cen.writeUInt16LE(20, 4); // version made by
    cen.writeUInt16LE(20, 6); // version needed
    cen.writeUInt16LE(0x0800, 8); // UTF-8 flag
    cen.writeUInt16LE(method, 10);
    cen.writeUInt16LE(time, 12);
    cen.writeUInt16LE(date, 14);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(payload.length, 20);
    cen.writeUInt32LE(entry.data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    // extra len / comment len / disk start / internal attrs stay zeroed
    cen.writeUInt32LE(0, 38); // external attrs
    cen.writeUInt32LE(offset, 42); // local header offset
    central.push(cen, nameBuf);

    offset += 30 + nameBuf.length + payload.length;
  }

  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // end of central directory signature
  eocd.writeUInt16LE(entries.length, 8); // entries on this disk
  eocd.writeUInt16LE(entries.length, 10); // entries total
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16); // central directory offset
  eocd.writeUInt16LE(0, 20); // comment length
  return Buffer.concat([...chunks, centralBuf, eocd]);
}
