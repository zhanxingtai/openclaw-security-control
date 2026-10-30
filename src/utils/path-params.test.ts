import { describe, it, expect } from 'vitest';
import { canonicalizePathParams } from './path-params.js';

describe('路径别名落盘收敛（canonicalizePathParams）', () => {
  it('同值别名收敛成单个规范名 path', () => {
    const expanded = {
      path: '/home/node/.openclaw/logs/gateway-restart.log',
      optional: true,
      file_path: '/home/node/.openclaw/logs/gateway-restart.log',
      filepath: '/home/node/.openclaw/logs/gateway-restart.log',
      filePath: '/home/node/.openclaw/logs/gateway-restart.log',
      file: '/home/node/.openclaw/logs/gateway-restart.log',
      src: '/home/node/.openclaw/logs/gateway-restart.log',
      source: '/home/node/.openclaw/logs/gateway-restart.log',
      target: '/home/node/.openclaw/logs/gateway-restart.log',
      destination: '/home/node/.openclaw/logs/gateway-restart.log',
    };
    const out = canonicalizePathParams(expanded);
    expect(Object.keys(out).sort()).toEqual(['optional', 'path']);
    expect(out.path).toBe('/home/node/.openclaw/logs/gateway-restart.log');
  });

  it('多路径语义（src 与 destination 不同）原样保留，不做收敛', () => {
    const multi = { src: '/a.txt', destination: '/b.txt' };
    const out = canonicalizePathParams(multi);
    expect(out.src).toBe('/a.txt');
    expect(out.destination).toBe('/b.txt');
    expect(out).not.toHaveProperty('path');
  });

  it('没有路径参数时原样返回', () => {
    expect(canonicalizePathParams({ command: 'ls' })).toEqual({ command: 'ls' });
  });
});
