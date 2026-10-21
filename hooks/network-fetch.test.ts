import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';

/**
 * global fetch 拦截覆盖——真实子进程驱动：
 * - 拦截生效：fetch 请求产生 network_http 事件；
 * - body 捕获：请求体与响应体（response.clone 路径）进入事件；
 * - defineProperty 锁定：安装后 globalThis.fetch 不可被赋值还原；
 * - fetch 路径的强制执行：blocked host 在请求发出前被拒。
 */

const hookPath = path.resolve(process.cwd(), 'hooks/network.js');

function runChild(script: string, env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const { NODE_OPTIONS, ...childEnv } = env;
    const cp = spawn(process.execPath, ['-e', script], { env: childEnv, cwd: process.cwd() });
    let stdout = '';
    let stderr = '';
    cp.stdout.on('data', (d) => (stdout += d.toString()));
    cp.stderr.on('data', (d) => (stderr += d.toString()));
    cp.on('error', reject);
    cp.on('close', () => resolve({ stdout, stderr }));
  });
}

describe('network hook 的 global fetch 拦截', () => {
  let logFile: string;
  let baseEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    logFile = path.join(os.tmpdir(), `openclaw-fetch-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
    baseEnv = {
      ...process.env,
      OPENCLAW_MONITOR_LOG_PATH: logFile,
      OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS: '0',
    };
  });

  afterEach(() => {
    try { fs.unlinkSync(logFile); } catch { /* ignore */ }
  });

  it('fetch 请求被拦截并捕获请求/响应体', async () => {
    const script = `
      const http = require('http');
      const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ echo: body, ok: true }));
        });
      });
      server.listen(0, '127.0.0.1', async () => {
        const port = server.address().port;
        require(${JSON.stringify(hookPath)});
        const res = await fetch('http://127.0.0.1:' + port + '/api/fetch-test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: 'hello-fetch' }),
        });
        const text = await res.text();
        console.log('---FETCH_RESULT---');
        console.log(JSON.stringify({ status: res.status, text }));
        setTimeout(() => process.exit(0), 300);
      });
    `;
    const { stdout } = await runChild(script, baseEnv);
    const marker = '---FETCH_RESULT---';
    const idx = stdout.indexOf(marker);
    expect(idx).toBeGreaterThanOrEqual(0);
    const transfer = JSON.parse(stdout.slice(idx + marker.length).trim());
    expect(transfer.status).toBe(200);
    expect(JSON.parse(transfer.text).echo).toContain('hello-fetch');

    // response.clone 路径捕获的响应体进入事件
    const events = fs.existsSync(logFile)
      ? fs.readFileSync(logFile, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
      : [];
    const event = events.find((e) => e.url === '/api/fetch-test');
    expect(event, `expected fetch event in log, got ${JSON.stringify(events.map((e) => e.url))}`).toBeDefined();
    expect(event.method).toBe('POST');
    expect(JSON.stringify(event)).toContain('hello-fetch');
  });

  it('安装后 globalThis.fetch 被 defineProperty 锁定，赋值还原抛错', async () => {
    const script = `
      'use strict';
      require(${JSON.stringify(hookPath)});
      const original = globalThis.fetch;
      let threw = false;
      try {
        globalThis.fetch = () => {};
      } catch (err) {
        threw = true;
      }
      console.log('---LOCK_RESULT---');
      console.log(JSON.stringify({ threw, stillHooked: globalThis.fetch !== undefined && globalThis.fetch !== null }));
      process.exit(0);
    `;
    const { stdout } = await runChild(script, baseEnv);
    const marker = '---LOCK_RESULT---';
    const idx = stdout.indexOf(marker);
    expect(idx).toBeGreaterThanOrEqual(0);
    const result = JSON.parse(stdout.slice(idx + marker.length).trim());
    expect(result.threw).toBe(true);
    expect(result.stillHooked).toBe(true);
  });

  it('blocked host 的 fetch 在连接前被拒并留痕', async () => {
    const script = `
      require(${JSON.stringify(hookPath)});
      (async () => {
        let message = '';
        try {
          await fetch('http://malicious-c2-1.com/beacon');
        } catch (err) {
          message = err.message;
        }
        console.log('---BLOCK_RESULT---');
        console.log(JSON.stringify({ message }));
        setTimeout(() => process.exit(0), 300);
      })();
    `;
    const env = { ...baseEnv, OPENCLAW_NETWORK_ENFORCE: 'true', OPENCLAW_NETWORK_BLOCKED_HOSTS: 'malicious-c2-1.com' };
    const { stdout } = await runChild(script, env);
    const marker = '---BLOCK_RESULT---';
    const idx = stdout.indexOf(marker);
    expect(idx).toBeGreaterThanOrEqual(0);
    const result = JSON.parse(stdout.slice(idx + marker.length).trim());
    expect(result.message).toContain('拦截');

    const events = fs.existsSync(logFile)
      ? fs.readFileSync(logFile, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
      : [];
    const blocked = events.find((e) => e.blocked === true);
    expect(blocked).toBeDefined();
    expect(JSON.stringify(blocked)).toContain('malicious-c2-1.com');
  });
});
