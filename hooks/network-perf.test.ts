import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';

/**
 * network hook 热路径性能三件套的行为级验证。
 * 全部用真实子进程驱动（同进程重载不可靠，沿用 hooks/network.test.ts 范式）。
 *
 * - ignore 前置过滤：isIgnoredTarget 与 isIgnoredEvent 判定一致，默认
 *   忽略表内的 LLM 主链路目标在 build 之前被丢弃；
 * - 64KB 采集上限：超大请求/响应体按既有 '...' 截断语义落盘，传输本身完整；
 * - 批量落盘可靠性：低于 flush 阈值的事件在进程退出时不丢失。
 */

const hookPath = path.resolve(process.cwd(), 'hooks/network.js');

function runChild(script: string, env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    // Strip NODE_OPTIONS: under vitest it carries the test-runner preload,
    // which must not leak into the hook-driven child process.
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

describe('network hook 热路径', () => {
  let logFile: string;
  let baseEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    logFile = path.join(os.tmpdir(), `openclaw-network-perf-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
    baseEnv = {
      ...process.env,
      OPENCLAW_MONITOR_LOG_PATH: logFile,
      OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS: '0',
    };
  });

  afterEach(() => {
    try { fs.unlinkSync(logFile); } catch { /* ignore */ }
  });

  it('isIgnoredTarget 前置过滤与 isIgnoredEvent 判定一致', async () => {
    const script = `
      const http = require('http');
      const server = http.createServer((req, res) => { res.end('ok'); });
      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        const hook = require(${JSON.stringify(hookPath)});
        const cases = [
          ['https://api.openai.com/v1/chat/completions', true],   // ignored by URL prefix
          ['https://registry.npmjs.org/whatever', true],          // ignored by host
          ['http://127.0.0.1:' + port + '/normal', false],        // normal target
          ['https://example.com/v1/chat/completions', true],      // URL match is host-agnostic
          ['https://example.com/callback/ws/endpoint', true],     // ignored by URL prefix
        ];
        const out = cases.map(([options, expected]) => {
          const pre = hook.isIgnoredTarget({ options, method: 'GET', headers: {}, body: '' });
          const built = hook.buildNetworkEvent(
            { options, method: 'GET', headers: {} },
            { statusCode: 200, statusMessage: 'OK', body: '' },
            Date.now()
          );
          const post = hook.isIgnoredEvent(built);
          return { expected, pre: pre.ignored, post };
        });
        console.log('---PREFILTER_RESULT---');
        console.log(JSON.stringify(out));
        server.close(() => process.exit(0));
      });
    `;
    const { stdout } = await runChild(script, baseEnv);
    const marker = '---PREFILTER_RESULT---';
    const idx = stdout.indexOf(marker);
    expect(idx).toBeGreaterThanOrEqual(0);
    const results = JSON.parse(stdout.slice(idx + marker.length).trim());
    expect(results).toHaveLength(5);
    for (const r of results) {
      expect(r.pre).toBe(r.expected);
      expect(r.post).toBe(r.expected);
    }
  });

  it('超 64KB 的响应体与请求体按截断语义落盘，传输保持完整', async () => {
    const script = `
      const http = require('http');
      const big = 'x'.repeat(200 * 1024);
      const server = http.createServer((req, res) => {
        let received = 0;
        req.on('data', (c) => { received += c.length; });
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'text/plain', 'x-received': String(received) });
          res.end(big);
        });
      });
      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        require(${JSON.stringify(hookPath)});
        const upload = http.request({ host: '127.0.0.1', port, path: '/upload', method: 'POST' }, (res) => {
          let got = 0;
          res.on('data', (c) => { got += c.length; });
          res.on('end', () => {
            console.log('---BIG_RESULT---');
            console.log(JSON.stringify({ receivedByServer: Number(res.headers['x-received']), receivedByClient: got }));
            setTimeout(() => process.exit(0), 200);
          });
        });
        upload.end(big);
      });
    `;
    const { stdout } = await runChild(script, baseEnv);
    const marker = '---BIG_RESULT---';
    const idx = stdout.indexOf(marker);
    expect(idx).toBeGreaterThanOrEqual(0);
    const transfer = JSON.parse(stdout.slice(idx + marker.length).trim());
    // transfer itself unaffected by the capture cap
    expect(transfer.receivedByServer).toBe(200 * 1024);
    expect(transfer.receivedByClient).toBe(200 * 1024);
    // captured event respects the existing truncation marker semantics
    const events = fs.existsSync(logFile)
      ? fs.readFileSync(logFile, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
      : [];
    expect(events.length).toBeGreaterThanOrEqual(1);
    const event = events[events.length - 1];
    expect(String(event.content).endsWith('...')).toBe(true);
    expect(String(event.content).length).toBeLessThanOrEqual(4096 + 3);
  });

  it('低于 flush 阈值的事件在进程退出时无丢失', async () => {
    const script = `
      const http = require('http');
      const server = http.createServer((req, res) => { res.end('ok'); });
      server.listen(0, '127.0.0.1', async () => {
        const port = server.address().port;
        require(${JSON.stringify(hookPath)});
        const get = (p) => new Promise((resolve, reject) => {
          http.get('http://127.0.0.1:' + port + p, (res) => {
            res.on('data', () => {});
            res.on('end', resolve);
          }).on('error', reject);
        });
        // 5 events < 16 threshold; exit immediately after the last one so the
        // only guaranteed writer is the process exit flush.
        await get('/flush-1');
        await get('/flush-2');
        await get('/flush-3');
        await get('/flush-4');
        await get('/flush-5');
        process.exit(0);
      });
    `;
    await runChild(script, baseEnv);
    const events = fs.existsSync(logFile)
      ? fs.readFileSync(logFile, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
      : [];
    const urls = events.map((e) => e.url);
    for (const expected of ['/flush-1', '/flush-2', '/flush-3', '/flush-4', '/flush-5']) {
      expect(urls).toContain(expected);
    }
  });

  it('超大非 JSON  body 的脱敏不退化（修复前 200KB 需 165 秒）', () => {
    // 纯函数级回归：buildNetworkEvent 会同步完成。修复前该用例必然超时
    // （关键字门控缺失时替换正则按 O(n²) 回溯），门控修复后毫秒级返回。
    delete require.cache[require.resolve(hookPath)];
    const hook = require(hookPath);
    try {
      const big = 'x'.repeat(200 * 1024);
      const event = hook.buildNetworkEvent(
        { options: 'http://example.com/upload', method: 'POST', headers: {} },
        { statusCode: 200, statusMessage: 'OK', body: big },
        Date.now()
      );
      expect(String(event.content).endsWith('...')).toBe(true);
      expect(String(event.content).length).toBeLessThanOrEqual(4096 + 3);
    } finally {
      hook.uninstall();
    }
  });

  it('关键字门控不改变脱敏行为（含关键字仍被替换）', () => {
    delete require.cache[require.resolve(hookPath)];
    const hook = require(hookPath);
    try {
      const body = 'grant_type=client_credentials&client_secret=supersecretvalue123&nonce=abc';
      const event = hook.buildNetworkEvent(
        { options: 'http://example.com/token', method: 'POST', headers: {} },
        { statusCode: 200, statusMessage: 'OK', body },
        Date.now()
      );
      // 响应体落在 response_body 字段（与请求体不同时）
      expect(String(event.response_body)).toContain('client_secret=***');
      expect(String(event.response_body)).not.toContain('supersecretvalue123');
      // 无关键字字段不受影响
      expect(String(event.response_body)).toContain('nonce=abc');
    } finally {
      hook.uninstall();
    }
  });
});
