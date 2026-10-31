import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
import { inflateRawSync } from 'zlib';
import { AssetCollector } from './asset-collector.js';
import { obfDecode } from './sensitive-obfuscate.js';
import type { AssetMonitorConfig, SecurityEvent } from './types.js';

const TOKEN = 'ghp_secret_token_12345';

interface Fixture {
  root: string;
  configPath: string;
  mcpPath: string;
  skillsRoot: string;
  statePath: string;
}

function writeJson(file: string, value: unknown): void {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), 'utf8');
}

function createFixture(): Fixture {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-collector-'));
  const configPath = path.join(root, 'openclaw.json');
  writeJson(configPath, {
    plugins: { 'sst-security-control-openclaw': { enabled: true } },
    mcpServers: {
      github: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-github'],
        env: { GITHUB_TOKEN: TOKEN, LOG_LEVEL: 'info' },
      },
    },
  });

  const skillsRoot = path.join(root, 'skills');
  fs.mkdirSync(path.join(skillsRoot, 'alpha'), { recursive: true });
  fs.writeFileSync(
    path.join(skillsRoot, 'alpha', 'SKILL.md'),
    '---\nname: alpha\nversion: 1.0.0\ndescription: test skill\n---\n# Alpha\n',
    'utf8'
  );
  fs.writeFileSync(path.join(skillsRoot, 'alpha', 'helper.txt'), 'helper', 'utf8');

  return {
    root,
    configPath,
    mcpPath: path.join(root, 'mcp.json'),
    skillsRoot,
    statePath: path.join(root, 'asset-state.json'),
  };
}

function mockCollector(reported: SecurityEvent[]): { report: (event: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> } {
  return {
    report: async (event: SecurityEvent) => {
      reported.push(event);
    },
    shutdown: async () => {},
  };
}

function createCollector(
  fixture: Fixture,
  reported: SecurityEvent[],
  extra?: Partial<AssetMonitorConfig>,
  options?: { blobDir?: string }
): AssetCollector {
  return new AssetCollector(
    mockCollector(reported),
    {
      enabled: true,
      scanIntervalMs: 60000,
      fullSnapshotIntervalMs: 0,
      statePersistencePath: fixture.statePath,
      ...extra,
    },
    { hostId: 'test-host' },
    {
      configPaths: [fixture.configPath],
      skillDirs: [fixture.skillsRoot],
      mcpPaths: [fixture.mcpPath],
    },
    { blobDir: options?.blobDir ?? path.join(fixture.root, 'asset-blobs') }
  );
}

/** 按内容寻址从 asset-blobs/ 读回包体原文（base64 文本）。 */
function readBlob(root: string, hash: string): string {
  return fs.readFileSync(path.join(root, 'asset-blobs', hash), 'utf8');
}

describe('AssetCollector', () => {
  let fixture: Fixture;
  let reported: SecurityEvent[];
  let collectors: AssetCollector[];

  beforeEach(() => {
    fixture = createFixture();
    reported = [];
    collectors = [];
  });

  afterEach(async () => {
    for (const c of collectors) {
      await c.shutdown();
    }
    fs.rmSync(fixture.root, { recursive: true, force: true });
  });

  function track(c: AssetCollector): AssetCollector {
    collectors.push(c);
    return c;
  }

  it('reports a full baseline on first run', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();

    expect(reported).toHaveLength(3);
    for (const event of reported) {
      expect(event.event_type).toBe('asset_add');
      expect(event.layer).toBe('asset');
      expect(event.layer).toBe('asset');
      expect(event.change_type).toBeUndefined();
      expect(event.host_id).toBe('test-host');
      expect(event.content_hash).toBeTruthy();
    }

    const ids = reported.map((e) => e.asset_id);
    expect(ids).toContain(`test-host:agent_config:${fixture.configPath}`);
    expect(ids).toContain(`test-host:mcp_server:${fixture.configPath}#github`);
    expect(ids).toContain(`test-host:skill:${path.join(fixture.skillsRoot, 'alpha')}`);

    const skill = reported.find((e) => e.asset_type === 'skill');
    expect(skill?.parsed?.name).toBe('alpha');
    expect(skill?.parsed?.version).toBe('1.0.0');
    expect(skill?.parsed?.file_count).toBe(2);
  });

  it('emits nothing on rescan when content is unchanged', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    expect(reported).toHaveLength(3);

    reported.length = 0;
    await c.scanNow();
    await c.scanNow();
    expect(reported).toHaveLength(0);
  });

  it('emits nothing when only mtime changes but content is identical', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    reported.length = 0;

    // Bump mtime without touching content.
    const future = new Date(Date.now() + 5000);
    fs.utimesSync(fixture.configPath, future, future);

    await c.scanNow();
    expect(reported).toHaveLength(0);
  });

  it('emits changed events with prev_hash when content changes', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    reported.length = 0;

    const cfg = JSON.parse(fs.readFileSync(fixture.configPath, 'utf8'));
    cfg.mcpServers.github.env.GITHUB_TOKEN = 'ghp_new_token_999';
    writeJson(fixture.configPath, cfg);

    await c.scanNow();

    // Both the config file asset and the embedded MCP server asset changed.
    expect(reported).toHaveLength(2);
    const mcp = reported.find((e) => e.asset_type === 'mcp_server');
    const cfgEvent = reported.find((e) => e.asset_type === 'agent_config');
    for (const event of [mcp, cfgEvent]) {
      expect(event?.event_type).toBe('asset_change');
      expect(event?.prev_hash).toBeTruthy();
      expect(event?.prev_hash).not.toBe(event?.content_hash);
    }
    const env = mcp?.parsed?.env as Record<string, string>;
    expect(obfDecode(env.GITHUB_TOKEN)).toBe('ghp_new_token_999');
  });

  it('emits exactly one added event for a newly discovered asset', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    reported.length = 0;

    fs.mkdirSync(path.join(fixture.skillsRoot, 'beta'), { recursive: true });
    fs.writeFileSync(
      path.join(fixture.skillsRoot, 'beta', 'SKILL.md'),
      '---\nname: beta\n---\n# Beta\n',
      'utf8'
    );

    await c.scanNow();
    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('asset_add');
    expect(reported[0].asset_type).toBe('skill');
  });

  it('emits exactly one removed event when an asset disappears', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    const baseline = reported.find((e) => e.asset_type === 'skill');
    reported.length = 0;

    fs.rmSync(path.join(fixture.skillsRoot, 'alpha'), { recursive: true, force: true });

    await c.scanNow();
    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('asset_remove');
    expect(reported[0].asset_type).toBe('skill');
    expect(reported[0].prev_hash).toBe(baseline?.content_hash);
    // asset_remove must not carry content_hash — the standard forbids it.
    expect(reported[0].content_hash).toBeUndefined();

    // And nothing further on the next scan.
    reported.length = 0;
    await c.scanNow();
    expect(reported).toHaveLength(0);
  });

  it('does not re-baseline after a restart (state restored from disk)', async () => {
    const c1 = track(createCollector(fixture, reported));
    await c1.initialize();
    await c1.shutdown();
    expect(reported).toHaveLength(3);

    reported.length = 0;
    const c2 = track(createCollector(fixture, reported));
    await c2.initialize();
    expect(reported).toHaveLength(0);
  });

  it('detects removals that happened while the plugin was stopped', async () => {
    const c1 = track(createCollector(fixture, reported));
    await c1.initialize();
    await c1.shutdown();

    fs.rmSync(fixture.configPath);
    reported.length = 0;

    const c2 = track(createCollector(fixture, reported));
    await c2.initialize();

    // agent_config + mcp_server from the deleted config file.
    expect(reported).toHaveLength(2);
    for (const event of reported) {
      expect(event.event_type).toBe('asset_remove');
    }
  });

  it('obfuscates sensitive MCP values and never leaks plaintext credentials', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();

    const mcp = reported.find((e) => e.asset_type === 'mcp_server');
    expect(mcp).toBeDefined();

    const env = mcp?.parsed?.env as Record<string, string>;
    expect(env.GITHUB_TOKEN).toMatch(/^obf:v1:/);
    expect(obfDecode(env.GITHUB_TOKEN)).toBe(TOKEN);
    expect(env.LOG_LEVEL).toBe('info');

    const auth = mcp?.parsed?.auth as Record<string, unknown>;
    expect(auth.present).toBe(true);
    expect(auth.type).toBe('key');
    expect(obfDecode(auth.value as string)).toBe(TOKEN);

    // The whole batch must not contain the plaintext token anywhere.
    expect(JSON.stringify(reported)).not.toContain(TOKEN);
  });

  it('collects standalone mcp.json servers (http transport, bearer auth)', async () => {
    writeJson(fixture.mcpPath, {
      mcpServers: {
        remote: {
          url: 'https://mcp.example.com/sse',
          headers: { Authorization: 'Bearer abc123' },
        },
      },
    });

    const c = track(createCollector(fixture, reported));
    await c.initialize();

    const mcp = reported.find((e) => e.asset_id === `test-host:mcp_server:${fixture.mcpPath}#remote`);
    expect(mcp).toBeDefined();
    expect(mcp?.parsed?.transport).toBe('http');
    expect(mcp?.parsed?.url).toBe('https://mcp.example.com/sse');
    const auth = mcp?.parsed?.auth as Record<string, unknown>;
    expect(auth.type).toBe('bearer');
    expect(obfDecode(auth.value as string)).toBe('Bearer abc123');
  });

  it('emits full snapshot events carrying prev_hash context', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    reported.length = 0;

    await c.snapshotNow();

    expect(reported).toHaveLength(3);
    for (const event of reported) {
      expect(event.event_type).toBe('asset_snapshot');
      expect(event.change_type).toBeUndefined();
      expect(event.prev_hash).toBe(event.content_hash);
    }
  });

  it('degrades files larger than maxFileSizeBytes to metadata-only assets', async () => {
    const bigPath = path.join(fixture.root, 'big.json');
    writeJson(bigPath, { data: 'x'.repeat(500) });

    const c = track(
      new AssetCollector(
        mockCollector(reported),
        {
          enabled: true,
          maxFileSizeBytes: 100,
          statePersistencePath: fixture.statePath,
        },
        { hostId: 'test-host' },
        { configPaths: [bigPath], skillDirs: [], mcpPaths: [] }
      )
    );
    await c.initialize();

    expect(reported).toHaveLength(1);
    expect(reported[0].parsed?.truncated).toBe(true);
    expect(reported[0].parsed?.keys).toBeUndefined();
    expect(reported[0].content_hash).toBeTruthy();
  });

  // 超限文件不 readFile 全量入内存。同尺寸改写内容并推进
  // mtime 强制重扫后仍无 asset_change —— 证明新内容从未被读入内存参与哈希。
  it('never reads over-cap file content (same-size rewrite emits no change)', async () => {
    const bigPath = path.join(fixture.root, 'big.json');
    writeJson(bigPath, { data: 'a'.repeat(500) });

    const c = track(
      new AssetCollector(
        mockCollector(reported),
        {
          enabled: true,
          maxFileSizeBytes: 100,
          statePersistencePath: fixture.statePath,
        },
        { hostId: 'test-host' },
        { configPaths: [bigPath], skillDirs: [], mcpPaths: [] }
      )
    );
    await c.initialize();
    expect(reported).toHaveLength(1);
    expect(reported[0].parsed?.truncated).toBe(true);

    writeJson(bigPath, { data: 'b'.repeat(500) });
    const future = new Date(Date.now() + 5000);
    fs.utimesSync(bigPath, future, future);
    reported.length = 0;
    await c.scanNow();

    expect(reported.filter((e) => e.asset_path === bigPath)).toHaveLength(0);
  });

  // 自定义 statePersistencePath 的父目录不存在时，锁获取
  // 不再每 tick ENOENT —— 首次扫描照常出基线，锁文件与状态文件都落盘。
  it('creates missing parent dirs for a custom statePersistencePath', async () => {
    const nestedStatePath = path.join(fixture.root, 'not-yet', 'created', 'asset-state.json');
    const c = track(
      new AssetCollector(
        mockCollector(reported),
        { enabled: true, statePersistencePath: nestedStatePath },
        { hostId: 'test-host' },
        { configPaths: [fixture.configPath], skillDirs: [], mcpPaths: [] }
      )
    );
    await c.initialize();

    // 基线照常上报即证明锁获取成功（initialize 的设计是首扫后释放锁交给
    // timer，因此此处不断言 .lock 文件存在）；状态文件也已落盘。
    expect(reported.length).toBeGreaterThan(0);
    expect(fs.existsSync(nestedStatePath)).toBe(true);
  });

  // 资产锁伪造抑制扫描。锁内放随机 nonce + 校验 holder pid 真实
  // 存在；伪造/异常持有发 tamper_detected，坏 JSON 按 stale 回收（保留告警），
  // 全部路径都不再静默关闭扫描。
  describe('lock hardening', () => {
    function lockFilePath(): string {
      return `${fixture.statePath}.lock`;
    }

    function writeLock(payload: unknown): void {
      fs.writeFileSync(lockFilePath(), typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8');
    }

    /** A pid that is guaranteed dead: spawn a child, let it exit, reuse its pid. */
    async function deadPid(): Promise<number> {
      const child = spawn(process.execPath, ['-e', 'process.exit(0)']);
      return new Promise((resolve) => {
        child.on('exit', () => resolve(child.pid!));
      });
    }

    it('reclaims a forged lock (dead pid + fresh timestamp) and emits x_openclaw_tamper_detected', async () => {
      writeLock({ pid: await deadPid(), acquiredAt: Date.now() });

      const c = track(createCollector(fixture, reported, { scanIntervalMs: 60000 }));
      await c.initialize();

      // 扫描未被抑制：基线照常上报。
      expect(reported.some((e) => e.event_type === 'asset_add')).toBe(true);
      // 伪造持有已被识别并留痕。
      const tamper = reported.find((e) => e.event_type === 'x_openclaw_tamper_detected');
      expect(tamper).toBeDefined();
      expect(tamper?.kind).toBe('forged_lock');
      expect(typeof tamper?.lock_pid).toBe('number');
    });

    it('treats a corrupted lock file as stale instead of silently disabling scans', async () => {
      writeLock('{{{ not-json');

      const c = track(createCollector(fixture, reported, { scanIntervalMs: 60000 }));
      await c.initialize();

      // 旧行为：JSON.parse 抛错 → return false → 扫描永久静默关闭。
      // 新行为：按 stale 回收，基线照常上报。
      expect(reported.some((e) => e.event_type === 'asset_add')).toBe(true);
    });

    it('stands down while a live foreign holder is refreshing, then reclaims after it dies', async () => {
      const holder = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)']);
      try {
        writeLock({ pid: holder.pid, acquiredAt: Date.now() });

        const c = track(createCollector(fixture, reported));
        await c.initialize();

        // 存活持有者 + 新鲜锁：本进程不扫描（initialize 的首扫即 stand down）。
        expect(reported.some((e) => e.event_type === 'asset_add')).toBe(false);

        // 持有者**真正退出后**（等 exit 事件 —— 事件驱动，不是 sleep）：
        // 一个 leader 周期内检出伪造签名（新鲜时间戳 + 死 pid），
        // 发 x_openclaw_tamper_detected 并回收锁，扫描恢复。
        // ⭐ 全程用 runLeaderCycle() 同步驱动（与 100ms 定时器同一码路径），
        //   不断言任何 wall-clock 时序 ⇒ 整机负载下不再抖动。
        await new Promise<void>((resolve) => {
          holder.once('exit', () => resolve());
          holder.kill('SIGKILL');
        });
        await c.runLeaderCycle();

        expect(reported.some((e) => e.event_type === 'asset_add')).toBe(true);
        expect(reported.some((e) => e.event_type === 'x_openclaw_tamper_detected' && e.kind === 'forged_lock')).toBe(true);
      } finally {
        holder.kill('SIGKILL');
      }
    });

    it('detects a lock replaced under a live holder (nonce mismatch) and re-asserts ownership', async () => {
      const c = track(createCollector(fixture, reported));
      await c.initialize();

      // ① 第一个 leader 周期：initialize 首扫后已释放锁 ⇒ 本周期重新创建锁。
      //   ⭐ 全程 runLeaderCycle() 同步驱动（与定时器同一码路径），
      //     scanIntervalMs 默认 60s ⇒ 定时器全程不参与 ⇒ 零 wall-clock 依赖。
      await c.runLeaderCycle();
      expect(fs.existsSync(lockFilePath())).toBe(true);

      // ② 同 UID 攻击者用我们的 pid 重写锁文件（nonce 不同）。
      writeLock({ pid: process.pid, acquiredAt: Date.now(), nonce: 'forged-nonce' });

      // ③ 第二个 leader 周期：检出 nonce 不匹配 ⇒ 留痕 lock_replaced，
      //   并把锁**顶回自己的 nonce**（writeFile 已在周期内 await 完成）。
      await c.runLeaderCycle();

      const tamper = reported.find(
        (e) => e.event_type === 'x_openclaw_tamper_detected' && e.kind === 'lock_replaced'
      );
      expect(tamper).toBeDefined();

      // 攻击者的锁被顶掉：nonce 恢复为持有者自己的值（③ 已同步落盘 ⇒ 直接读，无需轮询）。
      const data = JSON.parse(fs.readFileSync(lockFilePath(), 'utf8'));
      expect(typeof data.nonce).toBe('string');
      expect(data.nonce.length).toBeGreaterThan(0);
      expect(data.nonce).not.toBe('forged-nonce');
      expect(data.pid).toBe(process.pid);
      // 扫描一直在继续（未被抑制）。
      expect(reported.some((e) => e.event_type === 'asset_add')).toBe(true);
    });
  });

  it('emits nothing when disabled', async () => {
    const c = track(createCollector(fixture, reported, { enabled: false }));
    await c.initialize();
    await c.scanNow();
    expect(reported).toHaveLength(0);
  });

  it('emits content_hash + content_preview (no raw content) when collectContent is enabled', async () => {
    // 内容落盘收紧 —— 不再保留 obfuscated 原文，
    // 改存 sha256 + 前 256 字节脱敏预览。原文走 asset-blobs 内容寻址
    // 通道或干脆不存；parsed 走 lean 形态。
    const c = track(createCollector(fixture, reported, { collectContent: true }));
    await c.initialize();

    const cfgEvent = reported.find((e) => e.asset_type === 'agent_config');
    expect(cfgEvent?.parsed?.content).toBeUndefined();
    const hash = cfgEvent?.parsed?.content_hash as string;
    const preview = cfgEvent?.parsed?.content_preview as string;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(preview).toBeTruthy();
    expect(preview).not.toContain(TOKEN);
    expect(preview).toContain('obf:v1:');
  });

  it('summarizes config sections with obfuscation and depth caps', async () => {
    writeJson(fixture.configPath, {
      models: {
        main: { provider: 'openai', name: 'gpt-4o', apiKey: 'sk-live-secret-123' },
      },
      agents: [{ name: 'a1', model: 'main' }],
      deep: { l1: { l2: { l3: { l4: 'too-deep' } } } },
      big: { items: Array.from({ length: 30 }, (_, i) => i) },
    });

    const c = track(createCollector(fixture, reported));
    await c.initialize();

    const cfgEvent = reported.find((e) => e.asset_type === 'agent_config');
    const sections = cfgEvent?.parsed?.sections as Record<string, Record<string, unknown>>;
    expect(sections).toBeDefined();

    // Real values are visible for management...
    const main = (sections.models as Record<string, Record<string, unknown>>).main;
    expect(main.provider).toBe('openai');
    expect(main.name).toBe('gpt-4o');
    // ...but sensitive leaves are obfuscated and decodable by the consumer.
    expect(main.apiKey).toMatch(/^obf:v1:/);
    expect(obfDecode(main.apiKey as string)).toBe('sk-live-secret-123');
    expect(JSON.stringify(cfgEvent)).not.toContain('sk-live-secret-123');

    // Depth and array caps keep the payload bounded.
    const deep = sections.deep as Record<string, unknown>;
    expect(JSON.stringify(deep)).not.toContain('too-deep');
    expect((sections.big as Record<string, unknown>).items).toBe('[array:30]');
  });

  it('discovers skills in plugin-nested layouts (plugins/<pkg>/skills/<name>)', async () => {
    const pluginsRoot = path.join(fixture.root, 'plugins');
    const nested = path.join(pluginsRoot, 'feishu', 'skills', 'feishu-doc');
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(
      path.join(nested, 'SKILL.md'),
      '---\nname: feishu-doc\ndescription: 飞书文档读写操作\n---\n# feishu-doc\n',
      'utf8'
    );

    const c = track(
      new AssetCollector(
        mockCollector(reported),
        { enabled: true, statePersistencePath: fixture.statePath },
        { hostId: 'test-host' },
        { configPaths: [], skillDirs: [pluginsRoot], mcpPaths: [] }
      )
    );
    await c.initialize();

    expect(reported).toHaveLength(1);
    expect(reported[0].asset_type).toBe('skill');
    expect(reported[0].asset_id).toBe(`test-host:skill:${nested}`);
    expect(reported[0].parsed?.name).toBe('feishu-doc');
  });

  it('discovers per-agent configs recursively and extracts embedded mcpServers', async () => {
    const agentsRoot = path.join(fixture.root, 'agents');
    const agentDir = path.join(agentsRoot, 'mcp_audit', 'agent');
    fs.mkdirSync(agentDir, { recursive: true });
    writeJson(path.join(agentDir, 'agent.json'), { name: 'AI MCP Audit', model: 'main' });
    writeJson(path.join(agentDir, 'mcp.json'), {
      mcpServers: { db: { command: 'uvx', args: ['mcp-db'], env: { DB_PASSWORD: 'pw123' } } },
    });
    // Volatile dirs must be excluded.
    const sessionsDir = path.join(agentsRoot, 'mcp_audit', 'sessions');
    fs.mkdirSync(sessionsDir, { recursive: true });
    writeJson(path.join(sessionsDir, 'state.json'), { active: true });

    const c = track(
      new AssetCollector(
        mockCollector(reported),
        { enabled: true, statePersistencePath: fixture.statePath },
        { hostId: 'test-host' },
        { configPaths: [], skillDirs: [], mcpPaths: [], configRoots: [agentsRoot] }
      )
    );
    await c.initialize();

    expect(reported).toHaveLength(3);
    const ids = reported.map((e) => e.asset_id);
    expect(ids).toContain(`test-host:agent_config:${path.join(agentDir, 'agent.json')}`);
    expect(ids).toContain(`test-host:agent_config:${path.join(agentDir, 'mcp.json')}`);
    expect(ids).toContain(`test-host:mcp_server:${path.join(agentDir, 'mcp.json')}#db`);
    expect(ids.some((id) => id!.includes('sessions'))).toBe(false);

    const mcp = reported.find((e) => e.asset_type === 'mcp_server');
    const env = mcp?.parsed?.env as Record<string, string>;
    expect(obfDecode(env.DB_PASSWORD)).toBe('pw123');
    expect(JSON.stringify(reported)).not.toContain('pw123');
  });

  it('attaches a content-addressed ZIP package of the full skill directory when collectSkillPackage is on', async () => {
    const c = track(createCollector(fixture, reported, { collectSkillPackage: true }));
    await c.initialize();

    const skill = reported.find((e) => e.asset_type === 'skill');
    // 事件只带内容寻址 hash，包体（编码文本）按 hash 落在 asset-blobs/<hash>。
    const hash = skill?.asset_package_hash;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(skill?.asset_package).toBeUndefined();

    // Decode and walk the archive: both files must be inside, intact.
    const zip = Buffer.from(readBlob(fixture.root, hash!), 'base64');
    expect(zip.readUInt32LE(0)).toBe(0x04034b50);
    const entries = readZipEntries(zip);
    expect(entries.map((e) => e.name).sort()).toEqual(['SKILL.md', 'helper.txt']);
    const skillMd = entries.find((e) => e.name === 'SKILL.md');
    expect(skillMd?.data.toString('utf8')).toContain('name: alpha');
    expect(entries.find((e) => e.name === 'helper.txt')?.data.toString('utf8')).toBe('helper');

    // Manifest is present alongside the package; SKILL.md raw content is NOT
    // duplicated (it already lives inside the ZIP).
    const files = skill?.parsed?.files as Array<{ path: string; size: number; sha256: string }>;
    expect(files).toHaveLength(2);
    expect(files[0].sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(skill?.parsed?.content).toBeUndefined();
    expect(skill?.parsed?.name).toBe('alpha');
  });

  it('omits the package and marks package_omitted when it exceeds maxPackageBytes', async () => {
    const c = track(
      createCollector(fixture, reported, { collectSkillPackage: true, maxPackageBytes: 10 })
    );
    await c.initialize();

    const skill = reported.find((e) => e.asset_type === 'skill');
    expect(skill?.asset_package).toBeUndefined();
    expect(skill?.asset_package_hash).toBeUndefined();
    expect(skill?.parsed?.package_omitted).toBe('too_large');
    expect(skill?.parsed?.package_bytes).toBeGreaterThan(10);
    // Manifest still goes out so the consumer has per-file hashes.
    expect(skill?.parsed?.files).toHaveLength(2);
  });

  it('attaches no package by default', async () => {
    const c = track(createCollector(fixture, reported));
    await c.initialize();
    const skill = reported.find((e) => e.asset_type === 'skill');
    expect(skill?.asset_package).toBeUndefined();
    expect(skill?.asset_package_hash).toBeUndefined();
  });

  it('removed events carry no package', async () => {
    const c = track(createCollector(fixture, reported, { collectSkillPackage: true }));
    await c.initialize();
    reported.length = 0;

    fs.rmSync(path.join(fixture.skillsRoot, 'alpha'), { recursive: true, force: true });
    await c.scanNow();

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('asset_remove');
    expect(reported[0].asset_package).toBeUndefined();
    expect(reported[0].asset_package_hash).toBeUndefined();
  });

  it('excludes oversized single files from the skill package but keeps them in the manifest', async () => {
    const bigDir = path.join(fixture.skillsRoot, 'bigskill');
    fs.mkdirSync(bigDir, { recursive: true });
    fs.writeFileSync(path.join(bigDir, 'SKILL.md'), '---\nname: bigskill\n---\n');
    fs.writeFileSync(path.join(bigDir, 'big.bin'), Buffer.alloc(500, 7));

    const c = track(
      createCollector(fixture, reported, { collectSkillPackage: true, maxPackageEntryBytes: 100 })
    );
    await c.initialize();

    const skill = reported.find((e) => e.asset_path === bigDir);
    const hash = skill?.asset_package_hash;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(skill?.asset_package).toBeUndefined();
    expect(skill?.parsed?.package_omitted).toBeUndefined();
    expect(skill?.parsed?.package_excluded_files).toBe(1);

    const files = skill?.parsed?.files as Array<Record<string, unknown>>;
    const bigEntry = files.find((f) => f.path === 'big.bin');
    expect(bigEntry?.excluded).toBe('too_large');
    expect(bigEntry?.sha256).toMatch(/^[0-9a-f]{64}$/);

    const zip = Buffer.from(readBlob(fixture.root, hash!), 'base64');
    expect(readZipEntries(zip).map((e) => e.name)).toEqual(['SKILL.md']);
  });

  it('marks package_omitted as entries_too_large when every file exceeds the entry cap', async () => {
    const hugeDir = path.join(fixture.skillsRoot, 'hugeskill');
    fs.mkdirSync(hugeDir, { recursive: true });
    fs.writeFileSync(path.join(hugeDir, 'SKILL.md'), Buffer.alloc(500, 65));

    const c = track(
      createCollector(fixture, reported, { collectSkillPackage: true, maxPackageEntryBytes: 100 })
    );
    await c.initialize();

    const skill = reported.find((e) => e.asset_path === hugeDir);
    expect(skill?.asset_package).toBeUndefined();
    expect(skill?.asset_package_hash).toBeUndefined();
    expect(skill?.parsed?.package_omitted).toBe('entries_too_large');
  });

  it('attaches a single-file ZIP with the RAW config when collectConfigPackage is on', async () => {
    const c = track(createCollector(fixture, reported, { collectConfigPackage: true }));
    await c.initialize();

    const cfg = reported.find((e) => e.asset_type === 'agent_config');
    const pkgHash = cfg?.asset_package_hash;
    expect(pkgHash).toMatch(/^[0-9a-f]{64}$/);
    expect(cfg?.asset_package).toBeUndefined();

    const zip = Buffer.from(readBlob(fixture.root, pkgHash!), 'base64');
    const entries = readZipEntries(zip);
    expect(entries).toHaveLength(1);
    expect(entries[0].name).toBe('openclaw.json');
    // Package is intentionally raw for audit fidelity: the plaintext token is
    // inside the archive…
    expect(entries[0].data.toString('utf8')).toContain(TOKEN);
    // …while the event's structured fields keep it obfuscated.
    expect(JSON.stringify(cfg?.parsed)).not.toContain(TOKEN);
    const mcp = reported.find((e) => e.asset_type === 'mcp_server');
    expect(JSON.stringify(mcp?.parsed)).not.toContain(TOKEN);
  });

  it('does not repeat an unchanged config package when the content flips back', async () => {
    const c = track(createCollector(fixture, reported, { collectConfigPackage: true }));
    await c.initialize();

    const baseline = reported.find((e) => e.asset_type === 'agent_config');
    expect(baseline?.asset_package_hash).toMatch(/^[0-9a-f]{64}$/);

    // Flip the config to a second content, then flip it back to the original.
    // The second flip reproduces a package that was already shipped — carrying
    // the same content-addressed hash again is safe (no inline duplication),
    // and the blob already exists on disk.
    const original = fs.readFileSync(fixture.configPath, 'utf8');
    const cfg = JSON.parse(original);
    cfg.mcpServers.github.env.GITHUB_TOKEN = 'ghp_new_token_999';
    writeJson(fixture.configPath, cfg);
    await c.scanNow();

    writeJson(fixture.configPath, JSON.parse(original));
    await c.scanNow();

    const configChanges = reported.filter((e) => e.asset_type === 'agent_config');
    expect(configChanges.length).toBeGreaterThanOrEqual(3);
    // The last change restores the original content: same package → same hash,
    // referenced by content address instead of copying the payload.
    const last = configChanges[configChanges.length - 1];
    expect(last.event_type).toBe('asset_change');
    expect(last.asset_package).toBeUndefined();
    expect(last.asset_package_hash).toBe(baseline?.asset_package_hash);
    expect(last.content_hash).toBe(baseline?.content_hash);
  });

  it('omits the config package and marks package_omitted when it exceeds maxPackageBytes', async () => {    const c = track(
      createCollector(fixture, reported, { collectConfigPackage: true, maxPackageBytes: 10 })
    );
    await c.initialize();

    const cfg = reported.find((e) => e.asset_type === 'agent_config');
    expect(cfg?.asset_package).toBeUndefined();
    expect(cfg?.asset_package_hash).toBeUndefined();
    expect(cfg?.parsed?.package_omitted).toBe('too_large');
    expect(cfg?.parsed?.package_bytes).toBeGreaterThan(10);
    // Fallback: without the package, sections stay as the content visibility.
    expect(cfg?.parsed?.sections).toBeDefined();
  });

  it('reduces parsed to a lean description when the config package is attached', async () => {
    const c = track(
      createCollector(fixture, reported, { collectContent: true, collectConfigPackage: true })
    );
    await c.initialize();

    const cfg = reported.find((e) => e.asset_type === 'agent_config');
    expect(cfg?.asset_package_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(cfg?.asset_package).toBeUndefined();
    // Full content lives only in the blob; parsed keeps descriptive fields only.
    expect(cfg?.parsed?.content).toBeUndefined();
    expect(cfg?.parsed?.sections).toBeUndefined();
    expect(Object.keys(cfg?.parsed ?? {}).sort()).toEqual(
      ['file_name', 'format', 'keys', 'mcp_servers', 'plugins'].sort()
    );
  });

  it('re-baselines once when the payload-shape fingerprint changes', async () => {
    // First run with packaging OFF: baseline of 3, state persisted.
    const c1 = track(createCollector(fixture, reported));
    await c1.initialize();
    await c1.shutdown();
    expect(reported).toHaveLength(3);

    // Second run with packaging ON: fingerprint differs → full re-baseline,
    // and the skill event now carries its package hash.
    reported.length = 0;
    const c2 = track(createCollector(fixture, reported, { collectSkillPackage: true }));
    await c2.initialize();
    await c2.shutdown();
    expect(reported).toHaveLength(3);
    expect(reported.every((e) => e.event_type === 'asset_add')).toBe(true);
    expect(reported.find((e) => e.asset_type === 'skill')?.asset_package_hash).toMatch(/^[0-9a-f]{64}$/);

    // Third run with the SAME flags: fingerprint matches → silent again.
    reported.length = 0;
    const c3 = track(createCollector(fixture, reported, { collectSkillPackage: true }));
    await c3.initialize();
    expect(reported).toHaveLength(0);
  });

  it('blob 写盘失败时降级：事件省略 asset_package_hash，不抛异常', async () => {
    // blobDir 指向一个已存在的**文件**：mkdir 递归失败，写盘必然报错。
    const blocker = path.join(fixture.root, 'blob-blocker');
    fs.writeFileSync(blocker, 'occupied');

    const c = track(
      createCollector(fixture, reported, { collectSkillPackage: true }, { blobDir: blocker })
    );
    await expect(c.initialize()).resolves.toBeUndefined();

    const skill = reported.find((e) => e.asset_type === 'skill');
    expect(skill).toBeDefined();
    expect(skill?.asset_package).toBeUndefined();
    expect(skill?.asset_package_hash).toBeUndefined();
  });

  it('同一包内容在 asset-blobs/ 里只落一份（文件名即 hash）', async () => {
    const c = track(createCollector(fixture, reported, { collectConfigPackage: true }));
    await c.initialize();
    const baseline = reported.find((e) => e.asset_type === 'agent_config');

    // 内容翻转出去再翻回来：blob 文件仍然只有一份（同 hash 复用）。
    const original = fs.readFileSync(fixture.configPath, 'utf8');
    const cfg = JSON.parse(original);
    cfg.mcpServers.github.env.GITHUB_TOKEN = 'ghp_new_token_999';
    writeJson(fixture.configPath, cfg);
    await c.scanNow();
    writeJson(fixture.configPath, JSON.parse(original));
    await c.scanNow();

    // 翻转出去产生第二份不同内容的 blob；翻转回来同 hash 复用，不新增。
    const blobDir = path.join(fixture.root, 'asset-blobs');
    const blobs = fs.readdirSync(blobDir);
    expect(blobs).toHaveLength(2);
    expect(blobs).toContain(baseline?.asset_package_hash);
  });
});

/** Minimal ZIP local-header walker for package assertions. */
function readZipEntries(buf: Buffer): Array<{ name: string; data: Buffer }> {
  const out: Array<{ name: string; data: Buffer }> = [];
  let off = 0;
  while (off + 30 <= buf.length && buf.readUInt32LE(off) === 0x04034b50) {
    const method = buf.readUInt16LE(off + 8);
    const csize = buf.readUInt32LE(off + 18);
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8');
    const payloadStart = off + 30 + nameLen + extraLen;
    const payload = buf.subarray(payloadStart, payloadStart + csize);
    out.push({ name, data: method === 8 ? inflateRawSync(payload) : Buffer.from(payload) });
    off = payloadStart + csize;
  }
  return out;
}
