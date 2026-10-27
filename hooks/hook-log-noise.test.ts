/**
 * hook 预加载的启动/关闭诊断输出必须默认静默。
 *
 * 背景：mounter 与 network hook 靠 NODE_OPTIONS 被注入宿主里的**每一个**
 * node 进程，于是每一行诊断输出都会在容器里重复若干遍——安装与 CLI 输出
 * 里最显眼的一类噪音（"hooks mounter: loaded=2 …" 连着打四遍）。
 *
 * 契约：
 * - 默认静默：一切正常时不出声。
 * - 出问题必须出声：hook 文件缺失 / 加载失败 / 噪声过滤器被环境变量清空。
 * - 需要完整取证时用 OPENCLAW_HOOK_DEBUG=1（或单 hook 的开关）打开。
 * - 任何情况下都不写 stdout（见 hook-syntax.test.ts）。
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';

const mounterPath = path.resolve(process.cwd(), 'hooks/hook-mounter.js');
const networkHookPath = path.resolve(process.cwd(), 'hooks/network.js');

interface RunResult {
  stdout: string;
  stderr: string;
}

function runNode(script: string, envOverrides: Record<string, string | undefined>): Promise<RunResult> {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.OPENCLAW_HOOK_DEBUG;
  delete env.OPENCLAW_HOOK_MOUNT_DEBUG;
  delete env.OPENCLAW_NETWORK_HOOK_DEBUG;
  delete env.OPENCLAW_RUNTIME_HOOK_DEBUG;
  delete env.OPENCLAW_NETWORK_HOOK_IGNORE_HOSTS;
  delete env.OPENCLAW_NETWORK_HOOK_IGNORE_URLS;
  Object.assign(env, envOverrides);

  return new Promise((resolve, reject) => {
    const cp = spawn(process.execPath, ['-e', script], { env, cwd: process.cwd() });
    let stdout = '';
    let stderr = '';
    cp.stdout.on('data', (d) => (stdout += d.toString()));
    cp.stderr.on('data', (d) => (stderr += d.toString()));
    cp.on('error', reject);
    cp.on('close', () => resolve({ stdout, stderr }));
  });
}

function requireScript(file: string): string {
  return `require('${file.replace(/\\/g, '\\\\')}')`;
}

describe('hook mounter 启动输出', () => {
  it('全部正常加载时默认静默', async () => {
    const { stderr } = await runNode(requireScript(mounterPath), {});
    expect(stderr).not.toContain('hooks mounter:');
  });

  it('OPENCLAW_HOOK_MOUNT_DEBUG=1 时打印统计行', async () => {
    const { stderr } = await runNode(requireScript(mounterPath), {
      OPENCLAW_HOOK_MOUNT_DEBUG: '1',
    });
    expect(stderr).toContain('hooks mounter: loaded=2 skipped=0 failed=0');
  });

  it('总开关 OPENCLAW_HOOK_DEBUG=1 同样打开统计行', async () => {
    const { stderr } = await runNode(requireScript(mounterPath), { OPENCLAW_HOOK_DEBUG: '1' });
    expect(stderr).toContain('hooks mounter: loaded=2 skipped=0 failed=0');
  });

  it('hook 文件缺失时必须出声（问题不能被静默掉）', async () => {
    // 把 mounter 单独拷进临时目录：同目录的 runtime.js / network.js 都不存在
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hook-mounter-missing-'));
    const isolated = path.join(tmpDir, 'hook-mounter.js');
    fs.copyFileSync(mounterPath, isolated);

    try {
      const { stderr } = await runNode(requireScript(isolated), {});
      expect(stderr).toContain('hook file missing');
      expect(stderr).toContain('hooks mounter:');
      expect(stderr).toContain('skipped=2');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('network hook 启动/关闭输出', () => {
  it('默认静默：既不打 startup 也不打 shutdown drops', async () => {
    const { stderr } = await runNode(requireScript(networkHookPath), {});
    expect(stderr).not.toContain('[network-hook] startup:');
    expect(stderr).not.toContain('[network-hook] shutdown drops:');
  });

  it('OPENCLAW_HOOK_DEBUG=1 时打印 startup 与 shutdown drops', async () => {
    const { stderr } = await runNode(requireScript(networkHookPath), { OPENCLAW_HOOK_DEBUG: '1' });
    expect(stderr).toContain('[network-hook] startup:');
    expect(stderr).toContain('[network-hook] shutdown drops:');
  });

  it('噪声过滤器被环境变量清空时必须出声（默认配置被覆盖 = 过滤失效）', async () => {
    const { stderr } = await runNode(requireScript(networkHookPath), {
      OPENCLAW_NETWORK_HOOK_IGNORE_HOSTS: '',
    });
    expect(stderr).toContain('[network-hook] startup:');
    expect(stderr).toContain('IGNORE_HOSTS(n=0)');
  });

  it('IGNORE_URLS 被清空时同样出声', async () => {
    const { stderr } = await runNode(requireScript(networkHookPath), {
      OPENCLAW_NETWORK_HOOK_IGNORE_URLS: '',
    });
    expect(stderr).toContain('[network-hook] startup:');
    expect(stderr).toContain('IGNORE_URLS(n=0)');
  });
});
