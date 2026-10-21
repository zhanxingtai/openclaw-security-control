import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { spawn } from 'child_process';

// OPENCLAW_NETWORK_HOOK_ENABLED=false 时 hook-mounter 不得加载
// network.js；缺省视为开。
const mounterPath = path.resolve(process.cwd(), 'hooks/hook-mounter.js');

function runMounter(envOverrides: Record<string, string | undefined>): Promise<{ stdout: string; stderr: string }> {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.OPENCLAW_NETWORK_HOOK_ENABLED;
  Object.assign(env, envOverrides);
  const script = `
    require('${mounterPath.replace(/\\/g, '\\\\')}');
    console.log('runtimeHooked=' + Boolean(globalThis.__openclaw_runtime_hook_installed));
    console.log('networkHooked=' + Boolean(globalThis.__openclaw_network_hook_installed));
  `;
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

describe('hook mounter networkEnabled gate', () => {
  it('loads runtime.js and network.js by default', async () => {
    const { stdout } = await runMounter({});
    expect(stdout).toContain('runtimeHooked=true');
    expect(stdout).toContain('networkHooked=true');
  });

  it('skips network.js when OPENCLAW_NETWORK_HOOK_ENABLED=false', async () => {
    const { stdout } = await runMounter({ OPENCLAW_NETWORK_HOOK_ENABLED: 'false' });
    expect(stdout).toContain('runtimeHooked=true');
    expect(stdout).toContain('networkHooked=false');
  });
});
