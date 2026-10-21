import { describe, it, expect } from 'vitest';
import os from 'os';
import path from 'path';
import { normalizeConfig } from './config.js';

describe('normalizeConfig', () => {
  it('should use default values for empty config', () => {
    const config = normalizeConfig({});

    expect(config.collector.ndjsonPath).toBe(
      path.join(os.homedir(), '.openclaw', 'security-events.jsonl')
    );
    expect(config.collector.maxFileSizeBytes).toBe(100 * 1024 * 1024);
    expect(config.collector.maxEventsInMemory).toBe(5000);

    expect(config.application?.enabled).toBe(true);
    expect(config.application?.captureUserPrompt).toBe(true);
    expect(config.application?.captureSystemPrompt).toBe(true);
    expect(config.application?.captureAgentPlan).toBe(true);
    expect(config.application?.captureCodeMode).toBe(true);
    expect(config.application?.captureUserId).toBe(true);
    expect(config.application?.captureReasoning).toBe(true);
    expect(config.application?.userIdField).toBe('userId');
    expect(config.application?.maxContentLength).toBe(2000);
    expect(config.application?.maxResultPreviewLength).toBe(500);
    expect(config.application?.maxRawParamsLength).toBe(10000);
    expect(config.application?.maxCodeContentLength).toBe(5000);

    expect(config.network?.enabled).toBe(false);
    // Opt-in: system 层需宿主装 psutil，默认 false；src/initialize.ts
    // 启动时探测宿主环境，psutil 缺失则保持 false 并打 warn。
    expect(config.system?.enabled).toBe(false);
    expect(config.system?.procfs?.enabled).toBe(false);
    expect(config.system?.procfs?.pythonPath).toBe('python3');
    expect(config.system?.procfs?.scanIntervalMs).toBe(5000);
    expect(config.system?.procfs?.snapshotIntervalMs).toBe(0);
    expect(config.system?.procfs?.processNames).toEqual(['openclaw', 'node', 'python', 'hermes']);
    expect(config.system?.procfs?.excludeCommandLines).toEqual(['process_monitor.py']);
    expect(config.system?.procfs?.collectOpenFiles).toBe(false);
    expect(config.system?.procfs?.collectConnections).toBe(false);
    expect(config.system?.procfs?.collectChildren).toBe(true);
    expect(config.system?.procfs?.collectCpuPercent).toBe(false);
    // Safe defaults: do not scan/kill processes outside the current tool-call tree,
    // and keep autoKill disabled with a minimal risk flag set by default.
    expect(config.system?.procfs?.burstScanGlobal).toBe(false);
    expect(config.system?.procfs?.autoKill).toBe(false);
    expect(config.system?.procfs?.riskFlags).toEqual(['reverse_shell', 'skill_binary_execution']);
    expect(config.system?.procfs?.killSignal).toBe('SIGTERM');

    expect(config.system?.cgroups?.enabled).toBe(false);
    expect(config.system?.cgroups?.scanIntervalMs).toBe(5000);
    expect(config.system?.cgroups?.burstScanIntervalMs).toBe(200);
    expect(config.system?.cgroups?.cpuChangeThresholdPercent).toBe(5);
    expect(config.system?.cgroups?.memoryChangeThresholdPercent).toBe(5);
    expect(config.system?.cgroups?.ioChangeThresholdBytes).toBe(1024 * 1024);
    expect(config.system?.cgroups?.anomalyCpuSpikeThresholdPercent).toBe(50);
    expect(config.system?.cgroups?.anomalyMemoryThresholdPercent).toBe(80);
    expect(config.system?.cgroups?.fullFieldsInBurstOnly).toBe(true);
    expect(config.system?.cgroups?.heartbeatEnabled).toBe(false);
    expect(config.system?.cgroups?.aggregateWindowSeconds).toBe(60);

    // Recommended baseline: intervention enabled in enforce mode (Day-1
    // out-of-the-box blocking). Users who want monitoring-only can flip back
    // to 'audit' from the Control UI's Configuration view.
    // Default fail_strategy is fail_closed (changed from fail_open in 1.0
    // hardening: a single flaky rule no longer disables protection).
    expect(config.intervention?.enabled).toBe(true);
    expect(config.intervention?.mode).toBe('enforce');
    expect(config.intervention?.failStrategy).toBe('fail_closed');

    // Recommended baseline: asset monitor on (baseline + skill/config package, NO content)
    expect(config.assetMonitor?.enabled).toBe(true);
    expect(config.assetMonitor?.collectContent).toBe(false);
    expect(config.assetMonitor?.collectSkillPackage).toBe(true);
    expect(config.assetMonitor?.collectConfigPackage).toBe(true);

    // Opt-in: runtimeHooks 默认 false，需宿主设置 NODE_OPTIONS；src/initialize.ts
    // 探测 NODE_OPTIONS 是否引用 bundled hook，未引用则保持 false 并打 warn。
    expect(config.application?.runtimeHooks?.enabled).toBe(false);
    expect(config.application?.runtimeHooks?.networkEnabled).toBe(true);
    expect(config.application?.runtimeHooks?.logPath).toBe(
      path.join(os.homedir(), '.openclaw', 'security-events-runtime.jsonl')
    );
    expect(config.application?.runtimeHooks?.blockedFlags).toEqual([
      'reverse_shell',
      'download_execute',
      'mass_deletion',
      'privilege_escalation',
      'token_in_command',
      // sensitive_file_access 移出 hook 本地阻断名单
      //（与引擎层 block-process-sensitive-file 降 warn 同步）。
      'skill_binary_execution',
    ]);
    expect(config.application?.runtimeHooks?.excludeCommandLines).toEqual([]);
    expect(config.application?.runtimeHooks?.excludeNetworkUrls).toEqual([]);
  });

  it('should override default values', () => {
    const config = normalizeConfig({
      collector: {
        ndjsonPath: '/tmp/custom-events.jsonl',
      },
      application: {
        enabled: false,
        captureUserPrompt: false,
        captureUserId: false,
        captureReasoning: false,
        maxRawParamsLength: 500,
        maxCodeContentLength: 1000,
      },
      network: {
        enabled: true,
      },
    });

    expect(config.collector.ndjsonPath).toBe('/tmp/custom-events.jsonl');

    expect(config.application?.enabled).toBe(false);
    expect(config.application?.captureUserPrompt).toBe(false);
    expect(config.application?.captureUserId).toBe(false);
    expect(config.application?.captureReasoning).toBe(false);
    expect(config.application?.captureSystemPrompt).toBe(true);
    expect(config.application?.maxRawParamsLength).toBe(500);
    expect(config.application?.maxCodeContentLength).toBe(1000);

    expect(config.network?.enabled).toBe(true);
  });

  it('should merge cgroups config', () => {
    const config = normalizeConfig({
      system: {
        enabled: true,
        cgroups: {
          enabled: true,
          scanIntervalMs: 10000,
          burstScanIntervalMs: 500,
          cpuChangeThresholdPercent: 10,
          anomalyCpuSpikeThresholdPercent: 75,
        },
      },
    });

    expect(config.system?.enabled).toBe(true);
    expect(config.system?.cgroups?.enabled).toBe(true);
    expect(config.system?.cgroups?.scanIntervalMs).toBe(10000);
    expect(config.system?.cgroups?.burstScanIntervalMs).toBe(500);
    expect(config.system?.cgroups?.cpuChangeThresholdPercent).toBe(10);
    expect(config.system?.cgroups?.anomalyCpuSpikeThresholdPercent).toBe(75);
    // Unspecified fields keep defaults
    expect(config.system?.cgroups?.memoryChangeThresholdPercent).toBe(5);
    expect(config.system?.cgroups?.fullFieldsInBurstOnly).toBe(true);
  });

  it('should override system procfs config', () => {
    const config = normalizeConfig({
      system: {
        enabled: true,
        procfs: {
          enabled: true,
          pythonPath: '/usr/bin/python3',
          scanIntervalMs: 1000,
          snapshotIntervalMs: 30000,
          processNames: ['custom-agent'],
          excludeCommandLines: ['my-exclude'],
          collectOpenFiles: true,
          collectConnections: true,
          collectChildren: false,
          collectCpuPercent: true,
        },
      },
    });

    expect(config.system?.enabled).toBe(true);
    expect(config.system?.procfs?.enabled).toBe(true);
    expect(config.system?.procfs?.pythonPath).toBe('/usr/bin/python3');
    expect(config.system?.procfs?.scanIntervalMs).toBe(1000);
    expect(config.system?.procfs?.snapshotIntervalMs).toBe(30000);
    expect(config.system?.procfs?.processNames).toEqual(['custom-agent']);
    expect(config.system?.procfs?.excludeCommandLines).toEqual(['my-exclude']);
    expect(config.system?.procfs?.collectOpenFiles).toBe(true);
    expect(config.system?.procfs?.collectConnections).toBe(true);
    expect(config.system?.procfs?.collectChildren).toBe(false);
    expect(config.system?.procfs?.collectCpuPercent).toBe(true);
  });

  it('should override runtime hooks config', () => {
    const config = normalizeConfig({
      application: {
        runtimeHooks: {
          enabled: true,
          networkEnabled: false,
          logPath: '/custom/events.jsonl',
          blockedFlags: ['pipe_to_shell'],
        },
      },
    });

    expect(config.application?.runtimeHooks?.enabled).toBe(true);
    expect(config.application?.runtimeHooks?.networkEnabled).toBe(false);
    expect(config.application?.runtimeHooks?.logPath).toBe('/custom/events.jsonl');
    expect(config.application?.runtimeHooks?.blockedFlags).toEqual(['pipe_to_shell']);
  });

  // 死参数已从 DEFAULT_CONFIG/合并 schema 删除；旧配置文件
  // 残留这些键必须静默忽略（pick 只遍历 schema 键），既不报错也不透传。
  it('silently drops removed dead-param keys from legacy config files', () => {
    const config = normalizeConfig({
      application: {
        sensitiveHeaders: ['authorization'],
        runtimeHooks: { nodePreload: '/x.js', networkPreload: '/y.js' },
      },
      system: {
        fileMonitor: { enabled: true, paths: ['/tmp'] },
        auditd: { enabled: true, rules: ['a'] },
        containerEvents: { enabled: true, runtime: 'docker' },
      },
      intervention: {
        blockTemplateId: 'legacy-template',
        contextAdjustOnEnforce: 'block',
        guidance: { guidanceWindowSteps: 9 },
      },
    } as Record<string, unknown>);

    expect(config.application?.runtimeHooks?.enabled).toBe(false);
    expect(config.intervention?.mode).toBe('enforce');
    expect((config.application as Record<string, unknown>).sensitiveHeaders).toBeUndefined();
    expect((config.application?.runtimeHooks as Record<string, unknown>).nodePreload).toBeUndefined();
    expect((config.system as Record<string, unknown>).fileMonitor).toBeUndefined();
    expect((config.intervention as Record<string, unknown>).blockTemplateId).toBeUndefined();
    expect((config.intervention?.guidance as Record<string, unknown>).guidanceWindowSteps).toBeUndefined();
  });

  it('should use environment config when provided', () => {
    const config = normalizeConfig({
      environment: {
        hostId: 'host-001',
        containerId: 'abc123',
        podName: 'pod-001',
        namespace: 'ns-001',
      },
    });

    expect(config.environment?.hostId).toBe('host-001');
    expect(config.environment?.containerId).toBe('abc123');
    expect(config.environment?.podName).toBe('pod-001');
    expect(config.environment?.namespace).toBe('ns-001');
  });

  it('should expand leading ~ in output paths', () => {
    const config = normalizeConfig({
      collector: {
        ndjsonPath: '~/.openclaw/security-events.jsonl',
      },
      application: {
        runtimeHooks: {
          logPath: '~/.openclaw/security-events-runtime.jsonl',
        },
      },
    });

    expect(config.collector.ndjsonPath).toBe(
      path.join(os.homedir(), '.openclaw', 'security-events.jsonl')
    );
    expect(config.application?.runtimeHooks?.logPath).toBe(
      path.join(os.homedir(), '.openclaw', 'security-events-runtime.jsonl')
    );
  });
});


describe('normalizeConfig numeric poisoning', () => {
  it('falls back to defaults for NaN / non-numeric numeric fields across layers', () => {
    const config = normalizeConfig({
      application: {
        maxContentLength: 'abc',
        maxResultPreviewLength: NaN,
        sessionTtlMs: 'not-a-number',
      },
      system: {
        enabled: true,
        procfs: {
          enabled: true,
          scanIntervalMs: 'abc',
          snapshotIntervalMs: NaN,
          memoryRssChangeThresholdBytes: '1x',
          riskThreshold: {},
        },
        cgroups: {
          enabled: true,
          scanIntervalMs: 'nope',
          cpuChangeThresholdPercent: NaN,
        },
      },
      assetMonitor: {
        scanIntervalMs: 'bad',
        fullSnapshotIntervalMs: NaN,
      },
      intervention: {
        reloadIntervalMs: 'bad',
        decisionTimeoutMs: NaN,
      },
    });

    expect(config.application?.maxContentLength).toBe(2000);
    expect(config.application?.maxResultPreviewLength).toBe(500);
    expect(config.application?.sessionTtlMs).toBe(30 * 60 * 1000);

    expect(config.system?.procfs?.scanIntervalMs).toBe(5000);
    expect(config.system?.procfs?.snapshotIntervalMs).toBe(0);
    expect(config.system?.procfs?.memoryRssChangeThresholdBytes).toBe(1024 * 1024);
    expect(config.system?.procfs?.riskThreshold).toBe(1.0);
    expect(config.system?.cgroups?.scanIntervalMs).toBe(5000);
    expect(config.system?.cgroups?.cpuChangeThresholdPercent).toBe(5);

    expect(config.assetMonitor?.scanIntervalMs).toBe(300000);
    expect(config.assetMonitor?.fullSnapshotIntervalMs).toBe(86400000);
    expect(config.intervention?.reloadIntervalMs).toBe(30000);
    expect(config.intervention?.decisionTimeoutMs).toBe(50);
  });

  it('still accepts valid numeric strings and finite numbers', () => {
    const config = normalizeConfig({
      system: {
        procfs: {
          scanIntervalMs: '2500',
          burstScanIntervalMs: 50,
        },
      },
    });
    expect(config.system?.procfs?.scanIntervalMs).toBe(2500);
    expect(config.system?.procfs?.burstScanIntervalMs).toBe(50);
  });
});
