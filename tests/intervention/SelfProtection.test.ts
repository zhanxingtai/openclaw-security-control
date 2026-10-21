import { describe, it, expect } from 'vitest';
import * as SelfProtection from '../../src/intervention/SelfProtection.js';
import type { InterventionContext } from '../../src/intervention/types.js';

describe('SelfProtection', () => {
  function toolCtx(toolName: string, params: Record<string, unknown>): InterventionContext {
    return {
      actionType: 'tool_call',
      toolName,
      params,
      sessionId: 'sess-self',
      runId: 'run-001',
      agentId: 'agent-001',
    };
  }

  function msgCtx(content: string): InterventionContext {
    return {
      actionType: 'message_write',
      toolName: 'user_message',
      body: content,
      userPrompt: content,
      sessionId: 'sess-self',
      runId: 'run-001',
    };
  }

  describe('tool_call self-harm detection', () => {
    it('blocks setup-openclaw --uninstall command', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'node scripts/setup-openclaw.mjs --uninstall' })
      );
      expect(result.blocked).toBe(true);
      expect(result.decision?.decision).toBe('block');
      expect(result.decision?.blockCode).toBe('SELF_PROTECTION_001');
    });

    it('blocks setup-openclaw --cleanup command', () => {
      const result = SelfProtection.evaluate(
        toolCtx('bash', { command: 'node scripts/setup-openclaw.mjs --cleanup' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks npm uninstall openclaw-security-monitor', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'npm uninstall @zhanxing/openclaw-security-monitor' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks npm uninstall of the real package name sst-security-control-openclaw', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'npm uninstall @zhanxing/sst-security-control-openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks npm uninstall of unscoped sst-security-control-openclaw', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'npm uninstall sst-security-control-openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks openclaw plugin uninstall command', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'openclaw plugin uninstall openclaw-security-monitor' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks openclaw uninstall of the real package name sst-security-control-openclaw', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'openclaw plugins uninstall sst-security-control-openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks mv of real install directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'mv ~/.openclaw/extensions/sst-security-control-openclaw /tmp/backup' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks chmod of real install directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'chmod 000 ~/.openclaw/extensions/sst-security-control-openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks rm -r (no -f) of real install directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'rm -r ~/.openclaw/extensions/sst-security-control-openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('does not block npm uninstall of an unrelated package', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'npm uninstall lodash' })
      );
      expect(result.blocked).toBe(false);
    });

    it('does not block mv of an unrelated directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'mv /tmp/my-project-notes /tmp/backup' })
      );
      expect(result.blocked).toBe(false);
    });

    it('blocks deletion of .openclaw directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'rm -rf ~/.openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('does not block generic rm -rf node_modules cleanup', () => {
      const result = SelfProtection.evaluate(
        toolCtx('bash', { command: 'rm -rf node_modules' })
      );
      expect(result.blocked).toBe(false);
    });

    it('does not block benign ls command', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'ls -la /tmp' })
      );
      expect(result.blocked).toBe(false);
    });

    it('blocks file write to openclaw.json', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', { path: '~/.openclaw/openclaw.json', content: '{"plugins":{}}' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks file delete of plugin policy file', () => {
      const result = SelfProtection.evaluate(
        toolCtx('delete', { path: '~/.openclaw/security-policy.yaml' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks file delete of plugin extension directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('delete', { path: '~/.openclaw/extensions/openclaw-security-monitor' })
      );
      expect(result.blocked).toBe(true);
    });

    it('allows reading the security policy file', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_read', { path: '~/.openclaw/security-policy.yaml' })
      );
      expect(result.blocked).toBe(false);
    });

    it('allows reading events file for inspection', () => {
      const result = SelfProtection.evaluate(
        toolCtx('read', { path: '~/.openclaw/security-events.jsonl' })
      );
      expect(result.blocked).toBe(false);
    });

    it('blocks gateway config.patch that disables the plugin', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'config.patch',
          path: 'plugins',
          note: '重新卸载 openclaw-security-monitor 插件（从 allow 列表移除，设为 disabled）',
          raw: JSON.stringify({
            plugins: {
              allow: ['feishu', 'acpx'],
              entries: {
                'openclaw-security-monitor': { enabled: false },
              },
            },
          }),
        })
      );
      expect(result.blocked).toBe(true);
      expect(result.decision?.blockCode).toBe('SELF_PROTECTION_001');
    });

    it('blocks gateway config.set that removes the plugin from allow list', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'config.set',
          path: 'plugins.allow',
          raw: JSON.stringify(['feishu', 'acpx']),
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks gateway config.set on plugins.entries.<plugin>.enabled', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'config.set',
          path: 'plugins.entries.openclaw-security-monitor.enabled',
          value: false,
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks full openclaw.json rewrite via gateway that excludes plugin', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'config.write',
          path: '/root/.openclaw/openclaw.json',
          raw: JSON.stringify({
            plugins: {
              allow: ['feishu'],
              entries: {},
            },
          }),
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks plugin_manager disable action on the plugin', () => {
      const result = SelfProtection.evaluate(
        toolCtx('plugin_manager', {
          action: 'plugin.disable',
          plugin: 'openclaw-security-monitor',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks config_manager setting plugin entry to null', () => {
      const result = SelfProtection.evaluate(
        toolCtx('config_manager', {
          action: 'config.set',
          path: 'plugins.entries.openclaw-security-monitor',
          value: null,
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('allows gateway config.get of plugins', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'config.get',
          path: 'plugins',
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('allows gateway config.set that keeps plugin in allow list', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'config.set',
          path: 'plugins.allow',
          raw: JSON.stringify(['openclaw-security-monitor', 'feishu']),
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('blocks openclaw plugins uninstall command (plural)', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', {
          command: 'timeout 60 openclaw plugins uninstall --force openclaw-security-monitor 2>&1 | tail -60',
        })
      );
      expect(result.blocked).toBe(true);
      expect(result.decision?.blockCode).toBe('SELF_PROTECTION_001');
    });

    it('blocks openclaw plugins remove command (plural)', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', {
          command: 'openclaw plugins remove openclaw-security-monitor',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks openclaw extension uninstall command', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', {
          command: 'openclaw extensions uninstall openclaw-security-monitor',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks gateway restart with uninstall intent', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'restart',
          delayMs: 2000,
          note: 'security-monitor uninstalled; restarting gateway to drop in-memory hooks reference',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('allows benign gateway restart', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'restart',
          note: 'apply model configuration changes',
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('blocks gateway uninstall action targeting the plugin', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'uninstall',
          plugin: 'openclaw-security-monitor',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks gateway disable action targeting the plugin', () => {
      const result = SelfProtection.evaluate(
        toolCtx('gateway', {
          action: 'disable',
          plugin: 'openclaw-security-monitor',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks dedicated plugin_uninstall tool targeting the plugin', () => {
      const result = SelfProtection.evaluate(
        toolCtx('plugin_uninstall', {
          plugin: 'openclaw-security-monitor',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('does not block normal workspace file writes', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', { path: '/workspace/project/src/main.js', content: 'console.log(1)' })
      );
      expect(result.blocked).toBe(false);
    });

    it('does not block file writes inside the development checkout directory', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: 'E:/code/my-project/src/config.ts',
          content: 'export const x = 1;',
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('does not block normal user project src/intervention files', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/user/project/src/intervention/helper.ts',
          content: 'export const helper = () => {};',
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('does not block generic node_modules cleanup', () => {
      const result = SelfProtection.evaluate(
        toolCtx('bash', { command: 'rm -rf node_modules' })
      );
      expect(result.blocked).toBe(false);
    });
  });

  describe('message_write self-harm detection', () => {
    it('blocks Chinese uninstall request', () => {
      const result = SelfProtection.evaluateMessageWrite(
        msgCtx('请卸载openclaw-security-monitor插件')
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks Chinese disable request', () => {
      const result = SelfProtection.evaluateMessageWrite(
        msgCtx('禁用安全监控插件')
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks English uninstall request', () => {
      const result = SelfProtection.evaluateMessageWrite(
        msgCtx('Please uninstall the openclaw-security-monitor plugin.')
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks English disable request', () => {
      const result = SelfProtection.evaluateMessageWrite(
        msgCtx('disable the security monitor plugin')
      );
      expect(result.blocked).toBe(true);
    });

    it('allows normal user requests', () => {
      const result = SelfProtection.evaluateMessageWrite(
        msgCtx('分析今天的销售数据')
      );
      expect(result.blocked).toBe(false);
    });
  });

  describe('generic evaluate', () => {
    it('blocks tool_call self-harm via evaluate', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'npm uninstall openclaw-security-monitor' })
      );
      expect(result.blocked).toBe(true);
    });

    it('blocks message_write self-harm via evaluate', () => {
      const result = SelfProtection.evaluate(
        msgCtx('卸载openclaw-security-monitor')
      );
      expect(result.blocked).toBe(true);
    });
  });

  describe('hostile params shapes ', () => {
    it('does not throw RangeError on circularly-referencing params', () => {
      const params: Record<string, unknown> = { command: 'ls /tmp' };
      params.self = params;
      const result = SelfProtection.evaluate(toolCtx('exec', params));
      expect(result.blocked).toBe(false);
    });

    it('does not throw on mutually-referencing params and still matches reachable strings', () => {
      const a: Record<string, unknown> = {};
      const b: Record<string, unknown> = { ref: a };
      a.ref = b;
      const harmParams: Record<string, unknown> = { command: 'npm uninstall sst-security-control-openclaw', note: a };
      const result = SelfProtection.evaluate(toolCtx('exec', harmParams));
      expect(result.blocked).toBe(true);
    });

    it('does not throw on deeply-nested params beyond the depth budget', () => {
      let params: unknown = 'leaf';
      for (let i = 0; i < 200; i++) {
        params = { nested: params };
      }
      const result = SelfProtection.evaluate(toolCtx('exec', { deep: params }));
      expect(result.blocked).toBe(false);
    });
  });
});
