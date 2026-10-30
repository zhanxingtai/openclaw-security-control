/**
 * SelfProtection 按**操作目标**判定，不按全部参数文本判定：正文里引用受保护
 * 路径不构成破坏。锁定：① 写入目标不是插件资产 ⇒ 放行；② 写入目标就是插件资产
 * ⇒ 仍然阻断（阻断文案带命中路径）；③ 认不出目标路径参数 ⇒ 保守阻断。
 */
import { describe, it, expect } from 'vitest';
import * as SelfProtection from '../../src/intervention/SelfProtection.js';
import type { InterventionContext } from '../../src/intervention/types.js';

function toolCtx(toolName: string, params: Record<string, unknown>): InterventionContext {
  return {
    actionType: 'tool_call',
    toolName,
    params,
    sessionId: 'sess-469b',
    runId: 'run-001',
    agentId: 'agent-001',
  };
}

describe('SelfProtection 按目标路径判定', () => {
  describe('正文引用插件路径但写入目标无关 ⇒ 放行', () => {
    it('35e545fc：写 memory 笔记，正文提到 openclaw.json ⇒ 放行', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/workspace/memory/2026-10-29.md',
          content:
            '# 排查笔记\n/home/node/.openclaw/openclaw.json — 网关认证令牌(明文, 12 字符)…\n',
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('25800c20：写临时审计脚本，正文提到 state/openclaw.sqlite ⇒ 放行', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/tmp/cred-audit/inspect-live.mjs',
          content: "const live = '/home/node/.openclaw/state/openclaw.sqlite';\n",
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('d5906f14：写日志分析脚本，正文提到 security-events-runtime.jsonl ⇒ 放行', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/tmp/evlog.mjs',
          content: "const p = home + '/.openclaw/' + name;\n",
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('同型：正文提到 ~/.openclaw/cron/ ⇒ 放行', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/workspace/memory/notes.md',
          content: '定时任务在 ~/.openclaw/cron/ 下，先去读一下。\n',
        })
      );
      expect(result.blocked).toBe(false);
    });

    it('同型：正文提到 gateway.auth.token ⇒ 放行', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/workspace/memory/token.md',
          content: 'gateway.auth.token 的取值来源待查。\n',
        })
      );
      expect(result.blocked).toBe(false);
    });
  });

  describe('真阳性：写入目标就是插件资产 ⇒ 仍然阻断', () => {
    it('写网关主配置 openclaw.json ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/openclaw.json',
          content: '{"plugins":{}}',
        })
      );
      expect(result.blocked).toBe(true);
      expect(result.decision?.decision).toBe('block');
      expect(result.decision?.blockCode).toBe('SELF_PROTECTION_001');
    });

    it('写审计日志 security-events.jsonl ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/security-events.jsonl',
          content: '{}\n',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('写插件扩展目录 ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/extensions/sst-security-control-openclaw/index.js',
          content: '// tampered\n',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('写插件自有源码 src/intervention/** ⇒ 阻断（#469-B 补齐的 yaml 条目）', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/opt/sst-security-control-openclaw/src/intervention/RuleMatcher.ts',
          content: '// tampered\n',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('写插件自有构建产物 dist/index.ts ⇒ 阻断（#469-B 补齐的 yaml 条目）', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/opt/sst-security-control-openclaw/dist/index.ts',
          content: '// tampered\n',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('阻断文案带出实际命中的路径（理由与命中内容对齐）', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          path: '/home/node/.openclaw/openclaw.json',
          content: '{}',
        })
      );
      expect(result.blocked).toBe(true);
      expect(result.decision?.blockReason).toContain('openclaw.json');
      expect(result.decision?.blockReason).toContain('命中');
    });
  });

  describe('别名表：目标路径换个参数名照样认得出', () => {
    it('file_path 别名指向插件资产 ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          file_path: '/home/node/.openclaw/security-policy.yaml',
          content: 'rules: []',
        })
      );
      expect(result.blocked).toBe(true);
    });

    it('target 别名指向插件资产 ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('write', {
          target: '/home/node/.openclaw/security-events.jsonl',
          content: '{}',
        })
      );
      expect(result.blocked).toBe(true);
    });
  });

  describe('保守回退：认不出目标路径参数 ⇒ 仍然阻断（不放行）', () => {
    it('未识别的参数名 + 正文含受保护路径 ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('file_write', {
          some_unrecognized_path_key: '/home/node/.openclaw/openclaw.json',
          body: 'x',
        })
      );
      expect(result.blocked).toBe(true);
    });
  });

  describe('命令型工具口径不变：整条命令仍按受保护路径判定', () => {
    it('exec 覆盖写插件审计日志 ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'echo "{}" > /home/node/.openclaw/security-events.jsonl' })
      );
      expect(result.blocked).toBe(true);
    });

    it('exec 自毁命令 ⇒ 阻断', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'rm -rf ~/.openclaw' })
      );
      expect(result.blocked).toBe(true);
    });

    it('exec 纯读取插件审计日志 ⇒ 放行（只读不是篡改）', () => {
      const result = SelfProtection.evaluate(
        toolCtx('exec', { command: 'cat /home/node/.openclaw/security-events.jsonl | tail -5' })
      );
      expect(result.blocked).toBe(false);
    });
  });
});
