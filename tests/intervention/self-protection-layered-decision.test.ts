/**
 * 分层决策顺序回归：SelfProtection（硬编码）→ SPL 引擎。
 *
 * 为什么单独一个文件：SelfProtection.test.ts 只测硬编码层，
 * policy-testcases.test.ts 只测引擎层。**两层按什么顺序合起来决定最终决策，
 * 此前无任何测试覆盖**——store.beforeToolCall 的顺序是
 *   第 0 步 SelfProtection.evaluate(ctx)  →  命中即定案
 *   第 1 步 仅在第 0 步放行时才 engine.evaluate(ctx)
 * 单层测试全绿不能推出组合路径正确：一条规则可能在被硬编码层遮蔽时
 * 行为异常，或硬编码层判负而引擎有机会"救回"，组合语义无人断言。
 *
 * 本文件复刻 store.beforeToolCall 的顺序（store.ts 中 SelfProtection.evaluate
 * 与 interventionEngine.evaluate 的调用点）。store 顺序若变更，本文件需同步。
 *
 * 用 shipped 策略 + mode=audit + guidance:false：
 * - shipped 策略：测的是真发出去的规则，不是 fixture；
 * - guidance:false：逐用例独立求值，避免 Guidance 预算跨用例串扰。
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { InterventionEngineImpl } from '../../src/intervention/InterventionEngine.js';
import * as SelfProtection from '../../src/intervention/SelfProtection.js';
import type { InterventionContext } from '../../src/intervention/types.js';

const POLICY_PATH = resolve('policies/security-policy.spl.yaml');

/** 复刻 store.beforeToolCall 的层序，返回最终决策与定案层。 */
type Verdict = { decision: string; layer: string };

describe('SelfProtection → SPL 引擎 分层决策', () => {
  let engine: InterventionEngineImpl;
  let policyDir: string;

  beforeAll(async () => {
    // RuleLoader 沙箱只允许 ~/.openclaw 与 os.tmpdir()：把 shipped 策略复制到
    // 临时目录，保证评估的就是文件本身。
    policyDir = mkdtempSync(join(tmpdir(), 'layered-decision-'));
    writeFileSync(join(policyDir, 'policy.yaml'), readFileSync(POLICY_PATH, 'utf8'));
    engine = new InterventionEngineImpl({
      mode: 'audit',
      ruleLoader: { policyPath: join(policyDir, 'policy.yaml'), reloadIntervalMs: 0 },
      guidance: { enabled: false },
    });
    await engine.initialize();
  }, 30_000);

  afterAll(async () => {
    await engine?.shutdown();
    rmSync(policyDir, { recursive: true, force: true });
  });

  function decide(ctx: InterventionContext): Verdict {
    const sp = SelfProtection.evaluate(ctx);
    if (sp.blocked && sp.decision) {
      return { decision: sp.decision.decision, layer: 'SelfProtection' };
    }
    const d = engine.evaluateSync(ctx);
    const ids = (d.matchedPolicies ?? []).map((p) => p.policyId);
    return { decision: d.decision, layer: ids.join(',') || '-（无命中规则）' };
  }

  function toolCtx(toolName: string, params: Record<string, unknown>, tag: string): InterventionContext {
    return {
      actionType: 'agent_tool_call',
      toolName,
      params,
      sessionId: `layered:${tag}`,
    } as unknown as InterventionContext;
  }

  describe('gateway 族工具：自伤必拦', () => {
    // 逐条列出 layer，是刻意为之——哪一层兜住哪一条是治理信息：
    // 硬编码层漏判的形态必须由 SPL 规则接住，反之亦然，两层都不能是唯一防线
    // 之外的空档。
    const CASES: Array<{ name: string; tool: string; params: Record<string, unknown>; layer?: string }> = [
      {
        name: 'config.patch 改 plugins.allow（带 value 摘插件）',
        tool: 'gateway',
        params: { action: 'config.patch', path: 'plugins.allow', value: '["other-plugin"]' },
        layer: 'SelfProtection',
      },
      {
        name: 'config.set 关掉插件 enabled',
        tool: 'gateway',
        params: { action: 'config.set', path: 'plugins.entries.openclaw-security_monitor.enabled', value: 'false' },
        layer: 'SelfProtection',
      },
      {
        name: 'config.unset 摘掉整个插件条目',
        tool: 'gateway',
        params: { action: 'config.unset', path: 'plugin.entries.openclaw-security_monitor' },
        layer: 'SelfProtection',
      },
      {
        name: '载荷藏在 raw 里（path 无害）',
        tool: 'gateway',
        params: { action: 'config.set', path: 'x', raw: 'openclaw-security-monitor.enabled: false' },
        layer: 'SelfProtection',
      },
      {
        name: '整体重写 openclaw.json',
        tool: 'gateway',
        params: { action: 'config.write', path: 'openclaw.json', value: '{"plugins":{}}' },
        layer: 'SelfProtection',
      },
      {
        // 以下两条硬编码层判不出意图：isGatewayDisablingPlugin 的目标名只从
        // plugin/extension/pluginId/extensionId/id/target 取，目标写在 value
        // 字段时取不到。SPL 规则 self-protection-block-gateway-action 是唯一
        // 防线——删掉 plugins?/extensions? 分支即产生绕过。
        name: 'plugin.uninstall 目标写在 value（硬编码层盲区，靠 SPL 规则）',
        tool: 'gateway',
        params: { action: 'plugin.uninstall', value: 'openclaw-security_monitor' },
        layer: 'self-protection-block-gateway-action',
      },
      {
        name: 'plugin.disable 目标写在 value（硬编码层盲区，靠 SPL 规则）',
        tool: 'plugin_manager',
        params: { action: 'plugin.disable', value: 'openclaw-security_monitor' },
        layer: 'self-protection-block-gateway-action',
      },
      {
        name: 'extension.uninstall',
        tool: 'extension_manager',
        params: { action: 'extension.uninstall', value: 'openclaw-security_monitor' },
        layer: 'self-protection-block-gateway-action',
      },
      {
        // 无 value 的准入路径写入：载荷不在 params 里，intent 判别无从下手，
        // 由 self-protection-block-gateway-config-write 的 path 锚点接住。
        name: 'config.patch 改 plugins.allow（无 value，准入路径本身不可放行）',
        tool: 'gateway',
        params: { action: 'config.patch', path: 'plugins.allow' },
        layer: 'self-protection-block-gateway-config-write',
      },
    ];

    for (const c of CASES) {
      it(`拦下：${c.name}`, () => {
        const v = decide(toolCtx(c.tool, c.params, `mal:${c.name}`));
        expect(v.decision, `期望非放行，实际 ${v.decision}（layer=${v.layer}）`).not.toBe('allow');
        if (c.layer) {
          expect(v.layer, '定案层与治理记录不符——两层职责可能已漂移').toBe(c.layer);
        }
      });
    }
  });

  describe('gateway 族工具：良性运维必放行', () => {
    // 这组是防回归的核心：gateway config 写轴曾经只看 action 不看目标，
    // 导致下列操作全部被 critical + appealable:false 硬拦。
    const CASES: Array<{ name: string; tool: string; params: Record<string, unknown> }> = [
      { name: 'config.set 改日志级别', tool: 'gateway', params: { action: 'config.set', path: 'logging.level', value: 'debug' } },
      { name: 'config.patch 改服务超时', tool: 'gateway', params: { action: 'config.patch', path: 'server.timeoutMs', value: '30000' } },
      { name: 'config.unset 删无关实验开关', tool: 'gateway', params: { action: 'config.unset', path: 'experimental.flag' } },
      { name: 'config.set 改日志级别（config_manager 工具）', tool: 'config_manager', params: { action: 'config.set', path: 'logging.level', value: 'debug' } },
      { name: '只读 plugin.list', tool: 'gateway', params: { action: 'plugin.list' } },
      { name: '只读 config.get', tool: 'gateway', params: { action: 'config.get', path: 'plugins.entries' } },
      { name: '良性重启', tool: 'gateway', params: { action: 'restart', note: 'apply model configuration changes' } },
    ];

    for (const c of CASES) {
      it(`放行：${c.name}`, () => {
        const v = decide(toolCtx(c.tool, c.params, `ben:${c.name}`));
        expect(v.decision, `期望放行，实际 ${v.decision}（layer=${v.layer}）`).toBe('allow');
      });
    }
  });
});