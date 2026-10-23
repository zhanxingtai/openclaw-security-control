/**
 * 误报锚点：shipped 策略对**真实开发/运维操作**的判定基线。
 *
 * 存在理由：策略里的 testCases 是逐规则声明的，负例窄（`/tmp/scratch.txt`、
 * `/root/.cache/uv` 之类），量不到真实 agent 会产生的**命令形态与项目内配置路径**。
 * 静态 FP 风险体检对这些规则持续打高分，但打分的依据是词面共现
 * （规则文本里出现过 /tmp、curl、npm install 就加分），不是正则实际宽度——
 * 只有可执行的锚点能让"不要动这些规则"从说法变成可证伪的结论。
 *
 * 两类断言，都是有意为之：
 * 1. 良性必放行——将来谁给 block 规则加 paramsNotRegex 白名单（该语义是
 *    **显式 ALLOW**，加错等于豁免高危命令），这里会红。
 * 2. 良性但**按设计命中**——记录期望决策与命中的规则名，避免后来者把它当
 *    新发现的误报去"修"，从而改坏设计意图。
 *
 * 走生产层序（SelfProtection 先、引擎后），与 store.beforeToolCall 一致：
 * 断言必须是真实生效的那个答案，不是引擎单层的答案。
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { InterventionEngineImpl } from '../../src/intervention/InterventionEngine.js';
import * as SelfProtection from '../../src/intervention/SelfProtection.js';
import type { InterventionContext } from '../../src/intervention/types.js';

const POLICY_PATH = resolve('policies/security-policy.spl.yaml');

interface Anchor {
  name: string;
  tool: string;
  params: Record<string, unknown>;
  /** 期望决策；省略即期望 allow。 */
  decision?: string;
  /** decision 非 allow 时，期望命中的规则 id（避免"换个规则也拦"蒙混过关）。 */
  ruleId?: string;
}

describe('误报锚点：开发/运维良性操作', () => {
  let engine: InterventionEngineImpl;
  let policyDir: string;

  beforeAll(async () => {
    policyDir = mkdtempSync(join(tmpdir(), 'fp-anchors-'));
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

  function decide(anchor: Anchor, index: number): { decision: string; ruleIds: string[] } {
    const ctx = {
      actionType: 'agent_tool_call',
      toolName: anchor.tool,
      params: anchor.params,
      sessionId: `fp-anchor:${index}`,
    } as unknown as InterventionContext;
    const sp = SelfProtection.evaluate(ctx);
    if (sp.blocked && sp.decision) return { decision: sp.decision.decision, ruleIds: ['SelfProtection'] };
    const d = engine.evaluateSync(ctx);
    return { decision: d.decision, ruleIds: (d.matchedPolicies ?? []).map((p) => p.policyId) };
  }

  /** 良性必放行：常规清理、包管理、下载、项目内配置读写。 */
  const ALLOW: Anchor[] = [
    { name: '清理 node_modules', tool: 'exec', params: { command: 'rm -rf ./node_modules' } },
    { name: '清理 tmp 构建目录', tool: 'exec', params: { command: 'rm -rf /tmp/build-cache' } },
    { name: '清理下载目录旧包', tool: 'exec', params: { command: 'rm -rf ~/Downloads/old-archive' } },
    { name: 'git 清理未跟踪文件', tool: 'exec', params: { command: 'git clean -fd' } },
    { name: '删除项目 dist', tool: 'exec', params: { command: 'rm -rf /home/user/project/dist' } },
    { name: 'npm install', tool: 'exec', params: { command: 'npm install express' } },
    { name: 'pip install', tool: 'exec', params: { command: 'pip install requests' } },
    { name: 'curl 下载到 tmp', tool: 'exec', params: { command: 'curl -o /tmp/pkg.tar.gz https://example.com/pkg.tar.gz' } },
    { name: '写项目内 .env', tool: 'write', params: { path: '/home/user/project/.env' } },
    { name: '写项目内 .npmrc 配私有源', tool: 'write', params: { path: '/home/user/project/.npmrc' } },
    { name: 'IDE 编辑 ~/.bashrc', tool: 'edit', params: { path: '/home/user/.bashrc' } },
    { name: '删项目内 .env', tool: 'exec', params: { command: 'rm -f /home/user/project/.env' } },
    { name: '删 ~/.netrc', tool: 'exec', params: { command: 'rm -f /home/user/.netrc' } },
    { name: 'grep ~/.netrc 排查凭据', tool: 'exec', params: { command: 'grep -r token /home/user/.netrc' } },
    { name: 'chmod 600 ~/.netrc 收紧权限', tool: 'exec', params: { command: 'chmod 600 ~/.netrc' } },
  ];

  /**
   * 良性但按设计命中。三类，各有明确设计依据：
   * - modify/低危：constrain-user-data-path 对命中 path 做白名单约束，其 notes
   *   自述"零误报面（仅收紧白名单不丢字段）"。modify 是输出不是拦截。
   * - block/可申诉：block-exec-credential-file 的职责就是拦命令行读凭据——
   *   这正是本产品要拦的数据外泄向量。该规则已因 grep/awk/sed 字面检索
   *   误伤而收窄过一次，appealable:true 留了申诉通道。
   * - warn/可申诉：block-shell-rc-injection 拦 rc 文件追加，notes 明写
   *   "命中可申诉"，且刻意收窄到 exec 重定向/tee 通道。
   */
  const BY_DESIGN: Anchor[] = [
    { name: '写 ~/.netrc → 白名单约束（modify/低危）', tool: 'write', params: { path: '/home/user/.netrc' }, decision: 'modify', ruleId: 'constrain-user-data-path' },
    { name: '写 ~/.pypirc → 白名单约束（modify/低危）', tool: 'write', params: { path: '/home/user/.pypirc' }, decision: 'modify', ruleId: 'constrain-user-data-path' },
    { name: '写 ~/.aws/credentials → 白名单约束（modify/低危）', tool: 'write', params: { path: '/home/user/.aws/credentials' }, decision: 'modify', ruleId: 'constrain-user-data-path' },
    { name: '写 ~/.docker/config.json → 白名单约束（modify/低危）', tool: 'write', params: { path: '/home/user/.docker/config.json' }, decision: 'modify', ruleId: 'constrain-user-data-path' },
    { name: 'cat ~/.aws/credentials → 凭据读取拦截（block/可申诉）', tool: 'exec', params: { command: 'cat ~/.aws/credentials' }, decision: 'block', ruleId: 'block-exec-credential-file' },
    { name: '追加 PATH 到 ~/.bashrc → rc 注入告警（warn/可申诉）', tool: 'exec', params: { command: "echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc" }, decision: 'warn', ruleId: 'block-shell-rc-injection' },
  ];

  ALLOW.forEach((a, i) => {
    it(`放行：${a.name}`, () => {
      const r = decide(a, i);
      expect(r.decision, `期望 allow，实际 ${r.decision}（命中 ${r.ruleIds.join(',') || '无'}）`).toBe('allow');
    });
  });

  BY_DESIGN.forEach((a, i) => {
    it(`按设计命中：${a.name}`, () => {
      const r = decide(a, 1000 + i);
      expect(r.decision, `期望 ${a.decision}，实际 ${r.decision}（命中 ${r.ruleIds.join(',') || '无'}）`).toBe(a.decision);
      expect(r.ruleIds, '命中规则与设计记录不符——换规则兜住不等于设计没变').toContain(a.ruleId);
    });
  });
});