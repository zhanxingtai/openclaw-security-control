#!/usr/bin/env node
// scripts/probe-real-fp.mjs
// 业务常态负例探测：绕过 shipped testCases,用一组"业务常态"输入跑真引擎,
// 看哪些 block/warn 规则被命中 → 真实 FP 候选。
// 与 verify-rule-accuracy.mjs（设计时自测用例）互补
//
// 用法：
//   node scripts/probe-real-fp.mjs                # 文本报告
//   node scripts/probe-real-fp.mjs --json         # JSON
//   node scripts/probe-real-fp.mjs --repo=<path>  # 其他策略
//
// Exit: 0 正常 / 2 引擎加载失败

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath, pathToFileURL } from 'url';
import { createRequire } from 'module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const args = process.argv.slice(2);
const opts = {
  json: args.includes('--json'),
  repoPath: null,
};
for (const arg of args) {
  if (arg.startsWith('--repo=')) opts.repoPath = arg.slice('--repo='.length);
}

const REPO_DEFAULT = path.join(rootDir, 'policies', 'security-policy.spl.yaml');
const repoPath = opts.repoPath || REPO_DEFAULT;
if (!fs.existsSync(repoPath)) { console.error(`FAIL: 策略不存在 ${repoPath}`); process.exit(2); }

// 引擎加载
const engineEntry = path.join(rootDir, 'dist', 'src', 'intervention', 'InterventionEngine.js');
if (!fs.existsSync(engineEntry)) {
  console.error(`FAIL: dist/${path.basename(engineEntry)} 缺失,先 npm run build`);
  process.exit(2);
}
const silent = opts.json;
const savedLog = console.log;
if (silent) console.log = () => {};
const { InterventionEngineImpl } = await import(pathToFileURL(engineEntry).href);

// RuleLoader 沙箱
const policyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-real-fp-'));
fs.copyFileSync(repoPath, path.join(policyDir, 'policy.yaml'));
process.on('exit', () => fs.rmSync(policyDir, { recursive: true, force: true }));

const engine = new InterventionEngineImpl({
  mode: 'audit',
  ruleLoader: { policyPath: path.join(policyDir, 'policy.yaml'), reloadIntervalMs: 0 },
  guidance: { enabled: false },
});
await engine.initialize();

// ---------- 候选负例集 ----------
// 形式: (label, InterventionContext)
// 选型理由: 都是真实业务中合法的运维/开发动作,此类路径容易触发误报。
// 不是 negative testCase(不会改 shipped 策略),是 probe 用的临时输入。
const CANDIDATES = [
  {
    id: 'cat-root-npmrc',
    note: '运维查私有 npm registry 配置 — /root/ 宽口径候选',
    ctx: { actionType: 'process_start', riskFlags: ['sensitive_file_access'], params: { command: 'cat /root/.npmrc' } },
  },
  {
    id: 'vim-nginx-conf',
    note: '运维编辑 nginx 配置 — 命中 Tier-2 配置文件类规则',
    ctx: { actionType: 'process_start', params: { command: 'vim /etc/nginx/nginx.conf' } },
  },
  {
    id: 'crontab-list',
    note: '运维查定时任务 — 命中 crontab 相关规则',
    ctx: { actionType: 'process_start', params: { command: 'crontab -l' } },
  },
  {
    id: 'systemctl-user-status',
    note: '用户态查 systemd 单元 — 命中 systemctl --user 模式',
    ctx: { actionType: 'process_start', params: { command: 'systemctl --user status my-app' } },
  },
  {
    id: 'npm-install',
    note: '开发装包 — 命中包安装命令规则',
    ctx: { actionType: 'process_start', params: { command: 'npm install --save lodash' } },
  },
  {
    id: 'pip-install',
    note: '开发装包 — 命中包安装命令规则',
    ctx: { actionType: 'process_start', params: { command: 'pip install requests' } },
  },
  {
    id: 'wget-internal',
    note: '内网下载 — 命中 wget 命令规则',
    ctx: { actionType: 'process_start', params: { command: 'wget https://internal.corp.example.com/release.tar.gz' } },
  },
  {
    id: 'ssh-deploy',
    note: '内网 ssh 运维 — 命中 ssh 命令规则',
    ctx: { actionType: 'process_start', params: { command: "ssh deploy@web-01 'systemctl status nginx'" } },
  },
  {
    id: 'cat-etc-hosts',
    note: '查 DNS 映射 — process_start 通道已修,此处检查其他通道是否还命中',
    ctx: { actionType: 'process_start', params: { command: 'cat /etc/hosts' } },
  },
  {
    id: 'append-bashrc',
    note: '开发加 PATH — 命中 shell 配置文件写入规则',
    ctx: { actionType: 'process_start', params: { command: 'echo "export PATH=$PATH:/opt/bin" >> ~/.bashrc' } },
  },
  {
    id: 'read-aws-credentials',
    note: '运维查 AWS 凭据 — Tier-2 路径',
    ctx: { actionType: 'process_start', riskFlags: ['sensitive_file_access'], params: { command: 'cat ~/.aws/credentials' } },
  },
  {
    id: 'curl-github-release',
    note: '开发拉 github release — curl 命令 + github 域名',
    ctx: { actionType: 'process_start', params: { command: 'curl -L https://github.com/owner/repo/releases/latest' } },
  },
];

// ---------- Probe ----------
function isHit(decision) {
  return decision && decision !== 'allow';
}

const probe = [];
for (const c of CANDIDATES) {
  const ctx = { sessionId: `probe:${c.id}`, ...c.ctx };
  const out = engine.evaluateSync(ctx);
  const matched = (out.matchedPolicies || []).map((m) => ({
    id: m.policyId,
    name: m.policyName,
    decision: m.decision,
    severity: m.riskLevel,
    blockCode: m.blockCode,
  }));
  probe.push({
    id: c.id,
    note: c.note,
    input: c.ctx,
    finalDecision: out.decision,
    finalBlockCode: out.blockCode || null,
    matched,
    // "FP 候选" 标记:任何 block 规则命中,即便最终决策是 audit 降级,
    // 也意味着"运维动作触发了阻断/告警链路" — 这是用户原话"误报拦截"的本意。
    hasBlockMatch: matched.some((m) => m.decision === 'block'),
    hasWarnMatch: matched.some((m) => m.decision === 'warn'),
  });
}

// 汇总:按"被命中次数"统计规则 → 哪条规则被多少候选触发
const ruleHitCount = new Map();
for (const p of probe) {
  for (const m of p.matched) {
    if (m.decision !== 'block' && m.decision !== 'warn') continue; // 只看 block/warn(误报关切)
    if (!ruleHitCount.has(m.id)) ruleHitCount.set(m.id, { id: m.id, name: m.name, decision: m.decision, severity: m.severity, hitBy: [] });
    ruleHitCount.get(m.id).hitBy.push({ probeId: p.id, decision: m.decision, blockCode: m.blockCode });
  }
}
const rulesHit = [...ruleHitCount.values()].sort((a, b) => b.hitBy.length - a.hitBy.length || a.id.localeCompare(b.id));

// ---------- 输出 ----------
if (opts.json) {
  process.stdout.write(JSON.stringify({
    repoPath,
    candidates: CANDIDATES.length,
    probe,
    rulesHit,
  }, null, 2) + '\n');
} else {
  console.log = savedLog;
  console.log('=== Plan C · 业务常态负例候选 → shipped 规则命中探测 ===');
  console.log(`策略: ${repoPath}`);
  console.log(`候选数: ${CANDIDATES.length}    命中 block/warn 的规则数: ${rulesHit.length}\n`);

  console.log('--- 候选负例逐条结果(列出最终决策与 block 命中)---');
  for (const p of probe) {
    const icon = p.hasBlockMatch ? '🔴' : p.hasWarnMatch ? '🟠' : '🟢';
    console.log(`${icon} ${p.id}  → ${p.finalDecision}${p.finalBlockCode ? ' [' + p.finalBlockCode + ']' : ''}  (${p.note})`);
    if (p.matched.length === 0) {
      console.log('     (无规则命中)');
    } else {
      for (const m of p.matched) {
        console.log(`     - ${m.id}  decision=${m.decision}  severity=${m.severity}${m.blockCode ? '  [' + m.blockCode + ']' : ''}`);
      }
    }
  }

  console.log('\n--- 规则被候选命中次数(高 → 低)---');
  if (rulesHit.length === 0) {
    console.log('(无 block/warn 规则被候选负例触发 → shipped 策略目前对业务常态动作不会误伤)');
  } else {
    for (const r of rulesHit) {
      const blockHits = r.hitBy.filter((h) => h.decision === 'block').length;
      const warnHits = r.hitBy.filter((h) => h.decision === 'warn').length;
      console.log(`${r.id}  decision=${r.decision}  severity=${r.severity}  候选命中 ${r.hitBy.length} 次(block ${blockHits} / warn ${warnHits})`);
      for (const h of r.hitBy) {
        console.log(`     - probe=${h.probeId}  → ${h.decision}${h.blockCode ? ' [' + h.blockCode + ']' : ''}`);
      }
    }
  }
}
