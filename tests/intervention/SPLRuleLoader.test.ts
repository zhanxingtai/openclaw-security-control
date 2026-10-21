import { describe, it, expect } from 'vitest';
import { parseSPLPolicy } from '../../src/intervention/SPLRuleLoader.js';

describe('SPLRuleLoader', () => {
  it('parses a new SPL policy', () => {
    // v2 文件顶层 severity 直接读取；context_adjust 是 spec
    // 删除值，单规则容错把规则跳过 + 规则级 WARN，策略其余规则照常加载。
    const warns: string[] = [];
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'spl-policy', name: 'SPL Policy', version: '1.0.0' },
      mode: 'enforce',
      rules: [
        {
          id: 'keep', severity: 'medium',
          match: { action_type: ['tool_call'], action_name: ['file_read'] },
          severity: 'high',
          action: { decision: 'block' },
        },
        {
          id: 'guidance-rule', severity: 'medium',
          match: { action_type: ['file_read'] },
          severity: 'medium',
          action: {
            decision: 'context_adjust',
            guidance: {
              template_ref: 'guidance.default',
              template_params: { allowedScope: '仅允许白名单路径' },
            },
          },
        },
      ],
    }, { logger: { warn: (m) => warns.push(m), error: () => {} } });

    expect(policy.apiVersion).toBe('security.use/v2');
    expect(policy.metadata?.id).toBe('spl-policy');
    expect(policy.mode).toBe('enforce');
    // action_type 别名：tool_call → agent_tool_call，action_name → actionName
    expect(policy.rules[0].match.actionType).toEqual(['agent_tool_call']);
    expect(policy.rules[0].match.actionName).toEqual(['file_read']);
    expect(policy.rules[0].severity).toBe('high');
    // v2 文件 context_adjust 是删除值 → 单规则容错：
    // 规则被跳过 + 规则级 WARN。keep 规则照常加载。
    expect(policy.rules.find((r) => r.id === 'guidance-rule')).toBeUndefined();
    expect(policy.rules.find((r) => r.id === 'keep')?.action.decision).toBe('block');
    expect(warns.some((w) => w.includes('removed decision "context_adjust"'))).toBe(true);
    expect(warns.some((w) => w.includes('guidance-rule skipped'))).toBe(true);
  });

  it('parses a decision chain', () => {
    // 决策链前项 v2 仍合法（warn → block）。context_adjust 是 spec
    // 删除值，声明它的规则被单规则容错跳过。
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'chain-policy', name: 'Chain Policy', version: '1.0.0' },
      rules: [
        {
          id: 'chain-rule', severity: 'medium',
          match: { action_type: ['tool_call'] },
          action: {
            decision_chain: [
              { decision: 'warn', max_attempts: 2 },
              { decision: 'block', block: { blockReason: '引导无效' } },
            ],
          },
        },
      ],
    });

    expect(policy.rules[0].action.decisionChain).toHaveLength(2);
    expect(policy.rules[0].action.decisionChain?.[0].decision).toBe('warn');
    expect(policy.rules[0].action.decisionChain?.[1].decision).toBe('block');
  });

  it('merges top-level paramsRegex with params.path_regex', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'merge-policy', name: 'Merge Policy', version: '1.0.0' },
      rules: [
        {
          id: 'merge-rule', severity: 'medium',
          match: {
            action_type: ['tool_call'],
            action_name: ['exec'],
            params: {
              path_regex: ['^/etc/'],
            },
            paramsRegex: {
              command: ['cat\\s+/etc/'],
            },
          },
          action: { decision: 'block' },
        },
      ],
    });

    const match = policy.rules[0].match;
    expect(match.paramsRegex).toBeDefined();
    expect(match.paramsRegex?.path).toContain('^/etc/');
    expect(match.paramsRegex?.command).toContain('cat\\s+/etc/');
  });

  it('parses rule category', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'category-policy', name: 'Category Policy', version: '1.1.0' },
      rules: [
        {
          id: 'data-leak-upload-001', severity: 'medium',
          category: 'data_leak_monitoring',
          match: { actionType: ['process_start'], riskFlagsAny: ['data_exfiltration'] },
          action: { decision: 'warn', blockCode: 'DATA_LEAK_MONITORING_UPLOAD_001' },
        },
      ],
    });

    expect(policy.rules[0].category).toBe('data_leak_monitoring');
    expect(policy.rules[0].action.decision).toBe('warn');
  });

  it('parses warn decision and testCases', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'warn-policy', name: 'Warn Policy', version: '1.1.0' },
      rules: [
        {
          id: 'warn-rule', severity: 'medium',
          match: { actionType: ['process_start'] },
          action: { decision: 'warn' },
          testCases: [
            {
              name: '命中告警',
              input: { actionType: 'process_start', params: { command: 'x' } },
              expectedDecision: 'warn',
            },
          ],
        },
      ],
    });

    expect(policy.rules[0].action.decision).toBe('warn');
    expect(policy.rules[0].testCases).toHaveLength(1);
    expect(policy.rules[0].testCases?.[0].expectedDecision).toBe('warn');
  });

  it('parses standard array-form chain () into internal prior entries', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'chain-policy-2', name: 'Chain Policy 2', version: '1.1.0' },
      rules: [
        {
          id: 'data-leak-dump-exfil-001', severity: 'medium',
          match: {
            actionType: ['process_start'],
            riskFlagsAny: ['data_exfiltration'],
            chain: [
              {
                actionType: ['process_start'],
                paramsRegex: { command: ['\\bmysqldump\\b'] },
              },
            ],
          },
          action: { decision: 'warn' },
        },
      ],
    });

    const chain = policy.rules[0].match.chain;
    expect(chain?.prior).toHaveLength(1);
    expect(chain?.prior?.[0].action).toBe('process_start');
    expect(chain?.prior?.[0].bodyRegex).toContain('\\bmysqldump\\b');
  });

  it('parses object-form chain with withinSteps and paramsRegex links ', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'chain-window', name: 'Chain Window', version: '1.0.0' },
      rules: [
        {
          id: 'dump-then-exfil', severity: 'medium',
          match: {
            actionType: ['process_start'],
            riskFlagsAny: ['data_exfiltration'],
            chain: {
              withinSteps: 5,
              prior: [
                {
                  actionType: 'process_start',
                  paramsRegex: { command: ['\\bmysqldump\\b'] },
                },
              ],
            },
          },
          action: { decision: 'warn' },
        },
      ],
    });

    const chain = policy.rules[0].match.chain;
    // 窗口语义载体：对象形态 withinSteps 不再被丢弃（数组形态无从携带）。
    expect(chain?.withinSteps).toBe(5);
    // 对象形态链节的 paramsRegex.command 与数组形态同义（映射为内容扫描维度）。
    expect(chain?.prior?.[0].action).toBe('process_start');
    expect(chain?.prior?.[0].bodyRegex).toContain('\\bmysqldump\\b');
  });

  it('skips a rule with an invalid actionType instead of failing the whole policy ', () => {
    const warnings: string[] = [];
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'skip-bad-rule', name: 'Skip Bad Rule', version: '1.0.0' },
        rules: [
          {
            id: 'bad-actiontype', severity: 'medium',
            match: { actionType: ['tool_calll'] },
            action: { decision: 'block' },
          },
          {
            id: 'good-rule', severity: 'medium',
            match: { actionType: ['tool_call'] },
            action: { decision: 'warn' },
          },
        ],
      },
      { logger: { warn: (m) => warnings.push(m), error: () => {} } }
    );

    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('good-rule');
    expect(warnings.join('\n')).toMatch(/bad-actiontype skipped/);
  });

  it('treats non-boolean enabled as disabled with a warning ', () => {
    const warnings: string[] = [];
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'strict-enabled', name: 'Strict Enabled', version: '1.0.0' },
        rules: [
          { id: 'enabled-string-no', severity: 'medium', enabled: 'no', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
          { id: 'enabled-true', severity: 'medium', enabled: true, match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
          { id: 'enabled-default', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
          { id: 'enabled-false', severity: 'medium', enabled: false, match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
        ],
      },
      { logger: { warn: (m) => warnings.push(m), error: () => {} } }
    );

    // 字符串 "no" 不再被 Boolean() 静默当 true：记 warn 且按禁用处理。
    expect(policy.rules.find((r) => r.id === 'enabled-string-no')?.enabled).toBe(false);
    expect(policy.rules.find((r) => r.id === 'enabled-true')?.enabled).toBe(true);
    expect(policy.rules.find((r) => r.id === 'enabled-default')?.enabled).toBe(true);
    expect(policy.rules.find((r) => r.id === 'enabled-false')?.enabled).toBe(false);
    expect(warnings.join('\n')).toMatch(/enabled-string-no.*enabled must be a boolean/);
  });
});

describe('risk_level== 死条件加载期告警', () => {
  const base = {
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'risk-dead', name: 'RiskDead', version: '1.0.0' },
  };
  const mkLogger = () => {
    const warns: string[] = [];
    return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
  };

  it('risk_level== 残留表达式加载期告警', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy({
      ...base,
      rules: [{
        id: 'r1', severity: 'medium',
        match: { actionType: ['agent_tool_call'] },
        action: { decision: 'block', conditionalDecisions: [{ condition: 'risk_level==high', decision: 'block' }] },
      }],
    }, { logger });
    expect(warns.some((w) => w.includes('risk_level'))).toBe(true);
  });
});

// ============================================================================
// SPL v2 loader 行为（apiVersion 双读 + severity + 决策收窄 + 未实现字段 WARN）
// ============================================================================

describe('apiVersion v2 唯一支持', () => {
  const baseMeta = { id: 'v2-test', name: 'V2 Test', version: '1.0.0' };
  const baseRule = { id: 'r1', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'block' } };

  it('v2 文件直读，不发 WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      { apiVersion: 'security.use/v2', kind: 'Policy', metadata: baseMeta, rules: [baseRule] },
      { logger }
    );
    expect(warns.some((w) => w.includes('apiVersion'))).toBe(false);
  });

  it('v1 文件抛错（v1 兼容期已结束）', () => {
    const { logger } = mkLogger();
    expect(() =>
      parseSPLPolicy(
        { apiVersion: 'security.use/v1', kind: 'Policy', metadata: baseMeta, rules: [baseRule] },
        { logger }
      )
    ).toThrow(/unsupported SPL apiVersion: security.use\/v1/);
  });

  it('缺失 apiVersion 时抛错', () => {
    const { logger } = mkLogger();
    expect(() =>
      parseSPLPolicy(
        { kind: 'Policy', metadata: baseMeta, rules: [baseRule] },
        { logger }
      )
    ).toThrow(/unsupported SPL apiVersion/);
  });

  it('不支持的 apiVersion 抛错', () => {
    const { logger } = mkLogger();
    expect(() =>
      parseSPLPolicy(
        { apiVersion: 'security.use/v3', kind: 'Policy', metadata: baseMeta, rules: [baseRule] },
        { logger }
      )
    ).toThrow(/unsupported SPL apiVersion: security.use\/v3/);
  });
});

describe('顶层 severity', () => {
  const baseMeta = { id: 'sev-test', name: 'Severity Test', version: '1.0.0' };

  it('v2 读顶层 severity（合法值）', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        { id: 'r1', severity: 'high', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
      ],
    });
    expect(policy.rules[0].severity).toBe('high');
  });

  it('v2 非法 severity 值 WARN + 当作缺失', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          { id: 'r1', severity: 'urgent', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('severity must be one of'))).toBe(true);
  });

  it('v2 文件缺顶层 severity 时 throw 阻断加载（v2 无兼容期）', () => {
    // spec severity 必填。loader 缺 severity 必须 throw 而非 WARN——
    // 下游面板分级消费与决策评审矩阵都依赖该字段；WARN 路径会让策略
    // 静默缺失分级信息且不易察觉。
    const { logger } = mkLogger();
    expect(() =>
      parseSPLPolicy(
        {
          apiVersion: 'security.use/v2',
          kind: 'Policy',
          metadata: baseMeta,
          rules: [
            { id: 'r1', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
          ],
        },
        { logger }
      )
    ).toThrow(/severity is required at top level/);
  });
});

describe('决策枚举收窄', () => {
  const baseMeta = { id: 'dec-test', name: 'Decision Test', version: '1.0.0' };
  const mkLogger = () => {
    const warns: string[] = [];
    return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
  };

  it('v2 文件 substitute/context_adjust/degrade 静默跳过 + WARN（删除值 + 单规则容错）', () => {
    // v2 策略声明删除值时 loader 抛错；该抛错被单规则容错捕获，
    // 规则被跳过 + 规则级 WARN 提示"该规则被跳过"。
    // v2 不接受 v1 删除值；"单条规则错误不影响整体加载"的容错行为保留——
    // 规则丢弃+WARN。
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          { id: 'sub', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'substitute' } },
          { id: 'keep', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
        ],
      },
      { logger }
    );
    // substitute 规则被跳过，block 规则保留
    expect(policy.rules.find((r) => r.id === 'sub')).toBeUndefined();
    expect(policy.rules.find((r) => r.id === 'keep')?.action.decision).toBe('block');
    // 抛错转为 WARN
    expect(warns.some((w) => w.includes('removed decision "substitute"'))).toBe(true);
    expect(warns.some((w) => w.includes('sub skipped'))).toBe(true);
  });

  it('escalate 在 v2 是合法决策（核心 4 种 + audit + escalate）', () => {
    // escalate 不被 v1-mapper 改写；但 loader 内部仍保留 OpenClaw
    // 暂未实现 HITL 的处理（扩展位落地映射为 warn + WARN + notes
    // 注入），仅发一次决策收窄 WARN。
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        { id: 'esc-rule', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'escalate' } },
      ],
    }, { logger });
    expect(policy.rules[0].action.decision).toBe('warn');
    expect(warns.some((w) => w.includes('decision "escalate"'))).toBe(true);
  });

  it('guide/approve 静默跳过 + WARN（v2 拒绝 + 单规则容错）', () => {
    // 同上：loader 抛错 → 单规则容错 → 规则被跳过 + WARN
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          { id: 'g1', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'guide' } },
          { id: 'keep', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
        ],
      },
      { logger }
    );
    expect(policy.rules.find((r) => r.id === 'g1')).toBeUndefined();
    expect(policy.rules.find((r) => r.id === 'keep')?.action.decision).toBe('block');
    expect(warns.some((w) => w.includes('removed decision "guide"'))).toBe(true);
  });

  it('合法核心 4+audit 全部保留；escalate 落地映射为 warn', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        { id: 'a', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'allow' } },
        { id: 'w', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'warn' } },
        { id: 'b', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
        { id: 'm', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'modify' } },
        { id: 'au', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'audit' } },
        { id: 'es', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'escalate' } },
      ],
    });
    // escalate 经 loader 落地映射为 warn（OpenClaw 不支持 HITL），但其余决策
    // 不变。spec 中 escalate 是合法枚举值，B1 的映射是 OpenClaw 行为，
    // 不是迁移层。
    expect(policy.rules.map((r) => r.action.decision)).toEqual([
      'allow', 'warn', 'block', 'modify', 'audit', 'warn',
    ]);
  });
});

describe('x-openclaw-selfProtection 单一入口', () => {
  const baseMeta = { id: 'sp-test', name: 'SelfProtection Test', version: '1.0.0' };
  const mkLogger = () => {
    const warns: string[] = [];
    return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
  };

  it('v2 唯一读 x-openclaw-selfProtection', () => {
    // V2：项目扩展走 x-<project>- 前缀，selfProtection 唯一入口是
    // x-openclaw-selfProtection；legacy selfProtection 顶层键已移除。
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      'x-openclaw-selfProtection': {
        flags: 'i',
        groups: { g1: ['/etc/passwd'] },
      },
      rules: [],
    });
    expect(policy['x-openclaw-selfProtection']).toBeDefined();
    expect(policy['x-openclaw-selfProtection']?.groups?.g1).toEqual(['/etc/passwd']);
  });

  it('v2 文件 legacy selfProtection 顶层键被忽略（v1 兼容期结束）', () => {
    // V2：legacy selfProtection 既不被读取也不发 WARN
    // （避免破坏性噪音）。
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      selfProtection: {
        flags: 'i',
        groups: { g1: ['/etc/passwd'] },
      },
      rules: [],
    });
    expect(policy['x-openclaw-selfProtection']).toBeUndefined();
  });

  it('x- 与 legacy 同时存在时 x- 生效（不读 legacy、不发 legacy WARN）', () => {
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        'x-openclaw-selfProtection': { groups: { xGroup: ['/x'] } },
        selfProtection: { groups: { legacyGroup: ['/legacy'] } },
        rules: [],
      },
      { logger }
    );
    expect(policy['x-openclaw-selfProtection']?.groups?.xGroup).toEqual(['/x']);
    expect(policy['x-openclaw-selfProtection']?.groups?.legacyGroup).toBeUndefined();
    expect(warns.some((w) => w.includes('顶层 selfProtection 区段已读取'))).toBe(false);
  });
});

describe('未实现字段 WARN', () => {
  const baseMeta = { id: 'warn-field-test', name: 'Warn Field Test', version: '1.0.0' };
  const mkLogger = () => {
    const warns: string[] = [];
    return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
  };

  it('match.assetType 加载期 WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          { id: 'r1', severity: 'medium', match: { assetType: 'tool', actionType: ['tool_call'] }, action: { decision: 'block' } },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('match.assetType'))).toBe(true);
    expect(warns.some((w) => w.includes('OpenClaw 引擎未实现'))).toBe(true);
  });

  it('action.message 加载期 WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'r1', severity: 'medium',
            match: { actionType: ['tool_call'] },
            action: { decision: 'warn', message: '检测到风险操作' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('action.message'))).toBe(true);
  });

  it('未声明 assetType/message 时不发 WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          { id: 'r1', severity: 'medium', match: { actionType: ['tool_call'] }, action: { decision: 'block' } },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('match.assetType'))).toBe(false);
    expect(warns.some((w) => w.includes('action.message'))).toBe(false);
  });
});

// 共用 logger 工厂
function mkLogger() {
  const warns: string[] = [];
  return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
}

describe('V2 顶层 notes / regClause 字段透传', () => {
  const baseMeta = { id: 'notes-test', name: 'Notes Pass-through', version: '1.0.0' };

  it('顶层 notes: string 完整透传', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        {
          id: 'r-with-notes', severity: 'medium',
          match: { actionType: ['tool_call'] },
          severity: 'high',
          notes: '高置信反弹 shell 拦截；设计意图：覆盖 /dev/tcp、nc -e、mkfifo 管道等回连模式。',
          action: { decision: 'block' },
        },
      ],
    });
    expect(policy.rules[0].notes).toBe(
      '高置信反弹 shell 拦截；设计意图：覆盖 /dev/tcp、nc -e、mkfifo 管道等回连模式。'
    );
  });

  it('顶层 regClause: string[] 完整透传', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        {
          id: 'r-with-regclause', severity: 'medium',
          match: { actionType: ['tool_call'] },
          severity: 'medium',
          regClause: ['GDPR Art.32', 'ISO27001 A.13.2.1'],
          action: { decision: 'warn' },
        },
      ],
    });
    expect(policy.rules[0].regClause).toEqual(['GDPR Art.32', 'ISO27001 A.13.2.1']);
  });

  it('缺省时 notes / regClause 不出现（undefined 不暴露）', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        {
          id: 'r-no-extras', severity: 'medium',
          match: { actionType: ['tool_call'] },
          severity: 'low',
          action: { decision: 'audit' },
        },
      ],
    });
    expect('notes' in policy.rules[0]).toBe(false);
    expect('regClause' in policy.rules[0]).toBe(false);
  });

  it('空字符串 notes / 空数组 regClause 视为缺省', () => {
    // 解析层只做透传不过滤；空值不注入，避免下游面板/审计拿到空字段名。
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        {
          id: 'r-empty-extras', severity: 'medium',
          match: { actionType: ['tool_call'] },
          severity: 'low',
          notes: '',
          regClause: [],
          action: { decision: 'audit' },
        },
      ],
    });
    expect(policy.rules[0].notes).toBeUndefined();
    expect(policy.rules[0].regClause).toBeUndefined();
  });

  it('regClause 数组过滤非字符串元素', () => {
    const policy = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        {
          id: 'r-mixed-regclause', severity: 'medium',
          match: { actionType: ['tool_call'] },
          severity: 'low',
          regClause: ['GDPR Art.32', '', 42, null, 'ISO27001 A.13.2.1'],
          action: { decision: 'audit' },
        },
      ],
    });
    expect(policy.rules[0].regClause).toEqual(['GDPR Art.32', 'ISO27001 A.13.2.1']);
  });
});

describe('不可交付决策 + 缺 notes WARN', () => {
  const baseMeta = { id: 'notes-warn-test', name: 'Notes Warn', version: '1.0.0' };
  const mkLogger = () => {
    const warns: string[] = [];
    return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
  };

  it('缺 notes 的不可交付规则（block on process_start） → WARN', () => {
    // HOST_DELIVERABLE_DECISIONS 不支持 process_start 上挂 block，本规则
    // 依靠 store.ts warnDecisionNotDeliverable 留痕。loader 层必须 WARN
    // 提示作者补 notes 说明设计意图与替代留痕机制。
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'block-proc-cred',
            severity: 'critical',
            match: { actionType: ['process_start'] },
            action: { decision: 'block' },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.some(
        (w) =>
          w.includes('block-proc-cred') &&
          w.includes('不可交付组合') &&
          w.includes('block') &&
          w.includes('process_start')
      )
    ).toBe(true);
  });

  it('有 notes 的不可交付规则 → 静默（不告警）', () => {
    // notes 已声明时 loader 不告警。
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'block-proc-cred-with-notes',
            severity: 'critical',
            notes: 'process_start 事后留痕为设计意图；HOST_DELIVERABLE_DECISIONS 不支持 process_start 上挂 block，本规则依靠 store.ts warnDecisionNotDeliverable 留痕。',
            match: { actionType: ['process_start'] },
            action: { decision: 'block' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('不可交付组合'))).toBe(false);
  });

  it('可交付入口（agent_tool_call）上 block 即使缺 notes → 不告警', () => {
    // 入口可交付 + 缺 notes 不是问题（该约束只看不可交付组合）。
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'block-tool-call-no-notes',
            severity: 'high',
            match: { actionType: ['tool_call'] },
            action: { decision: 'block' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('不可交付组合'))).toBe(false);
  });

  it('process_start 上的 warn/audit/allow 决策即使缺 notes → 不告警', () => {
    // 仅 block/modify/escalate 算不可交付决策；warn/audit/allow 是
    // RECORD_ONLY，缺 notes 不构成该约束的关注点。
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'warn-proc-no-notes',
            severity: 'medium',
            match: { actionType: ['process_start'] },
            action: { decision: 'warn' },
          },
          {
            id: 'audit-proc-no-notes',
            severity: 'low',
            match: { actionType: ['network_http'] },
            action: { decision: 'audit' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('不可交付组合'))).toBe(false);
  });

  it('modify 与 escalate 决策在 process_start/network_http/agent_tool_result 上同样 WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'modify-proc-no-notes',
            severity: 'high',
            match: { actionType: ['network_http'] },
            action: { decision: 'modify' },
          },
          {
            id: 'escalate-result-no-notes',
            severity: 'high',
            match: { actionType: ['agent_tool_result'] },
            action: { decision: 'escalate' },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.filter((w) => w.includes('不可交付组合')).length
    ).toBe(2);
  });
});

/**
 * loader 校验收紧：
 *    category 8 值枚举 throw + 单规则隔离
 *    riskFlagsAny/All 字典 ⊆ 校验 throw + 单规则隔离
 *    PCRE (?i:) 内联 flag 加载期 WARN（同 ruleId 去重）
 *    actionType 别名展开加载期 WARN（按原值→规范值全局去重）
 *    decision=block 缺 blockCode/blockReason throw + 单规则隔离
 *    decision=modify 空对象 throw + 单规则隔离
 *    chain/conditional 项 deprecated decision 一致 throw + 单规则隔离
 */
describe('loader 校验收紧', () => {
  const baseMeta = { id: 'loader-tightening-test', name: 'Loader Tightening', version: '1.0.0' };
  const mkLogger = () => {
    const warns: string[] = [];
    return { warns, logger: { warn: (m: string) => { warns.push(m); }, error: () => {} } };
  };

  it('合法 category 8 值全部通过', () => {
    const { warns, logger } = mkLogger();
    const valid = [
      'self_protection',
      'intrusion_defense',
      'data_leak_monitoring',
      'sensitive_data_access',
      'supply_chain',
      'ssrf',
      'behavior_guidance',
      'data_desensitization',
    ];
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: valid.map((c, i) => ({
          id: `cat-${i}`,
          severity: 'medium',
          category: c,
          match: { actionType: ['agent_tool_call'] },
          action: { decision: 'allow' },
        })),
      },
      { logger }
    );
    expect(policy.rules).toHaveLength(8);
    expect(warns.filter((w) => w.includes('category must be one of'))).toHaveLength(0);
  });

  it('拼错 category → throw + 单规则隔离 + WARN 含 category must be one of', () => {
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'cat-bad',
            severity: 'medium',
            category: 'typo_category',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'allow' },
          },
          {
            id: 'cat-good',
            severity: 'medium',
            category: 'self_protection',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('cat-good');
    expect(warns.some((w) => w.includes('category must be one of'))).toBe(true);
    expect(warns.some((w) => w.includes('typo_category'))).toBe(true);
  });

  it('合法 riskFlagsAny/All 通过；非法 flag → throw + 单规则隔离', () => {
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'flag-good',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              riskFlagsAny: ['token_in_command', 'sensitive_file_access'],
            },
            action: { decision: 'allow' },
          },
          {
            id: 'flag-bad',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              riskFlagsAll: ['typo_flag_xyz'],
            },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('flag-good');
    expect(warns.some((w) => w.includes('riskFlagsAll contains unknown flags'))).toBe(true);
    expect(warns.some((w) => w.includes('typo_flag_xyz'))).toBe(true);
  });

  it('snake_case 别名 risk_flags_any / risk_flags_all 同样走字典校验', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'flag-snake-bad',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              risk_flags_any: ['typo_snake_flag'],
            },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('risk_flags_any contains unknown flags'))).toBe(true);
  });

  it('deprecated flag secret_in_content 加载期 WARN 提示替代 credential_exposure', () => {
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'flag-deprecated',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              riskFlagsAny: ['secret_in_content'],
            },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    // deprecated flag 仍可加载（不 throw），但要 WARN 提示
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('flag-deprecated');
    const deprecatedWarn = warns.find((w) => w.includes('deprecated flag "secret_in_content"'));
    expect(deprecatedWarn).toBeDefined();
    expect(deprecatedWarn).toContain('deprecated since 1.0.0');
  });

  it('deprecated flag WARN 模块级去重——同 rule 同 flag 第二次加载仅 WARN 一次', () => {
    const { warns, logger } = mkLogger();
    const policyIn = {
      apiVersion: 'security.use/v2' as const,
      kind: 'Policy' as const,
      metadata: baseMeta,
      rules: [
        {
          id: 'flag-deprecated-dup',
          severity: 'medium' as const,
          match: {
            actionType: ['agent_tool_call'] as const,
            riskFlagsAny: ['secret_in_content'],
          },
          action: { decision: 'allow' as const },
        },
      ],
    };
    // 第一次解析
    parseSPLPolicy(policyIn, { logger });
    const firstWarnCount = warns.filter((w) => w.includes('deprecated flag "secret_in_content"')).length;
    expect(firstWarnCount).toBe(1);
    // 第二次解析同输入（模块级 Set 跨调用去重）
    parseSPLPolicy(policyIn, { logger });
    const secondWarnCount = warns.filter((w) => w.includes('deprecated flag "secret_in_content"')).length;
    expect(secondWarnCount).toBe(1);
  });

  it('non-deprecated flag 不触发 deprecated WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'flag-current',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              riskFlagsAny: ['credential_exposure'],
            },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('deprecated flag'))).toBe(false);
  });

  it('PCRE (?i:) 内联 flag 加载期 WARN（含设计意图说明），同 ruleId 仅一次', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'pcre-i-rule',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              bodyRegex: ['(?i:hello)'],
            },
            action: { decision: 'allow' },
          },
          {
            id: 'pcre-i-rule-2',
            severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              bodyRegex: ['world'],
            },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    const pcreWarns = warns.filter((w) => w.includes('(?i:...)'));
    expect(pcreWarns).toHaveLength(1);
    expect(pcreWarns[0]).toContain('pcre-i-rule');
  });

  it('actionType 别名 message_write 加载期 WARN（原值→规范值，全局去重）', () => {
    // note: tool_call 在其他测试文件里已经被触发过（模块级 warnedActionTypeAliases
    // 共享），所以此处使用 message_write 验证同一别名 → 规范值的 WARN 文案。
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'alias-rule',
            severity: 'medium',
            match: { actionType: ['message_write'] },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.some((w) => w.includes('message_write') && w.includes('agent_message'))
    ).toBe(true);
  });

  it('同一别名多次 parse 仅发一次 WARN（全局去重）', () => {
    const { warns, logger } = mkLogger();
    const policy = {
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: baseMeta,
      rules: [
        {
          id: 'alias-twice',
          severity: 'medium',
          match: { actionType: ['message_write'] },
          action: { decision: 'allow' },
        },
      ],
    } as const;
    parseSPLPolicy(policy, { logger });
    const firstParseAliasWarns = warns.filter((w) => w.includes('message_write')).length;
    parseSPLPolicy(policy, { logger });
    const secondParseAliasWarns = warns.filter((w) => w.includes('message_write')).length;
    // 全局去重：第二次 parse 不再增长 WARN 计数
    expect(secondParseAliasWarns).toBe(firstParseAliasWarns);
  });

  it('规范名命中时不发 WARN（仅别名展开才发）', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'canon-rule',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'allow' },
          },
        ],
      },
      { logger }
    );
    expect(warns.filter((w) => w.includes('actionType alias'))).toHaveLength(0);
  });

  it('decision=block 缺 blockCode → throw + 单规则隔离', () => {
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'block-no-code',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'block', block: { blockReason: 'br' } },
          },
          {
            id: 'block-good',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'block', block: { blockCode: 'B001', blockReason: 'br' } },
          },
        ],
      },
      { logger }
    );
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('block-good');
    expect(warns.some((w) => w.includes('action.block requires non-empty blockCode'))).toBe(true);
  });

  it('decision=block 缺 blockReason → throw + 单规则隔离', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'block-no-reason',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'block', block: { blockCode: 'B002' } },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('action.block requires non-empty blockReason'))).toBe(true);
  });

  it('decision=modify 三个字段都为空 → throw + 单规则隔离', () => {
    const { warns, logger } = mkLogger();
    const policy = parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'modify-empty',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'modify', modify: {} },
          },
          {
            id: 'modify-good',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: {
              decision: 'modify',
              modify: { redactFields: ['body'] },
            },
          },
        ],
      },
      { logger }
    );
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('modify-good');
    expect(
      warns.some((w) => w.includes('action.modify must define at least one of'))
    ).toBe(true);
  });

  it('chain 项 deprecated decision substitute → throw + 单规则隔离', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'chain-dep',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: {
              decisionChain: [{ decision: 'substitute', when: 'true' }],
            },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.some((w) => w.includes('decision chain item 0: removed decision "substitute"'))
    ).toBe(true);
  });

  it('conditional 项 deprecated decision degrade → throw + 单规则隔离', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'cond-dep',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: {
              conditionalDecisions: [{ condition: 'true', decision: 'degrade' }],
            },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.some((w) => w.includes('conditional decision item 0: removed decision "degrade"'))
    ).toBe(true);
  });

  it('顶层 deprecated decision（context_adjust）仍抛错（回归）', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'top-dep',
            severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'context_adjust' },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('declares removed decision "context_adjust"'))).toBe(true);
  });

  it('blockCode 模式不符（无末尾 _NNN 数字）→ WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'm9-bad-pattern',
            category: 'self_protection',
            severity: 'high',
            match: { actionType: ['agent_tool_call'] },
            action: {
              decision: 'block',
              blockReason: 'test',
              blockCode: 'SELF_PROTECTION_BAD_CODE',
            },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.some((w) =>
        w.includes('blockCode') &&
        w.includes('模式不符合') &&
        w.includes('SELF_PROTECTION_BAD_CODE')
      )
    ).toBe(true);
  });

  it('blockCode 第一段与 category.uppercase() 不一致 → WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'm9-mismatch',
            category: 'self_protection',
            severity: 'high',
            match: { actionType: ['agent_tool_call'] },
            action: {
              decision: 'block',
              blockReason: 'test',
              blockCode: 'INTRUSION_DEFENSE_PRIV_ESC_001',
            },
          },
        ],
      },
      { logger }
    );
    expect(
      warns.some((w) =>
        w.includes('blockCode') &&
        w.includes('INTRUSION_DEFENSE_PRIV_ESC_001') &&
        w.includes('SELF')
      )
    ).toBe(true);
  });

  it('blockCode 正确（CATEGORY_威胁_NNN）且 category 匹配 → 无 WARN', () => {
    const { warns, logger } = mkLogger();
    parseSPLPolicy(
      {
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: baseMeta,
        rules: [
          {
            id: 'm9-good',
            category: 'self_protection',
            severity: 'high',
            match: { actionType: ['agent_tool_call'] },
            action: {
              decision: 'block',
              blockReason: 'test',
              blockCode: 'SELF_PROTECTION_GOOD_RULE_001',
            },
          },
        ],
      },
      { logger }
    );
    expect(warns.some((w) => w.includes('blockCode'))).toBe(false);
  });
});
