/**
 * OpenClaw Security Monitor - Rule Regex Cache
 *
 * 策略正则预编译旁路结构。
 * RuleLoader 在策略加载 / 热更新时一次性编译全部正则，
 * RuleMatcher 评估热路径只读编译产物，零现场 new RegExp。
 * 非法正则：跳过该规则并记告警（返回 ok=false），不导致加载失败。
 *
 * 编译期静态审计（无新依赖）。经典指数级回溯签名（如 (a+)+、(.*)*）
 * 判定为 unsafe，同样返回 ok=false 跳过该规则；一般嵌套量词（如 (?:\s+\S+)*，
 *  shipped 策略在用的线性安全形态）只记 warn 观察，不影响编译。
 */

import type { PolicyRegexEntry, PolicyRule } from './types.js';

interface CompiledChainRequirement {
  action?: string;
  actionName?: string;
  pathRegex?: RegExp[];
  urlRegex?: RegExp[];
  bodyRegex?: RegExp[];
}

export interface CompiledRuleRegexes {
  sessionRegex?: RegExp[];
  bodyRegex?: RegExp[];
  paramsRegex?: Record<string, RegExp[]>;
  paramsNotRegex?: Record<string, RegExp[]>;
  chain?: {
    withinSteps?: number;
    prior: CompiledChainRequirement[];
  };
}

export type RuleRegexCompileResult =
  | { ok: true; value: CompiledRuleRegexes }
  | { ok: false; pattern: string; reason?: 'invalid' | 'unsafe' };

/**
 * 灾难性回溯静态审计：组内为单一原子（含转义序列）叠加量词、组外再叠加 * / + /
 * 区间量词的经典形态，如 (a+)+、(.*)*、(\w+)+。这类模式可被极短输入打爆且
 * decisionTimeoutMs 的 Promise.race 对同步回溯无效，编译期直接拒绝。
 *
 * 判定口径：括号扫描器逐组解析，任何"带量词的组"其组内仍存在"带量词的组"
 * （含 | 分支内嵌套，逐支递归同理）一律拒绝编译；无嵌套组的量词组维持
 * 互补字符类豁免（(?:\s+\S+)* 等线性安全形态不回归）。
 */

/**
 * 括号扫描：返回 src 中全部 (...) 组的组体与紧随量词（字符类 [...] 与
 * 转义序列内的括号按字面处理，不参与配对）。栈式配对，容忍不平衡输入。
 */
function scanGroups(src: string): Array<{ inner: string; quantifier: string | null }> {
  const out: Array<{ inner: string; quantifier: string | null }> = [];
  const stack: number[] = [];
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === '\\') {
      i++;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      continue;
    }
    if (ch === '[') {
      inClass = true;
      continue;
    }
    if (ch === '(') {
      stack.push(i);
      continue;
    }
    if (ch === ')') {
      const start = stack.pop();
      if (start === undefined) continue;
      let quantifier: string | null = null;
      const next = src[i + 1];
      if (next === '*' || next === '+') {
        quantifier = next;
      } else if (next === '{') {
        const m = /^\{[^{}]*\}/.exec(src.slice(i + 1));
        if (m) quantifier = m[0];
      }
      out.push({ inner: src.slice(start + 1, i), quantifier });
    }
  }
  return out;
}

/**
 * 一般嵌套量词检测（观察级）：组内含任意量词且组外叠加 * / +。
 * 内层为互补字符类对序列（\s+\S+、\w+\W+、\d+\D+，如 shipped 策略的
 * (?:\s+\S+)*）时无回溯分叉点，属线性安全形态，不打 warn；其余嵌套量词
 * （单原子、交替分支、非互补序列）仍视为 suspicious 观察。
 */
const NESTED_QUANTIFIER_RE = /\([^()]*[*+][^()]*\)\s*[*+]/;

/** 互补字符类映射：\s↔\S、\w↔\W、\d↔\D（顺序无关）。 */
const COMPLEMENT_CLASS: Record<string, string> = { s: 'S', S: 's', w: 'W', W: 'w', d: 'D', D: 'd' };

/** 组内序列为互补字符类对（如 \s+\S+、\w+\W+\s+\S+）时线性安全。
 *  也涵盖字面字符类（如 [a-zA-Z]+）与空白类的互补：字面字符类不含空白，
 *  与 \s 天然不重叠，自身也无回溯分叉点。
 *  例：shipped 自防护规则 `-[a-zA-Z]*\s+`、`\s+-[a-zA-Z]+` 走此路径。 */
function isComplementaryClassSequence(inner: string): boolean {
  // 剥除非捕获前缀（?: ?= ?! ?<name> 与 (?i: 等内联标志组——运行时按整模式
  // 'i' 编译，见 compilePattern），再判定剩余序列是否互补字符类对。
  const body = inner.replace(/^\?(?::|=|!|<[^>]*>|[a-zA-Z-]+:)/, '');
  // 收集两类原子：反斜杠类（\s \S \w \W \d \D）+ 字面字符类（[...]）。
  const backslashAtoms = body.match(/\\[sSwWdD](?:[*+]|\{\d+(?:,\d*)?\})/g) ?? [];
  const literalClassAtoms = body.match(/\[[^\]]+\][*+]/g) ?? [];
  const atoms = [...backslashAtoms, ...literalClassAtoms];
  if (atoms.length < 2 || atoms.length % 2 !== 0) return false;
  // 残余字符仅允许字面量（不在原子内、也不带量词 / 交替 / pipe）。
  // 例：inner = `-[a-zA-Z]*\s+` → 原子为 `[a-zA-Z]*` + `\s+`，残余 `-` 是字面字符，
  // 与相邻原子无关回溯分叉点，允许通过。
  const rest = body
    .replace(/\\[sSwWdD](?:[*+]|\{\d+(?:,\d*)?\})/g, '')
    .replace(/\[[^\]]+\][*+]/g, '');
  if (/[*+?{}|]/.test(rest)) return false;
  // 配对规则：反斜杠互补对（\s↔\S 等）或 \s↔字面字符类 / \s↔非空白反斜杠类
  // （\S \W \D）。字面字符类按构造与 \s 不重叠，不需细查类内字符。
  for (let i = 0; i < atoms.length; i += 2) {
    const a1 = atoms[i];
    const a2 = atoms[i + 1];
    if (a1.startsWith('\\') && a2.startsWith('\\')) {
      if (COMPLEMENT_CLASS[a1[1]] !== a2[1]) return false;
      continue;
    }
    const a1IsWs = a1 === '\\s+' || a1 === '\\s*';
    const a2IsWs = a2 === '\\s+' || a2 === '\\s*';
    if (a1IsWs && (a2.startsWith('[') || (a2.startsWith('\\') && 'SWD'.includes(a2[1])))) continue;
    if (a2IsWs && (a1.startsWith('[') || (a1.startsWith('\\') && 'SWD'.includes(a1[1])))) continue;
    return false;
  }
  return true;
}

/** 单模式是否命中灾难性回溯签名（unsafe，拒绝编译）。
 *
 * 逐组扫描（scanGroups，字符类/转义感知），判定口径为"嵌套量词"：
 *  - 带量词的组，组体内任何"量化原子"（字符类/转义之外的 * + {n,m}）
 *    叠加外层量词即嵌套量词——一律拒绝（(a+)+、(.*)*、((a+)(b+))+、
 *    ((a|b)+)+ 等；含 | 的交替分支内嵌套逐支递归同理，任一分支出现量化
 *    原子即命中）；
 *  - 组体无量化原子 → 线性安全（(a|b)*、((a)(b))+、(a){2} 均放行）；
 *  - 唯一豁免：组体无嵌套组且为互补字符类序列（(?:\s+\S+)* 等 shipped
 *    策略在用的线性安全形态不回归）。
 * 口径说明：交替分支（含 |）内嵌套逐支审计，((a|b)+)+ 等形态同样拒绝，
 * 其余拒绝面为其超集。
 */
export function isCatastrophicallyUnsafePattern(pattern: string): boolean {
  for (const group of scanGroups(pattern)) {
    if (!group.quantifier) continue;
    if (!containsQuantifiedAtom(group.inner)) continue;
    if (group.inner.includes('(')) return true;
    if (!isComplementaryClassSequence(group.inner)) return true;
  }
  return false;
}

/** src 的字符类/转义之外是否出现量化原子（* + {n,m}）。 */
function containsQuantifiedAtom(src: string): boolean {
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === '\\') {
      i++;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      continue;
    }
    if (ch === '[') {
      inClass = true;
      continue;
    }
    if (ch === '*' || ch === '+') return true;
    if (ch === '{' && /^\{[^{}]*\}/.test(src.slice(i))) return true;
  }
  return false;
}

/** 单模式是否含嵌套量词（suspicious，仅 warn 观察）。 */
export function isSuspiciousNestedQuantifier(pattern: string): boolean {
  let any = false;
  for (const m of pattern.matchAll(/\(([^()]*[*+][^()]*)\)\s*[*+]/g)) {
    any = true;
    if (!isComplementaryClassSequence(m[1])) return true;
  }
  return any ? false : NESTED_QUANTIFIER_RE.test(pattern);
}

/** 收集规则全部维度的原始模式串（对象形态条目取其 pattern 字段）。 */
export function collectRulePatterns(rule: PolicyRule): string[] {
  const match = rule.match || {};
  const toSource = (e: PolicyRegexEntry): string => (typeof e === 'string' ? e : e.pattern);
  return [
    ...(match.sessionRegex || []).map(toSource),
    ...(match.bodyRegex || []).map(toSource),
    ...Object.values(match.paramsRegex || {}).flat().map(toSource),
    ...Object.values(match.paramsNotRegex || {}).flat().map(toSource),
    ...(match.chain?.prior || []).flatMap((p) => [
      ...(p.pathRegex || []).map(toSource),
      ...(p.urlRegex || []).map(toSource),
      ...(p.bodyRegex || []).map(toSource),
    ]),
    // modify.substitutePatterns 同样在评估期跑正则（DecisionComposer 逐字段
    // replace），却不受静态审计保护：一条 (a+)+ 形态的替换模式即可在纯同步
    // 评估里卡死线程、且 decisionTimeoutMs 抢不占。纳入同一收集口径后，
    // unsafe 的替换模式在加载期即隔离该规则。
    ...(rule.action?.modify?.substitutePatterns ?? []).map((s) => s.pattern),
    // modify.whitelistConstraint 在 DecisionComposer 现场 new RegExp，此前
    // 审计口径完全覆盖不到：一条 `(a|a)*` 形态的 whitelist 模式被静默接受，
    // 跑在主评估热路径里。统一纳入 collect 口径后，unsafe 模式在加载期即被
    // compileRuleRegexes 拒绝（fail-open 隔离单元隔离该规则）。
    ...Object.values(rule.action?.modify?.whitelistConstraint ?? {}),
  ];
}

/**
 * 规则是否仍在使用已废弃的 PCRE 内联标志写法（`(?i:...)` 作用域内联组 /
 * 裸 `(?i)` 前缀）。RuleLoader 据此在加载期打 WARN，引导迁移到规则级 /
 * 条目级 `flags` 字段。
 */
export function hasLegacyInlineFlags(rule: PolicyRule): boolean {
  return collectRulePatterns(rule).some((p) => p.includes('(?i:') || p.startsWith('(?i)'));
}

/** flags 合法性：仅允许 JS/Python 公共子集 i/m/s（禁 g/y，stateful lastIndex 交替命中）。 */
const VALID_REGEX_FLAGS = /^[ims]*$/;

function mergeFlags(...parts: Array<string | undefined>): string {
  let out = '';
  for (const part of parts) {
    if (!part) continue;
    for (const ch of part) {
      if (!out.includes(ch)) out += ch;
    }
  }
  return out;
}

/**
 * JS RegExp 不支持 PCRE 风格内联标志组 `(?i:...)`（`new RegExp` 直接
 * SyntaxError，整条规则因此被加载期隔离）。
 *
 * 首选写法是规则级 / 条目级 `flags` 字段（本函数直接尊重）。
 * 内联 `(?i:` 写法保留向后兼容翻译（出现即整模式追加 i 标志、开括号还原为
 * 普通组），RuleLoader 加载期对其打废弃 WARN 引导迁移；`(?-i:...)` 等降
 * 标志形态不做翻译，维持原样交给 new RegExp 报错走单规则隔离。
 *
 * flags 优先级：条目级 entry.flags 与规则级 ruleFlags 合并（去重）。
 */
function compilePattern(entry: PolicyRegexEntry, ruleFlags?: string): RegExp {
  const pattern = typeof entry === 'string' ? entry : entry.pattern;
  const entryFlags = typeof entry === 'string' ? undefined : entry.flags;
  for (const flags of [ruleFlags, entryFlags]) {
    if (flags !== undefined && !VALID_REGEX_FLAGS.test(flags)) {
      throw new Error(`invalid regex flags: ${JSON.stringify(flags)} (allowed: i/m/s)`);
    }
  }
  let flags = mergeFlags(ruleFlags, entryFlags);
  if (pattern.includes('(?i:')) {
    flags = mergeFlags(flags, 'i');
    return new RegExp(pattern.replace(/\(\?i:/g, '('), flags);
  }
  return new RegExp(pattern, flags);
}

function compilePatterns(patterns: PolicyRegexEntry[], ruleFlags?: string): RegExp[] {
  return patterns.map((p) => compilePattern(p, ruleFlags));
}

function compilePatternMap(map: Record<string, PolicyRegexEntry[]>, ruleFlags?: string): Record<string, RegExp[]> {
  const result: Record<string, RegExp[]> = {};
  for (const [key, patterns] of Object.entries(map)) {
    result[key] = compilePatterns(patterns || [], ruleFlags);
  }
  return result;
}

/**
 * 编译单条规则的全部正则维度。任一模式非法或命中灾难性回溯签名即返回
 * ok=false，调用方据此跳过该规则并记告警——单条规则的正则问题不得中断评估。
 */
export function compileRuleRegexes(rule: PolicyRule): RuleRegexCompileResult {
  const match = rule.match || {};
  const unsafe = collectRulePatterns(rule).find((p) => isCatastrophicallyUnsafePattern(p));
  if (unsafe !== undefined) {
    return { ok: false, pattern: unsafe, reason: 'unsafe' };
  }
  const ruleFlags = rule.flags;
  try {
    const value: CompiledRuleRegexes = {};

    if (match.sessionRegex && match.sessionRegex.length > 0) {
      value.sessionRegex = compilePatterns(match.sessionRegex, ruleFlags);
    }
    if (match.bodyRegex && match.bodyRegex.length > 0) {
      value.bodyRegex = compilePatterns(match.bodyRegex, ruleFlags);
    }
    if (match.paramsRegex && Object.keys(match.paramsRegex).length > 0) {
      value.paramsRegex = compilePatternMap(match.paramsRegex, ruleFlags);
    }
    if (match.paramsNotRegex && Object.keys(match.paramsNotRegex).length > 0) {
      value.paramsNotRegex = compilePatternMap(match.paramsNotRegex, ruleFlags);
    }
    if (match.chain && Array.isArray(match.chain.prior) && match.chain.prior.length > 0) {
      value.chain = {
        withinSteps: match.chain.withinSteps,
        prior: match.chain.prior.map((required) => ({
          action: required.action,
          actionName: required.actionName,
          pathRegex: required.pathRegex && required.pathRegex.length > 0 ? compilePatterns(required.pathRegex, ruleFlags) : undefined,
          urlRegex: required.urlRegex && required.urlRegex.length > 0 ? compilePatterns(required.urlRegex, ruleFlags) : undefined,
          bodyRegex: required.bodyRegex && required.bodyRegex.length > 0 ? compilePatterns(required.bodyRegex, ruleFlags) : undefined,
        })),
      };
    }

    return { ok: true, value };
  } catch (err) {
    // new RegExp 抛 SyntaxError 时不携带具体模式，从规则里定位第一个非法模式用于告警。
    // 定位器与编译器同口径（条目/规则级 flags + (?i: 兼容翻译），避免把已支持的写法误报为非法模式。
    const invalid = collectRulePatternEntries(rule).find((e) => {
      try {
        compilePattern(e, ruleFlags);
        return false;
      } catch {
        return true;
      }
    });
    return { ok: false, pattern: invalid ? (typeof invalid === 'string' ? invalid : invalid.pattern) : String(err), reason: 'invalid' };
  }
}

/** 收集规则全部维度的正则条目（保留对象形态，供编译定位器使用）。 */
function collectRulePatternEntries(rule: PolicyRule): PolicyRegexEntry[] {
  const match = rule.match || {};
  return [
    ...(match.sessionRegex || []),
    ...(match.bodyRegex || []),
    ...Object.values(match.paramsRegex || {}).flat(),
    ...Object.values(match.paramsNotRegex || {}).flat(),
    ...(match.chain?.prior || []).flatMap((p) => [
      ...(p.pathRegex || []),
      ...(p.urlRegex || []),
      ...(p.bodyRegex || []),
    ]),
  ];
}

// 懒编译兜底：未经过 RuleLoader 直接构造的规则（如单测），
// 进程内每个规则对象只编译一次，同样不在每次评估现场编译。
const lazyCompileCache = new WeakMap<PolicyRule, CompiledRuleRegexes | null>();

/**
 * 取规则的正则编译产物；非法正则返回 null（该规则不匹配）。
 */
export function getCompiledRuleRegexes(rule: PolicyRule): CompiledRuleRegexes | null {
  if (lazyCompileCache.has(rule)) {
    return lazyCompileCache.get(rule)!;
  }
  const result = compileRuleRegexes(rule);
  const compiled = result.ok ? result.value : null;
  lazyCompileCache.set(rule, compiled);
  return compiled;
}
