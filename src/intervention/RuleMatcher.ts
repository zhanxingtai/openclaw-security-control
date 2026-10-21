/**
 * OpenClaw Security Monitor - Rule Matcher
 *
 * Evaluates a single policy rule against an intervention context.
 * Supports SPL-style match fields.
 *
 * 正则维度全部改用 RuleRegexCache 的预编译产物（标准 3.2），
 * 评估热路径不出现现场 new RegExp；非法正则的规则在加载期被跳过
 * （compiled 为 null 时不匹配）。
 *
 * 匹配层加固——toolName/actionName 大小写不敏感；paramsRegex /
 * paramsNotRegex 递归提取嵌套对象/数组中的字符串逐值匹配（弃用
 * JSON.stringify 序列化匹配）；path 形态值在比较前生成归一化候选
 * （.. 点段解析、斜杠统一、盘符路径大小写折叠），原始值永远参与
 * 比较以兼容 shipped 策略锚点。归一化只用于匹配，不改写 ctx 留痕值。
 */

import type {
  InterventionContext,
  PolicyRule,
} from './types.js';
import { expandActionType } from './splActionType.js';
import { getCompiledRuleRegexes } from './RuleRegexCache.js';
import type { CompiledRuleRegexes } from './RuleRegexCache.js';

export interface RuleMatchResult {
  matched: boolean;
  rule?: PolicyRule;
}

export class RuleMatcher {
  /**
   * Match a rule against the given context.
   *
   * @param compiled 预编译正则产物（RuleLoader 加载期生成）；
   *                  缺省时按规则对象懒编译兜底（进程内仅一次）。
   *                  compiled 为 null 表示规则含非法正则，视为不匹配。
   */
  static match(
    ctx: InterventionContext,
    rule: PolicyRule,
    compiled?: CompiledRuleRegexes | null
  ): RuleMatchResult {
    if (!rule || rule.enabled === false) {
      return { matched: false };
    }

    const match = rule.match || {};
    const rx = compiled === undefined ? getCompiledRuleRegexes(rule) : compiled;
    if (rx === null) {
      // 非法 / 灾难性回溯正则（加载期已告警并留痕）：单规则隔离，视为不匹配，
      // 不得拖垮整次评估。
      return { matched: false };
    }

    // ctx actionType 展开结果每条规则相同，提升到评估入口一次计算，
    // 避免每规则重复展开。
    const ctxTypes = expandActionType(ctx.actionType);

    if (!this.matchActionType(ctxTypes, match)) return { matched: false };
    if (!this.matchActionName(ctx, match)) return { matched: false };
    if (!this.matchToolName(ctx, match)) return { matched: false };
    if (!this.matchRiskFlags(ctx, match)) return { matched: false };
    if (!this.matchSessionRegex(ctx, rx)) return { matched: false };
    if (!this.matchParamsRegex(ctx, match, rx)) return { matched: false };
    if (!this.matchParamsNotRegex(ctx, match, rx)) return { matched: false };
    if (!this.matchFieldEquals(ctx, match)) return { matched: false };
    if (!this.matchFieldIn(ctx, match)) return { matched: false };
    if (!this.matchBodyRegex(ctx, rx)) return { matched: false };
    if (!this.matchChain(ctx, rx)) return { matched: false };

    return { matched: true, rule };
  }

  private static matchActionType(ctxTypes: string[], match: PolicyRule['match']): boolean {
    if (!match.actionType || match.actionType.length === 0) return true;
    return match.actionType.some((t) => {
      if (t === '*') return true;
      return ctxTypes.some((ct) => ct === t);
    });
  }

  private static matchActionName(ctx: InterventionContext, match: PolicyRule['match']): boolean {
    if (!match.actionName || match.actionName.length === 0) return true;
    if (!ctx.toolName) return false;
    // 大小写不敏感；小写比较下已枚举大小写变体的规则仍等价命中
    // （相等蕴含小写相等），未知 agent 框架的 Tool/BASH 等命名同样纳入匹配。
    return match.actionName.some((n) => n === '*' || n.toLowerCase() === ctx.toolName!.toLowerCase());
  }

  private static matchToolName(ctx: InterventionContext, match: PolicyRule['match']): boolean {
    if (!match.toolName || match.toolName.length === 0) return true;
    if (!ctx.toolName) return false;
    return match.toolName.some((n) => n === '*' || n.toLowerCase() === ctx.toolName!.toLowerCase());
  }

  private static matchRiskFlags(ctx: InterventionContext, match: PolicyRule['match']): boolean {
    const flags = ctx.riskFlags || [];

    if (match.riskFlagsAll && match.riskFlagsAll.length > 0) {
      if (!match.riskFlagsAll.every((f) => flags.includes(f))) return false;
    }

    if (match.riskFlagsAny && match.riskFlagsAny.length > 0) {
      if (!match.riskFlagsAny.some((f) => flags.includes(f))) return false;
    }

    return true;
  }

  private static matchSessionRegex(ctx: InterventionContext, rx: CompiledRuleRegexes): boolean {
    if (!rx.sessionRegex) return true;
    if (!ctx.sessionId) return false;
    return rx.sessionRegex.some((re) => re.test(ctx.sessionId || ''));
  }

  private static matchParamsRegex(
    ctx: InterventionContext,
    match: PolicyRule['match'],
    rx: CompiledRuleRegexes
  ): boolean {
    const map = match.paramsRegex;
    if (!map) return true;
    const compiledMap = rx.paramsRegex;
    const params = ctx.params || {};

    // 热路径用 for-in 遍历，避免每次评估分配 Object.entries。
    for (const key in map) {
      if (!Object.prototype.hasOwnProperty.call(map, key)) continue;
      // 该 key 无编译产物只在非法正则时发生（compiled=null 已整体短路），
      // 这里做防御性跳过，保持"跳过该规则"语义。
      const compiled = compiledMap?.[key];
      if (!compiled) return false;
      // 递归提取 key 指向值（含嵌套对象/数组）中的全部字符串逐值
      // 匹配，任一候选命中即算该 key 命中。不再 JSON.stringify——为字符串
      // 设计的锚点正则此前无法命中藏进嵌套结构的命令，还会因引号/转义
      // 产生反向误报。key 存在但取不到任何可匹配值时视为不匹配。
      const value = this.getNestedValue(params, key);
      if (typeof value === 'string') {
        // 热路径：字符串值先直测原始值，未命中才归一化（见 testStringWithCandidates）。
        if (!this.testStringWithCandidates(compiled, value)) return false;
        continue;
      }
      const strings = this.collectMatchStrings(value);
      if (strings.length === 0) return false;
      let matched = false;
      for (let s = 0; s < strings.length && !matched; s++) {
        matched = this.testStringWithCandidates(compiled, strings[s]);
      }
      if (!matched) return false;
    }

    return true;
  }

  private static matchParamsNotRegex(
    ctx: InterventionContext,
    match: PolicyRule['match'],
    rx: CompiledRuleRegexes
  ): boolean {
    const map = match.paramsNotRegex;
    if (!map) return true;
    const compiledMap = rx.paramsNotRegex;
    const params = ctx.params || {};

    for (const key in map) {
      if (!Object.prototype.hasOwnProperty.call(map, key)) continue;
      const compiled = compiledMap?.[key];
      if (!compiled) return false;
      const value = this.getNestedValue(params, key);
      if (value === undefined || value === null) continue;
      // 与 paramsRegex 同一路径提取候选；豁免语义变为
      // "任一字符串值（含归一化候选）命中 notRegex 即否决该规则"。
      if (typeof value === 'string') {
        if (this.testStringWithCandidates(compiled, value)) return false;
        continue;
      }
      const strings = this.collectMatchStrings(value);
      for (let s = 0; s < strings.length; s++) {
        if (this.testStringWithCandidates(compiled, strings[s])) return false;
      }
    }

    return true;
  }

  private static matchFieldEquals(ctx: InterventionContext, match: PolicyRule['match']): boolean {
    const map = match.fieldEquals;
    if (!map) return true;
    const params = ctx.params || {};

    for (const key in map) {
      if (!Object.prototype.hasOwnProperty.call(map, key)) continue;
      const actual = this.getNestedValue(params, key);
      if (JSON.stringify(actual) !== JSON.stringify(map[key])) return false;
    }

    return true;
  }

  private static matchFieldIn(ctx: InterventionContext, match: PolicyRule['match']): boolean {
    const map = match.fieldIn;
    if (!map) return true;
    const params = ctx.params || {};

    for (const key in map) {
      if (!Object.prototype.hasOwnProperty.call(map, key)) continue;
      const expectedList = map[key];
      const actual = this.getNestedValue(params, key);
      const found = (expectedList || []).some((expected) => JSON.stringify(actual) === JSON.stringify(expected));
      if (!found) return false;
    }

    return true;
  }

  private static matchBodyRegex(ctx: InterventionContext, rx: CompiledRuleRegexes): boolean {
    if (!rx.bodyRegex) return true;
    const body = ctx.body || ctx.userPrompt || '';
    return rx.bodyRegex.some((re) => re.test(body));
  }

  private static matchChain(ctx: InterventionContext, rx: CompiledRuleRegexes): boolean {
    if (!rx.chain) return true;
    const prior = ctx.previousActions || [];
    if (!prior.length) return false;

    const withinSteps = rx.chain.withinSteps ?? prior.length;
    const window = prior.slice(-withinSteps);

    for (const required of rx.chain.prior) {
      const found = window.some((action) => {
        if (required.action && action.tool !== required.action) return false;
        if (required.actionName && action.tool !== required.actionName) return false;
        if (required.pathRegex && action.params) {
          const paths = this.collectStrings(action.params);
          if (!required.pathRegex.some((re) => paths.some((p) => re.test(p)))) return false;
        }
        if (required.urlRegex && action.params) {
          const urls = this.collectStrings(action.params);
          if (!required.urlRegex.some((re) => urls.some((u) => re.test(u)))) return false;
        }
        if (required.bodyRegex && action.params) {
          const bodies = this.collectStrings(action.params);
          if (!required.bodyRegex.some((re) => bodies.some((b) => re.test(b)))) return false;
        }
        return true;
      });
      if (!found) return false;
    }

    return true;
  }

  private static collectStrings(value: unknown): string[] {
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) return value.flatMap((v) => this.collectStrings(v));
    if (value && typeof value === 'object') {
      return Object.values(value).flatMap((v) => this.collectStrings(v));
    }
    return [];
  }

  private static getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    // 无点号键走快速路径，避免每次 split 分配数组。
    if (!path.includes('.')) {
      return obj[path];
    }
    const parts = path.split('.');
    let current: unknown = obj;
    for (const part of parts) {
      // 数组支持数字下标段（如 args.0），不再遇数组即返回 undefined。
      if (Array.isArray(current)) {
        const idx = Number(part);
        if (!Number.isInteger(idx) || idx < 0 || idx >= current.length) {
          return undefined;
        }
        current = current[idx];
      } else if (current && typeof current === 'object') {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }
    return current;
  }

  /** 单次提取的深度上限与节点预算。 */
  private static readonly MATCH_STRING_MAX_DEPTH = 32;
  private static readonly MATCH_STRING_MAX_NODES = 2000;
  /** 超限告警只打一次，避免逐事件刷屏。 */
  private static matchStringsTruncatedWarned = false;

  /**
   * 递归收集参与正则匹配的字符串值。字符串原样收集；
   * 数字/布尔按 String() 收集，标量形态与 JSON.stringify 结果一致，
   * 保证既有锚点仍可命中；null/undefined 不产生候选。
   *
   * 深度与节点预算：host 传入的 params 是 live 对象，可能循环引用或
   * 超深嵌套，无界递归会爆栈抛 RangeError，被评估 catch 后走 failStrategy
   * ——fail_open 下等价于整次评估全量放行。超限时只跳过越界
   * 子树并告警留痕，绝不上抛。
   */
  private static collectMatchStrings(value: unknown): string[] {
    const out: string[] = [];
    let nodes = 0;
    let truncated = false;
    // ancestors 只记录当前路径上的容器：既能断环，又不会因兄弟节点
    // 共享同一子树而漏收字符串。
    const ancestors = new Set<object>();
    const walk = (v: unknown, depth: number): void => {
      if (truncated) return;
      if (nodes >= RuleMatcher.MATCH_STRING_MAX_NODES) {
        truncated = true;
        return;
      }
      nodes++;
      if (typeof v === 'string') out.push(v);
      else if (typeof v === 'number' || typeof v === 'boolean') out.push(String(v));
      else if (Array.isArray(v)) {
        if (depth >= RuleMatcher.MATCH_STRING_MAX_DEPTH || ancestors.has(v)) {
          truncated = true;
          return;
        }
        ancestors.add(v);
        for (const item of v) walk(item, depth + 1);
        ancestors.delete(v);
      } else if (v && typeof v === 'object') {
        if (depth >= RuleMatcher.MATCH_STRING_MAX_DEPTH || ancestors.has(v)) {
          truncated = true;
          return;
        }
        ancestors.add(v);
        for (const item of Object.values(v)) walk(item, depth + 1);
        ancestors.delete(v);
      }
    };
    walk(value, 0);
    if (truncated && !RuleMatcher.matchStringsTruncatedWarned) {
      RuleMatcher.matchStringsTruncatedWarned = true;
      console.warn(
        `[RuleMatcher] params 嵌套超出提取上限（深度 ${RuleMatcher.MATCH_STRING_MAX_DEPTH} / 节点 ${RuleMatcher.MATCH_STRING_MAX_NODES}）或存在循环引用，`
          + '已跳过越界子树并继续评估；被跳过子树内的字符串不参与匹配'
      );
    }
    return out;
  }

  /**
   * 单字符串正则测试。原始值恒先测（保持 shipped 策略锚点兼容）；
   * 未命中且值为 path 形态时再测归一化候选。
   */
  private static testStringWithCandidates(compiled: RegExp[], s: string): boolean {
    for (let i = 0; i < compiled.length; i++) {
      if (compiled[i].test(s)) return true;
    }
    const candidates = this.pathCandidates(s);
    for (let c = 0; c < candidates.length; c++) {
      for (let i = 0; i < compiled.length; i++) {
        if (compiled[i].test(candidates[c])) return true;
      }
    }
    return false;
  }

  /** 字符串是否按路径形态处理：绝对/相对路径、盘符路径、无空白含分隔符的相对路径。 */
  private static isPathLike(s: string): boolean {
    const t = s.trim();
    if (!t) return false;
    if (/^[a-zA-Z]:[\\/]/.test(t)) return true;
    if (t.startsWith('/') || t.startsWith('./') || t.startsWith('../') || t.startsWith('~')) return true;
    return !/\s/.test(t) && /[\\/]/.test(t);
  }

  /** 点段解析（在统一为正斜杠的形态上执行）；绝对路径越界的 .. 钳制在根。 */
  private static resolveDotSegments(p: string): string {
    const winPrefix = /^[a-zA-Z]:\//.exec(p);
    const prefix = winPrefix ? winPrefix[0] : p.startsWith('/') ? '/' : '';
    const rest = p.slice(prefix.length);
    const out: string[] = [];
    for (const seg of rest.split('/')) {
      if (seg === '' || seg === '.') continue;
      if (seg === '..') {
        if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
        else if (!prefix) out.push('..');
      } else {
        out.push(seg);
      }
    }
    let resolved = prefix + out.join('/');
    if (!resolved) resolved = prefix || '.';
    if (p.endsWith('/') && !resolved.endsWith('/')) resolved += '/';
    return resolved;
  }

  // 归一化候选只依赖字符串本身，评估热路径上同值会反复出现（N 条规则
  // 扫同一 params），做有界进程内缓存避免重复点段解析。
  private static pathCandidateCache = new Map<string, string[]>();
  private static readonly PATH_CANDIDATE_CACHE_MAX = 4096;

  /** path 形态字符串的归一化候选（不含原始值本身），带进程内有界缓存。 */
  private static pathCandidates(value: string): string[] {
    if (!this.isPathLike(value)) return [];
    const cached = this.pathCandidateCache.get(value);
    if (cached) return cached;
    const resolved = this.resolveDotSegments(value.trim().replace(/\\/g, '/'));
    const isWinAbs = /^[a-zA-Z]:\//.test(resolved);
    const forms = [resolved];
    // NTFS 大小写不敏感：盘符绝对路径补充全小写形态。
    if (isWinAbs) forms.push(resolved.toLowerCase());
    const out: string[] = [];
    for (const f of forms) {
      out.push(f);
      const backslash = f.replace(/\//g, '\\');
      if (backslash !== f) out.push(backslash);
    }
    if (this.pathCandidateCache.size >= this.PATH_CANDIDATE_CACHE_MAX) {
      this.pathCandidateCache.clear();
    }
    this.pathCandidateCache.set(value, out);
    return out;
  }
}
