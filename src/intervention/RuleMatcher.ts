/**
 * OpenClaw Security Monitor - Rule Matcher
 *
 * Evaluates a single policy rule against an intervention context.
 * Supports SPL-style match fields.
 *
 * 正则维度全部改用 RuleRegexCache 的预编译产物，
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
import { maskMatchedText } from './match-evidence.js';
import type { RuleMatchEvidence } from './match-evidence.js';

export interface RuleMatchResult {
  matched: boolean;
  rule?: PolicyRule;
  /**
   * 命中证据：命中了哪个字段 / 哪条 pattern / 哪段文本（已打码）。
   * 非正则维度命中（`fieldEquals` / `fieldIn` / `chain` / `actionType`）
   * 时没有证据 —— 缺证据 ≠ 没有命中，只表示这条规则不是靠文本正则命中的。
   */
  evidence?: RuleMatchEvidence;
}

/** 单次正则命中在文本上的定位结果（供证据构造用）。 */
interface PatternHit {
  /** 命中的 pattern 下标（在该字段的 pattern 列表内，0 基）。 */
  index: number;
  /** 命中所在文本（原始值或归一化候选）。 */
  text: string;
  /** 命中子串本身。 */
  matched: string;
  /** 命中子串在 `text` 中的起始下标。 */
  matchIndex: number;
  /**
   * 命中的文本是原始值还是归一化候选。
   * ⛔ 归一化候选上的下标不是原始字段值里的下标 ⇒ 证据的
   *   `matchStart/matchEnd` 只能填 `-1`（占位），否则消费方按区间回查
   *   原始字段会定位到错误的字符。
   */
  normalized: boolean;
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
    const sessionOutcome = this.matchSessionRegex(ctx, rx);
    if (!sessionOutcome.matched) return { matched: false };
    // 命中证据：paramsRegex 命中记「哪个 key / 哪条 pattern / 哪段文本」；
    // paramsRegex 没命中但 bodyRegex 命中时退回 body 证据；两者都没有但
    // sessionRegex 命中时退回 sessionId 证据。非正则维度命中时没有证据。
    const paramsOutcome = this.matchParamsRegex(ctx, match, rx);
    if (!paramsOutcome.matched) return { matched: false };
    let evidence = paramsOutcome.evidence ?? sessionOutcome.evidence;
    if (!this.matchParamsNotRegex(ctx, match, rx)) return { matched: false };
    if (!this.matchFieldEquals(ctx, match)) return { matched: false };
    if (!this.matchFieldIn(ctx, match)) return { matched: false };
    const bodyOutcome = this.matchBodyRegex(ctx, rx);
    if (!bodyOutcome.matched) return { matched: false };
    if (!evidence) evidence = bodyOutcome.evidence;
    if (!this.matchChain(ctx, rx)) return { matched: false };

    return { matched: true, rule, evidence };
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

  /**
   * sessionId 维度匹配（产出 sessionRegex 证据）。
   * sessionId 不是敏感值，但"命中了哪条 session 规则"仍是定位信息 ⇒
   * 与 paramsRegex / bodyRegex 同口径产出证据。
   */
  private static matchSessionRegex(
    ctx: InterventionContext,
    rx: CompiledRuleRegexes
  ): { matched: boolean; evidence?: RuleMatchEvidence } {
    if (!rx.sessionRegex) return { matched: true };
    if (!ctx.sessionId) return { matched: false };
    const sessionId = ctx.sessionId;
    for (let i = 0; i < rx.sessionRegex.length; i++) {
      const re = rx.sessionRegex[i];
      re.lastIndex = 0;
      const m = re.exec(sessionId);
      if (!m) continue;
      return {
        matched: true,
        evidence: {
          fieldName: 'sessionId',
          pattern: re.source ?? '',
          matchType: 'sessionRegex',
          matchedText: maskMatchedText(m[0]),
          matchStart: m.index,
          matchEnd: m.index + m[0].length,
        },
      };
    }
    return { matched: false };
  }

  private static matchParamsRegex(
    ctx: InterventionContext,
    match: PolicyRule['match'],
    rx: CompiledRuleRegexes
  ): { matched: boolean; evidence?: RuleMatchEvidence } {
    const map = match.paramsRegex;
    if (!map) return { matched: true };
    const compiledMap = rx.paramsRegex;
    const exceptMap = rx.paramsRegexExcept;
    const params = ctx.params || {};

    // **缺 key 语义 = 跳过该 key**（与 `matchParamsNotRegex` 同口径）。
    //
    // 旧行为是「任一声明的 key 在 ctx 里不存在 ⇒ 整条规则不匹配」——多 key
    // 规则（自保护族 action/path/raw/value/content/data/note 共 7 key）几乎
    // 永远不命中，形同虚设。规则作者的自带 testCase 写明的预期语义是「缺
    // key 也拦」（准入路径本身不可放行）⇒ 缺 key 跳过才是预期。
    //
    // ⛔ 仍保留「一个 key 都没查 ⇒ 不匹配」（checkedAtLeastOne），不会把
    //   「ctx 完全没有相关参数」误判成命中。
    let checkedAtLeastOne = false;
    // 命中证据只记**第一条**命中的 key（多 key 规则命中时，取遍历序首个）；
    // 证据的用途是「定位到具体字段」，不是穷举全部命中面。
    let evidence: RuleMatchEvidence | undefined;

    // 热路径用 for-in 遍历，避免每次评估分配 Object.entries。
    for (const key in map) {
      if (!Object.prototype.hasOwnProperty.call(map, key)) continue;
      // 该 key 无编译产物只在非法正则时发生（compiled=null 已整体短路），
      // 这里做防御性跳过，保持"跳过该规则"语义。
      const compiled = compiledMap?.[key];
      if (!compiled) return { matched: false };
      const except = exceptMap?.[key];
      // 递归提取 key 指向值（含嵌套对象/数组）中的全部字符串逐值
      // 匹配，任一候选命中即算该 key 命中。不再 JSON.stringify——为字符串
      // 设计的锚点正则此前无法命中藏进嵌套结构的命令，还会因引号/转义
      // 产生反向误报。key 存在但取不到任何可匹配值时视为不匹配。
      const value = this.getNestedValue(params, key);
      if (typeof value === 'string') {
        // 热路径：字符串值先直测原始值，未命中才归一化（见 testStringWithCandidates）。
        const hit = this.testStringWithCandidatesEx(compiled, except, value);
        if (!hit) return { matched: false };
        checkedAtLeastOne = true;
        if (!evidence) evidence = this.buildEvidence(key, compiled, hit);
        continue;
      }
      const strings = this.collectMatchStrings(value);
      if (strings.length === 0) continue;
      let hit: PatternHit | undefined;
      for (let s = 0; s < strings.length && !hit; s++) {
        hit = this.testStringWithCandidatesEx(compiled, except, strings[s]);
      }
      if (!hit) return { matched: false };
      checkedAtLeastOne = true;
      if (!evidence) evidence = this.buildEvidence(key, compiled, hit);
    }

    return { matched: checkedAtLeastOne, evidence };
  }

  /**
   * 由一次正则命中构造结构化证据。
   * `matchedText` 走 {@link maskMatchedText}：命中片段里的 token 段替换为
   * `***` ⇒ 证据可定位到「哪一段」，但不把凭据原文抄进事件。
   * `matchStart/matchEnd` 指向原始字段值里的区间；命中发生在归一化候选上时
   * 置 `-1`（占位）——候选上的下标不是原始值的下标。
   */
  private static buildEvidence(
    field: string,
    compiled: RegExp[],
    hit: PatternHit
  ): RuleMatchEvidence {
    const located = !hit.normalized;
    return {
      fieldName: field,
      pattern: compiled[hit.index]?.source ?? '',
      matchType: 'paramsRegex',
      matchedText: maskMatchedText(hit.matched),
      matchStart: located ? hit.matchIndex : -1,
      matchEnd: located ? hit.matchIndex + hit.matched.length : -1,
    };
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

  private static matchBodyRegex(
    ctx: InterventionContext,
    rx: CompiledRuleRegexes
  ): { matched: boolean; evidence?: RuleMatchEvidence } {
    if (!rx.bodyRegex) return { matched: true };
    const body = ctx.body || ctx.userPrompt || '';
    const hit = this.matchTextAgainstPatterns(rx.bodyRegex, undefined, body);
    if (!hit) return { matched: false };
    return {
      matched: true,
      evidence: {
        fieldName: 'body',
        pattern: rx.bodyRegex[hit.index]?.source ?? '',
        matchType: 'bodyRegex',
        matchedText: maskMatchedText(hit.matched),
        matchStart: hit.matchIndex,
        matchEnd: hit.matchIndex + hit.matched.length,
      },
    };
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
    return this.testStringWithCandidatesEx(compiled, undefined, s) !== undefined;
  }

  /**
   * 逐条 pattern 判定一个字符串是否命中该 key。
   *
   * `except` 是条目级专属豁免（与 paramsRegex 下标一一对应）：某条 pattern
   * 命中但它自己的豁免也命中同一段文本时，这条 pattern 视为未命中——同 key
   * 的其它 pattern 不受影响。
   *
   * 豁免与 pattern 必须在同一段文本上比较：pattern 命中原串而豁免只命中
   * 归一化候选（反之亦然）都算"该文本未被豁免"，避免归一化路径把豁免绕开
   * 或凭空生效。
   *
   * 返回值带命中定位（哪条 pattern / 哪段文本 / 下标）⇒ 命中证据直接从这里
   * 构造，不必二次匹配。
   */
  private static testStringWithCandidatesEx(
    compiled: RegExp[],
    except: RegExp[][] | undefined,
    s: string
  ): PatternHit | undefined {
    const direct = this.matchTextAgainstPatterns(compiled, except, s);
    if (direct) {
      return {
        index: direct.index,
        text: s,
        matched: direct.matched,
        matchIndex: direct.matchIndex,
        normalized: false,
      };
    }
    const candidates = this.pathCandidates(s);
    for (let c = 0; c < candidates.length; c++) {
      const hit = this.matchTextAgainstPatterns(compiled, except, candidates[c]);
      if (hit) {
        return {
          index: hit.index,
          text: candidates[c],
          matched: hit.matched,
          matchIndex: hit.matchIndex,
          normalized: true,
        };
      }
    }
    return undefined;
  }

  /**
   * 同一段文本上：任一 pattern 命中且未被本条专属豁免命中 → 命中，
   * 并回报是哪一条 pattern、命中了哪段子串、子串在文本里的下标。
   * 用 `exec`（而非 `test`）是为了拿命中子串与下标 —— 证据构造需要。
   */
  private static matchTextAgainstPatterns(
    compiled: RegExp[],
    except: RegExp[][] | undefined,
    text: string
  ): { index: number; matched: string; matchIndex: number } | undefined {
    for (let i = 0; i < compiled.length; i++) {
      const re = compiled[i];
      // 规则 flags 只允许 i/m/s（禁 g/y）⇒ lastIndex 恒为 0；这里显式归零
      // 是防御性的（编译产物是进程内共享实例，不能带状态）。
      re.lastIndex = 0;
      const m = re.exec(text);
      if (!m) continue;
      const own = except?.[i];
      if (own && own.length > 0) {
        let exempted = false;
        for (let e = 0; e < own.length; e++) {
          own[e].lastIndex = 0;
          if (own[e].test(text)) { exempted = true; break; }
        }
        if (exempted) continue;
      }
      return { index: i, matched: m[0], matchIndex: m.index };
    }
    return undefined;
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
