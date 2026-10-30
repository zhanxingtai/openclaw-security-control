/**
 * OpenClaw Security Monitor - 命中证据（Match Evidence）
 *
 * 每条命中规则附带一条结构化证据，回答「这条规则凭哪一段文本命中」：
 * 命中发生在哪个字段、用的哪条 pattern、命中片段的位置区间。
 *
 * 字段：fieldName（`paramsRegex` 的 key / `body` / `sessionId`）、pattern
 * （规则里的正则原文）、matchType（`paramsRegex` / `bodyRegex` /
 * `sessionRegex`）、matchedText（命中片段，已打码）、matchStart/matchEnd
 * （片段在字段值中的字符区间）。
 *
 * ⛔ `matchedText` 必然打码：命中片段往往就是凭据本身（token 段），原样落
 *   事件等于把被拦下的密钥再抄一份进日志。打码由证据层自证（见
 *   {@link maskMatchedText}），不依赖采集侧的键名级脱敏兜底。
 *
 * ⚠️ 打码后 `matchedText` 的长度不等于 `matchEnd - matchStart`：区间指向
 *   原始字段值，文本是打码后的呈现。
 */

/**
 * 命中类别。插件侧目前只会产出 `paramsRegex` / `bodyRegex` / `sessionRegex`
 * 三种（其余维度命中时不产证据 ⇒ 缺证据 ≠ 没命中）。
 */
export type MatchType =
  | 'actionType'
  | 'paramsRegex'
  | 'sessionRegex'
  | 'bodyRegex'
  | 'fieldEquals'
  | 'riskFlags'
  | 'other';

/**
 * 单条命中证据（引擎内部形态）。
 *
 * 事件层（`src/types.ts`）用的是 snake_case 形态（`field_name` /
 * `match_start` …），转换点在采集层 —— 本结构是引擎内部形态。
 */
export interface RuleMatchEvidence {
  /** 命中的 ctx 字段名（`paramsRegex` 的 key / `body` / `sessionId`）。 */
  fieldName: string;
  /** 命中的正则原文（来自规则，不是用户数据）。 */
  pattern: string;
  /** 命中类别。 */
  matchType: MatchType;
  /** 命中片段（已打码，见 {@link maskMatchedText}）。 */
  matchedText: string;
  /**
   * 命中片段在**命中所在文本**中的字符起点。
   * 「命中所在文本」= 该字段的值；字段值是嵌套对象/数组时 = 递归抽出的
   * 那段字符串。命中发生在 path 归一化候选上时为 `-1`（占位）——候选上的
   * 下标不是原始值的下标。
   */
  matchStart: number;
  /** 命中片段在命中所在文本中的字符终点（不含）。 */
  matchEnd: number;
}

/** 打码占位符。 */
export const EVIDENCE_MASK = '***';

/**
 * 达到该长度的 token 段视为「可能是密钥」并整体打码。
 * 取 6：低于 6 的段（`curl` / `-u` / `admin`）保留下来还能让人看出命中
 * 片段的形状；≥6 的段一律 `***`。
 */
export const EVIDENCE_MASK_MIN_RUN = 6;

/**
 * token 段字符集：字母 / 数字 / `_` / `-` / `.` / `~` / `+` / `/`。
 * ⛔ 不含 `=`：`=` 在凭据里是分隔符（`password=xxx`）而不是密钥的一部分，
 *   留在段外，打码后仍能看出"这是 key=value 形态"。
 */
const TOKEN_RUN_RE = /[A-Za-z0-9_\-./~+]+/g;

/**
 * 把命中片段打码：长度 ≥ {@link EVIDENCE_MASK_MIN_RUN} 的 token 段整体
 * 替换为 `***`，短 token 保留。
 *
 * 例：
 * - `Bearer gx1234567890abcdef` → `*** ***`
 * - `curl -u admin:sup3rsecret` → `curl -u admin:***`
 * - `password=MySecretPass123` → `***=***`
 *
 * 命中片段为空（零宽匹配）时原样返回。
 */
export function maskMatchedText(text: string): string {
  if (!text) return text;
  return text.replace(TOKEN_RUN_RE, (run) =>
    run.length >= EVIDENCE_MASK_MIN_RUN ? EVIDENCE_MASK : run
  );
}

/**
 * 事件层形态（snake_case）—— `src/types.ts` 的
 * `intervention.matched_rules[].evidence`。
 */
export interface EventMatchEvidence {
  /** 命中的字段名（paramsRegex 的 key / `body` / `sessionId`）。 */
  field_name?: string;
  /** 命中的正则原文（来自规则，不是用户数据）。 */
  pattern?: string;
  /** 命中类别。 */
  match_type?: string;
  /** 命中片段（已打码）。 */
  matched_text?: string;
  /** 命中片段在字段原始值中的字符起点。 */
  match_start?: number;
  /** 命中片段在字段原始值中的字符终点（不含）。 */
  match_end?: number;
}

/**
 * 引擎内部证据 → 事件层形态（snake_case）。
 *
 * 事件契约用 snake_case（与 `matched_rules` 其余字段一致）；
 * 引擎内部用 camelCase（与 TS 惯例一致）⇒ 转换点唯一落在本函数。
 */
export function toEventEvidence(evidence: RuleMatchEvidence): EventMatchEvidence {
  return {
    field_name: evidence.fieldName,
    pattern: evidence.pattern,
    match_type: evidence.matchType,
    matched_text: evidence.matchedText,
    match_start: evidence.matchStart,
    match_end: evidence.matchEnd,
  };
}

