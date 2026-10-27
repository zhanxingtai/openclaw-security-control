import { redactValueContent } from './redact.js';

/** 会话标题最大长度（按 Unicode code point 计，省略号计入总长）。 */
export const DEFAULT_SESSION_TITLE_LENGTH = 30;

const ELLIPSIS = '…';

/**
 * 整条消息就是一个斜杠命令（/new、/clear、/model gpt-4 …）时不适合拿来当标题。
 *
 * 标题是 first-write-wins 的：一旦被 "/new" 钉死，后面真正的正题再也换不掉。
 * 只认"整条以斜杠命令开头"——正文里出现斜杠（"看下 /api/users 接口"）不算命令。
 * 要求命令名后是空白或结尾，避免把 "/api/users" 这类路径误判成命令。
 */
const SLASH_COMMAND_ONLY = /^\/[A-Za-z0-9][\w-]*(?:\s|$)/;

/**
 * 定长截断，按 Unicode code point 计数。
 *
 * 不复用 truncate.ts 的 truncateString()：它按 UTF-16 code unit 切，emoji 会被
 * 从代理对中间劈开（半个乱码字符），而且省略号是拼在 maxLen 之外的，实际长度
 * 变成 maxLen+3，与"≤30 字"这个对外契约不符。
 */
export function truncateByCodePoint(text: string, maxLength: number): string {
  const max = Number.isFinite(maxLength) && maxLength > 0 ? Math.floor(maxLength) : 0;
  if (max === 0) return '';
  const chars = Array.from(text);
  if (chars.length <= max) return text;
  if (max === 1) return chars[0] ?? '';
  return chars.slice(0, max - 1).join('') + ELLIPSIS;
}

/** 第一个 trim 后非空的行；整段都是空白时返回 undefined。 */
function firstMeaningfulLine(text: string): string | undefined {
  for (const line of text.split(/\r?\n/)) {
    if (line.trim().length > 0) return line;
  }
  return undefined;
}

/**
 * 从一条 user 消息派生会话标题。
 *
 * 流水线：脱敏(全文) → 取首个非空行 → 压行内空白 → 定长截断（≤30 字）。
 *
 * 顺序上有两个刻意选择：
 * - 脱敏先于截断。否则一个跨越 30 字边界的凭据会在标题里留下前缀。
 * - 压空白只压行内、保留换行给"取首行"用。先全局压空白再取首行会取不到行。
 *
 * 返回 undefined 表示"这条消息不适合当标题"（空白、纯斜杠命令），调用方应当
 * 继续等下一条有效消息，而不是把标题定成空串。
 */
export function deriveSessionTitle(
  raw: unknown,
  maxLength: number = DEFAULT_SESSION_TITLE_LENGTH
): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;
  if (SLASH_COMMAND_ONLY.test(trimmed)) return undefined;

  const redacted = redactValueContent(raw);

  const line = firstMeaningfulLine(redacted);
  if (line === undefined) return undefined;

  const collapsed = line.replace(/\s+/g, ' ').trim();
  if (collapsed.length === 0) return undefined;

  return truncateByCodePoint(collapsed, maxLength);
}
