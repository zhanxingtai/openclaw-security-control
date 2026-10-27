/**
 * OpenClaw Security Monitor - code-mode 实参提取
 *
 * code-mode（toolKind=code_mode_exec）事件的 params.command 装的是整段
 * JavaScript 程序，不是 shell 命令串。命令形态的规则（block-exec-sensitive-file、
 * 反弹 shell、插件路径引用等）拿整段程序当命令匹配，会把散文里的
 * "getent passwd"、"sudo cat /etc/shadow" 当成真实命令 —— 2026-10-27 的
 * 采集数据里 27 个被拦动作有 25 个是这类散文误报。
 *
 * 这里把程序里真正传给工具调用的实参（命令串、文件路径）抽出来，作为
 * 命令面交给规则匹配；写在 content/note 里的说明文字不再参与命令形态
 * 的匹配。
 *
 * 两条底线：
 *  1. 抽不到任何实参时不做裁剪（保留整段程序）—— 宁可多拦一次，也不因
 *     解析不了程序而漏掉真实命令。
 *  2. 只认"工具实参位"（命令/路径类属性值与它们的变量绑定），不扫全文的
 *     字符串字面量 —— 否则散文里的路径又会混回来。
 *
 * 路径类实参（tools.read({path:"/etc/shadow"})）也并入命令面：命令形态
 * 规则里的敏感路径模式（universal path patterns）就长在 command 键上，
 * 只走 path 键的话代码模式里的敏感文件读取会失去唯一的拦截点。
 */

/** 命令类实参键。 */
const COMMAND_KEYS = new Set([
  'command', 'cmd', 'script', 'shell', 'shellcommand', 'scripttext', 'args', 'argv',
]);

/** 路径类实参键（与 store.ts 的 normalizeFilePathParams 别名表同源）。 */
const PATH_KEYS = new Set([
  'path', 'file', 'filepath', 'file_path', 'filename', 'src', 'source', 'target', 'destination',
]);

/** 变量绑定解析深度上限（防互相引用导致的递归）。 */
const MAX_RESOLVE_DEPTH = 4;

function isIdent(text: string): boolean {
  return /^[A-Za-z_$][\w$]*$/.test(text);
}

function isQuote(ch: string): boolean {
  return ch === '"' || ch === "'" || ch === '`';
}

/**
 * 扫过字符串字面量，返回闭引号之后的下标。
 * 模板字面量里的 ${...} 插值整段跳过（插值内容不是静态文本）。
 */
function scanStringLiteral(src: string, start: number): number {
  const quote = src[start];
  let j = start + 1;
  while (j < src.length) {
    const c = src[j];
    if (c === '\\') {
      j += 2;
      continue;
    }
    if (c === quote) return j + 1;
    if (quote === '`' && c === '$' && src[j + 1] === '{') {
      let depth = 1;
      j += 2;
      while (j < src.length && depth > 0) {
        const d = src[j];
        if (isQuote(d)) {
          j = scanStringLiteral(src, j);
          continue;
        }
        if (d === '{') depth++;
        else if (d === '}') depth--;
        j++;
      }
      continue;
    }
    j++;
  }
  return src.length;
}

/** 扫过括号/花括号配对，返回配对闭合符之后的下标。 */
function scanBracket(src: string, start: number): number {
  const open = src[start];
  const close = open === '[' ? ']' : '}';
  let depth = 0;
  let j = start;
  while (j < src.length) {
    const c = src[j];
    if (isQuote(c)) {
      j = scanStringLiteral(src, j);
      continue;
    }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return j + 1;
    }
    j++;
  }
  return src.length;
}

/**
 * 从 start 起读一个"值表达式"的文本范围：字符串字面量 / 数组 / 对象 /
 * 标识符 / 拼接 / 调用表达式。顶层的 , } ; 视为结束。
 */
function readValueSpan(src: string, start: number): string {
  let i = start;
  while (i < src.length && /\s/.test(src[i])) i++;
  if (i >= src.length) return '';
  const ch = src[i];
  if (isQuote(ch)) {
    return src.slice(i, scanStringLiteral(src, i));
  }
  if (ch === '[' || ch === '{') {
    return src.slice(i, scanBracket(src, i));
  }
  let depth = 0;
  let j = i;
  while (j < src.length) {
    const c = src[j];
    if (isQuote(c)) {
      j = scanStringLiteral(src, j);
      continue;
    }
    if (c === '(' || c === '[' || c === '{') {
      depth++;
      j++;
      continue;
    }
    if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
      j++;
      continue;
    }
    if (depth === 0 && (c === ',' || c === ';')) break;
    j++;
  }
  return src.slice(i, j);
}

/** 按顶层分隔符切分（字符串与括号内不算分隔）。 */
function splitTopLevel(src: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  let j = 0;
  while (j < src.length) {
    const c = src[j];
    if (isQuote(c)) {
      j = scanStringLiteral(src, j);
      continue;
    }
    if (c === '(' || c === '[' || c === '{') {
      depth++;
      j++;
      continue;
    }
    if (c === ')' || c === ']' || c === '}') {
      depth--;
      j++;
      continue;
    }
    if (depth === 0 && c === sep) {
      parts.push(src.slice(last, j));
      last = j + 1;
    }
    j++;
  }
  parts.push(src.slice(last));
  return parts;
}

/** 是不是不含插值的静态字符串字面量。 */
function isStaticStringLiteral(text: string): boolean {
  if (text.length < 2) return false;
  const q = text[0];
  if (!isQuote(q) || text[text.length - 1] !== q) return false;
  if (q === '`' && text.includes('${')) return false;
  return true;
}

/** 去掉引号并还原转义。 */
function unquote(literal: string): string {
  const body = literal.slice(1, -1);
  return body.replace(/\\(.)/g, (_m, c: string) => {
    switch (c) {
      case 'n': return '\n';
      case 't': return '\t';
      case 'r': return '\r';
      default: return c;
    }
  });
}

/** 收集 const/let/var 绑定：变量名 → 初始化表达式原文。 */
function collectBindings(src: string): Map<string, string> {
  const bindings = new Map<string, string>();
  const re = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const expr = readValueSpan(src, m.index + m[0].length);
    if (expr) bindings.set(m[1], expr);
  }
  return bindings;
}

/**
 * 把一个值表达式解析成若干实参文本。
 *
 * - 静态字符串字面量 → 自身
 * - 数组 → 逐元素递归（元素是字符串才留）
 * - 标识符 → 顺着变量绑定再解析
 * - 拼接 → 逐段递归，可解析的片段留下、不可解析的片段跳过
 *
 * 任何解析不出来的东西（裸路径、函数调用结果、数字……）都返回空——
 * 宁可漏掉一个看不懂的实参，也不要把散文当成命令。
 */
function resolveValue(expr: string, bindings: Map<string, string>, depth: number): string[] {
  if (depth > MAX_RESOLVE_DEPTH) return [];
  const trimmed = expr.trim();
  if (!trimmed) return [];
  if (isStaticStringLiteral(trimmed)) return [unquote(trimmed)];
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const out: string[] = [];
    for (const el of splitTopLevel(trimmed.slice(1, -1), ',')) {
      out.push(...resolveValue(el, bindings, depth + 1));
    }
    return out;
  }
  if (isIdent(trimmed)) {
    const bound = bindings.get(trimmed);
    if (bound === undefined) return [];
    return resolveValue(bound, bindings, depth + 1);
  }
  const out: string[] = [];
  for (const part of splitTopLevel(trimmed, '+')) {
    out.push(...resolveValue(part, bindings, depth + 1));
  }
  return out;
}

/**
 * 从 code-mode 程序里抽出真正传给工具调用的实参（命令串 / 文件路径）。
 *
 * 只认"工具实参位"——命令类与路径类属性的值，以及它们引用的变量绑定。
 * 写在 content/note 这类属性里的散文不会被收进来。
 */
export function extractCodeModeOperands(source: string): string[] {
  if (!source) return [];
  const bindings = collectBindings(source);
  const out: string[] = [];
  const seen = new Set<string>();
  const re = /([A-Za-z_$][\w$]*)\s*:\s*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const key = m[1].toLowerCase();
    if (!COMMAND_KEYS.has(key) && !PATH_KEYS.has(key)) continue;
    const expr = readValueSpan(source, m.index + m[0].length);
    if (!expr) continue;
    for (const operand of resolveValue(expr, bindings, 0)) {
      if (!operand || seen.has(operand)) continue;
      seen.add(operand);
      out.push(operand);
    }
  }
  return out;
}

/**
 * 判断一份 params 是否来自 code-mode。
 *
 * 首选 toolKind（宿主明确标记）；toolKind 缺失时用结构特征兜底：
 * code-mode 事件的 params.code 与 params.command 同值（整段程序），
 * 原生 exec 事件没有 code 字段。
 */
export function isCodeModeParams(toolKind: string | undefined, params: Record<string, unknown>): boolean {
  if (toolKind === 'code_mode_exec') return true;
  if (toolKind !== undefined && toolKind !== 'native') return false;
  return typeof params.code === 'string' && params.command === params.code;
}

/**
 * 把 code-mode 的 params 收窄成"命令面"：params.command 由整段程序换成
 * 真正传给工具的实参。
 *
 * 抽不到实参时原样返回（保留整段程序）——解析不了程序时不缩小覆盖面。
 */
export function narrowCodeModeCommand(
  toolKind: string | undefined,
  params: Record<string, unknown>
): Record<string, unknown> {
  if (!isCodeModeParams(toolKind, params)) return params;
  const source = typeof params.code === 'string'
    ? params.code
    : (typeof params.command === 'string' ? params.command : '');
  if (!source) return params;
  const operands = extractCodeModeOperands(source);
  if (operands.length === 0) return params;
  return { ...params, command: operands.join('\n') };
}
