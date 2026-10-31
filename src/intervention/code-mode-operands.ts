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
 *
 * ⭐ **命令面 / 全文面两面模型**（#469-D · P3(b)）：
 *   - **命令面**（`params.command`）= 真正交给工具执行的实参 ⇒
 *     命令形态的规则只看它 ⇒ 散文不再触发误报；
 *   - **全文面**（`params.code_content`）= agent 写下的整段程序 ⇒
 *     审计与后续"内容形态"规则的锚点。
 *
 *   收窄只发生在**评估视图**里（`buildInterventionContext`）⇒ 事件里的
 *   `tool_params` 仍是宿主给的原始 params ⇒ **审计侧仍看得到全文**。
 */

/** 命令类实参键。 */
const COMMAND_KEYS = new Set([
  'command', 'cmd', 'script', 'shell', 'shellcommand', 'scripttext', 'args', 'argv',
]);

/** 路径类实参键（与 store.ts 的 normalizeFilePathParams 别名表同源）。 */
const PATH_KEYS = new Set([
  'path', 'file', 'filepath', 'file_path', 'filename', 'src', 'source', 'target', 'destination',
]);

/** 全文面锚点键（code-mode 程序原文）。 */
export const CODE_CONTENT_KEY = 'code_content';

/**
 * 是否为「命令面」键 —— 命令形态规则在这类键上匹配
 * （`command` / `cmd` / `script` … 与全文面锚点 `code_content`）。
 *
 * ⭐ 供申诉归因：code-mode 命中证据落在这些键上、且
 *   命令面未被收窄成实参列表时，命中面 = 整段程序文本（非实参）。
 */
export function isCommandSurfaceKey(field: string): boolean {
  return COMMAND_KEYS.has(field.toLowerCase()) || field === CODE_CONTENT_KEY;
}

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

/**
 * 变量绑定表。
 *
 * - `vars`：普通绑定（`const x = expr`）⇒ 变量名 → 初始化表达式原文。
 * - `destructured`：**数组解构**绑定（`for (const [a, b] of X)`）⇒
 *   变量名 → `{ source, index }`（取 X 每行的第 index 列）。
 *
 * ⭐ 解构绑定是 #469-D 的 D 样本形态：
 * ```js
 * const cmds = [["now-utc", "date -u +%Y-%m-%dT%H:%M:%S"]];
 * for (const [label, command] of cmds) { await exec({ command }); }
 * ```
 * 这里 `command` 既不是普通绑定（`const command =` 形式），也不在
 * `command:` 属性位上 —— 它是**属性简写** `{ command }` 的实参，
 * 值来自 for-of 解构 ⇒ 不认它就抽不到实参 ⇒ 命令面仍是整段程序。
 */
interface Bindings {
  vars: Map<string, string>;
  destructured: Map<string, { source: string; index: number }>;
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
 * 收集 for-of **数组解构**绑定：`for (const [a, b] of X)` ⇒
 * a → X 的第 0 列，b → X 的第 1 列。
 */
function collectDestructuredBindings(src: string): Map<string, { source: string; index: number }> {
  const out = new Map<string, { source: string; index: number }>();
  const re = /\bfor\s*(?:await\s*)?\(\s*(?:const|let|var)\s*\[([^\]]*)\]\s+of\s+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const source = readValueSpan(src, m.index + m[0].length);
    if (!source) continue;
    const names = m[1].split(',').map((n) => n.trim()).filter((n) => isIdent(n));
    names.forEach((name, index) => {
      out.set(name, { source, index });
    });
  }
  return out;
}

/** 收集全部绑定（普通 + 解构）。 */
function collectScope(src: string): Bindings {
  return {
    vars: collectBindings(src),
    destructured: collectDestructuredBindings(src),
  };
}

/**
 * 把一个值表达式解析成若干实参文本。
 *
 * - 静态字符串字面量 → 自身
 * - 数组 → 逐元素递归（元素是字符串才留）
 * - 标识符 → 顺着变量绑定再解析；解构绑定按「源数组每行的第 N 列」取值
 * - 拼接 → 逐段递归，可解析的片段留下、不可解析的片段跳过
 *
 * 任何解析不出来的东西（裸路径、函数调用结果、数字……）都返回空——
 * 宁可漏掉一个看不懂的实参，也不要把散文当成命令。
 */
function resolveValue(expr: string, scope: Bindings, depth: number): string[] {
  if (depth > MAX_RESOLVE_DEPTH) return [];
  const trimmed = expr.trim();
  if (!trimmed) return [];
  if (isStaticStringLiteral(trimmed)) return [unquote(trimmed)];
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const out: string[] = [];
    for (const el of splitTopLevel(trimmed.slice(1, -1), ',')) {
      out.push(...resolveValue(el, scope, depth + 1));
    }
    return out;
  }
  if (isIdent(trimmed)) {
    const bound = scope.vars.get(trimmed);
    if (bound !== undefined) return resolveValue(bound, scope, depth + 1);
    return resolveDestructured(trimmed, scope, depth + 1);
  }
  const out: string[] = [];
  for (const part of splitTopLevel(trimmed, '+')) {
    out.push(...resolveValue(part, scope, depth + 1));
  }
  return out;
}

/**
 * 解析解构绑定的取值：`for (const [a, b] of X)` 里的 `b` ⇒
 * X 每行的第 1 列。
 */
function resolveDestructured(name: string, scope: Bindings, depth: number): string[] {
  if (depth > MAX_RESOLVE_DEPTH) return [];
  const d = scope.destructured.get(name);
  if (!d) return [];
  const rows = resolveStringMatrix(d.source, scope, depth + 1);
  if (!rows) return [];
  const out: string[] = [];
  for (const row of rows) {
    const value = row[d.index];
    if (typeof value === 'string' && value) out.push(value);
  }
  return out;
}

/**
 * 把表达式解析成「字符串矩阵」（数组的数组），供数组解构按下标取值。
 *
 * ⚠️ **位置必须保持原位**：解析不出来的元素留 `undefined` 空位，
 * 不能跳过 —— 跳过会让后续列的下标整体错位（取到别的行的值）。
 */
function resolveStringMatrix(
  expr: string,
  scope: Bindings,
  depth: number
): (string | undefined)[][] | undefined {
  if (depth > MAX_RESOLVE_DEPTH) return undefined;
  const trimmed = expr.trim();
  if (!trimmed) return undefined;
  if (isIdent(trimmed)) {
    const bound = scope.vars.get(trimmed);
    if (bound === undefined) return undefined;
    return resolveStringMatrix(bound, scope, depth + 1);
  }
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const rows: (string | undefined)[][] = [];
    for (const el of splitTopLevel(trimmed.slice(1, -1), ',')) {
      const cell = el.trim();
      if (cell.startsWith('[') && cell.endsWith(']')) {
        const cols: (string | undefined)[] = [];
        for (const c of splitTopLevel(cell.slice(1, -1), ',')) {
          const cc = c.trim();
          if (isStaticStringLiteral(cc)) {
            cols.push(unquote(cc));
          } else {
            const parts = resolveValue(cc, scope, depth + 1);
            cols.push(parts.length ? parts.join('') : undefined);
          }
        }
        rows.push(cols);
      } else {
        const parts = resolveValue(cell, scope, depth + 1);
        rows.push([parts.length ? parts.join('') : undefined]);
      }
    }
    return rows;
  }
  return undefined;
}

/**
 * 扫出**属性简写**位置上的命令/路径类标识符。
 *
 * `exec({ command })` 里 `command` 是属性名、值来自变量 ⇒ 与
 * `exec({ command: cmd })` 是同一个"工具实参位"，但 `key:` 形态的
 * 扫描看不见它 ⇒ 专门补这一路。
 *
 * ⛔ 只认**命令/路径类**键名：函数实参里的同名变量（`f(a, command)`）
 *   不是"工具实参位"，不放进来（保持"只认工具实参位"这条底线）。
 * ⛔ 字符串字面量内部不扫（`text("a, command}")` 不是实参位）。
 */
function collectShorthandKeys(src: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (isQuote(c)) {
      i = scanStringLiteral(src, i);
      continue;
    }
    if (c === '{' || c === ',') {
      let j = i + 1;
      while (j < src.length && /\s/.test(src[j])) j++;
      const m = /^[A-Za-z_$][\w$]*/.exec(src.slice(j, j + 64));
      if (m) {
        const name = m[0];
        const lower = name.toLowerCase();
        if (COMMAND_KEYS.has(lower) || PATH_KEYS.has(lower)) {
          let k = j + name.length;
          while (k < src.length && /\s/.test(src[k])) k++;
          const next = src[k];
          if (next === ',' || next === '}') out.push(name);
        }
      }
      i = j;
      continue;
    }
    i++;
  }
  return out;
}

/**
 * 从 code-mode 程序里抽出真正传给工具调用的实参（命令串 / 文件路径）。
 *
 * 只认"工具实参位"——命令类与路径类属性的值、它们的变量绑定，以及
 * 属性简写（`{ command }`）的取值。写在 content/note 这类属性里的散文
 * 不会被收进来。
 */
export function extractCodeModeOperands(source: string): string[] {
  if (!source) return [];
  const scope = collectScope(source);
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (operand: string): void => {
    if (!operand || seen.has(operand)) return;
    seen.add(operand);
    out.push(operand);
  };

  // ① `key: value` 形态的命令/路径实参位
  const re = /([A-Za-z_$][\w$]*)\s*:\s*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const key = m[1].toLowerCase();
    if (!COMMAND_KEYS.has(key) && !PATH_KEYS.has(key)) continue;
    const expr = readValueSpan(source, m.index + m[0].length);
    if (!expr) continue;
    for (const operand of resolveValue(expr, scope, 0)) push(operand);
  }

  // ② 属性简写形态（`exec({ command })`）—— 值来自变量 / 解构绑定
  for (const name of collectShorthandKeys(source)) {
    for (const operand of resolveValue(name, scope, 0)) push(operand);
  }

  return out;
}

/**
 * 从 params 里去掉全文面锚点（`code_content`）。
 *
 * ⚠️ **只给「动作历史」用**：动作历史是 chain 匹配的输入源（chain 规则把
 *   历史动作的全部字符串拿来比 path/body 正则）⇒ 全文面（整段程序）留在
 *   里面会让 chain 规则扫到程序散文 ⇒ 多余命中。
 *   ⇒ 动作历史只留**命令面**（与真实执行一致）。
 */
export function stripCodeContent(
  params: Record<string, unknown> | undefined
): Record<string, unknown> | undefined {
  if (!params || !(CODE_CONTENT_KEY in params)) return params;
  const out = { ...params };
  delete out[CODE_CONTENT_KEY];
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
 * 真正传给工具的实参；同时把整段程序留在 `code_content`（全文面）。
 *
 * 抽不到实参时**不裁剪 command**（保留整段程序）——解析不了程序时不缩小
 * 覆盖面；但 `code_content` 仍然写入（全文面始终可得）。
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
  // ⛔ 抽不到实参 ⇒ command 保持整段程序（宁可多拦一次也不漏真实命令）；
  //   但全文面照样给出。
  if (operands.length === 0) {
    return { ...params, [CODE_CONTENT_KEY]: source };
  }
  return { ...params, command: operands.join('\n'), [CODE_CONTENT_KEY]: source };
}
