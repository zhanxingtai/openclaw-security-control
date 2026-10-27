/**
 * 从 src/types.ts 的 SecurityEvent 接口生成公开事件 JSON Schema。
 *
 * 手工维护 170+ 个字段的 schema 会立刻和类型定义脱节——这正是
 * `schema_version` 有版本号却没有 schema 可对的原因。这里把类型定义
 * 作为唯一事实源，生成 schemas/security-event-v1.schema.json；
 * tests/event-schema-coverage.test.ts 再校验生成物与类型定义一致。
 *
 * 解析策略：手写一个 brace/bracket/angle 感知的扫描器，而不是正则。
 * 正则切不出 `agents?: Array<{ ... }>` 这类嵌套字面量——而嵌套处正是
 * 1.1.0 改动最狠的地方（agents[].system_prompt → system_prompt_ref），
 * 恰恰是最需要被 schema 约束住的地方。
 *
 * 用法：node scripts/gen-event-schema.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const typesPath = path.join(root, 'src', 'types.ts');
const outPath = path.join(root, 'schemas', 'security-event-v1.schema.json');

const src = fs.readFileSync(typesPath, 'utf8');
const start = src.indexOf('export interface SecurityEvent {');
if (start < 0) throw new Error('SecurityEvent interface not found');
let depth = 0;
let end = -1;
for (let j = src.indexOf('{', start); j < src.length; j++) {
  if (src[j] === '{') depth++;
  else if (src[j] === '}') {
    depth--;
    if (depth === 0) {
      end = j;
      break;
    }
  }
}
if (end < 0) throw new Error('SecurityEvent interface end not found');
const body = src.slice(src.indexOf('\n', start) + 1, end);

// 类型别名解析：`export type SourceLayer = 'application' | ...`
// 注意：必须在**剥掉行注释之后**的副本上匹配——联合成员之间的注释行
// 可能带 ';'（如 "Deprecated alias kept for backward compatibility;"
// 旧实现用 [^;]+ 捕获，撞到注释里的分号就把别名截断，EventType 清单
// 因此曾只剩前 14 个成员。
const aliases = new Map();
const aliasRe = /^export type ([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);/gm;
const aliasSrc = src.replace(/\/\/[^\n]*/g, '');
let am;
while ((am = aliasRe.exec(aliasSrc)) !== null) {
  const value = am[2].replace(/\s+/g, ' ').trim();
  aliases.set(am[1], value);
}

/** 把 JSDoc / 行注释洗成一句可读的描述。 */
function cleanComment(raw) {
  let t = raw;
  if (t.startsWith('/*')) t = t.slice(2, t.endsWith('*/') ? -2 : undefined);
  else if (t.startsWith('//')) t = t.slice(2);
  t = t.replace(/^\s*\*+ ?/gm, '');
  t = t.replace(/\s+/g, ' ').trim();
  return t;
}

/**
 * 扫描一段类型文本，取出其中**直接**声明的字段。
 *
 * 文本可以是接口体（SecurityEvent 的花括号内内）），也可以是嵌套对象
 * 字面量的内容。嵌套对象的字段由 infer() 递归处理，不会在这里被误收。
 */
function parseFields(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  let pendingDesc = null;

  while (i < n) {
    // 空白
    while (i < n && /\s/.test(text[i])) i++;
    if (i >= n) break;

    // 注释
    if (text.startsWith('//', i)) {
      const eol = text.indexOf('\n', i);
      pendingDesc = cleanComment(text.slice(i, eol < 0 ? n : eol));
      i = eol < 0 ? n : eol + 1;
      continue;
    }
    if (text.startsWith('/*', i)) {
      const e = text.indexOf('*/', i + 2);
      pendingDesc = cleanComment(text.slice(i, e < 0 ? n : e + 2));
      i = e < 0 ? n : e + 2;
      continue;
    }

    // 字段名
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(text.slice(i));
    if (!m) {
      i++;
      continue;
    }
    const name = m[0];
    i += name.length;
    while (i < n && /\s/.test(text[i])) i++;

    let optional = false;
    if (text[i] === '?') {
      optional = true;
      i++;
      while (i < n && /\s/.test(text[i])) i++;
    }
    if (text[i] !== ':') continue; // 不是字段（少见的计算属性名等）
    i++; // 跳过 ':'

    // 类型文本：读到本层级的 ';' 为止，括号/花括号/尖括号各自配平。
    //
    // 注释**原样保留**在类型文本里：嵌套对象字面量里的 JSDoc 只有留在
    // 文本中，递归展开时才能被 parseFields 认领成字段描述。但注释里的
    // ';' 不能被当成分号终结符，所以遇到注释要整段跳过而不看内容。
    const typeStart = i;
    let d = 0;
    while (i < n) {
      const c = text[i];
      if (c === ';' && d === 0) break;
      if (c === '/' && text[i + 1] === '/') {
        const eol = text.indexOf('\n', i);
        i = eol < 0 ? n : eol;
        continue;
      }
      if (c === '/' && text[i + 1] === '*') {
        const e = text.indexOf('*/', i + 2);
        i = e < 0 ? n : e + 2;
        continue;
      }
      if (c === '{' || c === '[' || c === '<' || c === '(') d++;
      else if (c === '}' || c === ']' || c === ')' || c === '>') {
        if (d > 0) d--;
      }
      i++;
    }
    const type = text.slice(typeStart, i).trim();
    if (text[i] === ';') i++;

    out.push({ name, optional, type, description: pendingDesc });
    pendingDesc = null;
  }

  return out;
}

/** 取 `Foo<ARG>` 里 ARG 的原文（考虑嵌套的花括号/尖括号）。 */
function genericArg(text, start) {
  let d = 0;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === '<' || c === '{' || c === '[') d++;
    else if (c === '>' || c === '}' || c === ']') {
      if (c === '>') {
        if (d === 0) return text.slice(start, i);
        d--;
      } else {
        d--;
      }
    }
  }
  return text.slice(start);
}

/** 由 TS 类型文本推出 JSON Schema 片段。 */
function infer(typeText) {
  const raw = typeText.trim();
  if (!raw) return {};

  // 对象字面量类型 → 展开成真字段。
  // 注意：这里必须用未压缩空白的原文——压缩会把 JSDoc 压成单行，
  // 嵌套字段的描述就认不出来了。
  if (raw.startsWith('{') && raw.endsWith('}')) {
    return {
      type: 'object',
      properties: propertiesOf(raw.slice(1, -1)),
      additionalProperties: true,
    };
  }

  // Record<string, X> / 索引签名
  if (/^Record</.test(raw)) {
    return { type: 'object', additionalProperties: true };
  }

  // 数组
  if (raw.startsWith('Array<') || raw.startsWith('ReadonlyArray<')) {
    const inner = genericArg(raw, raw.indexOf('<') + 1).trim();
    return { type: 'array', items: infer(inner) };
  }
  // `Foo[]` 形式
  if (raw.endsWith('[]')) {
    return { type: 'array', items: infer(raw.slice(0, -2)) };
  }

  const t = raw.replace(/\s+/g, ' ').trim();

  // 联合：null / undefined 参与
  let resolved = t;
  if (aliases.has(t)) {
    resolved = aliases.get(t);
  }
  const parts = resolved
    .split('|')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const nullable = parts.includes('null') || parts.includes('undefined');
  const core = parts.filter((p) => p !== 'null' && p !== 'undefined');

  let schema;
  if (core.length === 0) {
    schema = {};
  } else if (core.length === 1) {
    const only = core[0];
    if (only === 'string' || only === 'number' || only === 'boolean') {
      schema = { type: only };
    } else if (only === 'object') {
      schema = { type: 'object' };
    } else if (only === 'unknown' || only === 'any' || only === 'never') {
      schema = {};
    } else {
      // 具名类型（接口、枚举别名等）——本 schema 不展开，由
      // additionalProperties 承载。
      schema = {};
    }
  } else if (core.every((p) => p === 'string' || p === 'number' || p === 'boolean')) {
    const kinds = new Set(core);
    schema = kinds.size === 1 ? { type: core[0] } : { type: [...kinds] };
  } else if (core.every((p) => /^'[^']*'$/.test(p))) {
    schema = { type: 'string', enum: core.map((p) => p.slice(1, -1)) };
  } else if (core.includes('string')) {
    // `EventType | string` 这类"字面量联合 + string"——对外就是字符串，
    // 具体取值由 README 的事件类型清单约束，不在 schema 里枚举。
    schema = { type: 'string' };
  } else {
    schema = {};
  }

  if (nullable && schema.type && !Array.isArray(schema.type)) {
    schema.type = [schema.type, 'null'];
  }
  return schema;
}

/** 一段字段声明文本 → JSON Schema 的 properties。 */
function propertiesOf(text) {
  const props = {};
  for (const f of parseFields(text)) {
    const s = infer(f.type);
    if (f.description) s.description = f.description;
    props[f.name] = s;
  }
  return props;
}

const properties = propertiesOf(body);

// 关键字段的说明（其余字段沿用 types.ts 里的 JSDoc）
const descriptions = {
  event_id: '事件唯一标识（UUID）。',
  event_type:
    '事件类型。本插件实际会写出的取值：' +
    (aliases.get('EventType') || '')
      .split('|')
      .map((s) => s.trim().replace(/^'|'$/g, ''))
      .filter(Boolean)
      .join('、') +
    '。宿主可能扩展自定义类型，因此不设 enum 约束。',
  layer: '事件所属层：application | system | asset。',
  ts: '事件发生时间（Unix 毫秒）。',
  schema_version: '事件 schema 版本，与 schemas/security-event-v1.schema.json 对应。',
  session_id: '会话标识。runtime 层事件在没有宿主会话上下文时为 null。',
  run_id: '运行标识。',
  agent_id: '智能体标识。',
  host_id: '宿主主机标识。',
  container_id: '容器标识。非容器部署时与 host_id 相同。',
  source: '采集来源，形如 <project>.<component>.<version>。',
  collection_method: '采集方式：hook | runtime | ebpf | procfs | agent_api | asset_sync。',
  collector: '采集器元数据（hook 名称、中间件名称、采集器名称）。',
  tool_call_id: '关联键：一次工具调用的唯一标识（插件合成，权威关联键）。',
  host_tool_call_id: '宿主原始的工具调用 id，仅用于与宿主日志对账。',
  blocked:
    '是否被策略拦截。恒为布尔值：false 表示未被拦截（不代表未被策略命中，warn/modify 记在 intervention.decision）。',
  status: '事件状态，取值随事件类型而异（success/failure、scheduled/started/finished、ended …）。',
  duration: '执行耗时（毫秒）。',
  result_size: '工具结果原始长度（未截断）。',
  result_preview: '工具结果预览（截断后的字符串）。',
  tool_params: '工具参数的规范化 JSON 字符串。',
  tool_params_length: 'tool_params 截断前的原始长度。',
  params: '工具参数（对象视图）。',
  system_prompt_ref:
    '系统提示词内容指纹（sha256 前 16 位十六进制）。事件流不再内嵌 system_prompt 全文；全文全局唯一一份落在与 security-events.jsonl 同目录的 security-prompts.jsonl，按完整 prompt_hash 内容寻址。',
  asset_package_hash:
    '资产包（zip）内容寻址 sha256。包体原文在 <ndjsonDir>/asset-blobs/<hash>，事件不再内嵌 asset_package。',
  content_truncated: '载荷是否被截断。true 时 content_length 仍是原始长度。',
  content_length: '载荷原始长度（未截断）。',
  content: '载荷内容（按配置截断后）。',
  intervention: '干预决策留痕。',
  risk_flags: '风险标签列表。',
  agents: '智能体清单（agent_start）。系统提示词只以 system_prompt_ref 形式出现。',
};
for (const [key, desc] of Object.entries(descriptions)) {
  if (properties[key]) properties[key].description = desc;
}

const schema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://github.com/zhanxingtai/openclaw-security-control/schemas/security-event-v1.schema.json',
  title: 'OpenClaw Security Monitor 事件',
  description:
    'security-events.jsonl 单行（NDJSON）的结构定义。每个事件对象都必须满足本 schema。' +
    '事件类型清单见 README「Security Events」一节。',
  type: 'object',
  required: ['event_id', 'event_type', 'layer', 'ts'],
  properties,
  additionalProperties: true,
};

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(schema, null, 2) + '\n', 'utf8');
console.log(`wrote ${path.relative(root, outPath)} (${Object.keys(properties).length} properties)`);
