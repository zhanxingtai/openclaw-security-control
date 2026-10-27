import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * 事件 JSON Schema 防脱节（1.1.0）。
 *
 * security-events.jsonl 每行都带 `schema_version`，但此前全仓没有任何
 * schema 可对——版本号是个空承诺。schemas/security-event-v1.schema.json
 * 由 src/types.ts 生成，本测试守住三条线：
 *
 *   1. 生成物与类型定义一致（改 types.ts 必须重跑生成脚本）；
 *   2. 已收敛掉的同义字段**不得**再回到 schema 里（raw_params / result /
 *      execution_status / execution_duration_ms / result_preview_length）；
 *   3. schema 真的能校验一份样例事件（结构层面）。
 *
 * 不引入 ajv：校验器只需要覆盖"必填字段存在 + 类型正确 + 未知字段不炸"
 * 这三件事，为它拉一个依赖不划算（仓库无运行时依赖）。
 */

const root = join(__dirname, '..');
const schemaPath = join(root, 'schemas', 'security-event-v1.schema.json');
const typesPath = join(root, 'src', 'types.ts');

/** 已收敛掉的同义字段——出现即回退。 */
const REMOVED_FIELDS = [
  'raw_params',
  'raw_params_length',
  'result',
  'execution_status',
  'execution_duration_ms',
  'result_preview_length',
  // 内容寻址改造：全文/包体不再内嵌事件，事件流只带 hash 引用。
  'system_prompt',
  'asset_package',
  // 字段收敛（agent.json 1.1.0）：params 对象视图删除，tool_params 为唯一载荷。
  'params',
];

interface EventSchema {
  $schema: string;
  required: string[];
  properties: Record<string, SchemaNode>;
  additionalProperties: boolean;
}

interface SchemaNode {
  type?: string | string[];
  enum?: string[];
  description?: string;
  properties?: Record<string, SchemaNode>;
  items?: SchemaNode;
}

function loadSchema(): EventSchema {
  return JSON.parse(readFileSync(schemaPath, 'utf8')) as EventSchema;
}

/** 从 src/types.ts 抠出 SecurityEvent 的顶层字段名。 */
function securityEventFields(): string[] {
  const src = readFileSync(typesPath, 'utf8');
  const start = src.indexOf('export interface SecurityEvent {');
  expect(start).toBeGreaterThan(-1);
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
  const body = src.slice(src.indexOf('\n', start), end);
  const fields: string[] = [];
  for (const m of body.matchAll(/^  ([a-zA-Z_][a-zA-Z0-9_]*)\??:/gm)) {
    fields.push(m[1]);
  }
  return fields;
}

describe('事件 JSON Schema', () => {
  it('schema 文件存在且是合法的 JSON Schema 2020-12', () => {
    expect(existsSync(schemaPath)).toBe(true);
    const schema = loadSchema();
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.type).toBe('object');
  });

  it('覆盖 SecurityEvent 的每一个顶层字段（改 types.ts 必须重跑生成脚本）', () => {
    const schema = loadSchema();
    const fields = securityEventFields();
    expect(fields.length).toBeGreaterThan(100);
    const missing = fields.filter((f) => !(f in schema.properties));
    expect(missing, `types.ts 里的字段未进 schema：${missing.join(', ')}`).toEqual([]);
  });

  it('已收敛的同义字段不得回到 schema', () => {
    const schema = loadSchema();
    for (const field of REMOVED_FIELDS) {
      expect(
        field in schema.properties,
        `${field} 已在 1.1.0 收敛掉，不应再出现在 schema 里`
      ).toBe(false);
    }
  });

  it('必填字段是 event_id / event_type / layer / ts', () => {
    const schema = loadSchema();
    expect([...schema.required].sort()).toEqual(['event_id', 'event_type', 'layer', 'ts']);
  });

  it('layer 的取值被约束为 application / system / asset', () => {
    const schema = loadSchema();
    expect(schema.properties.layer.enum).toEqual(['application', 'system', 'asset']);
  });

  it('role / status 枚举收紧（规范 agent.json），redacted_keys 是字符串数组', () => {
    const schema = loadSchema();
    expect(schema.properties.role?.enum).toEqual(['user', 'assistant', 'system']);
    // cron 三事件收敛后 scheduled/started/finished 不再是 status 取值：
    // 运行归 x_openclaw_cron_run（success/failure），配置变化归
    // cron_changed（modified——平台已登记 schema 的枚举口径）。
    expect(schema.properties.status?.enum).toEqual([
      'success',
      'failure',
      'blocked',
      'error',
      'modified',
      'ended',
    ]);
    expect(schema.properties.redacted_keys?.type).toBe('array');
    expect(schema.properties.redacted_keys?.items?.type).toBe('string');
    expect(schema.properties.raw_params_hash?.type).toBe('string');
  });

  it('嵌套对象字面量被展开（collector / agents[] 不是空壳）', () => {
    const schema = loadSchema();

    // collector 是内联对象字面量，展开后才有约束力。
    const collector = schema.properties.collector;
    expect(collector?.type).toBe('object');
    expect(Object.keys(collector?.properties ?? {}).sort()).toEqual([
      'collector_name',
      'hook_name',
      'middleware_name',
    ]);

    // agents[] 元素是内联对象字面量，1.1.0 把 system_prompt 换成了
    // system_prompt_ref——这正是消费方最需要被 schema 挡住的地方。
    const agent = schema.properties.agents?.items;
    expect(agent?.type).toBe('object');
    expect(agent?.properties?.system_prompt_ref).toBeDefined();
    expect(agent?.properties?.system_prompt).toBeUndefined();
  });

  it('校验一份样例事件通过', () => {
    const schema = loadSchema();
    const event = {
      comm: 'openclaw',
      event_id: 'e2239b7f-3884-4c4b-9150-7750bfa4a9e5',
      event_type: 'process_start',
      layer: 'system',
      ts: 1792997944872,
      schema_version: 1,
      pid: 132,
      session_id: null,
      run_id: null,
      agent_id: null,
      host_id: 'cb8d8837113c',
      container_id: 'cb8d8837113c',
      source: 'openclaw.runtime-hooks.v1',
      collection_method: 'runtime',
      collector: {
        hook_name: 'process_start',
        middleware_name: 'sst-security-control-openclaw',
        collector_name: 'runtime-hook-collector',
      },
      cmdline: 'git status',
      exe: 'git',
      process_name: 'git',
      blocked: false,
    };

    for (const key of schema.required) {
      expect(event, `样例事件缺少必填字段 ${key}`).toHaveProperty(key);
    }
    for (const [key, value] of Object.entries(event)) {
      const prop = schema.properties[key];
      if (!prop || !prop.type) continue;
      const types = Array.isArray(prop.type) ? prop.type : [prop.type];
      const actual =
        value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
      const ok =
        types.includes(actual) ||
        (actual === 'number' && types.includes('integer')) ||
        (value === null && types.includes('null'));
      expect(ok, `字段 ${key} 的类型 ${actual} 不在 schema 允许范围 ${types.join('|')} 内`).toBe(true);
    }
  });
});
