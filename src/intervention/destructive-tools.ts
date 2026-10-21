/**
 * 单源 destructive tool 字典。
 *
 * 设计原则：保守默认、显式扩展。SelfProtection 的"破坏性工具名"判定
 * 不再在 SelfProtection.ts 里硬编码枚举；这里暴露 set + helper。
 *
 * 任何超出下表的工具名必须经 plugins/agents 自身 manifest 显式声明
 * 写入能力（见 plugins.<id>.capabilities.destructive_write_tools），
 * 不要在这里塞新默认 —— 默认值的扩大会让"工具名白名单"从白名单
 * 退化为黑名单，blast radius 直接打到所有用户。
 */

const WRITE_TOOLS: ReadonlySet<string> = new Set([
  'file_write',
  'write',
  'Write',
  'fs.writeFile',
]);

const DELETE_TOOLS: ReadonlySet<string> = new Set([
  'file_delete',
  'delete',
  'remove',
  'rm',
  'Delete',
  'Remove',
]);

const EDIT_TOOLS: ReadonlySet<string> = new Set([
  'edit',
  'modify',
]);

const SHELL_MUTATION_TOOLS: ReadonlySet<string> = new Set([
  'chmod',
  'chown',
  'mv',
  'move',
]);

/** 全部默认 destructive 写工具（SelfProtection 判定 isDestructive 用）。 */
export const DEFAULT_DESTRUCTIVE_WRITE_TOOLS: ReadonlySet<string> = new Set([
  ...WRITE_TOOLS,
  ...DELETE_TOOLS,
  ...EDIT_TOOLS,
  ...SHELL_MUTATION_TOOLS,
]);

