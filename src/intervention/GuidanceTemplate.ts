/**
 * OpenClaw Security Monitor - Guidance Template
 *
 * Lightweight template engine for guidance prompts.
 * Supports simple variable substitution: {{variable}} or {{variable | fallback}}.
 */

import { existsSync, readFileSync, readdirSync } from 'fs';
import { resolve } from 'path';

export interface GuidanceTemplate {
  id: string;
  version?: string;
  locale?: string;
  body: string;
  variables?: string[];
}

export interface GuidanceTemplateStore {
  get(id: string): GuidanceTemplate | undefined;
  set(template: GuidanceTemplate): void;
  loadFromFile(path: string): GuidanceTemplate | undefined;
  loadFromDirectory(dir: string): number;
  list(): string[];
}

export interface TemplateRendererOptions {
  /** Maximum rendered length. */
  maxLength?: number;
  /** Default fallback for missing variables. */
  defaultFallback?: string;
}

export class GuidanceTemplateStoreImpl implements GuidanceTemplateStore {
  private templates = new Map<string, GuidanceTemplate>();

  get(id: string): GuidanceTemplate | undefined {
    return this.templates.get(id);
  }

  set(template: GuidanceTemplate): void {
    this.templates.set(template.id, template);
  }

  loadFromFile(path: string): GuidanceTemplate | undefined {
    if (!existsSync(path)) return undefined;
    try {
      const content = readFileSync(path, 'utf8');
      const parsed = JSON.parse(content) as GuidanceTemplate;
      if (!parsed.id || !parsed.body) {
        return undefined;
      }
      this.set(parsed);
      return parsed;
    } catch {
      return undefined;
    }
  }

  loadFromDirectory(dir: string): number {
    if (!existsSync(dir)) return 0;
    let count = 0;
    try {
      for (const entry of readdirSync(dir)) {
        if (entry.endsWith('.json')) {
          const loaded = this.loadFromFile(resolve(dir, entry));
          if (loaded) count++;
        }
      }
    } catch {
      // ignore directory read errors
    }
    return count;
  }

  list(): string[] {
    return Array.from(this.templates.keys());
  }
}

export class TemplateRenderer {
  constructor(private options: TemplateRendererOptions = {}) {}

  render(template: GuidanceTemplate, variables: Record<string, unknown>): string {
    const body = template.body;
    const maxLength = this.options.maxLength || 2000;

    const rendered = body.replace(/\{\{\s*([^}]+)\s*\}\}/g, (_, expr) => {
      const parts = expr.split('|').map((p: string) => p.trim());
      const key = parts[0];
      const fallback = parts[1] || this.options.defaultFallback || '';
      const value = this.getVariable(variables, key);
      if (value === undefined || value === null) {
        return fallback;
      }
      if (Array.isArray(value)) {
        return value.join(', ');
      }
      return String(value);
    });

    if (rendered.length > maxLength) {
      return rendered.slice(0, maxLength) + '\n...';
    }
    return rendered;
  }

  extractVariables(template: GuidanceTemplate): string[] {
    const vars = new Set<string>();
    const regex = /\{\{\s*([^}]+)\s*\}\}/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(template.body)) !== null) {
      const key = match[1].split('|')[0].trim();
      vars.add(key);
    }
    return Array.from(vars);
  }

  private getVariable(variables: Record<string, unknown>, key: string): unknown {
    const parts = key.split('.');
    let current: unknown = variables;
    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }
    return current;
  }
}

/** Built-in guidance templates shipped with the plugin. */
export function loadBuiltinTemplates(): GuidanceTemplate[] {
  return [
    {
      id: 'guidance.default',
      version: '1.0.0',
      locale: 'zh-CN',
      body: `检测到潜在风险：{{ risk_level | 中风险 }}

触发规则：{{ policy_name | 安全策略 }}
{{#if reg_clause}}涉及条款：{{ reg_clause }}{{/if}}

请按以下范围继续操作：
{{ allowed_scope | 请保持安全合规，避免访问敏感数据或执行高危命令。}}

{{#if alternatives}}建议替代方案：
{{ alternatives }}{{/if}}`,
    },
    {
      id: 'guidance.high_risk_command',
      version: '1.0.0',
      locale: 'zh-CN',
      body: `当前工具调用（{{ tool_name | 未知工具 }}）可能包含高危操作。

请重新评估：
1. 该命令是否必要？
2. 是否已读取目标文件/环境信息？
3. 是否可以先使用只读方式验证？

允许范围：{{ allowed_scope | 仅使用只读查询，禁止写入或删除操作。}}`,
    },
    {
      id: 'guidance.data_exfiltration',
      version: '1.0.0',
      locale: 'zh-CN',
      body: `检测到数据外发风险（{{ risk_flags | 无 }}）。

请确认：
- 目标地址 {{ target_host | 未知 }} 是否属于业务白名单
- 传输内容是否包含敏感信息
- 是否有更安全的替代通道

允许范围：{{ allowed_scope | 禁止向非白名单地址传输数据。}}`,
    },
  ];
}

export function normalizeTemplateRef(ref: string | { id?: string; path?: string }): {
  id?: string;
  path?: string;
} {
  if (typeof ref === 'string') {
    return { id: ref };
  }
  return { id: ref.id, path: ref.path };
}
