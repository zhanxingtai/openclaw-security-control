/**
 * OpenClaw Security Monitor - Rule Loader
 *
 * Loads policy rules from a local YAML or JSON file and supports hot reload.
 */

import { readFileSync, existsSync, statSync } from 'fs';
import { extname, join } from 'path';
import os from 'os';
import type { PolicyFile, PolicyRule, RuleLoaderOptions } from './types.js';
import { parseSPLPolicy } from './SPLRuleLoader.js';
import { safeFsPath } from '../utils/safeFsPath.js';
import { compileRuleRegexes, getCompiledRuleRegexes, collectRulePatterns, hasLegacyInlineFlags, isSuspiciousNestedQuantifier } from './RuleRegexCache.js';
import type { CompiledRuleRegexes } from './RuleRegexCache.js';


let yamlModule: typeof import('js-yaml') | undefined;
async function loadYamlModule(): Promise<typeof import('js-yaml') | undefined> {
  if (yamlModule) return yamlModule;
  try {
    yamlModule = await import('js-yaml');
    return yamlModule;
  } catch {
    return undefined;
  }
}

export class RuleLoader {
  private options: RuleLoaderOptions;
  private lastContent?: string;
  private lastMtimeMs?: number;
  private currentPolicy?: PolicyFile;
  private reloadTimer?: ReturnType<typeof setInterval>;
  private loadError?: string;
  // 策略正则加载期预编译缓存，键为规则对象；
  // 热更新产生新规则对象时随 load() 重建，旧键由 GC 回收。
  private compiledRegexMap = new WeakMap<PolicyRule, CompiledRuleRegexes | null>();

  constructor(options: RuleLoaderOptions) {
    this.options = options;
  }

  async initialize(): Promise<void> {
    await this.load();
    const interval = this.options.reloadIntervalMs ?? 30000;
    if (interval > 0) {
      this.reloadTimer = setInterval(() => {
        this.load().catch((err) => {
          this.logError(`rule reload failed: ${err instanceof Error ? err.message : String(err)}`);
        });
      }, interval);
    }
  }

  async shutdown(): Promise<void> {
    if (this.reloadTimer) {
      clearInterval(this.reloadTimer);
      this.reloadTimer = undefined;
    }
  }

  getPolicy(): PolicyFile {
    if (this.currentPolicy) {
      return this.currentPolicy;
    }
    return {
      version: '0.0.0',
      defaultAction: 'allow',
      metadata: { id: 'empty-policy', name: 'Empty Policy', version: '0.0.0' },
      rules: [],
    };
  }

  getLoadError(): string | undefined {
    return this.loadError;
  }

  /**
   * 取规则的正则预编译产物（标准 3.2）。
   * 返回 null 表示规则含非法或灾难性回溯正则（加载期已告警），调用方应跳过该规则。
   * 未命中缓存的规则走进程内懒编译兜底（每个规则对象仅一次）。
   */
  getCompiledRuleRegexes(rule: PolicyRule): CompiledRuleRegexes | null {
    if (this.compiledRegexMap.has(rule)) {
      return this.compiledRegexMap.get(rule)!;
    }
    return getCompiledRuleRegexes(rule);
  }

  private rebuildCompiledRegexCache(rules: PolicyRule[]): void {
    // 嵌套量词观察级告警按模式聚合：同一模式无论命中几条规则只打一行，
    // 避免内置策略共用形态（如 (?:\s+\S+)*）在每次启动刷大量重复行。
    const suspiciousByPattern = new Map<string, Set<string>>();
    for (const rule of rules) {
      // 自防护规则（id 以 `self-protection-` 开头）的形态经审查组逐条核验，
      // 已知线性安全（例：`-[a-zA-Z]*\s+` 由字面字符类 + 空白分隔构成，
      // 无回溯分叉点），不属于可疑观察级告警范围。
      const isShippedSelfProtection = rule.id?.startsWith('self-protection-');
      // 嵌套量词观察级告警：多数此类模式线性安全（如 (?:\s+\S+)*），不拒绝编译，
      // 但策略文件属受信输入面，加载期留痕便于审计回溯。
      for (const pattern of collectRulePatterns(rule)) {
        if (!isShippedSelfProtection && isSuspiciousNestedQuantifier(pattern)) {
          const ids = suspiciousByPattern.get(pattern) ?? new Set<string>();
          ids.add(rule.id);
          suspiciousByPattern.set(pattern, ids);
        }
      }
      // PCRE 内联标志写法（(?i:...) / 裸 (?i)）已废弃，应迁移到
      // 规则级/条目级 flags 字段。兼容翻译仍生效（见 RuleRegexCache.compilePattern），
      // 此处仅 WARN 引导迁移。
      if (hasLegacyInlineFlags(rule)) {
        this.options.logger?.warn?.(
          `[RuleLoader] rule ${rule.id} uses deprecated inline (?i flag syntax; migrate to the rule-level/entry "flags" field`
        );
      }
      const result = compileRuleRegexes(rule);
      if (!result.ok) {
        // 非法 / 灾难性回溯正则：加载不失败，记告警；评估期跳过该规则（单规则隔离）。
        this.options.logger?.warn?.(
          `[RuleLoader] rule ${rule.id} has ${result.reason === 'unsafe' ? 'catastrophically backtracking' : 'invalid'} regex pattern: ${result.pattern}; rule will be skipped during evaluation`
        );
        this.options.onRuleIssue?.({
          ruleId: rule.id,
          pattern: result.pattern,
          kind: result.reason === 'unsafe' ? 'unsafe' : 'invalid',
        });
        this.compiledRegexMap.set(rule, null);
      } else {
        this.compiledRegexMap.set(rule, result.value);
      }
    }
    for (const [pattern, ids] of suspiciousByPattern) {
      this.options.logger?.warn?.(
        `[RuleLoader] nested quantifiers (potential ReDoS surface) in ${ids.size} rule(s) [${[...ids].join(', ')}]: ${pattern}`
      );
    }
  }

  async load(): Promise<PolicyFile> {
    const path = this.options.policyPath;
    if (!path) {
      this.loadError = 'policyPath is not configured';
      console.error('[RuleLoader] policyPath is not configured');
      return this.getPolicy();
    }

    // I-C2-01: refuse to read policy files outside the per-user sandbox.
    // A misconfigured `intervention.policyPath` pointing at /etc/passwd
    // would otherwise be read and parsed. Tests use os.tmpdir() (CI writes
    // fixtures there); we accept it as a secondary root so the loader
    // remains exercisable without polluting ~/.openclaw. We deliberately
    // do NOT include process.cwd() — any cwd-relative policy path would
    // silently widen the sandbox to the user's working directory.
    // NOTE: the symlink-bypass risk on /tmp is mitigated upstream by
    // safeFsPath returning undefined when realpathSync fails (EACCES /
    // ELOOP / ENOENT), so an attacker cannot race a dangling symlink into
    // a successful load.
    const safePath = safeFsPath(path, [
      join(os.homedir(), '.openclaw'),
      os.tmpdir(),
    ]);
    if (!safePath) {
      this.loadError = `policyPath escapes ~/.openclaw sandbox: ${path}`;
      console.error(`[RuleLoader] ${this.loadError}`);
      try {
        this.options.audit?.({
          eventType: 'policy_load_failed',
          detail: this.loadError,
          ts: Date.now(),
        });
      } catch { /* ignore */ }
      this.currentPolicy = {
        version: '0.0.0',
        defaultAction: 'allow',
        metadata: { id: 'empty-policy', name: 'Empty Policy', version: '0.0.0' },
        rules: [],
      };
      this.rebuildCompiledRegexCache(this.currentPolicy.rules);
      return this.currentPolicy;
    }

    if (!existsSync(safePath)) {
      console.error(`[RuleLoader] policy file not found: ${safePath}`);
      // 留痕用：引擎层据此写 policy_missing 安全事件，而不是只剩 console 输出。
      this.loadError = `policy file not found: ${safePath}`;
      this.currentPolicy = {
        version: '0.0.0',
        defaultAction: 'allow',
        metadata: { id: 'empty-policy', name: 'Empty Policy', version: '0.0.0' },
        rules: [],
      };
      this.rebuildCompiledRegexCache(this.currentPolicy.rules);
      return this.currentPolicy;
    }

    try {
      const content = readFileSync(safePath, 'utf8');
      const stats = statSync(safePath);

      if (this.lastContent === content && this.lastMtimeMs === stats.mtimeMs) {
        return this.currentPolicy || this.getPolicy();
      }

      const isFirstLoad = this.lastContent === undefined;
      const parsed = await this.parseContent(content, safePath);
      this.currentPolicy = this.normalizePolicy(parsed);
      this.rebuildCompiledRegexCache(this.currentPolicy.rules);
      this.lastContent = content;
      this.lastMtimeMs = stats.mtimeMs;
      this.loadError = undefined;

      if (isFirstLoad) {
        console.log(`[RuleLoader] loaded ${this.currentPolicy.rules.length} rule(s) from ${safePath}`);
      } else {
        console.log(`[RuleLoader] policy changed, reloaded ${this.currentPolicy.rules.length} rule(s) from ${safePath}`);
      }
      if (this.currentPolicy.rules.length === 0) {
        console.warn('[RuleLoader] policy file parsed successfully but contains 0 rules');
      }
      return this.currentPolicy;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.loadError = `failed to load policy file ${safePath}: ${message}`;
      this.logError(this.loadError);
      // Surface to the audit channel so operators see the failure as a
      // structured event (not just console output) and can alert on it.
      try {
        this.options.audit?.({
          eventType: 'policy_load_failed',
          detail: `${safePath}: ${message}`,
          ts: Date.now(),
        });
      } catch { /* audit callback may be absent or itself broken */ }
      // Keep previous policy if it exists.
      return this.currentPolicy || this.getPolicy();
    }
  }

  private async parseContent(content: string, path: string): Promise<unknown> {
    const ext = extname(path).toLowerCase();
    if (ext === '.yaml' || ext === '.yml') {
      const yaml = await loadYamlModule();
      if (!yaml) {
        // Fallback to JSON if file exists as .json variant.
        const jsonPath = path.replace(/\.ya?ml$/i, '.json');
        if (existsSync(jsonPath)) {
          return JSON.parse(readFileSync(jsonPath, 'utf8'));
        }
        throw new Error('js-yaml is not installed; cannot parse YAML policy file');
      }
      // yaml.JSON_SCHEMA rejects !!omap / !!set / flow collections that
      // were the attack surface behind CVE GHSA-pm4m-ph32-ghv5 in 5.2.x.
      // Policies are pure JSON-compatible data, so the strict schema is safe.
      return yaml.load(content, { schema: yaml.JSON_SCHEMA });
    }

    return JSON.parse(content);
  }

  private normalizePolicy(parsed: unknown): PolicyFile {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('policy file must be an object');
    }

    const policy = parsed as Record<string, unknown>;

    if (policy.apiVersion === 'security.use/v2') {
      return parseSPLPolicy(parsed, { logger: this.options.logger });
    }

    // 只接受 SPL v2（apiVersion: security.use/v2）；legacy 策略格式
    // （version/defaultAction 无前缀字段）与 v1 迁移层均不支持。
    throw new Error(
      'unsupported policy format: expected apiVersion "security.use/v2" ' +
      '(v1 compatibility was removed; legacy version/defaultAction policy support was removed in 0.9.4)'
    );
  }

  private logError(message: string): void {
    this.options.logger?.error?.(`[RuleLoader] ${message}`);
  }
}
