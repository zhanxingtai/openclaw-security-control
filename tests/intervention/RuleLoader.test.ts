import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { RuleLoader } from '../../src/intervention/RuleLoader.js';

describe('RuleLoader', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'rule-loader-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads JSON policy file', async () => {
    const policyPath = join(tmpDir, 'policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'test-policy', name: 'Test Policy', version: '1.0.0' },
        rules: [
          {
            id: 'block-rule', severity: 'medium',
            match: { actionType: ['agent_tool_call'] },
            action: { decision: 'block', block: { blockCode: 'B001', blockReason: 'br' } },
          },
        ],
      })
    );

    const loader = new RuleLoader({ policyPath, reloadIntervalMs: 0 });
    await loader.initialize();
    const policy = loader.getPolicy();
    expect(policy.metadata.version).toBe('1.0.0');
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('block-rule');
    await loader.shutdown();
  });

  it('loads YAML policy file', async () => {
    const policyPath = join(tmpDir, 'policy.yaml');
    writeFileSync(
      policyPath,
      `apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: yaml-rule
    severity: medium
    match:
      actionType: ["agent_tool_call"]
    action:
      decision: block
      block:
        blockCode: "B001"
        blockReason: "from yaml"
`
    );

    const loader = new RuleLoader({ policyPath, reloadIntervalMs: 0 });
    await loader.initialize();
    const policy = loader.getPolicy();
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('yaml-rule');
    expect(policy.rules[0].action.decision).toBe('block');
    expect(policy.rules[0].action.block?.blockReason).toBe('from yaml');
    await loader.shutdown();
  });

  it('returns empty policy when file does not exist', async () => {
    const policyPath = join(tmpDir, 'missing.json');
    const loader = new RuleLoader({ policyPath, reloadIntervalMs: 0 });
    await loader.initialize();
    const policy = loader.getPolicy();
    expect(policy.rules).toHaveLength(0);
    expect(policy.defaultAction).toBe('allow');
    await loader.shutdown();
  });

  it('normalizes paramsRegex strings to arrays', async () => {
    const policyPath = join(tmpDir, 'policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'regex-policy', name: 'Regex Policy', version: '1.0.0' },
        rules: [
          {
            id: 'regex-rule', severity: 'medium',
            match: {
              actionType: ['agent_tool_call'],
              paramsRegex: { path: '^/etc/' },
            },
            action: { decision: 'block', block: { blockCode: 'B002', blockReason: 'br' } },
          },
        ],
      })
    );

    const loader = new RuleLoader({ policyPath, reloadIntervalMs: 0 });
    await loader.initialize();
    const policy = loader.getPolicy();
    expect(policy.rules[0].match.paramsRegex).toEqual({ path: ['^/etc/'] });
    await loader.shutdown();
  });

  it('keeps previous policy when file is invalid', async () => {
    const policyPath = join(tmpDir, 'policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'keep-policy', name: 'Keep Policy', version: '1.0.0' },
        rules: [{ id: 'good', severity: 'medium', match: {}, action: { decision: 'allow' } }],
      })
    );

    const loader = new RuleLoader({ policyPath, reloadIntervalMs: 0 });
    await loader.initialize();

    writeFileSync(policyPath, 'not valid json');
    await loader.load();
    const policy = loader.getPolicy();
    expect(policy.rules).toHaveLength(1);
    expect(loader.getLoadError()).toContain('failed to load policy file');
    await loader.shutdown();
  });
});
