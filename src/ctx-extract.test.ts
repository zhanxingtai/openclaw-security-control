import { describe, it, expect } from 'vitest';
import {
  extractAgentId,
  inferAgentIdFromSessionKey,
  inferAgentNameFromAgentDir,
  normalizeAgentStartContext,
} from './ctxExtract.js';

describe('inferAgentIdFromSessionKey', () => {
  it('extracts name from "agent:<name>:<suffix>" format', () => {
    expect(inferAgentIdFromSessionKey('agent:main:main')).toBe('main');
    expect(inferAgentIdFromSessionKey('agent:my-agent:session-123')).toBe('my-agent');
  });

  it('extracts name from "<name>-<timestamp>" format', () => {
    expect(inferAgentIdFromSessionKey('slug-generator-1788164367435')).toBe('slug-generator');
    expect(inferAgentIdFromSessionKey('data-analyzer-1234567890123')).toBe('data-analyzer');
  });

  it('returns undefined for plain UUIDs and unknown values', () => {
    expect(inferAgentIdFromSessionKey('f76b7a12-d0ff-47b9-a083-c9ce36a8bacd')).toBeUndefined();
    expect(inferAgentIdFromSessionKey('unknown')).toBeUndefined();
    expect(inferAgentIdFromSessionKey('')).toBeUndefined();
  });
});

describe('inferAgentNameFromAgentDir', () => {
  it('extracts name from OpenClaw workspace directory', () => {
    expect(inferAgentNameFromAgentDir('/root/.openclaw/workspace/main/')).toBe('main');
    expect(inferAgentNameFromAgentDir('/root/.openclaw/workspace/slug-generator/')).toBe('slug-generator');
    expect(inferAgentNameFromAgentDir('/home/user/.openclaw/workspace/data-agent')).toBe('data-agent');
  });

  it('falls back to the last path segment', () => {
    expect(inferAgentNameFromAgentDir('/some/custom/path/my-agent/')).toBe('my-agent');
  });

  it('returns undefined for invalid inputs', () => {
    expect(inferAgentNameFromAgentDir('')).toBeUndefined();
    expect(inferAgentNameFromAgentDir('unknown')).toBeUndefined();
  });
});

describe('extractAgentId', () => {
  it('prefers explicit agent identifiers', () => {
    expect(extractAgentId({ agentId: 'explicit-agent' })).toBe('explicit-agent');
    expect(extractAgentId({ agent_id: 'explicit-agent' })).toBe('explicit-agent');
    expect(extractAgentId({ agentConfig: { name: 'config-agent' } })).toBe('config-agent');
  });

  it('falls back to session key inference', () => {
    expect(extractAgentId({ session_id: 'agent:main:main' })).toBe('main');
    expect(extractAgentId({ sessionId: 'slug-generator-1788164367435' })).toBe('slug-generator');
  });

  it('ignores unknown session keys', () => {
    expect(extractAgentId({ session_id: 'unknown' })).toBeUndefined();
    expect(extractAgentId({ session_id: 'f76b7a12-d0ff-47b9-a083-c9ce36a8bacd' })).toBeUndefined();
  });
});

describe('normalizeAgentStartContext', () => {
  it('infers agent name from agentDir when missing', () => {
    const ctx = normalizeAgentStartContext({
      agentDir: '/root/.openclaw/workspace/main/',
      model: { provider: 'openai', name: 'gpt-4' },
    });
    expect(ctx).toBeDefined();
    expect(ctx?.agentConfig?.name).toBe('main');
    expect(ctx?.agentId).toBe('main');
  });

  it('keeps explicit agent name over inferred one', () => {
    const ctx = normalizeAgentStartContext({
      agentConfig: { name: 'ExplicitAgent' },
      agentDir: '/root/.openclaw/workspace/main/',
    });
    expect(ctx?.agentConfig?.name).toBe('ExplicitAgent');
  });

  it('infers agentId from session_id when no explicit agent id is present', () => {
    const ctx = normalizeAgentStartContext({
      session_id: 'agent:main:main',
    });
    expect(ctx?.agentId).toBe('main');
  });

  it('prefers sessionKey over raw sessionId to keep per-session correlation stable', () => {
    // OpenClaw 8.x passes both sessionId (UUID) and sessionKey
    // (agent:main:main) to before_agent_start, while other hooks only carry
    // sessionKey. sessionKey must win or the session identity splits.
    const ctx = normalizeAgentStartContext({
      sessionId: '802c7780-a12c-406a-9d3b-0a9e59b3ac6e',
      sessionKey: 'agent:main:main',
    });
    expect(ctx?.sessionKey).toBe('agent:main:main');
  });

  it('falls back to sessionId when sessionKey is absent', () => {
    const ctx = normalizeAgentStartContext({
      sessionId: '802c7780-a12c-406a-9d3b-0a9e59b3ac6e',
    });
    expect(ctx?.sessionKey).toBe('802c7780-a12c-406a-9d3b-0a9e59b3ac6e');
  });
});
