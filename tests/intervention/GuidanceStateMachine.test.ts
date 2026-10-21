import { describe, it, expect } from 'vitest';
import { GuidanceStateMachine } from '../../src/intervention/GuidanceStateMachine.js';
import type { InterventionContext } from '../../src/intervention/types.js';

describe('GuidanceStateMachine', () => {
  const baseCtx: InterventionContext = {
    actionType: 'tool_call',
    toolName: 'file_read',
    sessionId: 'session-1',
    runId: 'run-1',
    agentId: 'agent-1',
  };

  it('tracks attempts per session', () => {
    const sm = new GuidanceStateMachine({ defaultThreshold: 2 });
    sm.record(baseCtx, 'rule-a', 'first');
    sm.record(baseCtx, 'rule-a', 'second');

    expect(sm.isBudgetExhausted(baseCtx, 'rule-a')).toBe(true);
  });

  it('isolates different sessions', () => {
    const sm = new GuidanceStateMachine({ defaultThreshold: 2 });
    sm.record(baseCtx, 'rule-a', 'first');

    const otherCtx: InterventionContext = {
      ...baseCtx,
      sessionId: 'session-2',
    };
    expect(sm.isBudgetExhausted(otherCtx, 'rule-a')).toBe(false);
  });

  it('does not collapse unknown sessions into a shared global key', () => {
    const sm = new GuidanceStateMachine({ defaultThreshold: 2 });

    const unknownCtx1: InterventionContext = {
      ...baseCtx,
      sessionId: 'unknown',
      runId: 'run-1',
    };
    const unknownCtx2: InterventionContext = {
      ...baseCtx,
      sessionId: 'unknown',
      runId: 'run-2',
    };

    sm.record(unknownCtx1, 'rule-a', 'first');
    sm.record(unknownCtx2, 'rule-a', 'first');

    // Each unknown session should have its own counter, so neither exhausts its budget.
    expect(sm.isBudgetExhausted(unknownCtx1, 'rule-a')).toBe(false);
    expect(sm.isBudgetExhausted(unknownCtx2, 'rule-a')).toBe(false);
  });

  it('falls back to runId when sessionId is unknown', () => {
    const sm = new GuidanceStateMachine({ defaultThreshold: 2 });

    const unknownCtx: InterventionContext = {
      ...baseCtx,
      sessionId: 'unknown',
      runId: 'run-shared',
    };

    sm.record(unknownCtx, 'rule-a', 'first');
    sm.record(unknownCtx, 'rule-a', 'second');

    expect(sm.isBudgetExhausted(unknownCtx, 'rule-a')).toBe(true);
  });

  it('falls back to agentId when sessionId and runId are unknown', () => {
    const sm = new GuidanceStateMachine({ defaultThreshold: 2 });

    const unknownCtx: InterventionContext = {
      ...baseCtx,
      sessionId: 'unknown',
      runId: undefined,
      agentId: 'agent-shared',
    };

    sm.record(unknownCtx, 'rule-a', 'first');
    sm.record(unknownCtx, 'rule-a', 'second');

    expect(sm.isBudgetExhausted(unknownCtx, 'rule-a')).toBe(true);
  });

  it('cleans up expired states', () => {
    const sm = new GuidanceStateMachine({ defaultThreshold: 2, stateTtlMs: 1 });
    sm.record(baseCtx, 'rule-a', 'first');

    // Wait for TTL to expire
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(sm.cleanup()).toBe(1);
        expect(sm.getState(baseCtx, 'rule-a')).toBeUndefined();
        resolve();
      }, 10);
    });
  });
});
