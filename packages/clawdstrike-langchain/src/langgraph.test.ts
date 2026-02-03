import { describe, it, expect } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { createSecurityCheckpoint } from './langgraph.js';

describe('createSecurityCheckpoint', () => {
  it('returns block when any pending tool call is denied', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: event.eventType === 'command_exec' ? 'blocked' : undefined,
      }),
    };

    const checkpoint = createSecurityCheckpoint({ engine, config: { blockOnViolation: true } });

    const decision = await checkpoint.check({
      toolCalls: [{ name: 'bash', args: { cmd: 'rm -rf /' } }],
    });

    expect(decision.denied).toBe(true);
    await expect(checkpoint.route({ toolCalls: [{ name: 'bash', args: {} }] })).resolves.toBe('block');
  });
});

