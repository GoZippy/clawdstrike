import { createSecurityContext } from '@clawdstrike/adapter-core';
import type { AdapterConfig, Decision, PolicyEngineLike, SecurityContext, ToolInterceptor } from '@clawdstrike/adapter-core';

import { createLangChainInterceptor } from './interceptor.js';

export interface PendingToolCall {
  name: string;
  args: unknown;
}

export interface SecurityCheckpointNode {
  name: string;
  check(state: Record<string, unknown>): Promise<Decision>;
  route(state: Record<string, unknown>): Promise<'allow' | 'block' | 'warn'>;
}

export interface SecurityCheckpointOptions {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor;
  config?: AdapterConfig;
  context?: SecurityContext;
  createContext?: (state: Record<string, unknown>) => SecurityContext;
  extractToolCalls?: (state: Record<string, unknown>) => PendingToolCall[];
}

export function createSecurityCheckpoint(
  options: SecurityCheckpointOptions,
): SecurityCheckpointNode {
  const interceptor =
    options.interceptor
    ?? (options.engine
      ? createLangChainInterceptor(options.engine, options.config)
      : undefined);

  if (!interceptor) {
    throw new Error('createSecurityCheckpoint requires { interceptor } or { engine }');
  }

  const extractToolCalls = options.extractToolCalls ?? defaultExtractToolCalls;
  const createContext =
    options.createContext
    ?? ((state: Record<string, unknown>) =>
      options.context
      ?? createSecurityContext({
        sessionId: typeof state.sessionId === 'string' ? state.sessionId : undefined,
        metadata: { framework: 'langgraph' },
      }));

  return {
    name: 'clawdstrike_checkpoint',

    async check(state: Record<string, unknown>): Promise<Decision> {
      const toolCalls = extractToolCalls(state);
      const context = createContext(state);

      let warningDecision: Decision | null = null;

      for (const call of toolCalls) {
        const result = await interceptor.beforeExecute(call.name, call.args, context);

        if (result.decision.denied) {
          return result.decision;
        }

        if (result.decision.warn && !warningDecision) {
          warningDecision = result.decision;
        }
      }

      return (
        warningDecision
        ?? { allowed: true, denied: false, warn: false }
      );
    },

    async route(state: Record<string, unknown>): Promise<'allow' | 'block' | 'warn'> {
      const decision = await this.check(state);
      if (decision.denied) return 'block';
      if (decision.warn) return 'warn';
      return 'allow';
    },
  };
}

export function wrapToolNode<S extends Record<string, unknown>>(
  graph: { nodes: Map<string, (state: S) => Promise<S> | S>; addNode: (name: string, node: (state: S) => Promise<S> | S) => void },
  nodeName: string,
  checkpoint: SecurityCheckpointNode,
): void {
  const original = graph.nodes.get(nodeName);
  if (!original) {
    throw new Error(`Node '${nodeName}' not found`);
  }

  graph.addNode(nodeName, async (state: S) => {
    const decision = await checkpoint.check(state as Record<string, unknown>);
    if (decision.denied) {
      return {
        ...state,
        __clawdstrike_blocked: true,
        __clawdstrike_reason: decision.message ?? decision.reason ?? 'denied',
      } as S;
    }

    return await original(state);
  });
}

function defaultExtractToolCalls(state: Record<string, unknown>): PendingToolCall[] {
  const raw = state.toolCalls ?? state.tool_calls ?? state.pendingToolCalls;
  if (!Array.isArray(raw)) {
    return [];
  }

  const calls: PendingToolCall[] = [];
  for (const item of raw) {
    if (typeof item !== 'object' || item === null) {
      continue;
    }
    const rec = item as Record<string, unknown>;
    const name = typeof rec.name === 'string' ? rec.name : typeof rec.toolName === 'string' ? rec.toolName : undefined;
    if (!name) {
      continue;
    }
    calls.push({ name, args: rec.args ?? rec.parameters ?? rec.input });
  }
  return calls;
}

