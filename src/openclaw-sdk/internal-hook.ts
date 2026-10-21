// Vendored subset of OpenClaw 2026.9.4 internal-hook-types.ts.
//

export type InternalHookEventType = "command" | "session" | "agent" | "gateway" | "message";

export type InternalHookEvent = {
  type: InternalHookEventType;
  action: string;
  sessionKey: string;
  context: Record<string, unknown>;
  timestamp: Date;
  messages: string[];
};

export type InternalHookHandler = (event: InternalHookEvent) => Promise<void> | void;