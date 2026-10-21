// Vendored subset of OpenClaw 2026.9.4 runtime-lifecycle surface.

export type PluginRuntimeLifecycleRegistration = {
  id: string;
  description?: string;
  dispose?: () => void | Promise<void>;
  cleanup?: (ctx: {
    reason: PluginHostCleanupReason;
    sessionKey?: string;
    runId?: string;
  }) => void | Promise<void>;
};

export type PluginHostCleanupReason = "restart" | "disable" | "session-end" | "run-end";