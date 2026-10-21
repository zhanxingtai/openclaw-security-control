// Vendored subset of OpenClaw 2026.9.4 logger surface.

export type PluginLogger = {
  debug?: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  child?: (bindings: Record<string, unknown>) => PluginLogger;
};