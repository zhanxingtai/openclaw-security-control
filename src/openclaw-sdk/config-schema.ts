// Vendored subset of OpenClaw 2026.9.4 config-schema helpers.
//

export type OpenClawPluginConfigSchema = {
  parse: (value: unknown) => Record<string, unknown>;
  schema?: unknown;
};

export const emptyPluginConfigSchema: OpenClawPluginConfigSchema = {
  parse: (value: unknown) => (value && typeof value === "object" ? (value as Record<string, unknown>) : {}),
};