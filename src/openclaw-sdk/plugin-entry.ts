// Vendored subset of OpenClaw 2026.9.4 plugin-entry SDK.
//
// Why vendored:
// - This plugin must run independently ("独立运行" per project requirement),
//   without depending on the OpenClaw host's @openclaw/plugin-sdk being
//   installed.
// - We only need the surface required by OpenClaw 2026.9.4 plugin contract:
//   definePluginEntry, OpenClawPluginApi, InternalHookEvent, HttpRoute, and
//   configSchema helpers. The OpenClaw host loads our default export as a
//   plain object; runtime calls into our `register(api)` are typed against
//   this subset.
//

import { emptyPluginConfigSchema, type OpenClawPluginConfigSchema } from "./config-schema.js";
import type {
  OpenClawPluginApi,
  OperatorScope,
  PluginControlUiDescriptor,
  PluginControlUiSurface,
  PluginControlUiTabGroup,
} from "./plugin-api.js";
import type { OpenClawPluginNodeHostCommand, OpenClawPluginHttpRouteParams } from "./plugin-registration.js";
import type { InternalHookEvent, InternalHookEventType, InternalHookHandler } from "./internal-hook.js";
import type { PluginLogger } from "./logger.js";
import type { PluginRuntimeLifecycleRegistration, PluginHostCleanupReason } from "./runtime-lifecycle.js";
import type { PluginJsonValue } from "./json-value.js";

export type {
  InternalHookEvent,
  InternalHookEventType,
  InternalHookHandler,
  OpenClawPluginApi,
  OpenClawPluginConfigSchema,
  OpenClawPluginHttpRouteParams,
  OpenClawPluginNodeHostCommand,
  OperatorScope,
  PluginControlUiDescriptor,
  PluginControlUiSurface,
  PluginControlUiTabGroup,
  PluginLogger,
  PluginRuntimeLifecycleRegistration,
  PluginHostCleanupReason,
  PluginJsonValue,
};

export { emptyPluginConfigSchema };

type DefinePluginEntryOptions = {
  id: string;
  name: string;
  description: string;
  kind?: string;
  configSchema?: OpenClawPluginConfigSchema | (() => OpenClawPluginConfigSchema);
  nodeHostCommands?: readonly OpenClawPluginNodeHostCommand[];
  register: (api: OpenClawPluginApi) => void | Promise<void>;
};

/**
 * Canonical entry helper for non-channel plugins.
 *
 * Mirrors the shape of OpenClaw 2026.9.4's definePluginEntry: returns a
 * DefinedPluginEntry object the host can load directly. Vendored here so
 * the plugin does not depend on @openclaw/plugin-sdk at runtime.
 */
export function definePluginEntry(options: DefinePluginEntryOptions): {
  id: string;
  name: string;
  description: string;
  configSchema: OpenClawPluginConfigSchema;
  register: DefinePluginEntryOptions["register"];
} {
  const schema = options.configSchema ?? emptyPluginConfigSchema;
  return {
    id: options.id,
    name: options.name,
    description: options.description,
    configSchema: typeof schema === "function" ? schema() : schema,
    register: options.register,
  };
}