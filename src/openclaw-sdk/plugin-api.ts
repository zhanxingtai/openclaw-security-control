// Vendored subset of OpenClaw 2026.9.4 OpenClawPluginApi surface.
//
// Only the fields this plugin actually calls. The host provides the real
// implementation; this is the type contract for our `register(api)`.
//

import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import type { InternalHookEvent } from "./internal-hook.js";
import type { OpenClawPluginHttpRouteParams } from "./plugin-registration.js";
import type { PluginLogger } from "./logger.js";
import type { PluginRuntimeLifecycleRegistration } from "./runtime-lifecycle.js";

export type {
  IncomingMessage,
  ServerResponse,
  Duplex,
  OpenClawPluginHttpRouteParams,
  PluginLogger,
  PluginRuntimeLifecycleRegistration,
};

export type GatewayRequestHandler = (
  params: unknown,
) => Promise<unknown> | unknown;

// The host requires requiredScopes to be a closed set of operator scopes.
// Vendored as a string union so the plugin does not pull the host's enum.
export type OperatorScope =
  | "operator.admin"
  | "operator.read"
  | "operator.write"
  | "operator.approvals"
  | "operator.questions"
  | "operator.pairing"
  | "operator.talk"
  | "operator.talk.secrets";

// PluginControlUiDescriptor surface, as provided by the host.
export type PluginControlUiSurface =
  | "session"
  | "tool"
  | "run"
  | "settings"
  | "tab"
  | "widget";

export type PluginControlUiTabGroup = "control" | "settings" | "ops";

export type PluginControlUiDescriptor = {
  id: string;
  surface: PluginControlUiSurface;
  label: string;
  description?: string;
  placement?: string;
  slug?: string;
  schema?: unknown;
  requiredScopes?: OperatorScope[];
  icon?: string;
  // Absolute gateway-local path; rendered in a sandboxed iframe by the host.
  // Must start with "/" and may not use a protocol-relative scheme.
  path?: string;
  group?: PluginControlUiTabGroup;
  order?: number;
};

export type OpenClawPluginApi = {
  id: string;
  name: string;
  version?: string;
  description?: string;
  source: string;
  registrationMode: string;
  config: Record<string, unknown>;
  pluginConfig?: Record<string, unknown>;
  logger: PluginLogger;
  runtime: {
    registerRuntimeLifecycle?: (lifecycle: PluginRuntimeLifecycleRegistration) => void;
  };
  // Optional: minimal or older hosts may not expose the hook
  // dispatcher — register() guards the call and degrades to the typed
  // api.on(...) path (which see).
  registerHook?: (
    events: string | string[],
    handler: (event: InternalHookEvent) => Promise<void> | void,
    opts?: { name?: string; description?: string },
  ) => void;
  // Typed hook runner (OpenClaw 2026.9.4): dispatches 41 typed lifecycle
  // hooks (before_tool_call, after_tool_call, message_received, etc.).
  // Vendored loosely — the host provides real types; we narrow in the
  // hook-bridge layer.
  on?: (hookName: string, handler: (event: unknown, ctx?: unknown) => unknown) => void;
  registerHttpRoute?: (params: OpenClawPluginHttpRouteParams) => void;
  // Optional: hosts without a gateway WebSocket surface skip WS RPC; the
  // plugin's own HTTP route still serves the panel.
  registerGatewayMethod?: (
    method: string,
    handler: GatewayRequestHandler,
    opts?: {
      scope?: OperatorScope;
      profileAccess?: "independent" | "required";
    },
  ) => void;
  // Control UI descriptor: hosts differ on whether the descriptor is
  // attached via the nested session facade or the top-level form; we
  // accept both and prefer whichever the host exposes.
  session?: {
    controls?: {
      registerControlUiDescriptor?: (descriptor: PluginControlUiDescriptor) => void;
    };
  };
  registerControlUiDescriptor?: (descriptor: PluginControlUiDescriptor) => void;
};