// Vendored subset of OpenClaw 2026.9.4 plugin-registration types.
//

import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";

export type OpenClawPluginHttpRouteAuth = "gateway" | "plugin";
export type OpenClawPluginHttpRouteMatch = "exact" | "prefix";

export type OpenClawPluginHttpRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
) => Promise<boolean | void> | boolean | void;

export type OpenClawPluginHttpRouteUpgradeHandler = (
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
) => Promise<boolean | void> | boolean | void;

export type OpenClawPluginHttpRouteParams = {
  path: string;
  handler: OpenClawPluginHttpRouteHandler;
  handleUpgrade?: OpenClawPluginHttpRouteUpgradeHandler;
  auth: OpenClawPluginHttpRouteAuth;
  match?: OpenClawPluginHttpRouteMatch;
  replaceExisting?: boolean;
};

export type OpenClawPluginNodeHostCommand = {
  command: string;
  cap?: string;
  dangerous?: boolean;
  handle: (paramsJSON: string) => Promise<string> | string;
};