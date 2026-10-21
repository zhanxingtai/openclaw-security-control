// Vendored PluginJsonValue minimal subset.

export type PluginJsonValue =
  | string
  | number
  | boolean
  | null
  | { [key: string]: PluginJsonValue }
  | PluginJsonValue[];