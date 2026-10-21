#!/usr/bin/env node
/**
 * OpenClaw Security Monitor - Hook Mounter
 *
 * Loaded via NODE_OPTIONS before any user code. Conditionally preloads the
 * runtime.js + network.js hooks that live alongside this script in the
 * extensions directory, so the OpenClaw gateway boots even when the bundled
 * hook files are missing or corrupt.
 *
 * Direct --require of runtime.js / network.js would crash the whole Node
 * process on a missing file (the gateway container then enters a restart
 * loop that requires manual `docker cp` to recover). This wrapper degrades
 * gracefully: a missing file is logged at WARN level, a load error is caught
 * and reported, and execution always continues so the gateway stays up.
 *
 * Recommended NODE_OPTIONS:
 *   --require /path/to/extensions/sst-security-control-openclaw/hook-mounter.js
 */
const fs = require('fs');
const path = require('path');

// Master switch mirrored from application.runtimeHooks.networkEnabled by the
// plugin (OPENCLAW_NETWORK_HOOK_ENABLED). Unset means enabled so default
// behavior is unchanged; the plugin sets it at initialize time, so processes
// forked afterwards honor the toggle. Already-running processes are covered
// by the lazy check inside network.js itself.
function isNetworkHookDisabled() {
  const v = process.env.OPENCLAW_NETWORK_HOOK_ENABLED;
  return v === 'false' || v === '0';
}

const HOOK_FILES = ['runtime.js', 'network.js'];
let loaded = 0;
let skipped = 0;
let failed = 0;

for (const name of HOOK_FILES) {
  if (name === 'network.js' && isNetworkHookDisabled()) {
    console.log(
      `[openclaw-security-monitor] network hook disabled via OPENCLAW_NETWORK_HOOK_ENABLED=${process.env.OPENCLAW_NETWORK_HOOK_ENABLED}; skipping network.js`
    );
    skipped += 1;
    continue;
  }
  const target = path.join(__dirname, name);
  if (!fs.existsSync(target)) {
    console.warn(
      `[openclaw-security-monitor] hook file missing: ${target} ` +
        `- coverage for this layer will be unavailable until the file is restored`
    );
    skipped += 1;
    continue;
  }
  try {
    require(target);
    loaded += 1;
  } catch (err) {
    console.error(
      `[openclaw-security-monitor] failed to load ${name}: ` +
        (err instanceof Error ? err.message : String(err))
    );
    failed += 1;
  }
}

console.log(
  `[openclaw-security-monitor] hooks mounter: loaded=${loaded} skipped=${skipped} failed=${failed}`
);
