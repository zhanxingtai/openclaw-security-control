/**
 * OpenClaw Security Monitor - Hook Mounter
 *
 * ⚠ 本文件只被 `NODE_OPTIONS=--require` 加载，**不要加 shebang**。
 *
 * `#!` 是 JavaScript 里唯一"必须出现在文件最开头"的语法。它对被 require
 * 的模块没有任何功能价值（只有直接 execve 才需要），却是整个文件里唯一
 * 能一行毁掉整个宿主的字节：只要有任何东西被插到它前面 —— BOM、宿主安装
 * 器改写、编辑器、license header 注入、tar/zip 往返 —— 文件就从"合法 CJS"
 * 变成 SyntaxError。而本文件正是 NODE_OPTIONS 的预加载入口，语法错意味着
 * gateway 在加载任何插件之前就死掉，插件连"把副本修回去"的机会都没有
 * （自举死锁的又一种形态，2026-10 在新环境上实测命中）。
 *
 * 去掉 shebang 之后，"首字节被人动过"从致命错误降级为一句普通注释。
 *
 * ⚠ 本文件（本目录所有 hook）**只写 stderr，绝不写 stdout**。
 *
 * NODE_OPTIONS 会扩散到宿主里的**每一个** node 进程，包括那些把 stdout 当
 * 数据通道去解析的机器进程 —— 典型如 OpenClaw CLI 拉起的 SQLite 只读
 * worker，它的 stdout 是一段 JSON，加一行日志就变成"invalid JSON"。
 * 预加载在别人进程的最早期抢到的 stdout，等于替别人决定协议。
 *
 * 2026-10-23 实测：mounter 的统计行（`hooks mounter: loaded=2 …`）走了
 * console.log → CLI 直接报 `SQLite read-only worker returned invalid JSON`。
 *
 * Loaded via NODE_OPTIONS before any user code. Conditionally preloads the
 * runtime.js + network.js hooks that live alongside this script, so the
 * OpenClaw gateway boots even when the bundled hook files are missing or
 * corrupt.
 *
 * Direct --require of runtime.js / network.js would crash the whole Node
 * process on a missing file (the gateway container then enters a restart
 * loop that requires manual `docker cp` to recover). This wrapper degrades
 * gracefully: a missing file is logged at WARN level, a load error is caught
 * and reported, and execution always continues so the gateway stays up.
 *
 * Recommended NODE_OPTIONS (the plugin's own data directory — the installer
 * does not own it, so an upgrade never removes it):
 *   --require ~/.openclaw/sst-security-control-openclaw/hooks/hook-mounter.js
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
    console.error(
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

console.error(
  `[openclaw-security-monitor] hooks mounter: loaded=${loaded} skipped=${skipped} failed=${failed}`
);
