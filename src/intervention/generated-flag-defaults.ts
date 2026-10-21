// GENERATED FILE — 由 scripts/generate-detection-patterns.mjs 从
// policies/security-policy.spl.yaml 的 metadata.flagRegistry 生成（单源化产物）。
// 请勿手改；改动源请编辑 spl.yaml 后执行 npm run build:prod。
//
// 三套默认处置名单：
//   - GENERATED_HOOK_BLOCKED_FLAGS     → runtime hook 本地阻断（hooks/runtime.js
//     DEFAULT_BLOCKED_FLAGS 与 store.ts OPENCLAW_RUNTIME_BLOCKED_FLAGS 默认值）
//   - GENERATED_MONITOR_AUTOKILL_FLAGS → process monitor autokill 默认名单
//    （monitor/process_monitor.py DEFAULT_CONFIG.riskFlags）
//   - GENERATED_ENGINE_HIGH_RISK_FLAGS → 引擎 fail_open_high_risk_only 高危回退
//    （本目录 types.ts DEFAULT_HIGH_RISK_FLAGS）

export const GENERATED_HOOK_BLOCKED_FLAGS: readonly string[] = [
  'reverse_shell',
  'download_execute',
  'mass_deletion',
  'privilege_escalation',
  'token_in_command',
  'skill_binary_execution',
];

export const GENERATED_MONITOR_AUTOKILL_FLAGS: readonly string[] = [
  'reverse_shell',
];

export const GENERATED_ENGINE_HIGH_RISK_FLAGS: readonly string[] = [
  'reverse_shell',
  'download_execute',
  'mass_deletion',
  'privilege_escalation',
  'data_exfiltration',
  'token_in_command',
  'sensitive_file_access',
  'skill_binary_execution',
];
