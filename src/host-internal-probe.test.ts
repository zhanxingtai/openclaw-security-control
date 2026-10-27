import { describe, it, expect } from 'vitest';
import { hasAgentAttribution, matchHostInternalProbe } from './host-internal-probe.js';

/**
 * 这些命令全部来自真实采样（宿主网关空闲期的自身维护动作）。
 * 命令形态逐字取自 security-events.jsonl，判定结果就是"应当被排除"的
 * 宿主内部只读探针。
 */
const HOST_PROBES: Array<[string, string]> = [
  ['/usr/bin/lsof -nP -iTCP:18789 -sTCP:LISTEN -FpFcn', 'lsof_port_probe'],
  ['/usr/bin/lsof -nP -iTCP:18789 -sTCP:LISTEN -Fpc', 'lsof_port_probe'],
  ['ps -p 1 -o user=', 'ps_single_pid_probe'],
  ['ps -p 1 -ww -o ppid= -o command=', 'ps_single_pid_probe'],
  ['ps -p 7 -ww -o ppid= -o command=', 'ps_single_pid_probe'],
  ['ps -p 6 -o user=', 'ps_single_pid_probe'],
  ['systemctl --system is-system-running', 'systemctl_state_probe'],
  [
    'busctl --machine node@ --user --auto-start=no get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Version',
    'busctl_version_probe',
  ],
  ['npm root -g', 'global_package_root'],
  ['pnpm root -g', 'global_package_root'],
  ['/usr/local/share/corepack/v1/pnpm/12.9.0/pnpm-native root -g', 'global_package_root'],
  ['npm config get globalconfig', 'npm_config_globalconfig'],
  ['getent passwd node', 'getent_passwd_user'],
  ['ip -4 route show default', 'ip_default_route'],
  ['df -kP / /etc/hosts', 'df_disk_usage'],
  [
    'git -C /home/node/.openclaw/workspace rev-parse --show-toplevel --verify HEAD^{commit}',
    'git_workspace_probe',
  ],
  ['git -C /home/node/.openclaw/workspace rev-parse --show-toplevel', 'git_workspace_probe'],
  ['git -C /home/node/.openclaw/workspace rev-parse --verify HEAD^{commit}', 'git_workspace_probe'],
  [
    'git -C /home/node/.openclaw/workspace rev-parse --show-toplevel --verify --quiet HEAD',
    'git_workspace_probe',
  ],
  ['git -C /home/node/.openclaw/workspace rev-parse --abbrev-ref HEAD', 'git_workspace_probe'],
  ['git -C /home/node/.openclaw/workspace symbolic-ref --quiet HEAD', 'git_workspace_probe'],
  [
    'git -C /home/node/.openclaw/workspace show-ref --verify --quiet refs/heads/master',
    'git_workspace_probe',
  ],
  ['git -C /app rev-parse --show-toplevel', 'git_workspace_probe'],
  [
    'git -c maintenance.autoDetach=false -c gc.autoDetach=false -C /app rev-parse --show-toplevel',
    'git_workspace_probe',
  ],
  [
    'git -c maintenance.autoDetach=false -c gc.autoDetach=false -C /home/node/.openclaw/workspace rev-parse --abbrev-ref HEAD',
    'git_workspace_probe',
  ],
  ['git -C /home/node/.openclaw/workspace hash-object -t tree --stdin', 'git_workspace_probe'],
  [
    'git -C /home/node/.openclaw/workspace -c core.quotePath=false diff -M 4b825dc642cb6eb9a060e54bf8d69288fbee4904 --name-status -z',
    'git_workspace_probe',
  ],
  [
    'git -C /home/node/.openclaw/workspace -c core.quotePath=false ls-files --others --exclude-standard -z',
    'git_workspace_probe',
  ],
];

describe('matchHostInternalProbe', () => {
  it.each(HOST_PROBES)('识别宿主只读探针 %s', (command, expected) => {
    expect(matchHostInternalProbe(command)).toBe(expected);
  });

  it('不把宽口径的端口列举当成探针（少了 LISTEN 过滤）', () => {
    expect(matchHostInternalProbe('/usr/bin/lsof -nP -iTCP:18789')).toBeNull();
    expect(matchHostInternalProbe('/usr/bin/lsof -nP -iTCP -sTCP:LISTEN')).toBeNull();
  });

  it('不把宽口径的 ps 列举当成探针', () => {
    expect(matchHostInternalProbe('ps aux')).toBeNull();
    expect(matchHostInternalProbe('ps -ef')).toBeNull();
    expect(matchHostInternalProbe('ps -p 1')).toBeNull();
  });

  it('不把其他 systemd / busctl 查询当成探针', () => {
    expect(matchHostInternalProbe('systemctl status nginx')).toBeNull();
    expect(matchHostInternalProbe('systemctl --system is-active nginx')).toBeNull();
    expect(matchHostInternalProbe('busctl --user list')).toBeNull();
  });

  it('不把会带凭据的 npm / git 查询当成探针', () => {
    expect(
      matchHostInternalProbe('npm config list --location=project --json=false --long=false')
    ).toBeNull();
    expect(matchHostInternalProbe('npm install --omit=dev --ignore-scripts')).toBeNull();
    expect(matchHostInternalProbe('git -C /app config --get remote.origin.url')).toBeNull();
    expect(matchHostInternalProbe('git clone https://x-token:ghp_abcdefghij1234@example.com/repo.git')).toBeNull();
    expect(matchHostInternalProbe('git -C /app fetch')).toBeNull();
    expect(matchHostInternalProbe('git -C /app push origin main')).toBeNull();
    expect(matchHostInternalProbe('git -C /app rev-parse --show-toplevel -w')).toBeNull();
  });

  it('不把全量用户枚举 / 其他系统查询当成探针', () => {
    expect(matchHostInternalProbe('getent passwd')).toBeNull();
    expect(matchHostInternalProbe('ip neigh show')).toBeNull();
    expect(matchHostInternalProbe('ip route show')).toBeNull();
    expect(matchHostInternalProbe('df -h')).toBeNull();
  });

  it('不把凭据类与拓扑类命令当成探针', () => {
    expect(matchHostInternalProbe('gh auth token --hostname github.com')).toBeNull();
    expect(matchHostInternalProbe('crontab -l')).toBeNull();
    expect(matchHostInternalProbe('claude auth status --json')).toBeNull();
    expect(matchHostInternalProbe('tailscale serve status --json')).toBeNull();
  });

  it('不把 shell 包装的命令当成探针', () => {
    expect(
      matchHostInternalProbe('/bin/sh -l -c lsof -nP -iTCP:18789 -sTCP:LISTEN -FpFcn')
    ).toBeNull();
    expect(matchHostInternalProbe('/usr/bin/sh -c ps -p 1 -o user=')).toBeNull();
    expect(matchHostInternalProbe('/bin/sh -c git -C /app rev-parse --show-toplevel')).toBeNull();
  });

  it('空命令行不匹配任何探针', () => {
    expect(matchHostInternalProbe('')).toBeNull();
    expect(matchHostInternalProbe('   ')).toBeNull();
  });
});

describe('hasAgentAttribution', () => {
  it('没有任何归属字段时判定为宿主自身动作', () => {
    expect(hasAgentAttribution({})).toBe(false);
    expect(hasAgentAttribution({ session_id: undefined, tool_call_id: undefined })).toBe(false);
  });

  it('任一归属字段存在时判定为 agent 动作的产物', () => {
    expect(hasAgentAttribution({ session_id: 'sess-1' })).toBe(true);
    expect(hasAgentAttribution({ run_id: 'run-1' })).toBe(true);
    expect(hasAgentAttribution({ agent_id: 'agent-1' })).toBe(true);
    expect(hasAgentAttribution({ tool_call_id: 'call-1' })).toBe(true);
    expect(hasAgentAttribution({ tool_name: 'exec' })).toBe(true);
  });
});
