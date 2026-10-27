# sst-security-control-openclaw

**English** · [简体中文](https://github.com/zhanxingtai/openclaw-security-control/blob/main/README.zh.md)

An open-source runtime security plugin for OpenClaw. It provides local risk detection, security event logging, and blocking of high-risk operations.

**Highlights**: batteries included. Runs locally out of the box — no account registration, no cloud connectivity.

## Installation

### Plugin marketplace

Published on the [ClawHub](https://clawhub.ai/) plugin marketplace — search `sst-security-control-openclaw` there, or install from the CLI:

```bash
# 1. Look up the package in the marketplace (optional)
openclaw plugins search sst-security-control-openclaw

# 2. Install from the marketplace
openclaw plugins install clawhub:@zhanxing/sst-security-control-openclaw --accept-capabilities
openclaw plugins enable sst-security-control-openclaw
openclaw gateway restart
```

### Build from source

```bash
# 1. Build the package
npm install --legacy-peer-deps
npm run build:prod

# 2. Copy the tarball to the target server
scp install/sst-security-control-openclaw-1.0.2.tgz root@server:~/.openclaw/

# 3. Install on the server (run these two commands in separate terminal sessions)
openclaw plugins install npm-pack:$HOME/.openclaw/sst-security-control-openclaw-1.0.2.tgz --accept-capabilities --force
openclaw plugins enable sst-security-control-openclaw
openclaw gateway restart
```

## Uninstall

```bash
openclaw plugins uninstall sst-security-control-openclaw
```

## Capabilities

- Agent session and behavior event logging (NDJSON)
- High-risk actions (reverse shells, sensitive file access, and similar) are blocked in `enforce` mode; everything else is only flagged and warned
- Runtime status and event panel (Control UI → SST Security Control)

### Security panel

The panel shows events, interventions, assets, and policy hits. OpenClaw 9.4's Control UI hosts it in a sandboxed iframe that cannot use `localStorage`, so the tab itself renders blank — open the standalone panel directly:

```text
http://<host>:<port>/openclaw-security-monitor/panel
```

## Configuration

The default configuration shipped with a fresh install is already tuned to a production baseline and works as-is. To adjust it:

```bash
openclaw plugins config sst-security-control-openclaw --set \
  "intervention.mode=audit" \
  "application.enabled=true"
```

Key configuration options:

| Option | Default | Description |
|------|--------|------|
| `intervention.mode` | `enforce` | `audit` (log only) or `enforce` (block) |
| `application.enabled` | `true` | Application event collection switch |
| `application.runtimeHooks.enabled` | `false` | Enable runtime hooks (requires `NODE_OPTIONS`) |
| `intervention.failStrategy` | `fail_closed` | Behavior when the intervention engine fails or times out (`fail_open` allow / `fail_closed` block) |
| `collector.ndjsonPath` | `~/.openclaw/security-events.jsonl` | Event log path |

## Custom SPL Rules

Blocking is driven by SPL declarative rules (YAML, `apiVersion: security.use/v1`). A ready-to-use rule set ships with the package; see [policies/security-policy.spl.yaml](https://github.com/zhanxingtai/openclaw-security-control/blob/main/policies/security-policy.spl.yaml) for rule examples. Before switching to `enforce` mode, copy the policy file to `~/.openclaw/security-policy.yaml` and review the rules.

## Security Events

Events are NDJSON lines. The `event_type` values this version actually emits, by layer.
Types prefixed with `x_openclaw_` are project extensions: the platform ingest
(`validate_batch`) rejects whole batches containing unregistered bare-name types,
while unregistered `x_<project>_` extensions pass after common-field validation.

| Layer | Event types | Requires Runtime Hooks |
|-------|-------------|------------------------|
| Application | `agent_session_start` / `agent_session_end`, `agent_start` / `agent_stop`, `x_openclaw_subagent_start` / `x_openclaw_subagent_progress` / `x_openclaw_subagent_end`, `agent_message`, `agent_tool_call` / `agent_tool_result`, `cron_changed`, `x_openclaw_cron_run`, `code_mode_exec`, `reasoning` | no |
| Application (file) | `file_read` / `file_write` / `file_delete` / `file_privilege` — derived from tool names (`fs.readFile` → `file_read`) | no |
| System (process) | `process_start`, `x_openclaw_process_change` / `process_exit` / `x_openclaw_process_snapshot` | `process_start`: **yes** |
| System (cgroup) | `x_openclaw_cgroup_snapshot` / `x_openclaw_cgroup_anomaly` | no (needs `system.enabled`) |
| System (network) | `network_http` | **yes** |
| Asset | `asset_add` / `asset_change` / `asset_remove` / `asset_snapshot` | no |
| Self-protection | `x_openclaw_protection_degraded`, `x_openclaw_tamper_detected`, `x_openclaw_runtime_hook_unloaded` | no |

## Roadmap

- [x] **1.0.0 · Event collection + observability + rule analysis**: NDJSON event stream, Control UI panel, SPL rule security analysis
- [ ] **1.1.0 · Semantic detection SDK**: introduce a standalone semantic detection SDK alongside the existing SPL rule engine to improve detection coverage

## Project Home

- Website: [https://www.zhihuizhanxing.com](https://www.zhihuizhanxing.com)
- Source: [https://github.com/zhanxingtai/openclaw-security-control](https://github.com/zhanxingtai/openclaw-security-control)
- X: [@StarSightTec](https://x.com/StarSightTec)
- WeChat Official Account:

  ![WeChat Official Account](assets/wechat-mp-qr.jpg)

## Support

To report a security vulnerability or request urgent support, contact us by email (please do not disclose security details in a public GitHub issue):

- Security email: <support@zhihuizhanxing.com>

General usage questions and feature requests go to GitHub Issues.

## License

[Apache-2.0](https://github.com/zhanxingtai/openclaw-security-control/blob/main/LICENSE) — dependency declarations are in `package.json`.