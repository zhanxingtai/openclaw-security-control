# sst-security-control-openclaw

[English](https://github.com/zhanxingtai/openclaw-security-control/blob/main/README.md) · **简体中文**

面向 OpenClaw 的开源运行安全插件，提供本地风险检测、安全事件记录及高风险操作阻断。

**特性**：开箱即用，默认本地独立运行，无需注册账号，不连接云端服务。

## 安装

### 插件市场安装

插件已上架 [ClawHub](https://clawhub.ai/) 插件市场，搜索 `sst-security-control-openclaw` 即可找到，也可直接用命令行安装：

```bash
# 1. 在插件市场中检索（可选）
openclaw plugins search sst-security-control-openclaw

# 2. 从插件市场安装
openclaw plugins install clawhub:@zhanxing/sst-security-control-openclaw --accept-capabilities
openclaw plugins enable sst-security-control-openclaw
openclaw gateway restart
```

### 源码构建安装

```bash
# 1. 构建安装包
npm install --legacy-peer-deps
npm run build:prod

# 2. 上传 tarball 到目标服务器
scp install/sst-security-control-openclaw-1.0.2.tgz root@server:~/.openclaw/

# 3. 在服务器上安装（两行命令必须拆两个终端会话）
openclaw plugins install npm-pack:$HOME/.openclaw/sst-security-control-openclaw-1.0.2.tgz --accept-capabilities --force
openclaw plugins enable sst-security-control-openclaw
openclaw gateway restart
```

## 卸载

```bash
openclaw plugins uninstall sst-security-control-openclaw
```

## 主要能力

- 智能体会话及行为事件记录（NDJSON 格式）
- 高危动作（反弹 shell、敏感文件访问等）在 `enforce` 模式下阻断，其余行为仅标记告警
- 运行状态与事件查看面板（Control UI → SST Security Control）

### 安全监控面板

面板展示事件、拦截、资产与策略命中。OpenClaw 9.4 的 Control UI 把面板放在
sandbox iframe 里渲染，该环境不允许使用 `localStorage`，因此 Tab 内不渲染内容
——请直接访问独立面板：

```text
http://<host>:<port>/openclaw-security-monitor/panel
```

## 配置

首次安装默认配置已按生产基线调好，可直接使用。如需调整：

```bash
openclaw plugins config sst-security-control-openclaw --set \
  "intervention.mode=audit" \
  "application.enabled=true"
```

关键配置选项：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `intervention.mode` | `enforce` | `audit`（仅记录）或 `enforce`（阻断） |
| `application.enabled` | `true` | 应用事件采集开关 |
| `application.runtimeHooks.enabled` | `false` | 启用运行时 hooks（需 NODE_OPTIONS 配置） |
| `intervention.failStrategy` | `fail_closed` | 干预引擎故障/超时时的策略（`fail_open` 放行 / `fail_closed` 阻断） |
| `collector.ndjsonPath` | `~/.openclaw/security-events.jsonl` | 事件日志路径 |

## 自定义 SPL 规则

阻断策略为 SPL 声明式规则（YAML，`apiVersion: security.use/v1`），随包提供开箱规则集，规则示例见 [policies/security-policy.spl.yaml](https://github.com/zhanxingtai/openclaw-security-control/blob/main/policies/security-policy.spl.yaml)。切换到 `enforce` 模式前，建议将策略文件复制到 `~/.openclaw/security-policy.yaml` 并审核规则。

## 安全事件

事件为 NDJSON 行。本版本实际会写出的 `event_type`，按层分。
带 `x_openclaw_` 前缀的是项目扩展类型：平台接入层（`validate_batch`）对未登记
的裸名类型整批拒收 NDJSON，而未登记的 `x_<project>_` 前缀扩展只校验公共字段后放行。

| 层 | 事件类型 | 需要运行时 hooks |
|----|---------|-------------------|
| 应用 | `agent_session_start` / `agent_session_end`、`agent_start` / `agent_stop`、`x_openclaw_subagent_start` / `x_openclaw_subagent_progress` / `x_openclaw_subagent_end`、`agent_message`、`agent_tool_call` / `agent_tool_result`、`cron_changed`、`x_openclaw_cron_run`、`code_mode_exec`、`reasoning` | 否 |
| 应用（文件） | `file_read` / `file_write` / `file_delete` / `file_privilege` —— 由工具名归一化而来（`fs.readFile` → `file_read`） | 否 |
| 系统（进程） | `process_start`、`x_openclaw_process_change` / `process_exit` / `x_openclaw_process_snapshot` | `process_start`：**是** |
| 系统（cgroup） | `x_openclaw_cgroup_snapshot` / `x_openclaw_cgroup_anomaly` | 否（需 `system.enabled`） |
| 系统（网络） | `network_http` | **是** |
| 资产 | `asset_add` / `asset_change` / `asset_remove` / `asset_snapshot` | 否 |
| 自保护 | `x_openclaw_protection_degraded`、`x_openclaw_tamper_detected`、`x_openclaw_runtime_hook_unloaded` | 否 |

## 后续计划

- [x] **1.0.0 · 事件采集 + 可观测 + 规则分析**：NDJSON 事件流、Control UI 面板、SPL 规则安全分析
- [ ] **1.1.0 · 语义识别 SDK**：在现有 SPL 规则引擎旁接入独立语义识别 SDK，提升检测能力

## 项目主页

- 官网：[https://www.zhihuizhanxing.com](https://www.zhihuizhanxing.com)
- 源码：[https://github.com/zhanxingtai/openclaw-security-control](https://github.com/zhanxingtai/openclaw-security-control)
- X（Twitter）：[@StarSightTec](https://x.com/StarSightTec)
- 微信公众号：

  ![微信公众号](assets/wechat-mp-qr.jpg)

## 支持

发现安全漏洞或需要紧急支持，请通过邮件联系（请勿在 GitHub issue 公开披露安全细节）：

- 安全邮箱：<support@zhihuizhanxing.com>

普通使用问题与功能请求走 GitHub Issues。

## 许可证

[Apache-2.0](https://github.com/zhanxingtai/openclaw-security-control/blob/main/LICENSE) — 依赖声明见 `package.json`。
