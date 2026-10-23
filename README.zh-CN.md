# sst-security-control-openclaw

[English](README.md) · **简体中文**

面向 OpenClaw 的开源运行安全插件，提供本地风险检测、安全事件记录及高风险操作阻断。

**特性**：开箱即用，默认本地独立运行，无需注册账号，不连接云端服务。

## 安装

```bash
# 1. 构建安装包
npm install --legacy-peer-deps
npm run build:prod

# 2. 上传 tarball 到目标服务器
scp install/sst-security-control-openclaw-1.0.1.tgz root@server:~/.openclaw/

# 3. 在服务器上安装（两行命令必须拆两个终端会话）
openclaw plugins install npm-pack:$HOME/.openclaw/sst-security-control-openclaw-1.0.1.tgz --accept-capabilities --force
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

阻断策略为 SPL 声明式规则（YAML，`apiVersion: security.use/v1`），随包提供开箱规则集，规则示例见 [policies/security-policy.spl.yaml](policies/security-policy.spl.yaml)。切换到 `enforce` 模式前，建议将策略文件复制到 `~/.openclaw/security-policy.yaml` 并审核规则。

## 安全事件

事件为 NDJSON 行，主要事件类型包括：

- `agent_session_start` / `agent_start` / `agent_stop`
- `agent_tool_call` / `agent_tool_result`
- `runtime_spawn_intent` / `runtime_spawn_denied`
- `security_audit`（内嵌守卫命中、循环检测、令牌异常）

## 后续计划

- [x] **1.0.0 · 事件采集 + 可观测 + 规则分析**：NDJSON 事件流、Control UI 面板、SPL 规则安全分析
- [ ] **1.1.0 · 语义识别 SDK**：在现有 SPL 规则引擎旁接入独立语义识别 SDK，提升检测能力

## 项目主页

- 官网：[https://www.zhihuizhanxing.com](https://www.zhihuizhanxing.com)
- 源码：[https://github.com/zhanxingtai/openclaw-security-control](https://github.com/zhanxingtai/openclaw-security-control)
- 微信公众号：

  ![微信公众号](assets/wechat-mp-qr.jpg)

## 支持

发现安全漏洞或需要紧急支持，请通过邮件联系（请勿在 GitHub issue 公开披露安全细节）：

- 安全邮箱：<support@zhihuizhanxing.com>

普通使用问题与功能请求走 GitHub Issues。

## 许可证

[Apache-2.0](LICENSE) — 依赖声明见 `package.json`。
