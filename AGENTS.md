# OpenClaw Security Monitor - Agent Guidelines

## 1. 构建约定（强制）

### 1.1 不要只用 `npm run build`

`npm run build` 只执行 `tsc`，仅生成 `dist/` 目录，**不会**重新生成可部署的安装包 `install/sst-security-control-openclaw-*.tgz`。

### 1.2 任何源码改动后，必须执行完整生产构建

修改 `src/` 下的任何代码后，若需要生成或更新部署产物，必须执行：

```bash
npm run build:prod
```

该命令会：
1. 清空并重新编译 `dist/`（`tsc --noEmitOnError`）
2. 将编译产物复制到 `install/application/`
3. 复制运行时 hooks、Python monitor、策略文件、README 等到 `install/`
4. 生成 `install/package.json`、`install/index.js`、`install/openclaw.plugin.json`
5. 下载 Python wheel 到 `install/system/vendor`
6. 在 `install/` 内执行 `npm pack` 生成新的 `.tgz`
7. 清理中间产物

> 插件严格自包含，**无** `install.sh` 也不再附带任何外部 setup 脚本；启动期能力在 `src/initialize.ts` 内由插件自身完成。

### 1.3 CI / 带测试的构建

若需要跑完全部测试并打包，使用：

```bash
npm run build:ci
```

等价于 `node scripts/build.js`（先 clean + compile + test + package）。

## 2. 验证清单

完成生产构建后，必须确认以下文件的时间戳和大小已更新：

- [ ] `install/sst-security-control-openclaw-*.tgz`

可通过以下命令快速校验包内是否包含本次代码改动：

```bash
ls -la install/
tar -tzf install/sst-security-control-openclaw-1.0.0.tgz | grep -E "changed/file|changed/keyword"
```

## 3. 避免重复测试反模式

**问题模式**：只运行 `npm run build` 或只提交 `src/` 代码，没有重新生成 `install/*.tgz`，导致测试/部署时仍在使用旧构建产物，重复验证失败。

**正确做法**：
- 每次声称“构建完成”前，先确认 `install/` 下 `.tgz` 的时间戳已更新。
- 不要把 `dist/` 当作最终交付物；部署安装包以 `install/*.tgz` 为准。
- 提交前检查 `git status`，确认 `install/sst-security-control-openclaw-*.tgz` 已变更。

## 4. 相关脚本

| 命令 | 作用 | 是否生成 install/*.tgz |
|------|------|------------------------|
| `npm run build` | 仅 TypeScript 编译到 `dist/` | ❌ |
| `npm run build:prod` | 编译 + 打包，跳过测试 | ✅ |
| `npm run build:ci` | 编译 + 跑全量测试 + 打包 | ✅ |
| `npm run test` | 仅运行测试 | ❌ |
| `npm run lint` | 仅 ESLint 检查 | ❌ |

## 5. OSS 分支维护（github-main，强制）

GitHub 公开仓库（remote `github`）走独立孤儿分支 `github-main`，与内网分支（默认 `initiative/open-source-compliance`）双轨维护。

### 5.1 红线

- **禁止在 `github-main` 上直接 commit**（含 amend/rebase/cherry-pick）。该分支上的 commit 只允许由 `scripts/oss-sync.sh` 产出。
- OSS commit 身份固定为 `hixss <17995374+hixss@users.noreply.github.com>`，**绝不使用**全局 git 配置里的内部身份（`support@zhihuizhanxing.com`）。
- **绝不执行 `git push --mirror`** 到 `github` remote——会绕过所有防护把内网全量历史推到公网。
- 不在 `github` remote 上创建 HTTPS 地址；推送只走已配置的 SSH 通道。

### 5.2 标准发版同步

```bash
bash scripts/oss-sync.sh "release: v1.1.0 说明"
```

脚本自动完成：squash 内网增量到 `github-main`（noreply 身份）→ 内网分支打 `-s ours` 锚点并推送 origin → 推送 GitHub main。打 tag 需手动：

```bash
git tag -a v1.1.0 -m "release v1.1.0"
git push github v1.1.0
```

若 squash 出现冲突（常见于 OSS 分支历史被重写后的 add/add），脚本会中止；解决后手动完成剩余步骤（`git checkout --theirs <file>` → `git add` → 带 noreply 身份 `git commit` → 重跑脚本或手动打锚点推送）。

### 5.3 身份兜底

`scripts/git-hooks/pre-commit` 会拒绝在 `github-main` 上使用非 noreply 身份的提交。每个克隆点执行一次启用：

```bash
git config core.hooksPath scripts/git-hooks
```
