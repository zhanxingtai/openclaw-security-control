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
