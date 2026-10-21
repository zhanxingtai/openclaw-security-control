#!/usr/bin/env bash
# OSS 发版同步：内网开发分支 → github-main → GitHub
#
# 用法：bash scripts/oss-sync.sh "commit message" [内网分支名]
#
# 约束：github-main 禁止手动 commit，所有 OSS commit 必须由本脚本产出，
# 身份硬编码为 GitHub noreply（见下方 OSS_NAME/OSS_EMAIL），避免内部邮箱
# 被烧录进公开仓库历史。pre-commit 钩子（scripts/git-hooks/）为兜底防线。
set -euo pipefail

OSS_NAME="hixss"
OSS_EMAIL="17995374+hixss@users.noreply.github.com"
OSS_BRANCH="github-main"
GITHUB_REMOTE="github"
INTERNAL_REMOTE="origin"

MSG="${1:?用法: bash scripts/oss-sync.sh \"commit message\" [internal-branch]}"
INTERNAL_BRANCH="${2:-initiative/open-source-compliance}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$(git branch --show-current)" = "$OSS_BRANCH" ]; then
  echo "[oss-sync] 请勿在 $OSS_BRANCH 上运行本脚本，请先切回内网分支。" >&2
  exit 1
fi

echo "[oss-sync] 1/3 squash $INTERNAL_BRANCH -> $OSS_BRANCH"
git checkout "$OSS_BRANCH"
# OSS 分支历史可能被重写（如 noreply 身份修正），merge-base 会失效；
# squash 的增量由树对比得出，与血缘无关，真实内容分叉仍会产生冲突。
git merge --squash --allow-unrelated-histories "$INTERNAL_BRANCH"
if git diff --cached --quiet; then
  echo "[oss-sync] 无增量可同步，终止。"
  git checkout "$INTERNAL_BRANCH"
  exit 0
fi
git -c user.name="$OSS_NAME" -c user.email="$OSS_EMAIL" commit -m "$MSG"

echo "[oss-sync] 2/3 内网分支打锚点并推送 $INTERNAL_REMOTE"
git checkout "$INTERNAL_BRANCH"
git merge -s ours --allow-unrelated-histories "$OSS_BRANCH" -m "chore: absorb oss sync"
git push "$INTERNAL_REMOTE" "$INTERNAL_BRANCH"

echo "[oss-sync] 3/3 推送 GitHub"
git checkout "$OSS_BRANCH"
git push "$GITHUB_REMOTE" "$OSS_BRANCH:main"

echo "[oss-sync] 完成：$OSS_BRANCH -> $GITHUB_REMOTE/main"
