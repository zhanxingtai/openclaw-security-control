/**
 * ClawHub 上架的 source 归属信息（GitHub repository / Commit SHA / Package path）。
 *
 * 为什么需要单独一个脚本：ClawHub 详情页把插件 README 里的**相对**图片路径
 * 按 release 的 source 改写成 raw.githubusercontent.com 的绝对地址（上游
 * clawhub PR #2412：buildReadmeAssetBaseUrl(release) 用 source.repo +
 * 40 位 source.commit 拼 base URL）。缺 repo/commit 时，相对引用既不会被
 * 改写、也不会被代理，详情页上 assets/wechat-mp-qr.jpg 直接 404——发布时
 * 的告警说的就是这件事。
 *
 * 而归属信息**手抄必错**，本仓有两个坑：
 *   1. commit 必须是 GitHub 上真实存在的 40 位 SHA。本仓 `origin` 指向内网
 *      Gitea 镜像，GitHub 远端叫 `github`；clawhub CLI 只在 origin 指向
 *      GitHub 时才自动探测归属，所以从本地目录发布时归属是空的。抄本地
 *      HEAD 也不行——那个提交只在 Gitea 上，raw.githubusercontent 拿不到
 *      （实测 404）。
 *   2. commit 指向的树必须和待发布包的内容一致，否则归属指向的是另一份
 *      代码（上游记录过的失效模式：ClawHub 与 npm 同版本不同构建）。
 *
 * 所以本脚本只做一件事：算出**唯一正确**的那组值，并证明它是对的——
 *   - 仓库必须是 github.com 上的 owner/repo；
 *   - commit 取 GitHub 远端分支上、工作区与之逐字节相同的那个提交
 *     （内容不一致就拒绝出值，而不是给一个会 404 的 SHA）；
 *   - README 里每个相对图片路径，都必须在该 commit 的树里真实存在
 *     （与上游 detectRelativeReadmeAssets 同口径）。
 *
 * 用法：
 *   node scripts/clawhub-source.mjs            # 打印归属信息 + 发布命令
 *   node scripts/clawhub-source.mjs --check    # 只校验（内容不一致即非零退出）
 *   node scripts/clawhub-source.mjs --stamp    # 把归属信息写进 clawhub.source.json
 *
 * 打印出来的发布命令还带 --display-name：ClawHub 侧没有合法的地方放"人类可读的
 * 插件名"（宿主清单的顶层字段里没有 displayName，package.json#openclaw.plugin.label
 * 只对宿主 UI 生效），不回退的话市场列表上就只有包名 slug。
 *
 * --stamp 写的是仓库根的 clawhub.source.json，不是宿主清单：宿主清单
 * （openclaw.plugin.json）只允许静态能力元数据，装机规格归 package.json#openclaw
 * .install，而 ClawHub 的 source 归属既不在清单里也不在 package.json 里——它是
 * 发布时传给 CLI 的 --source-* 参数。落一份仓内记录只为"这次发布对应哪个提交"
 * 可查，权威归属永远是发布命令里的 --source-commit。
 *
 * --stamp 的已知性质：记录里的 commit 是"打戳之前"那棵树的提交，而打戳本身
 * 又要再提交一次——所以记录的 SHA 天然比公开分支落后一个提交。这不是 bug，
 * 是自指（提交无法包含自己的 SHA）导致的固有结果。图片改写只要求该提交里存在
 * 相应文件，这一条不受影响。
 */
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

/**
 * @typedef {{ repo: string, commit: string, ref: string, path: string }} SourceAttribution
 * @typedef {{ code: number, stdout: string, stderr: string }} GitResult
 * @typedef {(args: string[], cwd?: string) => GitResult} GitRunner
 */

const COMMIT_RE = /^[0-9a-f]{40}$/;
const REPO_RE = /^[^/\s]+\/[^/\s]+$/;

/**
 * 从远端 URL 里解析 GitHub 的 owner/repo。认得 git@ / https / ssh 三种写法。
 * 只接受仓库根 URL——带 /tree/main 之类后缀的一律不认（那是网页地址，
 * 不是仓库地址）。
 *
 * @param {string} url
 * @returns {string | null} owner/repo，或 null 表示不是 GitHub 仓库地址
 */
export function parseGitHubRepo(url) {
  if (typeof url !== 'string') return null;
  const trimmed = url.trim();
  const m = /^(?:(?:https?|ssh):\/\/)?(?:[^@/\s]+@)?github\.com[/:]([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/.exec(
    trimmed
  );
  if (!m) return null;
  const repo = `${m[1]}/${m[2]}`;
  return REPO_RE.test(repo) ? repo : null;
}

/**
 * 挑出 GitHub 远端：优先叫 `github` 的，其次 URL 指向 github.com 的。
 *
 * 本仓 origin 是内网 Gitea 镜像，所以「取 origin」是错的取法。
 *
 * @param {GitRunner} run
 * @param {string} cwd
 * @returns {{ name: string, url: string } | null}
 */
export function pickGitHubRemote(run, cwd = ROOT) {
  const result = run(['remote', '-v'], cwd);
  if (result.code !== 0) return null;
  /** @type {Map<string, string>} */
  const urls = new Map();
  for (const line of result.stdout.split('\n')) {
    const m = /^(\S+)\s+(\S+)\s+\((fetch|push)\)$/.exec(line.trim());
    if (!m) continue;
    if (m[3] === 'fetch') urls.set(m[1], m[2]);
  }
  const named = urls.get('github');
  if (named && parseGitHubRepo(named)) return { name: 'github', url: named };
  for (const [name, url] of urls) {
    if (parseGitHubRepo(url)) return { name, url };
  }
  return null;
}

/**
 * 扫出 README 里的相对图片引用，口径与上游 detectRelativeReadmeAssets 对齐：
 * 只认相对路径；http(s)、协议相对（//）、data:、mailto:、tel:、纯片段一律不算。
 *
 * @param {string} markdown
 * @returns {string[]} 去重后的相对图片路径
 */
export function detectRelativeReadmeAssets(markdown) {
  /** @type {string[]} */
  const found = [];
  const push = (raw) => {
    if (!raw) return;
    const value = raw.trim();
    if (!value) return;
    if (/^(?:https?:)?\/\//i.test(value)) return;
    if (/^(?:data|mailto|tel):/i.test(value)) return;
    if (value.startsWith('#')) return;
    const clean = value.split('#')[0].split('?')[0];
    if (!clean) return;
    if (!found.includes(clean)) found.push(clean);
  };
  // Markdown 图片：![alt](path "title")
  for (const m of markdown.matchAll(/!\[[^\]]*\]\(\s*([^)\s]+)/g)) push(m[1]);
  // HTML 图片：<img src="path">
  for (const m of markdown.matchAll(/<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) push(m[1]);
  return found;
}

/**
 * 校验一组归属信息本身是否合法（不看 git）。
 *
 * @param {Partial<SourceAttribution>} attribution
 * @returns {SourceAttribution}
 */
export function assertSourceAttribution(attribution) {
  const repo = attribution.repo ?? '';
  const commit = attribution.commit ?? '';
  const ref = attribution.ref ?? '';
  const pkgPath = attribution.path ?? '';

  const problems = [];
  if (!REPO_RE.test(repo)) problems.push(`repository 不是合法的 owner/repo：${JSON.stringify(repo)}`);
  if (!COMMIT_RE.test(commit)) {
    problems.push(`commit 必须是 40 位十六进制 SHA：${JSON.stringify(commit)}`);
  }
  if (!ref) problems.push('ref 不能为空');
  if (!pkgPath) problems.push('package path 不能为空');
  if (problems.length > 0) {
    throw new Error(`ClawHub source 归属信息不合法：\n${problems.map((p) => `  - ${p}`).join('\n')}`);
  }
  return { repo, commit, ref, path: pkgPath };
}

/**
 * 生成发布命令。--source-path 是包在仓库里的相对路径，本仓在根目录即 "."。
 *
 * listing.displayName 是**上架展示名**，必须显式传，不能指望清单兜底：宿主清单
 * 的合法顶层字段里没有 displayName，CLI 的回退顺序是 pluginManifest.name →
 * package.json#displayName → README 的 H1，前两者在本仓都只会给出
 * "sst-security-control-openclaw" 这种包名。人类可读的标签在
 * package.json#openclaw.plugin.label 里。
 *
 * 这里不自动带 --categories：清单的 categories 是**宿主**的插件浏览分类
 * （openclaw 的 PLUGIN_CATEGORY_SLUGS），ClawHub 的 --categories 是市场目录
 * 的 slug，两套取值空间不同且后者由服务端校验，猜错会被发布接口打回。
 *
 * @param {SourceAttribution} attribution
 * @param {string} artifact 待发布的归档（tgz 路径或目录）
 * @param {{ displayName?: string }} [listing]
 * @returns {string}
 */
export function renderPublishCommand(attribution, artifact, listing = {}) {
  const lines = [`clawhub package publish ${artifact} \\`];
  const displayName = listing.displayName?.trim();
  if (displayName) {
    lines.push(`  --display-name "${displayName}" \\`);
  }
  lines.push(
    `  --source-repo ${attribution.repo} \\`,
    `  --source-commit ${attribution.commit} \\`,
    `  --source-ref ${attribution.ref} \\`,
    `  --source-path ${attribution.path}`
  );
  return lines.join('\n');
}

/**
 * 从仓内文件里取上架展示信息。
 *
 * 显示名取 package.json#openclaw.plugin.label —— 那是本仓唯一一处"人类可读的
 * 插件名"的权威来源（清单里没有合法字段能放它）。
 *
 * @param {string} [root]
 * @returns {{ displayName: string }}
 */
export function resolveListing(root = ROOT) {
  let label = '';
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    const value = pkg?.openclaw?.plugin?.label;
    if (typeof value === 'string') label = value.trim();
  } catch (err) {
    throw new Error(
      `读取 package.json 失败，无法取上架显示名：${err instanceof Error ? err.message : String(err)}`
    );
  }
  return { displayName: label };
}

/**
 * 算出归属信息，并证明它对得上待发布的内容。
 *
 * 判定"对得上"的依据有两条，缺一不可：
 *   1. 工作区干净（git status --porcelain 为空）——否则包里会有不在任何提交
 *      里的内容，归属无从指起；
 *   2. 该 commit 的树与工作区逐字节相同（git diff --quiet）——否则归属指向
 *      的是另一份代码。
 *
 * @param {GitRunner} run
 * @param {{ cwd?: string, ref?: string, packagePath?: string, readmeFiles?: string[] }} options
 * @returns {SourceAttribution}
 */
export function resolveSourceAttribution(run, options = {}) {
  const cwd = options.cwd ?? ROOT;
  const ref = options.ref ?? 'main';
  const packagePath = options.packagePath ?? '.';

  const remote = pickGitHubRemote(run, cwd);
  if (!remote) {
    throw new Error(
      '找不到 GitHub 远端。本仓 origin 指向内网 Gitea 镜像，GitHub 远端叫 github；' +
        '没有它就没有 raw.githubusercontent.com 的归属来源。'
    );
  }
  const repo = parseGitHubRepo(remote.url);
  if (!repo) {
    throw new Error(`远端 ${remote.name} 的地址不是 GitHub 仓库：${remote.url}`);
  }

  const commitResult = run(['rev-parse', '--verify', `${remote.name}/${ref}`], cwd);
  const commit = commitResult.code === 0 ? commitResult.stdout.trim() : '';
  if (!COMMIT_RE.test(commit)) {
    throw new Error(
      `本地没有 ${remote.name}/${ref} 的提交对象。先执行 ` +
        `\`git fetch ${remote.name} ${ref}\`（或先跑 scripts/oss-sync.sh 把内容同步到 GitHub），` +
        '再重新计算归属信息。'
    );
  }

  const status = run(['status', '--porcelain'], cwd);
  if (status.code !== 0) {
    throw new Error(`git status 执行失败：${status.stderr.trim()}`);
  }
  if (status.stdout.trim() !== '') {
    throw new Error(
      '工作区不干净，归属信息无从指起。先把改动提交（提交后还要同步到 GitHub），' +
        '再重新计算归属信息。\n' +
        status.stdout
          .split('\n')
          .slice(0, 10)
          .map((line) => `  ${line}`)
          .join('\n')
    );
  }

  const diff = run(['diff', '--quiet', commit, '--'], cwd);
  if (diff.code !== 0) {
    throw new Error(
      `提交 ${commit} 的内容与当前工作区不一致，归属会指向另一份代码。` +
        '先把当前内容同步到 GitHub（scripts/oss-sync.sh），再重新计算归属信息。'
    );
  }

  const attribution = assertSourceAttribution({ repo, commit, ref, path: packagePath });

  // README 里的相对图片必须在这个 commit 的树里真实存在——否则详情页上的
  // 改写地址会指向一个没有该文件的提交（404 换了个地方出现）。
  const readmeFiles = options.readmeFiles ?? ['README.md', 'README.zh.md'];
  for (const rel of readmeFiles) {
    const abs = path.join(cwd, rel);
    if (!fs.existsSync(abs)) continue;
    const markdown = fs.readFileSync(abs, 'utf8');
    for (const asset of detectRelativeReadmeAssets(markdown)) {
      const exists = run(['cat-file', '-e', `${commit}:${asset}`], cwd);
      if (exists.code !== 0) {
        throw new Error(
          `README(${rel}) 引用的相对图片 ${asset} 在提交 ${commit} 的树里不存在，` +
            '详情页改写后的地址会 404。请先提交该图片再发布。'
        );
      }
    }
  }

  return attribution;
}

/**
 * 把归属信息写进仓内的归属记录（clawhub.source.json 的内容）。
 *
 * 不写宿主清单：宿主清单的合法顶层字段里没有"source 归属"这一项，
 * 装机规格归 package.json#openclaw.install，而 install 块里也没有 source
 * 子结构——归属信息只存在于 ClawHub 的发布载荷里。
 *
 * @param {Record<string, any> | null | undefined} existing 已有记录（没有则传 null）
 * @param {SourceAttribution} attribution
 * @returns {Record<string, any>} 新的记录对象（不改原对象）
 */
export function stampSourceAttribution(existing, attribution) {
  const prev = existing && typeof existing === 'object' ? existing : {};
  return {
    ...prev,
    repo: attribution.repo,
    url: `https://github.com/${attribution.repo}`,
    ref: attribution.ref,
    commit: attribution.commit,
    path: attribution.path,
  };
}

/**
 * @param {string[]} args
 * @param {string[]} cwd
 * @returns {GitResult}
 */
function defaultRun(args, cwd) {
  try {
    const stdout = execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    const e = /** @type {any} */ (err);
    return {
      code: typeof e.status === 'number' ? e.status : 1,
      stdout: e.stdout ? String(e.stdout) : '',
      stderr: e.stderr ? String(e.stderr) : String(e.message ?? ''),
    };
  }
}

/**
 * @param {string[]} argv
 */
function main(argv) {
  const mode = argv.includes('--stamp') ? 'stamp' : argv.includes('--check') ? 'check' : 'print';
  const attribution = resolveSourceAttribution(defaultRun, {});

  if (mode === 'stamp') {
    const recordPath = path.join(ROOT, 'clawhub.source.json');
    let existing = null;
    if (fs.existsSync(recordPath)) {
      try {
        existing = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
      } catch (err) {
        throw new Error(`已有归属记录 ${recordPath} 不是合法 JSON：${err instanceof Error ? err.message : String(err)}`);
      }
    }
    fs.writeFileSync(
      recordPath,
      JSON.stringify(stampSourceAttribution(existing, attribution), null, 2) + '\n',
      'utf8'
    );
    console.log(`[clawhub-source] 已写入 ${path.relative(ROOT, recordPath)}：`);
  }

  console.log('ClawHub source 归属信息：');
  console.log(`  GitHub repository : ${attribution.repo}`);
  console.log(`  Commit SHA       : ${attribution.commit}`);
  console.log(`  Ref              : ${attribution.ref}`);
  console.log(`  Package path     : ${attribution.path}`);
  console.log('');
  console.log('发布命令（缺 --source-* 时详情页的相对图片会 404）：');
  console.log(renderPublishCommand(attribution, 'install/<你的插件>.tgz', resolveListing(ROOT)));
  console.log('');
  console.log('网页上传时对应填：');
  console.log(`  GitHub repository : ${attribution.repo}`);
  console.log(`  Commit SHA       : ${attribution.commit}`);
  console.log(`  Package path     : ${attribution.path}（包在仓库根目录）`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`[clawhub-source] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
