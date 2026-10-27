#!/usr/bin/env node
/**
 * OpenClaw 安全监控插件 - 构建脚本
 *
 * Usage:
 *   node scripts/build.js         # clean + compile + test + package install/
 *   node scripts/build.js --test  # clean + compile + test + package install/
 *   node scripts/build.js --no-test # clean + compile + package install/
 */

import { execSync, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import * as yaml from 'js-yaml';
import { assertVersionConsistency } from './version-check.mjs';
import {
  assertPublishMetadata,
  buildInstallOpenClawMeta,
} from './clawhub-metadata.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');
const installDir = path.join(rootDir, 'install');
// The embedded Python monitor and Node preload hooks sit at the repo
// root rather than under src/. Fall back to the old paths when absent
// (build.js may run from either tree).
const monitorSrc = fs.existsSync(path.join(rootDir, 'monitor'))
  ? path.join(rootDir, 'monitor')
  : path.join(rootDir, 'src', 'monitor');
const hooksSrc = fs.existsSync(path.join(rootDir, 'hooks'))
  ? path.join(rootDir, 'hooks')
  : path.join(rootDir, 'src', 'hooks');

const args = process.argv.slice(2);
const runTests = !args.includes('--no-test');

function log(message) {
  console.log(`[build] ${message}`);
}

function run(command, options = {}) {
  log(`> ${command}`);
  try {
    execSync(command, {
      stdio: 'inherit',
      cwd: rootDir,
      env: process.env,
      ...options,
    });
  } catch (err) {
    console.error(`[build] Command failed: ${command}`);
    process.exit(err.status || 1);
  }
}

function rmDir(dir) {
  if (fs.existsSync(dir)) {
    log(`Cleaning ${path.relative(rootDir, dir)}`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function copyFile(src, dest) {
  const destDir = path.dirname(dest);
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, dest);
}

// 缓存与测试产物一律不进包。tsconfig 的 `exclude: ["**/*.test.ts"]` 只约束
// tsc 的编译产物，管不到 copyDir 对源码目录的原样拷贝——hooks/*.test.ts 和
// monitor/.pytest_cache/（本地跑 pytest 留下的，已被 .gitignore 忽略）此前
// 就是这样漏进 tgz 的。规则挂在 copyDir 内部而非逐个调用点，新增拷贝路径
// 不会重新引入。
const CACHE_DIR_NAMES = ['__pycache__', '.pytest_cache'];
const TEST_FILE_RE = /\.test\.[cm]?[jt]sx?$/;

function copyDir(src, dest, options = {}) {
  const excludeNames = options.excludeNames || [];
  const excludeExtensions = options.excludeExtensions || [];
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (CACHE_DIR_NAMES.includes(entry.name) || TEST_FILE_RE.test(entry.name)) {
      continue;
    }
    if (excludeNames.includes(entry.name)) {
      continue;
    }
    const ext = path.extname(entry.name).toLowerCase();
    if (excludeExtensions.includes(ext)) {
      continue;
    }
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath, options);
    } else {
      copyFile(srcPath, destPath);
    }
  }
}

/**
 * Copy runtime npm dependencies (currently js-yaml + transitive argparse)
 * from the build host's node_modules into the install bundle's
 * application/node_modules/ folder. Without this, RuleLoader's
 * `import('js-yaml')` fails inside the extracted plugin (no parent npm
 * install runs in the typical tar+load workflow), leaving the intervention
 * engine with an empty (allow-all) policy — block-sensitive-system-files
 * and friends become silently inert. Skips a dep that isn't installed
 * locally; the bundle's package.json still lists it so a follow-up
 * `npm install` on the target host can recover.
 */
function vendorRuntimeDeps(applicationDir) {
  const deps = ['js-yaml', 'argparse'];
  const rootNm = path.join(rootDir, 'node_modules');
  for (const dep of deps) {
    const src = path.join(rootNm, dep);
    if (!fs.existsSync(src)) {
      log(`runtime dep ${dep} not present in build host node_modules; skipping (bundle will need npm install)`);
      continue;
    }
    const dest = path.join(applicationDir, 'node_modules', dep);
    copyDir(src, dest, {
      // browser/: Node runtime 不需要 js-yaml 的浏览器构建
      // bin/:  CLI 入口不进 tgz
      // LICENSE/CHANGELOG.md/README.md:  vendored 元数据,与 install/LICENSE 重复且运行时不需要
      excludeNames: ['.bin', 'test', 'tests', 'browser', 'bin', 'LICENSE'],
      excludeExtensions: ['.cmd', '.ps1', '.map', '.d.ts', '.md'],
    });
    log(`vendored ${dep} → ${path.relative(rootDir, dest)}`);
  }
}

// Platforms the offline vendor cache must cover. abi3 wheels (cp37-abi3)
// ship since psutil 5.9, so a single wheel per tag covers Python 3.8+ on each
// platform. Tags must match the exact platform tags psutil publishes on PyPI
// (verified against psutil 7.2.2); a mismatched tag makes pip skip the wheel.
const VENDOR_PLATFORMS = [
  'manylinux2010_x86_64', // composes manylinux2010/manylinux_2_12/manylinux_2_28
  'manylinux2014_aarch64', // composes manylinux2014/manylinux_2_17/manylinux_2_28
  'musllinux_1_2_x86_64',
  'musllinux_1_2_aarch64',
  'win_amd64',
  'win_arm64',
  'macosx_10_9_x86_64',
  'macosx_11_0_arm64',
];

// Returns true only when every configured platform already has a wheel in the
// vendor dir. A partial cache (e.g. yesterday's single Windows wheel) must be
// refilled, so "any wheel exists" is deliberately not enough.
function isVendorComplete(vendorDir) {
  if (!fs.existsSync(vendorDir)) {
    return false;
  }
  const wheels = fs.readdirSync(vendorDir).filter((f) => f.endsWith('.whl'));
  return VENDOR_PLATFORMS.every((p) => wheels.some((f) => f.includes(p)));
}

function downloadPythonVendor() {
  const requirementsPath = path.join(monitorSrc, 'requirements.txt');
  if (!fs.existsSync(requirementsPath)) {
    log('Python requirements.txt not found; skipping vendor download');
    return;
  }

  const vendorDir = path.join(installDir, 'system', 'vendor');
  if (isVendorComplete(vendorDir)) {
    log(`vendor fully populated at ${path.relative(rootDir, vendorDir)}; skipping`);
    return;
  }

  const pipCommands = ['pip3', 'pip', 'python3 -m pip', 'python -m pip'];
  let pipCmd;
  for (const cmd of pipCommands) {
    try {
      execSync(`${cmd} --version`, { stdio: 'ignore' });
      pipCmd = cmd;
      break;
    } catch {
      // try next
    }
  }

  if (!pipCmd) {
    log('pip not found on build host; skipping vendor download (setup will fall back to online pip)');
    return;
  }

  fs.mkdirSync(vendorDir, { recursive: true });

  // pip's --platform only takes effect when a single non-native tag is given;
  // passing several at once makes it silently fall back to the current host's
  // wheel. So loop one download per platform, into the shared vendor dir.
  // pip skips the save when the exact wheel is already present in --dest, so
  // re-runs cheaply refill only what is missing.
  log(`downloading Python wheels into ${path.relative(rootDir, vendorDir)}`);
  let downloaded = 0;
  for (const platform of VENDOR_PLATFORMS) {
    const cmd = `${pipCmd} download --dest "${vendorDir}" --requirement "${requirementsPath}" --only-binary=:all: --python-version 3.8 --platform ${platform}`;
    try {
      execSync(cmd, { stdio: 'inherit' });
      downloaded += 1;
    } catch (err) {
      log(`pip download failed for ${platform}: ${err.message}`);
    }
  }
  const wheels = fs.readdirSync(vendorDir).filter((f) => f.endsWith('.whl'));
  log(`cached ${wheels.length} wheel(s): ${wheels.join(', ')}`);

  const missing = VENDOR_PLATFORMS.filter(
    (p) => !wheels.some((f) => f.includes(p))
  );
  if (missing.length > 0) {
    log(`vendor incomplete; missing platforms: ${missing.join(', ')} (setup will fall back to online pip on those hosts)`);
  }
}

function packageInstall() {
  log('Packaging install directory');

  rmDir(installDir);
  fs.mkdirSync(installDir, { recursive: true });

  // Install bundle layout keeps application/ and system/ directory names
  // for high readability. The embedded Python monitor is copied separately
  // to system/ so it does not also appear under application/.
  // Also exclude the dist-only plugin manifest; the root manifest is the source
  // of truth for the install bundle.
  copyDir(distDir, path.join(installDir, 'application'), {
    excludeNames: ['monitor', 'openclaw.plugin.json'],
    excludeExtensions: ['.pyc', '.map'], // .map: 生产不需要 source map
  });

  // Vendor runtime npm dependencies next to application/ so the bundle
  // is self-contained. Without this, RuleLoader's `import('js-yaml')`
  // fails inside the extracted plugin (no parent npm install runs in
  // the typical `tar -xzf ... && load` workflow), leaving the
  // intervention engine running with an empty (allow-all) policy and
  // every block rule — including block-sensitive-system-files — silently
  // inert.
  vendorRuntimeDeps(path.join(installDir, 'application'));

  // Note: dist/assets/ is already copied into install/application/assets/
  // by the preceding `copyDir(distDir, install/application, ...)` step,
  // so the favicon is bundled automatically. findFaviconPath walks
  // ../assets first, which matches the install layout exactly.

  if (fs.existsSync(monitorSrc)) {
    copyDir(monitorSrc, path.join(installDir, 'system'), {
      // run_tests.py / test_process_monitor.py: 测试文件不进 tgz
      // （*.test.ts 由 copyDir 统一排除，此处只剩 Python 命名不带后缀的）
      excludeNames: ['run_tests.py', 'test_process_monitor.py'],
      excludeExtensions: ['.pyc'],
    });
  }

  // Copy runtime hooks into the install bundle.
  // hooks/ 下是未编译的 .ts 源码，copyDir 会统一排掉 *.test.ts（tsconfig 的
  // exclude 只管 tsc 产物，管不到这里的原样拷贝）。
  if (fs.existsSync(hooksSrc)) {
    copyDir(hooksSrc, path.join(installDir, 'hooks'), {
      excludeExtensions: ['.pyc', '.map'],
    });
  }

  // The plugin is strictly self-contained per the OpenClaw 9.4 spec — no
  // external install helpers are shipped. Bootstrap (policy seed, hook copy,
  // psutil probe) lives in src/initialize.ts and runs inside register().

  // Generate a stripped-down package.json for the deployment bundle.
  // Point main directly at application/index.js for clarity.
  const rootPkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
  const pluginManifest = JSON.parse(
    fs.readFileSync(path.join(rootDir, 'openclaw.plugin.json'), 'utf8')
  );
  const installPkg = {
    name: pluginManifest.name,
    version: rootPkg.version,
    description: rootPkg.description,
    type: rootPkg.type,
    main: 'application/index.js',
    types: 'application/index.d.ts',
    // ClawHub 的上架校验读的是**归档根**的 package.json，也就是即将写进 tgz
    // 的这一份。历史上这里只搬了 extensions，compat/build/install 连同
    // repository/bugs/homepage 一起丢在仓库根，于是上架报
    // "package.json / Package manifest / Missing metadata"——仓库根看着齐全，
    // 发布的包里没有。搬运规则见 scripts/clawhub-metadata.mjs。
    openclaw: buildInstallOpenClawMeta(rootPkg, './index.js'),
    files: [
      'application',
      'application/node_modules',
      'system',
      'hooks',
      'policies',
      'schemas',
      'index.js',
      'openclaw.plugin.json',
      'README.md',
      // 中文版 README 随包分发：npm 包页只渲染 README.md（英文），
      // 中文用户拿到 tgz 后没有 README.zh.md 就只能读英文安装步骤。
      'README.zh.md',
      // 维护者文档（docs/INSTALL.md、docs/CHANGELOG.md 等）不进 tgz；
      // 用户面向安装步骤在 README。其余维护者文档保留在仓库供审计，
      // 但不出现在公开 npm tarball。
      'examples',
      'system/vendor',
      // 合规材料：Apache-2.0 要求随分发附带许可文本。
      'LICENSE',
    ],
    keywords: rootPkg.keywords,
    author: rootPkg.author,
    license: rootPkg.license,
    // 上架页要跳转仓库 / 提 issue，靠的就是这三个；漏了不影响装，但
    // ClawHub 目录页上会是三个空位。
    repository: rootPkg.repository,
    bugs: rootPkg.bugs,
    homepage: rootPkg.homepage,
    peerDependencies: rootPkg.peerDependencies,
    peerDependenciesMeta: rootPkg.peerDependenciesMeta,
    dependencies: rootPkg.dependencies,
    engines: rootPkg.engines,
  };
  // 打包前拦：metadata 缺一项就打 tgz，等于把错误产物送到用户的上传动作上。
  assertPublishMetadata(installPkg, 'install 端 package.json（ClawHub 上架清单）');
  fs.writeFileSync(
    path.join(installDir, 'package.json'),
    JSON.stringify(installPkg, null, 2) + '\n'
  );

  // Create a root re-export entry so OpenClaw can load from the package root
  // regardless of how the plugin is discovered.
  fs.writeFileSync(
    path.join(installDir, 'index.js'),
    "export * from './application/index.js';\nexport { default } from './application/index.js';\n"
  );

  // Copy plugin manifest to the plugin root, verbatim.
  // 清单里不注入 main/entry：`main`/`entry` 不是宿主清单的合法顶层字段
  // （ClawHub 的 manifest-unknown-fields 校验会判非法）。宿主按
  // package.json#openclaw.extensions 解析入口，那一份由 buildInstallOpenClawMeta
  // 搬运成 "./index.js"，指向 install/index.js 再导出挂件。
  fs.writeFileSync(
    path.join(installDir, 'openclaw.plugin.json'),
    JSON.stringify(pluginManifest, null, 2) + '\n'
  );

  copyFile(path.join(rootDir, 'README.md'), path.join(installDir, 'README.md'));
  copyFile(path.join(rootDir, 'README.zh.md'), path.join(installDir, 'README.zh.md'));
  // 合规材料：Apache-2.0 要求随分发附带许可文本。
  copyFile(path.join(rootDir, 'LICENSE'), path.join(installDir, 'LICENSE'));
  // Ship the canonical intervention policy as policies/security-policy.yaml so
  // setup can seed it. The former examples/security-policy.yaml mirror is gone:
  // it was byte-identical to policies/ and the setup seed template was dropped,
  // leaving no tracked reference to examples/ anywhere in the repo.
  const policyPaths = [
    path.join(rootDir, 'policies', 'security-policy.spl.yaml'),
    path.join(rootDir, 'policies', 'security-policy.yaml'),
    path.join(rootDir, 'policies', 'security-policy.legacy.yaml'),
  ];
  const policySrc = policyPaths.find((p) => fs.existsSync(p));
  if (policySrc) {
    fs.mkdirSync(path.join(installDir, 'policies'), { recursive: true });
    copyFile(policySrc, path.join(installDir, 'policies', 'security-policy.yaml'));
    // examples/ 已下线:不进 tgz(与 policies/ 字节级重复),仓库也不再跟踪该目录。

    // Ship a JSON sibling of the policy: RuleLoader falls back to the .json
    // variant when js-yaml is unavailable in the deployment, which otherwise
    // leaves the intervention engine running with an empty (allow-all) policy.
    const policyJson = JSON.stringify(yaml.load(fs.readFileSync(policySrc, 'utf8')), null, 2) + '\n';
    fs.writeFileSync(path.join(installDir, 'policies', 'security-policy.json'), policyJson);
    log('generated security-policy.json fallback (for deployments without js-yaml)');

    // SPL 策略 JSON Schema 随包分发：使用方编写自定义
    // 策略时的权威参考；schema 同时被 SPLRuleLoader 注释引用。v2 schema 对应
    // security.use/v2（当前合同）；v1 schema 仅作为 legacy 合同
    // 保留（本仓库不发行任何 v1 平台合同，保留 v1 schema 仅用于外部
    // 校验工具兼容）。
    const policySchemaV2Src = path.join(rootDir, 'policies', 'spl-policy-v2.schema.json');
    if (fs.existsSync(policySchemaV2Src)) {
      copyFile(policySchemaV2Src, path.join(installDir, 'policies', 'spl-policy-v2.schema.json'));
      log('copied spl-policy-v2.schema.json (security.use/v2 当前合同)');
    }
  }

  // 事件 JSON Schema 随包分发：security-events.jsonl 每行都带
  // schema_version，但此前全仓没有任何事件 schema 可对——版本号是空的
  // 承诺。消费方（SIEM / 自建工具）需要这份文件才能校验落盘数据。
  const eventSchemaSrc = path.join(rootDir, 'schemas', 'security-event-v1.schema.json');
  if (fs.existsSync(eventSchemaSrc)) {
    fs.mkdirSync(path.join(installDir, 'schemas'), { recursive: true });
    copyFile(eventSchemaSrc, path.join(installDir, 'schemas', 'security-event-v1.schema.json'));
    log('copied security-event-v1.schema.json (事件落盘格式合同)');
  }

  // risk-flags.json 随包分发：SPLRuleLoader 加载期校验 riskFlagsAny/All 拼写
  // 是否在字典中；缺失时跳过校验并 WARN。
  // 需要同时复制到 application/policies/（运行时 loader 路径 ../../
  const riskFlagsSrc = path.join(rootDir, 'policies', 'risk-flags.json');
  if (fs.existsSync(riskFlagsSrc)) {
    copyFile(riskFlagsSrc, path.join(installDir, 'policies', 'risk-flags.json'));
    copyFile(riskFlagsSrc, path.join(installDir, 'application', 'policies', 'risk-flags.json'));
    log('copied risk-flags.json (root + application)');
  }

  // Generate the installable tarball inside install/.
  // OpenClaw 8.2's archive extractor does not support PAX headers, which npm pack
  // on Windows emits. Use GNU tar with --format=ustar to produce a compatible
  // tarball; fall back to npm pack if GNU tar is unavailable.
  const tarballName = `${installPkg.name}-${installPkg.version}.tgz`;
  const tarballPath = path.join(installDir, tarballName);
  const packTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ocsm-pack-'));
  const packStagingDir = path.join(packTempDir, 'package');
  fs.mkdirSync(packStagingDir, { recursive: true });
  copyDir(installDir, packStagingDir);

  let packedTarballName = '';
  let useGnuTar = false;
  try {
    execSync('tar --version', { stdio: 'ignore' });
    useGnuTar = true;
  } catch {
    useGnuTar = false;
  }

  if (useGnuTar) {
    log('Creating ustar tarball in install/');
    try {
      execSync(`tar --format=ustar -czf "${tarballName}" package`, {
        cwd: packTempDir,
        stdio: 'ignore',
        env: process.env,
      });
      packedTarballName = tarballName;
    } catch (err) {
      log(`tar --format=ustar failed: ${err.message}; falling back to npm pack`);
      useGnuTar = false;
    }
  }

  if (!useGnuTar) {
    log('Creating npm-pack tarball in install/');
    execSync('npm pack --silent', {
      cwd: packTempDir,
      stdio: 'ignore',
      env: process.env,
    });
    const packedTarballs = fs
      .readdirSync(packTempDir)
      .filter((name) => name.endsWith('.tgz'))
      .sort((a, b) => fs.statSync(path.join(packTempDir, b)).mtimeMs - fs.statSync(path.join(packTempDir, a)).mtimeMs);
    if (packedTarballs.length === 0) {
      throw new Error('npm pack did not produce a tarball');
    }
    packedTarballName = packedTarballs[0];
  }

  fs.copyFileSync(path.join(packTempDir, packedTarballName), tarballPath);
  fs.rmSync(packTempDir, { recursive: true, force: true });
  log(`created ${tarballName}`);

  // Keep only the tarball in install/ for distribution. The expanded bundle
  // contents are intermediate build artifacts. install.sh is no longer
  // generated — the plugin is strictly self-contained per the OpenClaw 9.4
  // plugin spec; install is `openclaw plugins install npm-pack:<tarball>`.
  const keepNames = new Set([tarballName]);
  for (const entry of fs.readdirSync(installDir, { withFileTypes: true })) {
    if (keepNames.has(entry.name)) {
      continue;
    }
    const fullPath = path.join(installDir, entry.name);
    fs.rmSync(fullPath, { recursive: true, force: true });
  }

  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else {
        files.push(fullPath);
      }
    }
  }
  walk(installDir);

  log(`Install package (${files.length} files):`);
  for (const file of files.sort()) {
    const stat = fs.statSync(file);
    const relPath = path.relative(installDir, file);
    console.log(`  - ${relPath} (${stat.size} bytes)`);
  }
}

// 完整性断言：build.js 打的 tgz 内部 layout 是 `package/<...>`（install/ 是
// staging 目录,不出现在 tgz 内）。OpenClaw 装入后从 `application/index.js`
// 加载插件。若编译入口缺失,OpenClaw 会报"package install requires compiled
// runtime output",与历史上 `npm run pack` 走 `tsc && npm pack`(漏打 dist/)的
// 现象一致。此处硬性阻断：缺任一关键文件即 build 失败,避免错误 tgz 进入
// install/。
function assertInstallTarballIntegrity(tarballPath, installDir) {
  if (!fs.existsSync(tarballPath)) {
    log(`FAIL: tgz not found at ${tarballPath}`);
    process.exit(1);
  }
  let entries;
  // Windows 上 GNU tar 把 `E:\...` 绝对路径的 `E:` 当 host 解析("Cannot connect
  // to E: resolve failed")，cwd + 相对路径绕开。同脚本其它 tar 调用也在
  // packTempDir 子目录里走相对路径。
  try {
    const r = spawnSync('tar', ['-tzf', path.basename(tarballPath)], {
      cwd: path.dirname(tarballPath),
      encoding: 'utf8',
    });
    if (r.status !== 0) {
      throw new Error(`tar exit ${r.status}: ${r.stderr || r.stdout || '(no output)'}`);
    }
    // CI runner 的 tar 可能是 bsdtar（Windows 自带），输出 CRLF，
    // 残留 \r 会让下面的路径比对全部失配——按 \r?\n 切分。
    entries = (r.stdout || '').split(/\r?\n/).filter(Boolean);
  } catch (err) {
    log(`FAIL: cannot list tarball entries: ${err.message}`);
    process.exit(1);
  }
  // tgz 内 layout：包根 `package/`，install/ 是 staging 目录不进 tgz，
  // tgz 实际是 install/ 目录内容的镜像。关键路径必须存在（编译入口、
  // 插件清单、策略）。注：策略在 install 阶段重命名为 security-policy.yaml
  // （去掉 .spl 中缀,OpenClaw runtime 加载用此名）。
  // 预加载文件名单钉死在此：NODE_OPTIONS 只能 --require 一个随包分发的文件，
  // 而 hooks/package.json 的 "type": "commonjs" 是它们能被 --require 的前提 ——
  // 少了它，根 package.json 的 "type": "module" 会把 hooks/*.js 当 ESM，
  // Node 启动期直接 ERR_REQUIRE_ESM。
  // 与 src/hook-locations.ts 的 HOOK_BASENAMES 一一对应（由
  // tests/hook-locations.test.ts 断言两侧相等，防止各自演进失配）。
  // 注意不能改成"现读 hooks/ 目录"：断言跑在 install/ 被裁剪成只剩 tgz 之后，
  // 那时目录已不存在，会让必含检查静默退化成空集。
  const REQUIRED_HOOK_FILES = ['hook-mounter.js', 'runtime.js', 'network.js'];
  const required = [
    'package/application/index.js',              // 编译入口（dist/ index.js 拷贝）
    'package/package.json',                      // install 端 package.json（runtime 用）
    'package/openclaw.plugin.json',              // 插件清单
    'package/policies/security-policy.yaml',     // shipped SPL 策略（install 阶段 rename）
    'package/hooks/package.json',                // hooks 的 commonjs 类型声明（--require 前提）
    ...REQUIRED_HOOK_FILES.map((f) => `package/hooks/${f}`),
  ];
  const missing = required.filter(
    (p) => !entries.some((e) => e === p || e.startsWith(p + '/') || e === p)
  );
  if (missing.length > 0) {
    log(`FAIL: tarball ${path.basename(tarballPath)} 缺少 ${missing.length} 项关键文件：`);
    for (const m of missing) log(`  - ${m}`);
    log('  提示：历史上 `npm run pack` 走 `tsc && npm pack`（依赖 package.json files 字段）' +
        '会漏打 dist/，本断言正是为此而设。请改用 `npm run pack`（已重定向到 build.js）。');
    log('  完整 entry 列表前 30：');
    for (const e of entries.slice(0, 30)) log(`    ${e}`);
    process.exit(1);
  }
  // 反向断言：测试/缓存产物不得进包。tsconfig 的 exclude 只约束 tsc 产物，
  // 管不到 copyDir 对源码目录的原样拷贝——hooks/*.test.ts 与
  // monitor/.pytest_cache/ 曾这样静默进包。正向的"必含"检查看不见这类泄漏
  // （entry 只是多了几行，测试仍绿），所以反向钉死，新泄漏直接让构建失败。
  const leaked = entries.filter(
    (e) => TEST_FILE_RE.test(e) || CACHE_DIR_NAMES.some((c) => e.split('/').includes(c))
  );
  if (leaked.length > 0) {
    log(`FAIL: tarball ${path.basename(tarballPath)} 含 ${leaked.length} 个测试/缓存产物：`);
    for (const e of leaked) log(`  - ${e}`);
    log('  提示：检查 copyDir 的 exclude 规则；若新增了拷贝路径，确认它没有绕开统一过滤。');
    process.exit(1);
  }
  // 双向契约：归档里 hooks/*.js 的实际名单必须与 REQUIRED_HOOK_FILES 完全一致。
  // 只查"必含"看不见"多带"——多出来的 hook 没人 require，等于白占包体；而名单
  // 与 src/hook-locations.ts 失配更糟：插件会去找一个包内不存在的文件。
  const actualHookJs = entries
    .filter((e) => /^package\/hooks\/[^/]+\.js$/.test(e))
    .map((e) => e.slice('package/hooks/'.length))
    .sort();
  const hookListMismatch = actualHookJs.join(",") !== [...REQUIRED_HOOK_FILES].sort().join(",");
  if (hookListMismatch) {
    log(`FAIL: tarball ${path.basename(tarballPath)} hooks/*.js 名单与 REQUIRED_HOOK_FILES 不一致`);
    log(`  归档内: ${actualHookJs.join(", ") || "(空)"}`);
    log(`  期望  : ${REQUIRED_HOOK_FILES.join(", ")}`);
    log('  提示：新增/删除 hook 文件时同步改 scripts/build.js 的 REQUIRED_HOOK_FILES 与');
    log('  src/hook-locations.ts 的 HOOK_BASENAMES（tests/hook-locations.test.ts 会比对两者）。');
    process.exit(1);
  }
  // 遗留布局反断言：包根下不得再出现 hook 副本。1.0.x 把它们拷进
  // extensions/<id>/（安装目录），宿主安装器按"目录实有内容 vs 包清单"对账时
  // 会把这几个文件判成无法解释的外来文件、每次装/升级都提示删除；而删掉它们
  // 又会让 NODE_OPTIONS --require 找不到文件，gateway 起不来。把 hook 放回
  // 包根等于把那个自举死锁重新写回安装流程。
  const legacyHookAtRoot = REQUIRED_HOOK_FILES.filter((f) => entries.includes(`package/${f}`));
  if (legacyHookAtRoot.length > 0) {
    log(`FAIL: tarball ${path.basename(tarballPath)} 包根含遗留布局的 hook 副本：`);
    for (const f of legacyHookAtRoot) log(`  - package/${f}`);
    log('  提示：hook 只应随包分发在 package/hooks/ 下（并由 src/hook-locations.ts 指向该目录）；');
    log('  运行期副本写到插件数据目录 $OPENCLAW_HOME/<id>/hooks/，不要写进安装目录。');
    process.exit(1);
  }
  log(`tarball integrity OK: ${path.basename(tarballPath)} 含 ${required.length} 项关键文件、hook 名单一致、0 个测试/缓存产物（${entries.length} entries）`);
}

function main() {
  log('Starting build...');

  // Fail fast when any version copy drifted from package.json.
  assertVersionConsistency(rootDir);
  log('Version copies consistent with package.json');

  rmDir(distDir);

  log('Running TypeScript compiler');
  run('node node_modules/typescript/bin/tsc --noEmitOnError');

  // 事件 JSON Schema 由 src/types.ts 生成。放在构建里而不是让人手记着跑，
  // 是为了保证"随包分发的 schema"永远不会落后于类型定义——schema 是公开
  // 合同，漂移了就等于对消费方撒谎。
  run('node scripts/gen-event-schema.mjs');

  // 检测模式单源生成（spl.yaml → hooks/monitor/SelfProtection
  // 产物 + flag 默认名单 TS）。生成失败（双侧编译/子集 lint/字典校验不过）
  // 即构建失败。
  run('node scripts/generate-detection-patterns.mjs');

  // SelfProtection 的模式产物需与编译后的模块同目录（dist/
  // intervention/），供其运行时加载；缺失时模块回退内置常量 + WARN。
  const spGenerated = path.join(rootDir, 'policies', 'generated', 'self-protection-patterns.generated.json');
  const spDestDir = path.join(distDir, 'src', 'intervention');
  fs.mkdirSync(spDestDir, { recursive: true });
  fs.copyFileSync(spGenerated, path.join(spDestDir, 'self-protection-patterns.generated.json'));

  // Copy the embedded Python monitor into dist/ so it is included in the
  // published package and in the install bundle.
  const monitorSrc = path.join(rootDir, 'src', 'monitor');
  const monitorDist = path.join(distDir, 'monitor');
  if (fs.existsSync(monitorSrc)) {
    copyDir(monitorSrc, monitorDist, { excludeExtensions: ['.pyc'] });
  }

  // Copy plugin manifest into dist/ so OpenClaw can discover the plugin.
  // 逐字复制：main/entry 不是宿主清单的合法字段，注入它们会被 ClawHub 的
  // manifest-unknown-fields 校验判非法（见 install/ 端清单的同款注释）。
  const distManifest = JSON.parse(
    fs.readFileSync(path.join(rootDir, 'openclaw.plugin.json'), 'utf8')
  );
  fs.writeFileSync(
    path.join(distDir, 'openclaw.plugin.json'),
    JSON.stringify(distManifest, null, 2) + '\n'
  );

  // Copy static assets (favicon, branding) into dist/ so the runtime can
  // serve them via the /favicon.ico HTTP route. The path resolution inside
  // index.ts walks ../assets first, which is exactly the layout produced
  // when install/application/index.js looks for assets/logo.ico one level up.
  const assetsSrc = path.join(rootDir, 'assets');
  if (fs.existsSync(assetsSrc)) {
    copyDir(assetsSrc, path.join(distDir, 'assets'));
  }

  if (runTests) {
    log('Running tests');
    run('npx vitest run');
  } else {
    log('Skipping tests (--no-test)');
  }

  packageInstall();

  // 完整性断言：build.js 打的 tgz 内部 layout
  // 是 `package/install/<...>`（install/ 目录镜像），OpenClaw 实际入口是
  // `package/install/application/index.js`（与 `extensions: ./index.ts` 配套：
  // 装入 OpenClaw 时由 runtime 重写为 `./install/application/index.js`）。
  // 历史上 `npm run pack` 走 `tsc && npm pack`（依赖 package.json `files` 字段）
  // 漏打 dist/，导致 OpenClaw 报"package install requires compiled runtime output"。
  // 此处硬性断言：tgz 内必须含编译产物入口，否则构建失败。
  // 注：tgz 名以 `openclaw.plugin.json#name` 为准（已 strip scope），不要用
  // `package.json#name`（带 `@zhanxing/` 前缀）。
  const pluginManifest = JSON.parse(
    fs.readFileSync(path.join(rootDir, 'openclaw.plugin.json'), 'utf8')
  );
  const rootPkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
  const tgzName = `${pluginManifest.name}-${rootPkg.version}.tgz`;
  const tgzPath = path.join(installDir, tgzName);
  assertInstallTarballIntegrity(tgzPath, installDir);

  // dist/ is only a transient TypeScript output directory. The install bundle
  // already contains everything needed for deployment, so remove dist/ to keep
  // the workspace clean.
  rmDir(distDir);

  log('Build completed successfully');
}

main();
