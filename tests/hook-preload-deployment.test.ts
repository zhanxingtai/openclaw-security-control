import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { spawn } from "child_process";
import { installHooksInto } from "../src/initialize.js";

/**
 * 部署契约的真实形状：`NODE_OPTIONS=--require <某个绝对路径>` + 一个真实
 * Node 进程。这里刻意起子进程而不是在 vitest 里 `require()` —— `--require`
 * 解析失败发生在 Node **启动期**，只有真起一个进程才算验到。
 *
 * 三条用例分别钉住：预加载目标能用（正向）、目标被删就起不来（死锁机制）、
 * 以及 hook-mounter 才是唯一扛得住"兄弟文件缺失"的入口（容错）。
 */

const HOOK_NAMES = ["hook-mounter.js", "runtime.js", "network.js"] as const;
const REPO_HOOKS = path.resolve(process.cwd(), "hooks");

let dataDir: string;
/** 插件数据目录下的预加载目录，与 src/hook-locations.ts 的布局一致。 */
let preloadDir: string;
/** 播种函数按 OPENCLAW_HOME 划定可写范围，测试里指向临时目录。 */
let savedOpenClawHome: string | undefined;

beforeEach(() => {
  dataDir = mkdtempSync(path.join(tmpdir(), "hook-preload-"));
  savedOpenClawHome = process.env.OPENCLAW_HOME;
  process.env.OPENCLAW_HOME = dataDir;
  preloadDir = path.join(dataDir, "sst-security-control-openclaw", "hooks");
  mkdirSync(preloadDir, { recursive: true });
  for (const name of HOOK_NAMES) copyFileSync(path.join(REPO_HOOKS, name), path.join(preloadDir, name));
  // hooks/ 目录靠自带的 package.json 固定为 commonjs；脱离源码树后必须把
  // 它一起带走，否则父目录的 "type": "module" 会让 --require 直接 ERR_REQUIRE_ESM。
  copyFileSync(path.join(REPO_HOOKS, "package.json"), path.join(preloadDir, "package.json"));
});

afterEach(() => {
  rmSync(dataDir, { recursive: true, force: true });
  if (savedOpenClawHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = savedOpenClawHome;
});

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function spawnNodeWithPreload(
  requireTarget: string | null,
  script: string,
  extraEnv?: Record<string, string>
): Promise<RunResult> {
  // 先剥掉继承来的开关、再叠加调用方的 —— 顺序反了会把 extraEnv 里刚设的
  // 值一起删掉，测试于是悄悄测了另一条分支。
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.OPENCLAW_NETWORK_HOOK_ENABLED;
  Object.assign(env, extraEnv);
  if (requireTarget !== null) env.NODE_OPTIONS = `--require ${requireTarget}`;
  // vitest 自身带 preload，继承下来会与本用例的断言互相干扰。
  delete (env as Record<string, unknown>).VITEST;
  return new Promise((resolve, reject) => {
    const cp = spawn(process.execPath, ["-e", script], { env, cwd: dataDir });
    let stdout = "";
    let stderr = "";
    cp.stdout.on("data", (d) => (stdout += d.toString()));
    cp.stderr.on("data", (d) => (stderr += d.toString()));
    cp.on("error", reject);
    cp.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function runNodeWithPreload(requireTarget: string | null, extraEnv?: Record<string, string>): Promise<RunResult> {
  // moduleLoadHooked 读的是 Module._load 上的标记：两个 hook 抢同一个属性时，
  // 断言"谁装的"没有意义，要断言的是"最终仍处于被钩住状态"。
  const script = [
    "console.log('runtimeHooked=' + Boolean(globalThis.__openclaw_runtime_hook_installed))",
    "console.log('moduleLoadHooked=' + Boolean(require('module')._load.__openclaw_hookModuleLoad))",
  ].join(";");
  return spawnNodeWithPreload(requireTarget, script, extraEnv);
}

describe("NODE_OPTIONS 预加载数据目录下的 hook", () => {
  it("指向 hook-mounter.js 时进程正常启动且 hook 生效", async () => {
    const r = await runNodeWithPreload(path.join(preloadDir, "hook-mounter.js"));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("runtimeHooked=true");
    // 随包 package.json 的 type:commonjs 是 --require 能成立的前提。
    expect(r.stderr).not.toContain("MODULE_NOT_FOUND");
    expect(r.stderr).not.toContain("ERR_REQUIRE_ESM");
  });

  it("两个 hook 一起预加载时不产生任何 error 级噪音", async () => {
    // 回归：runtime.js 先加载并把 Module._load 用 defineProperty 锁成不可写，
    // 随后加载的 network.js 再用裸赋值改同一个属性 → 每次启动抛
    // "Cannot assign to read only property '_load'"（error 级，且把整个
    // Module 源码 dump 出来）。用户现场就是这么刷屏的。http/https/fetch 在
    // network.js 的 install() 里已直接装好，那条钩子只是兜底，跳过无损。
    const r = await runNodeWithPreload(path.join(preloadDir, "hook-mounter.js"));
    expect(r.code).toBe(0);
    expect(r.stderr).not.toMatch(/\berror:/);
    expect(r.stdout).not.toMatch(/\berror:/);
    expect(r.stdout + r.stderr).not.toContain("Cannot assign to read only property");
    // 兜底钩子被 runtime.js 接管后，Module._load 依然处于被钩住状态 ——
    // 跳过不等于丢失拦截。
    expect(r.stdout).toContain("moduleLoadHooked=true");
  });

  it("指向 runtime.js 时同样生效（遗留部署的直接引用写法仍兼容）", async () => {
    const r = await runNodeWithPreload(path.join(preloadDir, "runtime.js"));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("runtimeHooked=true");
  });

  it("预加载目标不存在时进程起不来 —— 这就是删插件目录会锁死的原因", async () => {
    // 反向用例：证明"预加载路径所在目录不能由安装器拥有"不是洁癖。
    // `--require` 在 Node 启动期解析，文件缺失 → 进程直接死，插件没有任何
    // 机会运行到"把 hook 拷回去"那一步，自举死锁由此成立。
    rmSync(preloadDir, { recursive: true, force: true });
    const r = await runNodeWithPreload(path.join(preloadDir, "runtime.js"));
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("Cannot find module");
  });

  it("hook-mounter 在兄弟 hook 缺失时降级而非拖垮进程", async () => {
    // 这条是"首推 hook-mounter.js"的全部理由：直接 --require runtime.js 时
    // 缺文件即进程死亡，而 mounter 只打 WARN。这也让"指向数据目录"这种
    // 布局在文件尚未落盘的那次启动里是安全的。
    unlinkSync(path.join(preloadDir, "runtime.js"));
    unlinkSync(path.join(preloadDir, "network.js"));
    const r = await runNodeWithPreload(path.join(preloadDir, "hook-mounter.js"));
    expect(r.code).toBe(0);
    // 缺失提示与统计行一律走 stderr。
    expect(r.stderr).toContain("hook file missing");
    expect(r.stderr).toContain("skipped=2");
    expect(r.stdout).toContain("runtimeHooked=false");
  });

  it("hook-mounter 在同目录只有一个孤立文件时也照常退出", async () => {
    // 自愈路径的兜底：NODE_OPTIONS 指向的 mounter 存在但内容为空/损坏时，
    // 至少不能把整个 gateway 带崩。
    writeFileSync(path.join(preloadDir, "hook-mounter.js"), "// empty\n", "utf8");
    const r = await runNodeWithPreload(path.join(preloadDir, "hook-mounter.js"));
    expect(r.code).toBe(0);
  });

  it("直接预加载随包目录里的 hook-mounter.js 也能起来（零残留写法）", async () => {
    // NODE_OPTIONS 指向插件安装目录内的 hooks/hook-mounter.js —— 不落任何
    // 副本的写法。随包目录自带 package.json（type: commonjs），所以这条
    // 路径同样必须是可加载的。
    const r = await runNodeWithPreload(path.join(REPO_HOOKS, "hook-mounter.js"));
    expect(r.code).toBe(0);
    expect(r.stderr).not.toContain("SyntaxError");
  });

  it("预加载不污染子进程的 stdout —— 机器进程靠它解析 JSON", async () => {
    // 线上故障的第二个形态（2026-10-23）：mounter 的统计行走 console.log。
    // NODE_OPTIONS 扩散到宿主里每一个 node 进程，OpenClaw CLI 的 SQLite 只读
    // worker 也在其中，它的 stdout 是一段 JSON —— 被塞进一行日志后，CLI 直接
    // 报 `SQLite read-only worker returned invalid JSON`。这条用例把那个
    // worker 的形状原样搬过来：子进程只往 stdout 写一段 JSON，stdout 必须
    // 逐字节等于它自己写的内容。
    const worker = `process.stdout.write(JSON.stringify({ worker: "sqlite-readonly", rows: 3 }))`;
    const r = await spawnNodeWithPreload(path.join(preloadDir, "hook-mounter.js"), worker);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('{"worker":"sqlite-readonly","rows":3}');
    expect(() => JSON.parse(r.stdout)).not.toThrow();
    // 默认静默：mounter 的统计行只是诊断信息，而 NODE_OPTIONS 扩散到宿主里
    // 每一个 node 进程，一行成功日志会在容器里重复若干遍（安装输出噪音）。
    expect(r.stderr).not.toContain("hooks mounter:");
  });

  it("调试开关打开时诊断信息走 stderr，仍不碰 stdout", async () => {
    // 诊断信息不是被删掉了，是被收进开关里：打开开关后它必须出现在 stderr
    // （而不是 stdout）——否则又回到 2026-10-23 那个 SQLite worker 事故。
    const worker = `process.stdout.write(JSON.stringify({ worker: "sqlite-readonly", rows: 3 }))`;
    const r = await spawnNodeWithPreload(path.join(preloadDir, "hook-mounter.js"), worker, {
      OPENCLAW_HOOK_MOUNT_DEBUG: "1",
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('{"worker":"sqlite-readonly","rows":3}');
    expect(r.stderr).toContain("hooks mounter: loaded=2");
  });

  it("调试日志全开时同样不占用 stdout", async () => {
    // 打开两个 hook 的 DEBUG 开关：log() 会真的写日志。若还有任何一条留在
    // stdout，上面那条"stdout 逐字节相等"的性质立刻被破坏 —— 这条用例把
    // 回归挡在"只有默认配置才有问题"之前。
    const worker = `process.stdout.write('{"ok":true}')`;
    const r = await spawnNodeWithPreload(path.join(preloadDir, "hook-mounter.js"), worker, {
      OPENCLAW_RUNTIME_HOOK_DEBUG: "1",
      OPENCLAW_NETWORK_HOOK_DEBUG: "1",
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('{"ok":true}');
  });

  it("network hook 被关闭时的提示也走 stderr", async () => {
    // 这条提示是 mounter 自己的输出（不是 hook 的 log()），单独钉一次：上一条
    // 开着 DEBUG 的用例里 network.js 被跳过、它的 log() 没参与，容易漏掉。
    const worker = `process.stdout.write('{"ok":true}')`;
    const r = await spawnNodeWithPreload(path.join(preloadDir, "hook-mounter.js"), worker, {
      OPENCLAW_NETWORK_HOOK_ENABLED: "false",
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('{"ok":true}');
    expect(r.stderr).toContain("network hook disabled via OPENCLAW_NETWORK_HOOK_ENABLED=false");
  });
});

/**
 * 播种路径的防线：随包源被谁改坏过（本次线上故障的原始形态），落进预加载
 * 目录的副本必须仍然是"能被 --require 加载"的文件。
 *
 * 故障形态（2026-10 实测）：有人在 shebang 前面插了一行，于是 `#!` 落到
 * 第 2 行。Node 只认字节 0 处的 shebang → 整份文件 SyntaxError → 宿主
 * 进程在加载任何插件之前就退出 → 插件没有机会把副本修回去（自举死锁）。
 */
describe("播种：随包源被污染时仍产出可加载的副本", () => {
  /** 造一份"shebang 不在首字节"的随包源，复现线上故障的原始形态。 */
  function seedPollutedSource(dir: string): string {
    mkdirSync(dir, { recursive: true });
    for (const name of HOOK_NAMES) {
      const original = readFileSync(path.join(REPO_HOOKS, name), "utf8");
      writeFileSync(
        path.join(dir, name),
        `// generated by installer\n#!/usr/bin/env node\n${original}`,
        "utf8"
      );
    }
    copyFileSync(path.join(REPO_HOOKS, "package.json"), path.join(dir, "package.json"));
    return dir;
  }

  it("污染源（shebang 落到第 2 行）播种出的副本仍能被 --require 加载", async () => {
    const polluted = seedPollutedSource(path.join(dataDir, "polluted-hooks"));
    const target = path.join(dataDir, "sst-security-control-openclaw", "hooks");
    installHooksInto(polluted, target);

    const seeded = readFileSync(path.join(target, "hook-mounter.js"), "utf8");
    expect(seeded).not.toMatch(/^\s*#!/m);

    const r = await runNodeWithPreload(path.join(target, "hook-mounter.js"));
    expect(r.code).toBe(0);
    expect(r.stderr).not.toContain("SyntaxError");
    expect(r.stdout).toContain("runtimeHooked=true");
  });

  it("installHooksInto 不碰 package.json —— 模块类型锚点只由 ensureBundledHooks 播到数据目录", () => {
    // installHooksInto 也用于遗留安装目录（extensions/<id>/）。1.0.x 布局下
    // 插件**就装在**那里，hooksDir 恰好是 extensions/<id>/hooks，于是播种
    // package.json 的目标会落在插件自己的清单上：覆盖 = 宿主读到
    // main: runtime.js / type: commonjs；新建 = 把整个安装目录的模块类型
    // 钉成 commonjs，连插件自己的 index.js 一起废掉。两条都是硬伤，所以
    // 这个职责从 installHooksInto 里摘出去，只留给数据目录
    // （见 tests/initialize-probes.test.ts）。
    const polluted = seedPollutedSource(path.join(dataDir, "polluted-hooks-2"));
    const target = path.join(dataDir, "sst-security-control-openclaw", "hooks");
    installHooksInto(polluted, target);
    // beforeEach 已经手工放过一份（测试自己需要它来让 --require 成立），
    // 内容不能被改动，也不能多出别的文件。
    expect(readdirSync(target).sort()).toEqual([...HOOK_NAMES, "package.json"].sort());
  });

  it("随包源语法坏掉且目标为空时落占位入口，而不是一份能把宿主打死的语法错文件", async () => {
    const broken = path.join(dataDir, "broken-hooks");
    mkdirSync(broken, { recursive: true });
    writeFileSync(path.join(broken, "hook-mounter.js"), "function (\n", "utf8");
    // 全新部署：目标目录里什么都没有，只有这时才需要占位入口兜底。
    const target = path.join(dataDir, "fresh-sst-security-control-openclaw", "hooks");
    mkdirSync(target, { recursive: true });
    installHooksInto(broken, target);

    const r = await runNodeWithPreload(path.join(target, "hook-mounter.js"));
    // 覆盖从"整个宿主起不来"降级为"这一层没有覆盖"：进程起得来，占位入口
    // 在日志里说清自己是降级的。
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("degraded");

    // 入口坏了 = 整层失效：留全局标记，探针据此判成未生效（面板不谎报）。
    const stub = readFileSync(path.join(target, "hook-mounter.js"), "utf8");
    expect(stub).toContain("__openclaw_security_hook_degraded = true");
  });

  it("只有兄弟 hook 坏掉时不把整层判死（入口坏了才算整层失效）", () => {
    const broken = path.join(dataDir, "broken-sibling-hooks");
    mkdirSync(broken, { recursive: true });
    // 入口是好的，坏的是 network.js：那一层没有覆盖，但进程层照常工作，
    // 不该因此把整层 runtimeHooks 判成失效。
    copyFileSync(path.join(REPO_HOOKS, "hook-mounter.js"), path.join(broken, "hook-mounter.js"));
    writeFileSync(path.join(broken, "network.js"), "function (\n", "utf8");
    const target = path.join(dataDir, "sibling-sst-security-control-openclaw", "hooks");
    mkdirSync(target, { recursive: true });
    installHooksInto(broken, target);

    const entry = readFileSync(path.join(target, "hook-mounter.js"), "utf8");
    expect(entry).not.toContain("__openclaw_security_hook_degraded");
    const sibling = readFileSync(path.join(target, "network.js"), "utf8");
    expect(sibling).toContain("degraded placeholder");
    expect(sibling).not.toContain("__openclaw_security_hook_degraded = true");
  });

  it("随包源坏掉时不拿占位文件顶掉一份还能用的旧副本", async () => {
    // 存量部署手上那份是被 Node 正常加载过的。拿它换成一个"什么都不做"的
    // 占位文件，等于用"有覆盖"换"零覆盖" —— 对一个还在正常拦截的进程来说
    // 是纯粹的倒退。正确做法是留着旧副本 + 告警，让覆盖继续。
    const broken = path.join(dataDir, "broken-but-previously-working");
    mkdirSync(broken, { recursive: true });
    writeFileSync(path.join(broken, "hook-mounter.js"), "function (\n", "utf8");

    // beforeEach 已经往 preloadDir 放过一份完好的三件套，那就是"存量副本"。
    const good = readFileSync(path.join(preloadDir, "hook-mounter.js"), "utf8");
    installHooksInto(broken, preloadDir);
    expect(readFileSync(path.join(preloadDir, "hook-mounter.js"), "utf8")).toBe(good);

    const r = await runNodeWithPreload(path.join(preloadDir, "hook-mounter.js"));
    expect(r.code).toBe(0);
    // 覆盖还在（runtime hook 真的装上了），也没有降级标记。
    expect(r.stderr).not.toContain("degraded");
    expect(r.stdout).toContain("runtimeHooked=true");
  });
});
