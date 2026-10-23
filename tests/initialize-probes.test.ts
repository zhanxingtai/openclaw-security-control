import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, readdirSync, rmSync, existsSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";
import {
  seedDefaultPolicy,
  ensureBundledHooks,
  installHooksInto,
  probeRuntimeHookLoaded,
  probeLegacyHookPathInUse,
  isSafePythonPath,
  probePythonPsutil,
  applyBootstrapResults,
} from "../src/initialize.js";
import { normalizeConfig } from "../src/config.js";

/**
 * initialize.ts bootstrap 探针。
 * 覆盖 seedDefaultPolicy / ensureBundledHooks 升级逻辑 /
 * probeRuntimeHookLoaded / probePythonPsutil（含 isSafePythonPath 闸门）/
 * applyBootstrapResults 的强制降级语义。
 */

/**
 * 随包 hook 源目录（源码树里的 hooks/，与 ensureBundledHooks 经
 * findBundledDir("hooks") 解析到的同一目录）。测试从源文件现读期望内容，
 * 不写死版本字面量。
 */
const BUNDLED_HOOKS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../hooks"
);

let tmpDir: string;
const savedEnv: Record<string, string | undefined> = {};

/** 插件自有数据目录里的预加载目录（beforeEach 把 OPENCLAW_HOME 指向 tmpDir）。 */
const preloadDirForTest = () =>
  path.join(tmpDir, "sst-security-control-openclaw", "hooks");

function setEnv(key: string, value: string | undefined): void {
  if (!(key in savedEnv)) savedEnv[key] = process.env[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

beforeEach(() => {
  tmpDir = mkdtempSync(path.join(tmpdir(), "init-probes-"));
  setEnv("OPENCLAW_HOME", tmpDir);
  setEnv("OPENCLAW_EXTENSIONS_DIR", undefined);
  delete process.env.NODE_OPTIONS;
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("seedDefaultPolicy", () => {
  it("目标已存在时不覆盖（返回 false）", () => {
    const target = path.join(tmpDir, "existing.yaml");
    writeFileSync(target, "custom");
    expect(seedDefaultPolicy(target)).toBe(false);
    expect(readFileSync(target, "utf8")).toBe("custom");
  });

  it("bundled 模板缺失（源码树未构建）时优雅返回 false，不写文件", () => {
    // security-policy.yaml 由 build.js 从 SPL 生成进 install/policies，
    // 源码树中不存在 —— 探针必须优雅降级而不是抛错。
    const target = path.join(tmpDir, "policy", "security-policy.yaml");
    expect(seedDefaultPolicy(target)).toBe(false);
    expect(existsSync(target)).toBe(false);
  });
});

describe("ensureBundledHooks 升级逻辑", () => {
  const enabledConfig = () =>
    normalizeConfig({ application: { runtimeHooks: { enabled: true } } });

  // 预加载副本的目标目录是插件**自己的数据目录**，不是宿主安装目录
  // （$OPENCLAW_HOME/extensions/<id>/）。见 src/hook-locations.ts。
  const preloadDir = () => path.join(tmpDir, "sst-security-control-openclaw", "hooks");
  const extensionsDir = () => path.join(tmpDir, "extensions", "sst-security-control-openclaw");
  const bundledSource = (file: string) => readFileSync(path.join(BUNDLED_HOOKS_DIR, file), "utf8");

  it("首次安装：拷贝 hook 三件套并返回 true", () => {
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    for (const f of ["runtime.js", "network.js", "hook-mounter.js"]) {
      expect(existsSync(path.join(preloadDir(), f))).toBe(true);
    }
  });

  it("数据目录里带上 hooks/package.json（type: commonjs）", () => {
    // 数据目录里没有 package.json 时，模块类型由最近的祖先 package.json
    // 决定：宿主若在 ~/.openclaw/package.json 里写了 "type": "module"，
    // 三件套就被当成 ESM —— ESM 里 require 未定义，预加载一进去就抛错，
    // 同样让宿主进程在启动期退出。随包的 hooks/package.json 必须一起带走。
    ensureBundledHooks(enabledConfig());
    const pkg = JSON.parse(readFileSync(path.join(preloadDir(), "package.json"), "utf8"));
    expect(pkg.type).toBe("commonjs");
  });

  it("落盘的是归一化后的副本（不带 shebang），随包源被改坏也不会产出语法错文件", () => {
    // 随包源若被谁在前面插了内容（shebang 不在首字节 / BOM），逐字节拷过去
    // 就是一份"一 require 就 SyntaxError"的文件 —— 而它正是 NODE_OPTIONS 的
    // 预加载目标，宿主进程会在加载任何插件之前就退出。
    ensureBundledHooks(enabledConfig());
    for (const f of ["runtime.js", "network.js", "hook-mounter.js"]) {
      const content = readFileSync(path.join(preloadDir(), f), "utf8");
      expect(content).not.toMatch(/^\s*#!/m);
      expect(content.charCodeAt(0)).not.toBe(0xfeff);
    }
  });

  it("不向宿主安装目录写入任何文件（残留与自举死锁的根因）", () => {
    // 1.0.x 把副本拷进 extensions/<id>/，而那三个文件不在安装包清单里：
    // 宿主安装器每次装/升级都提示"删除未清理文件"，删掉又让
    // NODE_OPTIONS --require 找不到文件 → gateway 起不来 → 插件无从重建。
    // NEW 部署不再往那里写 —— 除非 NODE_OPTIONS 仍引用着它（见下一条）。
    expect(process.env.NODE_OPTIONS).toBeUndefined();
    ensureBundledHooks(enabledConfig());
    expect(existsSync(extensionsDir())).toBe(false);
    expect(existsSync(path.join(tmpDir, "extensions"))).toBe(false);
  });

  it("NODE_OPTIONS 仍指向遗留副本时继续刷新它（安全修复必须送达存量用户）", () => {
    // 兼容期：用户还没改 compose，副本还得跟着版本走，否则升级带来的 hook
    // 修复到不了他们的进程 —— 那正是当初引入指纹比对要解决的同一件事。
    const legacyTarget = path.join(extensionsDir(), "runtime.js");
    process.env.NODE_OPTIONS = `--require ${legacyTarget}`;
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(existsSync(legacyTarget)).toBe(true);
    expect(readFileSync(legacyTarget, "utf8")).toBe(bundledSource("runtime.js"));
    // 数据目录那一份照旧也要有，用户改完 NODE_OPTIONS 就能直接切过去。
    expect(existsSync(path.join(preloadDir(), "hook-mounter.js"))).toBe(true);
  });

  it("遗留路径刷新时目录里不新增任何文件（1.0.x 布局的存量部署）", () => {
    // 存量部署的真实形态：插件装在 extensions/<id>/，NODE_OPTIONS 指着那里
    // 的一份副本。兼容期规则要求继续刷新它 —— 否则升级带来的 hook 修复
    // （含 stdout→stderr 那条）到不了他们的进程。但**只能刷新那三个 .js**：
    // 这个目录由宿主安装器拥有，任何新增文件（哪怕是随包的
    // hooks/package.json）都会变成安装器对账时"无法解释的外来文件"，
    // 于是装一次提示一次、删了又起不来 —— 正是本次要根治的那个循环。
    const legacyTarget = path.join(extensionsDir(), "hook-mounter.js");
    process.env.NODE_OPTIONS = `--require ${legacyTarget}`;
    ensureBundledHooks(enabledConfig());
    expect(existsSync(legacyTarget)).toBe(true);
    expect(readdirSync(extensionsDir()).sort()).toEqual(
      ["hook-mounter.js", "network.js", "runtime.js"].sort()
    );
    // 数据目录那一份（含模块类型锚点）照旧播种，用户改完 NODE_OPTIONS 就能切。
    expect(existsSync(path.join(preloadDir(), "package.json"))).toBe(true);
  });

  it("遗留目录与插件安装目录重合时不覆盖插件自己的 package.json", () => {
    // 1.0.x 布局下插件**就装在** extensions/<id>/，于是 findBundledDir("hooks")
    // 解析到的 hooksDir 恰好是 legacyDir/hooks，而 legacyDir 就是插件的安装
    // 目录。播种 hooks/package.json 时目标路径落在 legacyDir/package.json ——
    // 那就是宿主要读的插件清单。覆盖它等于把 manifest 换成 hooks 的
    // （main: runtime.js / type: commonjs），插件直接加载不起来了。
    const installDir = path.join(tmpDir, "extensions", "sst-security-control-openclaw");
    const bundled = path.join(installDir, "hooks");
    mkdirSync(bundled, { recursive: true });
    for (const f of ["runtime.js", "network.js", "hook-mounter.js", "package.json"]) {
      writeFileSync(path.join(bundled, f), bundledSource(f), "utf8");
    }
    const manifest = `${JSON.stringify(
      { name: "@zhanxing/sst-security-control-openclaw", main: "index.js", type: "module" },
      null,
      2
    )}\n`;
    writeFileSync(path.join(installDir, "package.json"), manifest, "utf8");

    installHooksInto(bundled, installDir);
    expect(readFileSync(path.join(installDir, "package.json"), "utf8")).toBe(manifest);
  });

  it("NODE_OPTIONS 改指数据目录后不再写遗留目录（迁移完成即收手）", () => {
    process.env.NODE_OPTIONS = `--require ${path.join(preloadDir(), "hook-mounter.js")}`;
    ensureBundledHooks(enabledConfig());
    expect(existsSync(extensionsDir())).toBe(false);
  });

  it("已装副本与随包副本一致时不重复拷贝（返回 false）", () => {
    ensureBundledHooks(enabledConfig());
    expect(ensureBundledHooks(enabledConfig())).toBe(false);
  });

  it("已装副本内容被改动时恢复为随包副本", () => {
    ensureBundledHooks(enabledConfig());
    const target = path.join(preloadDir(), "runtime.js");
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// tampered\n`);
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(bundledSource("runtime.js"));
  });

  it("文件尾部的改动（第 200 字节之后）也能触发升级", () => {
    // 旧实现只读文件头若干字节比对 tag，尾部修复对它完全不可见 ——
    // 这正是"OPENCLAW_MONITOR_LOG_PATH 修复重装多次仍送不到容器"的成因。
    ensureBundledHooks(enabledConfig());
    const target = path.join(preloadDir(), "runtime.js");
    const pristine = bundledSource("runtime.js");
    expect(pristine.length).toBeGreaterThan(200); // 前提：内容确实越过旧读取窗口
    // 只在文件末尾附近改动，正文前 200 字节保持逐字节相同
    const tailTampered = `${pristine.slice(0, pristine.length - 10)}// XXXXXXX\n`;
    expect(tailTampered.slice(0, 200)).toBe(pristine.slice(0, 200));
    writeFileSync(target, tailTampered);
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(pristine);
  });

  it("hook-mounter.js（无版本 tag）也能随内容变化升级", () => {
    // 该文件从来没有 tag。旧实现下两边都读到 undefined、判定相等而跳过，
    // 自 tag 机制引入以来对老用户从未更新过。内容哈希对它一视同仁。
    ensureBundledHooks(enabledConfig());
    const target = path.join(preloadDir(), "hook-mounter.js");
    expect(bundledSource("hook-mounter.js")).not.toMatch(/^\/\/ openclaw-hook:/m);
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// stale\n`);
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(bundledSource("hook-mounter.js"));
  });

  it("只改版本 tag 不触发拷贝（tag 已不承载判定语义）", () => {
    // tag 是给人读的信息性注释，不参与指纹；改它不该让用户重新落盘 hook。
    ensureBundledHooks(enabledConfig());
    const target = path.join(preloadDir(), "runtime.js");
    const pristine = bundledSource("runtime.js");
    writeFileSync(target, pristine.replace(/^\/\/ openclaw-hook:.*$/m, "// openclaw-hook: v0.0.1"));
    expect(ensureBundledHooks(enabledConfig())).toBe(false);
    expect(readFileSync(target, "utf8")).toContain("// openclaw-hook: v0.0.1");
  });

  it("runtimeHooks 未启用时照样 seed（顺序无关是硬约束）", () => {
    // 回归：旧实现在 !runtimeHooks.enabled 时首行 return false，于是目标文件
    // 要等一次成功启动才会出现 —— 而启动本身要求 --require 成功。"先配
    // NODE_OPTIONS 再开开关"这条路必然起不来，且用户进不去把开关打开。
    const disabled = normalizeConfig({ application: { runtimeHooks: { enabled: false } } });
    expect(ensureBundledHooks(disabled)).toBe(true);
    for (const f of ["runtime.js", "network.js", "hook-mounter.js"]) {
      expect(existsSync(path.join(preloadDir(), f))).toBe(true);
    }
  });

  it("未启用时不打印 recommend NODE_OPTIONS（不怂恿改动没要求的环境变量）", () => {
    const logs: string[] = [];
    const disabled = normalizeConfig({ application: { runtimeHooks: { enabled: false } } });
    ensureBundledHooks(disabled, { info: (m: string) => logs.push(m), warn: (m: string) => logs.push(m) });
    expect(logs.join("\n")).not.toContain("recommend NODE_OPTIONS");
    expect(logs.join("\n")).toContain("installed bundled runtime hooks");
  });

  it("启用时才打印 recommend NODE_OPTIONS", () => {
    const logs: string[] = [];
    ensureBundledHooks(enabledConfig(), { info: (m: string) => logs.push(m), warn: (m: string) => logs.push(m) });
    expect(logs.join("\n")).toContain("recommend NODE_OPTIONS=--require");
  });
});

describe("probeRuntimeHookLoaded", () => {
  it("NODE_OPTIONS 引用遗留安装目录的 runtime hook 时返回 true（兼容存量部署）", () => {
    process.env.NODE_OPTIONS = "--require /home/node/.openclaw/extensions/sst-security-control-openclaw/runtime.js";
    expect(probeRuntimeHookLoaded()).toBe(true);
  });

  it("hook-mounter.js 一律认（安装目录 / 数据目录 / 随包目录三种布局）", () => {
    // 回归：旧实现用正则猜路径形状，只认路径里带 runtime 的写法，于是三个
    // 文件里唯一被推荐给 NODE_OPTIONS 的 hook-mounter.js 反被判成"外人的
    // hook" → 误杀 → 强制关停 runtimeHooks.enabled → 连副本都不再刷新。
    for (const target of [
      "/home/node/.openclaw/extensions/sst-security-control-openclaw/hook-mounter.js",
      path.join(preloadDirForTest(), "hook-mounter.js"),
      path.join(BUNDLED_HOOKS_DIR, "hook-mounter.js"),
    ]) {
      process.env.NODE_OPTIONS = `--require ${target}`;
      expect(probeRuntimeHookLoaded()).toBe(true);
    }
  });

  it("认 --require=x / -r 简写与多个 require 条目", () => {
    process.env.NODE_OPTIONS = "--max-old-space-size=512 -r /some/other/preload.js --require=/home/node/.openclaw/sst-security-control-openclaw/hooks/runtime.js";
    expect(probeRuntimeHookLoaded()).toBe(true);
  });

  it("NODE_OPTIONS 缺失或引用无关脚本时返回 false", () => {
    expect(probeRuntimeHookLoaded()).toBe(false);
    process.env.NODE_OPTIONS = "--require /some/other/preload.js";
    expect(probeRuntimeHookLoaded()).toBe(false);
  });

  it("别处同名 runtime.js 不算我们的 hook（避免误判为已覆盖）", () => {
    process.env.NODE_OPTIONS = "--require /opt/vendor/runtime.js";
    expect(probeRuntimeHookLoaded()).toBe(false);
  });
});

describe("probeLegacyHookPathInUse", () => {
  it("指向遗留安装目录时返回该路径", () => {
    const legacy = "/home/node/.openclaw/extensions/sst-security-control-openclaw/runtime.js";
    process.env.NODE_OPTIONS = `--require ${legacy}`;
    // 返回的是绝对化后的路径：win32 下 resolve() 会补盘符，比对时按平台归一。
    expect(probeLegacyHookPathInUse()).toBe(path.resolve(legacy));
  });

  it("指向数据目录时返回 undefined（已迁移，不该再提示）", () => {
    process.env.NODE_OPTIONS = `--require ${path.join(preloadDirForTest(), "hook-mounter.js")}`;
    expect(probeLegacyHookPathInUse()).toBeUndefined();
  });
});

describe("isSafePythonPath（RCE 闸门）", () => {
  it("接受裸 python3 / python3.x 及合规绝对路径", () => {
    expect(isSafePythonPath("python3")).toBe(true);
    expect(isSafePythonPath("python3.12")).toBe(true);
    expect(isSafePythonPath("/usr/bin/python3")).toBe(true);
  });

  it("拒绝相对路径、错误 basename 与注入形态", () => {
    expect(isSafePythonPath("./python3")).toBe(false);
    expect(isSafePythonPath("bin/python3")).toBe(false);
    expect(isSafePythonPath("python")).toBe(false);
    expect(isSafePythonPath("/usr/bin/evil")).toBe(false);
    expect(isSafePythonPath("python3 -c import os")).toBe(false);
    expect(isSafePythonPath("")).toBe(false);
  });
});

describe("probePythonPsutil", () => {
  it("system 层全关时短路返回 true（不 spawn）", () => {
    const config = normalizeConfig({});
    expect(probePythonPsutil(config)).toBe(true);
  });

  it("非法 pythonPath 不执行直接返回 false", () => {
    const config = normalizeConfig({
      system: { procfs: { enabled: true, pythonPath: "evil-script" } },
    });
    expect(probePythonPsutil(config)).toBe(false);
  });
});

describe("applyBootstrapResults 强制降级", () => {
  it("runtimeHook 未加载时关闭 runtimeHooks 并给出原因", () => {
    const config = normalizeConfig({ application: { runtimeHooks: { enabled: true } } });
    const { config: next, forcedDisabled } = applyBootstrapResults(config, {
      runtimeHookLoaded: false,
      pythonPsutil: true,
    });
    expect(next.application?.runtimeHooks?.enabled).toBe(false);
    expect(forcedDisabled.some((f) => f.path === "application.runtimeHooks.enabled")).toBe(true);
  });

  it("psutil 缺失时级联关闭 system 各层", () => {
    const config = normalizeConfig({
      system: { enabled: true, procfs: { enabled: true }, cgroups: { enabled: true } },
    });
    const { config: next, forcedDisabled } = applyBootstrapResults(config, {
      runtimeHookLoaded: true,
      pythonPsutil: false,
    });
    expect(next.system?.enabled).toBe(false);
    expect(next.system?.procfs?.enabled).toBe(false);
    expect(next.system?.cgroups?.enabled).toBe(false);
    const paths = forcedDisabled.map((f) => f.path);
    expect(paths).toContain("system.enabled");
    expect(paths).toContain("system.procfs.enabled");
    expect(paths).toContain("system.cgroups.enabled");
    // 原配置不被修改（深拷贝）
    expect(config.system?.enabled).toBe(true);
  });

  it("探针全通过时配置原样保留", () => {
    const config = normalizeConfig({ application: { runtimeHooks: { enabled: true } } });
    const { config: next, forcedDisabled } = applyBootstrapResults(config, {
      runtimeHookLoaded: true,
      pythonPsutil: true,
    });
    expect(next.application?.runtimeHooks?.enabled).toBe(true);
    expect(forcedDisabled).toHaveLength(0);
  });
});
