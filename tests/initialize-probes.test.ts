import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";
import {
  seedDefaultPolicy,
  ensureBundledHooks,
  probeRuntimeHookLoaded,
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

  const extDir = () => path.join(tmpDir, "extensions", "sst-security-control-openclaw");
  const bundledSource = (file: string) => readFileSync(path.join(BUNDLED_HOOKS_DIR, file), "utf8");

  it("首次安装：拷贝 hook 三件套并返回 true", () => {
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    for (const f of ["runtime.js", "network.js", "hook-mounter.js"]) {
      expect(existsSync(path.join(extDir(), f))).toBe(true);
    }
  });

  it("已装副本与随包副本一致时不重复拷贝（返回 false）", () => {
    ensureBundledHooks(enabledConfig());
    expect(ensureBundledHooks(enabledConfig())).toBe(false);
  });

  it("已装副本内容被改动时恢复为随包副本", () => {
    ensureBundledHooks(enabledConfig());
    const target = path.join(extDir(), "runtime.js");
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// tampered\n`);
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(bundledSource("runtime.js"));
  });

  it("文件尾部的改动（第 200 字节之后）也能触发升级", () => {
    // 旧实现只读文件头若干字节比对 tag，尾部修复对它完全不可见 ——
    // 这正是"OPENCLAW_MONITOR_LOG_PATH 修复重装多次仍送不到容器"的成因。
    ensureBundledHooks(enabledConfig());
    const target = path.join(extDir(), "runtime.js");
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
    const target = path.join(extDir(), "hook-mounter.js");
    expect(bundledSource("hook-mounter.js")).not.toMatch(/^\/\/ openclaw-hook:/m);
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// stale\n`);
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(bundledSource("hook-mounter.js"));
  });

  it("只改版本 tag 不触发拷贝（tag 已不承载判定语义）", () => {
    // tag 是给人读的信息性注释，不参与指纹；改它不该让用户重新落盘 hook。
    ensureBundledHooks(enabledConfig());
    const target = path.join(extDir(), "runtime.js");
    const pristine = bundledSource("runtime.js");
    writeFileSync(target, pristine.replace(/^\/\/ openclaw-hook:.*$/m, "// openclaw-hook: v0.0.1"));
    expect(ensureBundledHooks(enabledConfig())).toBe(false);
    expect(readFileSync(target, "utf8")).toContain("// openclaw-hook: v0.0.1");
  });

  it("runtimeHooks 未启用时直接返回 false", () => {
    const disabled = normalizeConfig({ application: { runtimeHooks: { enabled: false } } });
    expect(ensureBundledHooks(disabled)).toBe(false);
  });
});

describe("probeRuntimeHookLoaded", () => {
  it("NODE_OPTIONS 引用 runtime hook 时返回 true", () => {
    process.env.NODE_OPTIONS = "--require /home/node/.openclaw/extensions/sst-security-control-openclaw/runtime.js";
    expect(probeRuntimeHookLoaded()).toBe(true);
  });

  it("NODE_OPTIONS 缺失或引用无关脚本时返回 false", () => {
    expect(probeRuntimeHookLoaded()).toBe(false);
    process.env.NODE_OPTIONS = "--require /some/other/preload.js";
    expect(probeRuntimeHookLoaded()).toBe(false);
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
