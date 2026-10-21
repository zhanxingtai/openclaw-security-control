import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
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

  it("首次安装：拷贝 hook 三件套并返回 true", () => {
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    const ext = path.join(tmpDir, "extensions", "sst-security-control-openclaw");
    for (const f of ["runtime.js", "network.js", "hook-mounter.js"]) {
      expect(existsSync(path.join(ext, f))).toBe(true);
    }
  });

  it("版本标签一致时不重复拷贝（返回 false）", () => {
    ensureBundledHooks(enabledConfig());
    expect(ensureBundledHooks(enabledConfig())).toBe(false);
  });

  it("目标版本标签过期时升级拷贝", () => {
    ensureBundledHooks(enabledConfig());
    const ext = path.join(tmpDir, "extensions", "sst-security-control-openclaw");
    const target = path.join(ext, "runtime.js");
    // 人为把目标标签改旧，下一次 ensureBundledHooks 必须发现并升级
    const content = readFileSync(target, "utf8");
    writeFileSync(target, content.replace(/\/\/ openclaw-hook: v\S+/, "// openclaw-hook: v0.0.1"));
    expect(ensureBundledHooks(enabledConfig())).toBe(true);
    expect(readFileSync(target, "utf8")).toContain("// openclaw-hook: v1.0.0");
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
