import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import {
  HOOK_BASENAMES,
  PREFERRED_PRELOAD_BASENAME,
  isHookBasename,
  parseRequireTargets,
  matchHookRequires,
  isInside,
  resolvePreloadTarget,
  resolveLegacyDir,
  resolvePreloadDir,
  findBundledDir,
} from "../src/hook-locations.js";

const savedEnv: Record<string, string | undefined> = {};
let tmpDir: string;

function setEnv(key: string, value: string | undefined): void {
  if (!(key in savedEnv)) savedEnv[key] = process.env[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

beforeEach(() => {
  tmpDir = mkdtempSync(path.join(tmpdir(), "hook-locations-"));
  setEnv("OPENCLAW_HOME", tmpDir);
  setEnv("OPENCLAW_EXTENSIONS_DIR", undefined);
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("HOOK_BASENAMES", () => {
  it("首选入口是 hook-mounter.js（graceful degrade 入口）", () => {
    expect(PREFERRED_PRELOAD_BASENAME).toBe("hook-mounter.js");
    expect(HOOK_BASENAMES[0]).toBe(PREFERRED_PRELOAD_BASENAME);
  });

  it("isHookBasename 只认三个预加载文件名", () => {
    for (const name of HOOK_BASENAMES) {
      expect(isHookBasename(name)).toBe(true);
    }
    expect(isHookBasename("evil.js")).toBe(false);
    expect(isHookBasename("")).toBe(false);
  });

  it("与 scripts/build.js 的 REQUIRED_HOOK_FILES 一一对应（构建期同样钉死）", () => {
    // 两侧各自编码"包内随包分发哪些 hook"：TS 侧决定插件去找谁、拷谁，
    // build 侧断言归档里必须有哪些。失配的后果是插件去找一个包内不存在的
    // 文件（或反过来，包里白带一个没人 require 的 hook）。构建脚本不能 import
    // TS，因此一致性只能由测试钉住。
    const buildSrc = readFileSync(
      path.join(process.cwd(), "scripts", "build.js"),
      "utf8"
    );
    const literal = buildSrc.match(/REQUIRED_HOOK_FILES\s*=\s*\[([^\]]*)\]/)?.[1];
    expect(literal, "build.js 里找不到 REQUIRED_HOOK_FILES").toBeTruthy();
    const fromBuild = (literal as string)
      .split(",")
      .map((s) => s.trim().replace(/^['"]|['"]$/g, ""))
      .filter(Boolean)
      .sort();
    expect(fromBuild).toEqual([...HOOK_BASENAMES].sort());
  });

  it("hooks/ 目录下的实际 .js 文件与 HOOK_BASENAMES 一致", () => {
    const hooksDir = path.join(process.cwd(), "hooks");
    const actual = readdirSync(hooksDir)
      .filter((f) => f.endsWith(".js"))
      .sort();
    expect(actual).toEqual([...HOOK_BASENAMES].sort());
  });
});

describe("isInside（path containment）", () => {
  it("正确判定子路径", () => {
    expect(isInside(path.join(tmpDir, "a", "b"), tmpDir)).toBe(true);
    expect(isInside(path.join(tmpDir, "a"), tmpDir)).toBe(true);
  });

  it("排除父目录与同级", () => {
    expect(isInside(tmpDir, path.join(tmpDir, "a"))).toBe(false);
    // `relative` 跨出 parent 时返回 `..` 起头或绝对路径。
    expect(isInside(path.join(tmpDir, "evil"), path.join(tmpDir, "a"))).toBe(false);
  });

  it("前缀撞车但不构成子路径时返回 false（修 prefix-collision 漏洞）", () => {
    // 旧实现用 startsWith(`/home/node/.openclaw`) 判包含，于是
    // `/home/node/.openclaw-evil` 能蒙混过关。
    expect(isInside(tmpDir + "-evil", tmpDir)).toBe(false);
  });
});

describe("parseRequireTargets（NODE_OPTIONS 切分）", () => {
  it("认 --require x / -r x / --require=x 三种形态", () => {
    expect(parseRequireTargets("--require a.js")).toEqual(["a.js"]);
    expect(parseRequireTargets("-r a.js")).toEqual(["a.js"]);
    expect(parseRequireTargets("--require=a.js")).toEqual(["a.js"]);
  });

  it("多条 --require 全部收集，顺序保留", () => {
    expect(parseRequireTargets("--require a.js --require b.js -r c.js")).toEqual([
      "a.js",
      "b.js",
      "c.js",
    ]);
  });

  it("混入无关 token 不影响结果", () => {
    expect(parseRequireTargets("--max-old-space-size=512 --require a.js -r b.js --inspect")).toEqual([
      "a.js",
      "b.js",
    ]);
  });

  it("空串 / undefined 安全返回空数组", () => {
    expect(parseRequireTargets("")).toEqual([]);
    expect(parseRequireTargets(undefined)).toEqual([]);
  });
});

describe("matchHookRequires（按路径归属判定）", () => {
  it("指向数据目录内的 hook 时认", () => {
    const target = path.join(resolvePreloadDir(), "hook-mounter.js");
    const matches = matchHookRequires(`--require ${target}`);
    expect(matches).toHaveLength(1);
    expect(matches[0].basename).toBe("hook-mounter.js");
    expect(matches[0].inPreloadDir).toBe(true);
    expect(matches[0].inLegacyDir).toBe(false);
  });

  it("指向遗留安装目录的 hook 时认（兼容 1.0.x 部署）", () => {
    const target = path.join(resolveLegacyDir(), "runtime.js");
    const matches = matchHookRequires(`--require ${target}`);
    expect(matches).toHaveLength(1);
    expect(matches[0].basename).toBe("runtime.js");
    expect(matches[0].inLegacyDir).toBe(true);
    expect(matches[0].inPreloadDir).toBe(false);
  });

  it("指向 OPENCLAW_EXTENSIONS_DIR 下的 hook 也认（路径不带插件 id）", () => {
    setEnv("OPENCLAW_EXTENSIONS_DIR", path.join(tmpDir, "custom-ext"));
    mkdirSync(path.join(tmpDir, "custom-ext"), { recursive: true });
    const target = path.join(tmpDir, "custom-ext", "hook-mounter.js");
    const matches = matchHookRequires(`--require ${target}`);
    expect(matches.some((m) => m.resolved === path.resolve(target) && m.inLegacyDir)).toBe(true);
  });

  it("hook-mounter.js 在随包目录下也认（零残留写法，install/hooks/*.js）", () => {
    // 模拟安装包内的 hooks/ 目录。findBundledDir 通过 import.meta.url 向上找，
    // 测试仓库场景下"../hooks" 即存在，这里直接校验该分支命中。
    const bundled = findBundledDir("hooks");
    expect(bundled).toBeDefined();
    const target = path.join(bundled as string, "hook-mounter.js");
    const matches = matchHookRequires(`--require ${target}`);
    expect(matches.some((m) => m.inBundledDir && m.basename === "hook-mounter.js")).toBe(true);
  });

  it("无关路径的同名 hook 不认（避免把别人家的 runtime.js 当我们的）", () => {
    const matches = matchHookRequires("--require /opt/vendor/runtime.js");
    expect(matches).toHaveLength(0);
  });

  it("非 hook basename 一律不认", () => {
    const target = path.join(resolvePreloadDir(), "something-else.js");
    expect(matchHookRequires(`--require ${target}`)).toEqual([]);
  });

  it("多条命中时全部返回", () => {
    const a = path.join(resolvePreloadDir(), "hook-mounter.js");
    const b = path.join(resolveLegacyDir(), "runtime.js");
    const matches = matchHookRequires(`--require ${a} --require ${b}`);
    expect(matches).toHaveLength(2);
  });
});

describe("resolvePreloadTarget / resolvePreloadDir", () => {
  it("预加载目标是数据目录下的 hook-mounter.js", () => {
    const target = resolvePreloadTarget();
    expect(target.endsWith(path.join("sst-security-control-openclaw", "hooks", "hook-mounter.js"))).toBe(true);
    expect(path.dirname(target)).toBe(resolvePreloadDir());
  });
});