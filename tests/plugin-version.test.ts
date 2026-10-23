import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";
import { resolvePluginVersion } from "../index.js";

/**
 * resolvePluginVersion —— 运行时版本解析。
 *
 * 这个函数此前零测试覆盖，而它对开发树是坏的：仓库根 package.json 的 name
 * 带 npm scope（@zhanxing/sst-security-control-openclaw），旧判据要求与无
 * scope 的 PLUGIN_ID 精确相等，于是开发树和 dist/ 静默返回 "0.0.0-unknown"
 * —— 不抛错、不告警，面板副标题和启动日志显示的是一个长得像正常值的假版本。
 * 安装后之所以正常，是因为 build.js 会剥掉 scope 写安装包的 package.json。
 *
 * 这里用临时目录伪造各种真实布局（开发树 / 安装包 / dist / 子包嵌套），
 * 把三条加载路径和几个退化场景都钉住。
 */

const UNKNOWN = "0.0.0-unknown";

let root: string;

/** 在 root 下铺一棵目录树，返回一个指向 <dir>/index.js 的模块 URL。 */
function layout(dirs: string[], files: Record<string, unknown | string>): string {
  for (const dir of dirs) mkdirSync(path.join(root, dir), { recursive: true });
  for (const [rel, data] of Object.entries(files)) {
    const target = path.join(root, rel);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, typeof data === "string" ? data : JSON.stringify(data));
  }
  return pathToFileURL(path.join(root, dirs[dirs.length - 1], "index.js")).href;
}

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "plugin-version-"));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("resolvePluginVersion", () => {
  it("本仓库开发树下解析出真实版本（而不是 unknown 兜底值）", () => {
    // 夹具只能证明逻辑，证明不了"当前这棵树"的状态。这条直接拿本模块的
    // 真实起点跑一遍：仓库根 package.json 带 @zhanxing/ scope，是最容易
    // 回归的路径。改名/换 scope 后这里会立刻响，而不是等到有人注意到面板
    // 副标题写着 0.0.0-unknown。
    const realVersion = JSON.parse(
      readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../package.json"), "utf8")
    ).version;
    expect(realVersion).not.toBe(UNKNOWN);
    expect(resolvePluginVersion()).toBe(realVersion);
  });

  it("开发树：包名带 npm scope 时仍解析出版本", () => {
    // 回归用例。判据只比无 scope 形式时，这里会返回 UNKNOWN，
    // 面板副标题/启动日志在本地开发时显示 0.0.0-unknown。
    const url = layout(["src"], {
      "package.json": { name: "@zhanxing/sst-security-control-openclaw", version: "3.1.4" },
    });
    expect(resolvePluginVersion(url)).toBe("3.1.4");
  });

  it("安装包：build.js 剥掉 scope 后的包名同样解析", () => {
    // 用户实际运行环境。application/ 下没有 package.json，需要向上走到
    // package/package.json —— 断言向上查找层数够用（起始第 2 层命中）。
    const url = layout(["package/application"], {
      "package/package.json": { name: "sst-security-control-openclaw", version: "1.0.1" },
    });
    expect(resolvePluginVersion(url)).toBe("1.0.1");
  });

  it("dist 构建产物：起点更深一层也解析得到", () => {
    const url = layout(["dist"], {
      "package.json": { name: "@zhanxing/sst-security-control-openclaw", version: "2.0.0" },
    });
    expect(resolvePluginVersion(url)).toBe("2.0.0");
  });

  it("向上查找会跳过嵌套的无关子包，继续走到本插件的 package.json", () => {
    const url = layout(["packages/inner/src"], {
      "packages/inner/package.json": { name: "some-other-lib", version: "9.9.9" },
      "package.json": { name: "sst-security-control-openclaw", version: "1.2.3" },
    });
    expect(resolvePluginVersion(url)).toBe("1.2.3");
  });

  it("找不到本插件的 package.json 时返回 unknown 兜底值", () => {
    const url = layout(["nested"], {
      "package.json": { name: "totally-unrelated", version: "9.9.9" },
    });
    expect(resolvePluginVersion(url)).toBe(UNKNOWN);
  });

  it("package.json 损坏时继续向上查找，不抛异常", () => {
    const url = layout(["broken"], {
      "broken/package.json": "{ not json at all",
      "package.json": { name: "sst-security-control-openclaw", version: "4.5.6" },
    });
    expect(resolvePluginVersion(url)).toBe("4.5.6");
  });

  it("包名对上但 version 不是字符串时返回 unknown，不返回 undefined", () => {
    const url = layout(["weird"], {
      "package.json": { name: "sst-security-control-openclaw", version: 123 },
    });
    expect(resolvePluginVersion(url)).toBe(UNKNOWN);
  });

  it("目录树里完全没有 package.json 时返回 unknown", () => {
    // tmpdir 上溯到根都不该命中本插件名
    expect(resolvePluginVersion(layout(["nowhere"], {}))).toBe(UNKNOWN);
  });
});
