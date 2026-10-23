import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain-JS build helper, no type declarations
import {
  assertSourceAttribution,
  detectRelativeReadmeAssets,
  parseGitHubRepo,
  pickGitHubRemote,
  renderPublishCommand,
  resolveSourceAttribution,
  stampSourceAttribution,
} from "../scripts/clawhub-source.mjs";

/**
 * ClawHub source 归属信息的计算与校验。
 *
 * 背景：ClawHub 详情页把插件 README 里的相对图片按 release 的 source 改写成
 * raw.githubusercontent.com 绝对地址（上游 clawhub PR #2412）。缺 repo/commit
 * 就不改写，assets/*.jpg 在详情页 404。归属信息手抄必错——本仓 origin 是内网
 * Gitea 镜像，GitHub 远端叫 github，且本地 HEAD 那个提交只在 Gitea 上
 * （raw 取不到，实测 404）。所以本测试钉的是"算出来的那组值是对的"：
 *   1. 远端解析：只认 github.com 的仓库根 URL
 *   2. 相对图片识别：与上游 detectRelativeReadmeAssets 同口径
 *   3. 取值前提：工作区干净 + 与该 commit 的树逐字节相同
 *   4. README 里的相对图片必须在该 commit 的树里真实存在
 */

const COMMIT = "ea29225dd042632958af5acd197f68d1504ef2c9";

describe("parseGitHubRepo", () => {
  it("认得 git@ / https / ssh 三种远端写法", () => {
    expect(parseGitHubRepo("git@github.com:zhanxingtai/openclaw-security-control.git")).toBe(
      "zhanxingtai/openclaw-security-control"
    );
    expect(parseGitHubRepo("https://github.com/zhanxingtai/openclaw-security-control")).toBe(
      "zhanxingtai/openclaw-security-control"
    );
    expect(parseGitHubRepo("https://github.com/zhanxingtai/openclaw-security-control.git")).toBe(
      "zhanxingtai/openclaw-security-control"
    );
    expect(parseGitHubRepo("ssh://git@github.com/zhanxingtai/openclaw-security-control.git")).toBe(
      "zhanxingtai/openclaw-security-control"
    );
  });

  it("拒绝非 GitHub 地址与网页地址", () => {
    expect(parseGitHubRepo("http://git.example.com/internal-mirror/openclaw-security-control")).toBeNull();
    expect(parseGitHubRepo("https://github.com/zhanxingtai/openclaw-security-control/tree/main")).toBeNull();
    expect(parseGitHubRepo("")).toBeNull();
  });
});

describe("pickGitHubRemote", () => {
  const run = (args: string[]) => {
    if (args[0] === "remote") {
      return {
        code: 0,
        stdout:
          "origin\thttp://git.example.com/internal-mirror/openclaw-security-control (fetch)\n" +
          "origin\thttp://git.example.com/internal-mirror/openclaw-security-control (push)\n" +
          "github\tgit@github.com:zhanxingtai/openclaw-security-control.git (fetch)\n" +
          "github\tgit@github.com:zhanxingtai/openclaw-security-control.git (push)\n",
        stderr: "",
      };
    }
    return { code: 1, stdout: "", stderr: "" };
  };

  it("跳过 origin 这类内网镜像，挑中 GitHub 远端", () => {
    expect(pickGitHubRemote(run)?.name).toBe("github");
  });
});

describe("detectRelativeReadmeAssets", () => {
  it("只认相对图片，http(s)/协议相对/data:/锚点一律排除", () => {
    const markdown = [
      "![WeChat](assets/wechat-mp-qr.jpg)",
      '<img src="assets/logo.png" />',
      "![remote](https://example.com/a.png)",
      "![proto](//example.com/b.png)",
      "![inline](data:image/png;base64,AAA)",
      "![anchor](#section)",
      "![mail](mailto:a@b.c)",
    ].join("\n");
    expect(detectRelativeReadmeAssets(markdown)).toEqual(["assets/wechat-mp-qr.jpg", "assets/logo.png"]);
  });
});

describe("assertSourceAttribution", () => {
  it("40 位 SHA + owner/repo + ref + path 才算合法", () => {
    expect(
      assertSourceAttribution({
        repo: "zhanxingtai/openclaw-security-control",
        commit: COMMIT,
        ref: "main",
        path: ".",
      }).commit
    ).toBe(COMMIT);
  });

  it("短 SHA / 非 GitHub 仓库 / 空 path 都拒绝", () => {
    expect(() =>
      assertSourceAttribution({ repo: "zhanxingtai/openclaw-security-control", commit: "abc123", ref: "main", path: "." })
    ).toThrow(/40 位/);
    expect(() =>
      assertSourceAttribution({ repo: "not-a-repo", commit: COMMIT, ref: "main", path: "." })
    ).toThrow(/owner\/repo/);
    expect(() =>
      assertSourceAttribution({ repo: "zhanxingtai/openclaw-security-control", commit: COMMIT, ref: "main", path: "" })
    ).toThrow(/package path/);
  });
});

describe("renderPublishCommand", () => {
  it("四个 --source-* 齐全", () => {
    const cmd = renderPublishCommand(
      { repo: "zhanxingtai/openclaw-security-control", commit: COMMIT, ref: "main", path: "." },
      "install/pkg.tgz"
    );
    expect(cmd).toContain("--source-repo zhanxingtai/openclaw-security-control");
    expect(cmd).toContain(`--source-commit ${COMMIT}`);
    expect(cmd).toContain("--source-ref main");
    expect(cmd).toContain("--source-path .");
    expect(cmd).toContain("install/pkg.tgz");
  });
});

describe("resolveSourceAttribution", () => {
  /**
   * 造一个 git 替身：只按需应答，其余一律失败。
   * @param {Record<string, { code: number, stdout?: string }>} table
   */
  const fakeGit = (table: Record<string, { code: number; stdout?: string }>) => {
    return (args: string[]) => {
      const key = args.join(" ");
      const hit = table[key];
      if (!hit) return { code: 1, stdout: "", stderr: `no such command: ${key}` };
      return { code: hit.code, stdout: hit.stdout ?? "", stderr: "" };
    };
  };

  const baseTable = {
    "remote -v": {
      code: 0,
      stdout:
        "origin\thttp://git.example.com/internal-mirror/openclaw-security-control (fetch)\n" +
        "github\tgit@github.com:zhanxingtai/openclaw-security-control.git (fetch)\n",
    },
    [`rev-parse --verify github/main`]: { code: 0, stdout: `${COMMIT}\n` },
    "status --porcelain": { code: 0, stdout: "" },
    [`diff --quiet ${COMMIT} --`]: { code: 0 },
    [`cat-file -e ${COMMIT}:assets/wechat-mp-qr.jpg`]: { code: 0 },
  };

  it("工作区干净且与 commit 同树时给出归属信息", () => {
    const attribution = resolveSourceAttribution(fakeGit(baseTable), {
      cwd: process.cwd(),
      readmeFiles: [],
    });
    expect(attribution).toEqual({
      repo: "zhanxingtai/openclaw-security-control",
      commit: COMMIT,
      ref: "main",
      path: ".",
    });
  });

  it("工作区脏 → 拒绝出值（否则归属指向的内容对不上）", () => {
    const table = { ...baseTable, "status --porcelain": { code: 0, stdout: " M package.json\n" } };
    expect(() => resolveSourceAttribution(fakeGit(table), { cwd: process.cwd(), readmeFiles: [] })).toThrow(
      /工作区不干净/
    );
  });

  it("与该 commit 不同树 → 拒绝出值", () => {
    const table = { ...baseTable, [`diff --quiet ${COMMIT} --`]: { code: 1 } };
    expect(() => resolveSourceAttribution(fakeGit(table), { cwd: process.cwd(), readmeFiles: [] })).toThrow(
      /与当前工作区不一致/
    );
  });

  it("README 里的相对图片不在该 commit 里 → 拒绝出值", () => {
    const table = { ...baseTable, [`cat-file -e ${COMMIT}:assets/wechat-mp-qr.jpg`]: { code: 1 } };
    expect(() =>
      resolveSourceAttribution(fakeGit(table), { cwd: process.cwd(), readmeFiles: ["README.md"] })
    ).toThrow(/wechat-mp-qr\.jpg/);
  });
});

describe("stampSourceAttribution", () => {
  it("把归属信息写进宿主清单的 clawhubSpec.source", () => {
    const manifest = {
      openclaw: { install: { clawhubSpec: { source: { type: "git", url: "https://github.com/x/y", ref: "main" } } } },
    };
    const stamped = stampSourceAttribution(manifest, {
      repo: "zhanxingtai/openclaw-security-control",
      commit: COMMIT,
      ref: "main",
      path: ".",
    });
    const source = (stamped.openclaw as any).install.clawhubSpec.source;
    expect(source.repo).toBe("zhanxingtai/openclaw-security-control");
    expect(source.commit).toBe(COMMIT);
    expect(source.path).toBe(".");
    // 原对象不能被就地改写
    expect((manifest.openclaw as any).install.clawhubSpec.source.commit).toBeUndefined();
  });
});
