import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import path from "path";
// @ts-expect-error -- plain-JS build helper, no type declarations
import {
  assertPublishMetadata,
  buildInstallOpenClawMeta,
  REQUIRED_PUBLISH_FIELDS,
} from "../scripts/clawhub-metadata.mjs";

/**
 * ClawHub 上架元数据断言。
 *
 * 背景：ClawHub 的 publish 校验读的是**发布归档根**的 package.json。本仓发出去
 * 的是 install/*.tgz，归档根即 `package/package.json` —— 由 build.js 生成，
 * 白名单式挑字段。上架报 "package.json / Package manifest / Missing metadata"
 * 的根因就是挑漏了：仓库根那份齐全，但没搬进包里。
 *
 * build.js 在 npm pack 之前调 assertPublishMetadata，所以搬漏会在构建期炸。
 * 本测试钉的是两件构建期拦不住的事：
 *   1. 搬运规则本身（搬哪些、从哪搬、入口路径怎么改写）
 *   2. 本仓真实文件能满足 ClawHub 的全部要求 —— 防止有人给仓库根删字段时
 *      只看见测试里的 fixture 是绿的
 */

const ROOT = path.resolve(__dirname, "..");

/** @returns {Record<string, any>} */
function readRepoJson(rel: string): Record<string, any> {
  return JSON.parse(readFileSync(path.join(ROOT, rel), "utf8"));
}

/** 与 build.js 的 installPkg 形状一致：仓库根字段 + 搬运来的 openclaw 块。 */
function shippedManifestShape(
  rootPkg: Record<string, any>,
  pluginManifest: Record<string, any>
): Record<string, any> {
  return {
    name: pluginManifest.name,
    version: rootPkg.version,
    description: rootPkg.description,
    type: rootPkg.type,
    keywords: rootPkg.keywords,
    author: rootPkg.author,
    license: rootPkg.license,
    repository: rootPkg.repository,
    bugs: rootPkg.bugs,
    homepage: rootPkg.homepage,
    peerDependencies: rootPkg.peerDependencies,
    peerDependenciesMeta: rootPkg.peerDependenciesMeta,
    openclaw: buildInstallOpenClawMeta(rootPkg, pluginManifest, "./index.js"),
  };
}

describe("buildInstallOpenClawMeta", () => {
  it("carries compat/build from package.json and install from the plugin manifest", () => {
    const rootPkg = {
      openclaw: {
        extensions: ["./index.ts"],
        compat: { pluginApi: ">=2026.9.4" },
        build: { openclawVersion: "2026.9.4" },
      },
    };
    const manifest = { openclaw: { install: { clawhubSpec: { owner: "zhanxing" } } } };

    const meta = buildInstallOpenClawMeta(rootPkg, manifest, "./index.js");

    expect(meta.extensions).toEqual(["./index.js"]);
    expect(meta.compat).toEqual({ pluginApi: ">=2026.9.4" });
    expect(meta.build).toEqual({ openclawVersion: "2026.9.4" });
    expect(meta.install).toEqual(manifest.openclaw.install);
  });

  it("rewrites the entry for the built bundle instead of reusing the repo entry", () => {
    // 仓库根声明的是 TS 源码入口，tgz 里是编译产物 —— 照抄 "./index.ts" 会让
    // ClawHub/宿主在发布包里找一个不存在的文件。
    const rootPkg = { openclaw: { extensions: ["./index.ts"] } };
    const meta = buildInstallOpenClawMeta(rootPkg, {}, "./index.js");
    expect(meta.extensions).toEqual(["./index.js"]);
    expect(meta.extensions).not.toContain("./index.ts");
  });

  it("omits compat/build/install when the source has none, rather than emitting empty blocks", () => {
    // 空块比没有更糟：assertPublishMetadata 会把 {} 当成"字段存在"放过去吗？
    // 不会（它按 undefined 判），但保留 undefined 让 JSON.stringify 整个省掉，
    // 报错信息里的字段名也更干净。
    const meta = buildInstallOpenClawMeta({ openclaw: {} }, {}, "./index.js");
    expect(meta).toEqual({ extensions: ["./index.js"] });
    expect("compat" in meta).toBe(false);
    expect("install" in meta).toBe(false);
  });
});

describe("assertPublishMetadata", () => {
  const complete = {
    description: "d",
    license: "Apache-2.0",
    author: "a",
    repository: { type: "git", url: "https://example.com/x.git" },
    openclaw: {
      extensions: ["./index.js"],
      compat: { pluginApi: ">=2026.9.4" },
      build: { openclawVersion: "2026.9.4" },
      install: { clawhubSpec: { owner: "zhanxing" } },
    },
  };

  it("passes a complete manifest and returns the checked field list", () => {
    const result = assertPublishMetadata(complete, "test");
    expect(result.pluginApi).toBe(">=2026.9.4");
    expect(result.checked).toEqual(REQUIRED_PUBLISH_FIELDS.map((f) => f.path));
  });

  it("reports every missing field at once", () => {
    // 逐个修、逐个重传是这类校验最费时的地方：断言必须一次列全。
    let message = "";
    try {
      assertPublishMetadata(
        { description: "已声明", openclaw: { extensions: ["./index.js"] } },
        "test"
      );
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toContain("license");
    expect(message).toContain("author");
    expect(message).toContain("repository");
    expect(message).toContain("openclaw.compat.pluginApi");
    expect(message).toContain("openclaw.build.openclawVersion");
    expect(message).toContain("openclaw.install.clawhubSpec");
    // 已声明的字段不该出现在缺失清单里
    expect(message).not.toContain("  - description");
  });

  it("rejects a || pluginApi range that publish validation lets through but the installer misreads", () => {
    // 宿主安装侧按空白切 token 后 AND 求值，"||" 列表被读成字面 token 从而静默
    // 判否 —— 发布绿灯、装不上。必须在构建期拦。
    expect(() =>
      assertPublishMetadata(
        {
          ...complete,
          openclaw: {
            ...complete.openclaw,
            compat: { pluginApi: ">=2026.4.1 || >=2026.9.4" },
          },
        },
        "test"
      )
    ).toThrow(/||/);
  });

  it("names the source so a build-time failure points at the right manifest", () => {
    expect(() => assertPublishMetadata({}, "install 端 package.json")).toThrow(
      /install 端 package\.json/
    );
  });
});

describe("repo metadata (real files)", () => {
  it("satisfies ClawHub's requirements after being carried into the bundle manifest", () => {
    const rootPkg = readRepoJson("package.json");
    const manifest = readRepoJson("openclaw.plugin.json");
    const shipped = shippedManifestShape(rootPkg, manifest);
    expect(() => assertPublishMetadata(shipped, "repo")).not.toThrow();
  });

  it("declares a single-comparator pluginApi matching the host it vendors against", () => {
    // compat 下限跟着 src/openclaw-sdk 的 vendor 基线走，不跟 package.json#version
    // 走（后者是插件发版号）。换 vendor 基线时要一并改这里。
    const rootPkg = readRepoJson("package.json");
    const manifest = readRepoJson("openclaw.plugin.json");
    const pluginApi = buildInstallOpenClawMeta(rootPkg, manifest, "./index.js").compat.pluginApi;
    const minHost = manifest.host_compat[0].min_version;
    expect(pluginApi).toBe(`>=${minHost}`);
    expect(pluginApi).not.toMatch(/\s|\|\|/);
  });

  it("keeps build.openclawVersion in step with the manifest's host_compat floor", () => {
    // 两处都描述"支持到哪个宿主版本"，漂移会让 ClawHub 报
    // package-min-host-version-drift。
    const rootPkg = readRepoJson("package.json");
    const manifest = readRepoJson("openclaw.plugin.json");
    const meta = buildInstallOpenClawMeta(rootPkg, manifest, "./index.js");
    expect(meta.build.openclawVersion).toBe(manifest.host_compat[0].min_version);
  });
});