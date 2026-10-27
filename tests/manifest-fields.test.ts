import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import path from "path";
// @ts-expect-error -- plain-JS build helper, no type declarations
import {
  findUnknownCategories,
  findUnknownContractKeys,
  findUnknownManifestFields,
  SUPPORTED_MANIFEST_FIELDS,
} from "../scripts/openclaw-manifest-contract.mjs";

/**
 * 宿主清单的字段契约。
 *
 * 背景：ClawHub 上架校验（`clawhub package validate`）把宿主不认识的
 * 顶层字段判成 manifest-unknown-fields、把宿主不认识的 contracts 键判成
 * manifest-unknown-contracts，两条都是硬错误。本仓的清单一度带着
 * displayName / schema_version / host_compat / capabilities / secrets /
 * main / entry / openclaw / risk_flags 九个非法顶层字段，以及
 * contracts.hooks / gatewayMethods / httpRoutes 三个非法契约键，上架直接被拒。
 *
 * 合法字段集是"最低宿主版本 ∩ 最新宿主版本"，见
 * scripts/openclaw-manifest-contract.mjs 的说明。宿主清单的字段集随宿主版本
 * 变，本仓 pin 的是交集——交集里的字段在两边都合法。
 *
 * 运行时行为（hook / 网关方法 / HTTP 路由）不再由清单声明，改由注册代码
 * 拥有，断言在 tests/rpc-coverage.test.ts。
 */

const ROOT = path.resolve(__dirname, "..");

/** @returns {Record<string, any>} */
function readManifest(): Record<string, any> {
  return JSON.parse(readFileSync(path.join(ROOT, "openclaw.plugin.json"), "utf8"));
}

describe("openclaw.plugin.json 顶层字段", () => {
  it("不含宿主不认识的字段", () => {
    const unknown = findUnknownManifestFields(readManifest());
    expect(unknown, `宿主不认识的顶层字段：${JSON.stringify(unknown)}`).toEqual([]);
  });

  it("id / name / version / configSchema 齐全（宿主的硬性要求）", () => {
    const manifest = readManifest();
    expect(typeof manifest.id).toBe("string");
    expect(manifest.id.length).toBeGreaterThan(0);
    expect(typeof manifest.name).toBe("string");
    expect(typeof manifest.version).toBe("string");
    expect(manifest.configSchema).toBeTruthy();
  });

  it("categories 只用宿主认的 slug", () => {
    const unknown = findUnknownCategories(readManifest());
    expect(unknown, `宿主不认识的分类：${JSON.stringify(unknown)}`).toEqual([]);
  });
});

describe("openclaw.plugin.json 的 contracts", () => {
  it("不含宿主不认识的契约键", () => {
    const unknown = findUnknownContractKeys(readManifest());
    expect(unknown, `宿主不认识的 contracts 键：${JSON.stringify(unknown)}`).toEqual([]);
  });

  it("本插件不声明任何契约（它不拥有 provider / tool）", () => {
    // contracts 的语义是"静态能力归属"：本插件既不提供模型 provider，
    // 也不注册 agent tool（面板 RPC 与 hook 都走运行时注册），
    // 所以整块 contracts 都不该出现。
    const manifest = readManifest();
    expect(manifest.contracts).toBeUndefined();
  });
});

describe("openclaw.plugin.json 的 uiHints", () => {
  /** PluginConfigUiHint 允许的键（宿主 PluginConfigUiHint = Pick<ConfigUiHint, ...>）。 */
  const ALLOWED_HINT_KEYS = new Set([
    "label",
    "help",
    "tags",
    "advanced",
    "sensitive",
    "placeholder",
    "presentation",
    "multiline",
  ]);

  it("每条 hint 只含宿主认识的键", () => {
    const hints = readManifest().uiHints ?? {};
    for (const [configPath, hint] of Object.entries(hints as Record<string, any>)) {
      expect(typeof hint, `hint ${configPath} 必须是对象`).toBe("object");
      expect(Array.isArray(hint), `hint ${configPath} 必须是对象`).toBe(false);
      for (const key of Object.keys(hint)) {
        expect(
          ALLOWED_HINT_KEYS.has(key),
          `hint ${configPath} 含宿主不认识的键 ${key}`
        ).toBe(true);
      }
    }
  });

  it("每条 hint 指向 configSchema 里真实存在的配置路径", () => {
    // uiHints 的键是"配置路径"，不是自由文本标签。曾经塞过 "tabs"（一个对象）
    // 和 "panelUrl"（一个字符串）——两者都不是配置路径，前者的 description
    // 键还不被 PluginConfigUiHint 接受。
    const manifest = readManifest();
    const hints = manifest.uiHints ?? {};
    const roots = new Set(Object.keys(manifest.configSchema?.properties ?? {}));
    for (const configPath of Object.keys(hints as Record<string, any>)) {
      const root = String(configPath).split(".")[0];
      expect(
        roots.has(root),
        `hint ${configPath} 的根 ${root} 不在 configSchema.properties 里`
      ).toBe(true);
    }
  });
});

describe("合法字段集本身", () => {
  it("不含本仓用过的历史非法字段（防止把旧字段加回白名单）", () => {
    // 这几个字段曾在清单里出现过，全部被 ClawHub 判为非法。白名单里出现它们
    // 意味着有人为了"让某个旧字段合法"而扩了白名单——那等于把上架时的硬错误
    // 重新引入，只是挪到了本地检查之外。
    const retired = [
      "displayName",
      "schema_version",
      "host_compat",
      "capabilities",
      "secrets",
      "main",
      "entry",
      "openclaw",
      "risk_flags",
    ];
    for (const field of retired) {
      expect(
        SUPPORTED_MANIFEST_FIELDS.includes(field),
        `${field} 是宿主不认识的字段，不该出现在合法字段集里`
      ).toBe(false);
    }
  });

  it("contracts 白名单不含 hook / 网关方法 / HTTP 路由这类运行期键", () => {
    // 这三类曾经被当作契约键写进清单，宿主加载器从来就不读它们。
    const runtimeKeys = ["hooks", "gatewayMethods", "httpRoutes"];
    const manifest = readManifest();
    expect(manifest.contracts).toBeUndefined();
    for (const key of runtimeKeys) {
      expect(Object.keys(manifest).includes(key)).toBe(false);
    }
  });
});
