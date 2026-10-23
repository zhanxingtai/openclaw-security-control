import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
// @ts-expect-error -- plain-JS build helper, no type declarations
import {
  assertVersionConsistency,
  collectVersionCopies,
} from "../scripts/version-check.mjs";

/**
 * 版本号单一来源断言。
 *
 * package.json 是唯一权威版本，唯一允许存在的副本是
 * openclaw.plugin.json#version（宿主清单契约）。build.js 构建前运行
 * assertVersionConsistency，漂移必须导致构建失败并报告漂移位置。
 *
 * 同时钉住"不该被 gate 的东西确实不被 gate"：fixture 里 hook tag、
 * hooks/package.json、src/store.ts 全部故意写成跟 package.json 不同的值，
 * 检查仍须通过。这是本次收敛的核心保证——把不该对齐的副本移出 gate 后，
 * 它们再漂移也不会有人来拦，反过来也证明它们确实已不在副本清单里。
 */

const VERSION = "9.9.9";

let root: string;

function writeJson(rel: string, data: Record<string, unknown>): void {
  writeFileSync(path.join(root, rel), JSON.stringify(data));
}

function seedFixture(version: string): void {
  mkdirSync(path.join(root, "hooks"), { recursive: true });
  mkdirSync(path.join(root, "src"), { recursive: true });
  writeJson("package.json", { name: "sst-security-control-openclaw", version });
  writeJson("openclaw.plugin.json", { version });
  // 以下三处刻意与 package.json 不同：它们不在 gate 内
  writeJson("hooks/package.json", { name: "hooks", version: "0.9.0" });
  writeFileSync(
    path.join(root, "hooks/runtime.js"),
    "#!/usr/bin/env node\n// openclaw-hook: v0.9.3\n"
  );
  writeFileSync(
    path.join(root, "hooks/network.js"),
    `#!/usr/bin/env node\n// openclaw-hook: v${version}\n`
  );
  writeFileSync(
    path.join(root, "src/store.ts"),
    `export class Store {\n  readonly version = '2.0.0';\n}\n`
  );
}

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "version-check-"));
  seedFixture(VERSION);
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("assertVersionConsistency", () => {
  it("passes when the plugin manifest matches package.json", () => {
    const audit = assertVersionConsistency(root);
    expect(audit.expected).toBe(VERSION);
    expect(audit.copies).toHaveLength(1);
    expect(audit.copies[0].label).toBe("openclaw.plugin.json#version");
    expect(audit.copies[0].value).toBe(VERSION);
  });

  it("does not gate hook tags, hooks/package.json or src/store.ts", () => {
    // seedFixture 把这三处都写成跟 package.json 不一致的值；不抛错即证明
    // 它们已从副本清单里移除，不再要求每次发版手工对齐
    expect(() => assertVersionConsistency(root)).not.toThrow();
    expect(collectVersionCopies(root).copies).toHaveLength(1);
  });

  it("fails and names the drifted copy when plugin manifest drifts", () => {
    writeJson("openclaw.plugin.json", { version: "0.0.1" });
    expect(() => assertVersionConsistency(root)).toThrow(
      /openclaw\.plugin\.json#version: 0\.0\.1 \(expected 9\.9\.9\)/
    );
  });

  it("flags a missing manifest version as drift", () => {
    writeJson("openclaw.plugin.json", {});
    expect(() => assertVersionConsistency(root)).toThrow(
      /openclaw\.plugin\.json#version: \(missing\)/
    );
  });

  it("reports the manifest drift alone, without unrelated labels", () => {
    writeJson("openclaw.plugin.json", { version: "1.0.0" });
    let message = "";
    try {
      assertVersionConsistency(root);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toContain("openclaw.plugin.json#version: 1.0.0");
    expect(message).toContain(`expected ${VERSION}`);
    expect(message).not.toContain("header tag");
    expect(message).not.toContain("hooks/package.json");
    expect(message).not.toContain("src/store.ts");
  });
});

describe("collectVersionCopies", () => {
  it("uses package.json as the expected version", () => {
    writeJson("package.json", { name: "sst-security-control-openclaw", version: "1.2.3" });
    const audit = collectVersionCopies(root);
    expect(audit.expected).toBe("1.2.3");
    // every copy then counts as drifted
    expect(audit.copies.every((c) => c.value !== audit.expected)).toBe(true);
  });
});
