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
 * package.json 是唯一权威版本；build.js 构建前运行
 * assertVersionConsistency，任何副本漂移都必须导致构建失败并报告
 * 漂移位置。这里用临时目录搭建最小假仓库，覆盖一致/单点漂移/
 * 多点漂移三种路径，不实际跑构建。
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
  writeJson("hooks/package.json", { name: "hooks", version });
  writeFileSync(
    path.join(root, "hooks/runtime.js"),
    `#!/usr/bin/env node\n// openclaw-hook: v${version}\n`
  );
  writeFileSync(
    path.join(root, "hooks/network.js"),
    `#!/usr/bin/env node\n// openclaw-hook: v${version}\n`
  );
  writeFileSync(
    path.join(root, "src/store.ts"),
    `export class Store {\n  readonly version = '${version}';\n}\n`
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
  it("passes when every copy matches package.json", () => {
    const audit = assertVersionConsistency(root);
    expect(audit.expected).toBe(VERSION);
    expect(audit.copies).toHaveLength(5);
    for (const copy of audit.copies) {
      expect(copy.value).toBe(VERSION);
    }
  });

  it("fails and names the drifted copy when plugin manifest drifts", () => {
    writeJson("openclaw.plugin.json", { version: "0.0.1" });
    expect(() => assertVersionConsistency(root)).toThrow(
      /openclaw\.plugin\.json#version: 0\.0\.1 \(expected 9\.9\.9\)/
    );
  });

  it("fails when a hook header tag drifts", () => {
    writeFileSync(
      path.join(root, "hooks/runtime.js"),
      "#!/usr/bin/env node\n// openclaw-hook: v0.9.3\n"
    );
    let message = "";
    try {
      assertVersionConsistency(root);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toContain("hooks/runtime.js header tag: 0.9.3");
    expect(message).toContain(`expected ${VERSION}`);
  });

  it("fails when the hooks sub-package version drifts", () => {
    writeJson("hooks/package.json", { name: "hooks", version: "0.9.0" });
    expect(() => assertVersionConsistency(root)).toThrow(
      /hooks\/package\.json#version: 0\.9\.0/
    );
  });

  it("reports every drifted copy in one error", () => {
    writeJson("openclaw.plugin.json", { version: "1.0.0" });
    writeFileSync(
      path.join(root, "src/store.ts"),
      `export class Store {\n  readonly version = '2.0.0';\n}\n`
    );
    let message = "";
    try {
      assertVersionConsistency(root);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toContain("openclaw.plugin.json#version: 1.0.0");
    expect(message).toContain("src/store.ts readonly version: 2.0.0");
    // non-drifted copies are not listed
    expect(message).not.toContain("hooks/runtime.js header tag:");
  });

  it("flags a missing hook version tag", () => {
    writeFileSync(path.join(root, "hooks/network.js"), "#!/usr/bin/env node\n");
    expect(() => assertVersionConsistency(root)).toThrow(
      /hooks\/network\.js header tag: \(tag missing\)/
    );
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
