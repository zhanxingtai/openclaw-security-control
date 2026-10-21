import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, symlinkSync, mkdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { safeFsPath } from "../src/utils/safeFsPath.js";

/**
 * safeFsPath 安全分支——防 /etc/shadow 类读取的闸门：
 * - 正常路径（含 ~ 展开、相对路径）在允许根内 → 返回 realpath；
 * - 词法逃逸（../..）→ undefined；
 * - 符号链接逃逸（根内链接指向根外真实文件）→ undefined；
 * - ELOOP（符号链接成环）→ undefined；
 * - ENOENT（文件尚不存在）→ 返回绝对路径，让下游报"文件不存在"。
 */

let root: string;
let outside: string;

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "safe-fs-root-"));
  outside = mkdtempSync(path.join(tmpdir(), "safe-fs-outside-"));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});

describe("safeFsPath 安全分支", () => {
  it("根内真实文件返回 realpath", () => {
    const file = path.join(root, "sub", "policy.yaml");
    mkdirSync(path.dirname(file));
    writeFileSync(file, "x");
    expect(safeFsPath(file, [root])).toBe(file);
  });

  it("词法逃逸（..）拒绝", () => {
    const escaped = path.join(root, "..", "evil.yaml");
    expect(safeFsPath(escaped, [root])).toBeUndefined();
    expect(safeFsPath(path.join(root, "sub", "..", "..", "evil"), [root])).toBeUndefined();
  });

  it("根外绝对路径拒绝", () => {
    const file = path.join(outside, "secret.txt");
    writeFileSync(file, "x");
    expect(safeFsPath(file, [root])).toBeUndefined();
  });

  it("符号链接逃逸拒绝：根内链接指向根外真实文件", () => {
    const secret = path.join(outside, "shadow-like.txt");
    writeFileSync(secret, "top-secret");
    const link = path.join(root, "link-out");
    symlinkSync(secret, link);
    expect(safeFsPath(link, [root])).toBeUndefined();
  });

  it("ELOOP（符号链接成环）拒绝", () => {
    const a = path.join(root, "loop-a");
    const b = path.join(root, "loop-b");
    symlinkSync(a, b);
    symlinkSync(b, a);
    expect(safeFsPath(a, [root])).toBeUndefined();
  });

  it("ENOENT 放行绝对路径（下游报「文件不存在」而非误判越界）", () => {
    const missing = path.join(root, "not-yet", "file.yaml");
    expect(safeFsPath(missing, [root])).toBe(path.resolve(missing));
  });

  it("~ 展开到 homedir 后按根校验（不在根内则拒绝）", () => {
    expect(safeFsPath("~/whatever", [root])).toBeUndefined();
  });

  it("空值/非字符串拒绝", () => {
    expect(safeFsPath(undefined, [root])).toBeUndefined();
    expect(safeFsPath("", [root])).toBeUndefined();
  });
});
