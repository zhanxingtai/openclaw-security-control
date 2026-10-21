import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, symlinkSync, mkdirSync, writeFileSync, realpathSync } from "fs";
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
 *
 * 断言一律以 realpathSync.native 的实际输出为基准：macOS 的 /var 是
 * /private/var 的符号链接、GitHub Actions Windows 的 TEMP 是 8.3 短名
 * （RUNNER~1），这些平台下 tmpdir 的词法形式 ≠ 文件系统形式。
 */
const real = (p: string) => (realpathSync.native ?? realpathSync)(p);

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
    expect(safeFsPath(file, [root])).toBe(real(file));
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
    expect(safeFsPath(missing, [root])).toBe(path.join(real(root), "not-yet", "file.yaml"));
  });

  it("~ 展开到 homedir 后按根校验（不在根内则拒绝）", () => {
    expect(safeFsPath("~/whatever", [root])).toBeUndefined();
  });

  it("空值/非字符串拒绝", () => {
    expect(safeFsPath(undefined, [root])).toBeUndefined();
    expect(safeFsPath("", [root])).toBeUndefined();
  });
});

describe("safeFsPath 根路径自身含符号链接/别名（CI 回归）", () => {
  // macOS os.tmpdir()=/var/folders/... 实为 /private/var；GitHub Actions
  // Windows 的 TEMP 为 8.3 短名 C:\Users\RUNNER~1\...。根不做 realpath 时，
  // 这些平台下根内一切路径都会被误判逃逸（policy-testcases/panel-auth-rce
  // 在 macos/windows CI 全量 allow 的根因）。
  it("根是指向真实目录的符号链接时，根内文件放行并返回 realpath", () => {
    const realRoot = path.join(outside, "real-root");
    mkdirSync(realRoot);
    const file = path.join(realRoot, "policy.yaml");
    writeFileSync(file, "x");
    const linkRoot = path.join(root, "link-root");
    symlinkSync(realRoot, linkRoot, "dir");
    expect(safeFsPath(path.join(linkRoot, "policy.yaml"), [linkRoot])).toBe(real(file));
  });

  it("根内符号链接逃逸仍拒绝（根 unwound 不削弱逃逸检测）", () => {
    const realRoot = path.join(outside, "real-root");
    mkdirSync(realRoot);
    const secret = path.join(outside, "shadow-like.txt");
    writeFileSync(secret, "top-secret");
    const linkRoot = path.join(root, "link-root");
    symlinkSync(realRoot, linkRoot, "dir");
    const linkOut = path.join(realRoot, "link-out");
    symlinkSync(secret, linkOut);
    expect(safeFsPath(path.join(linkRoot, "link-out"), [linkRoot])).toBeUndefined();
  });

  it("根内尚不存在的路径（ENOENT）在符号链接根下同样放行", () => {
    const realRoot = path.join(outside, "real-root");
    mkdirSync(realRoot);
    const linkRoot = path.join(root, "link-root");
    symlinkSync(realRoot, linkRoot, "dir");
    const missing = path.join(linkRoot, "not-yet", "file.yaml");
    expect(safeFsPath(missing, [linkRoot])).toBe(path.join(real(realRoot), "not-yet", "file.yaml"));
  });

  it("不存在的根（ENOENT）不拓宽到已存在祖先", () => {
    // root 存在、root/.openclaw 不存在：允许根为后者时，root/evil 不得放行
    expect(safeFsPath(path.join(root, "evil.yaml"), [path.join(root, ".openclaw")])).toBeUndefined();
  });
});
