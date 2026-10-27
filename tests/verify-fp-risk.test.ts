import { describe, expect, it } from "vitest";
import { execFileSync } from "child_process";
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { load as loadYaml } from "js-yaml";

/**
 * scripts/verify-fp-risk.mjs 的回归护栏。
 *
 * 这份测试取代了此前的 scripts/_smoke-fp-risk.test.mjs —— 后者是 .mjs，
 * 不在 vitest 的 include 范围（只收 .test.ts）里，CI 从不执行，也从未被
 * 手工跑过（它硬编码的 "block 规则数 = 37" 早已随策略扩容变成 55），
 * 于是长期处于"看起来是测试、实际从不生效"的状态。
 *
 * 关键点：**不硬编码策略数字**。block 规则数会随策略扩容单调变化，把
 * 它写死等于给 CI 埋一颗每加一条规则就炸的雷。这里改为从策略 YAML
 * 独立推导期望集合，与脚本输出逐条比对 —— 脚本的筛选逻辑一旦漂移
 * （漏算、误算、enabled 判定写错）依旧会被抓到，而策略正常增删不会误报。
 */

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCRIPT = path.join(ROOT, "scripts", "verify-fp-risk.mjs");
const POLICY = path.join(ROOT, "policies", "security-policy.spl.yaml");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function run(args: string[]): RunResult {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      encoding: "utf8",
      cwd: ROOT,
    });
    return { code: 0, stdout, stderr: "" };
  } catch (err) {
    const e = err as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      code: e.status ?? 1,
      stdout: e.stdout?.toString() ?? "",
      stderr: e.stderr?.toString() ?? "",
    };
  }
}

interface FpReport {
  repoPath: string;
  threshold: number;
  summary: { total: number; red: number; orange: number; green: number };
  findings: Array<{ id: string; severity: string; priority: number | string; score: number; bucket: string }>;
}

/** 从策略 YAML 独立推导"参与评分的 block 规则"集合。 */
function expectedBlockRuleIds(): string[] {
  const parsed = loadYaml(readFileSync(POLICY, "utf8")) as {
    rules?: Array<{ id?: string; enabled?: boolean; action?: { decision?: string } }>;
  };
  const rules = parsed.rules ?? [];
  return rules
    .filter((r) => r.enabled !== false && r.action?.decision === "block")
    .map((r) => String(r.id))
    .sort();
}

describe("scripts/verify-fp-risk.mjs", () => {
  it("默认自测输出含 FP 报告标题 + 三档分布", () => {
    const { code, stdout } = run([]);
    expect(code).toBe(0);
    expect(stdout).toContain("FP 风险评分报告");
    expect(stdout).toContain("🔴");
    expect(stdout).toContain("🟠");
    expect(stdout).toContain("🟢");
  });

  it("--json 输出合法 JSON 且 summary 字段完整", () => {
    const { code, stdout } = run(["--json"]);
    expect(code).toBe(0);
    const report = JSON.parse(stdout) as FpReport;
    expect(report.repoPath).toBeTruthy();
    expect(typeof report.threshold).toBe("number");
    expect(typeof report.summary.red).toBe("number");
    expect(typeof report.summary.orange).toBe("number");
    expect(typeof report.summary.green).toBe("number");
    expect(Array.isArray(report.findings)).toBe(true);
  });

  it("--repo=<不存在路径> → exit 2", () => {
    const { code, stderr } = run(["--repo=__no_such_policy__.yaml"]);
    expect(code).toBe(2);
    expect(stderr).toContain("策略文件不存在");
  });

  it("--strict 默认 threshold（5）下 exit 0（🔴 未超阈值）", () => {
    const { code } = run(["--strict"]);
    expect(code).toBe(0);
  });

  it("--strict --threshold=4（CI 形态）exit 0", () => {
    const { code } = run(["--strict", "--threshold=4"]);
    expect(code).toBe(0);
  });

  it("评分的 block 规则集合与策略文件独立推导结果逐条一致", () => {
    const { stdout } = run(["--json"]);
    const report = JSON.parse(stdout) as FpReport;
    const expected = expectedBlockRuleIds();
    const actual = report.findings.map((f) => f.id).sort();
    expect(report.summary.total).toBe(expected.length);
    expect(actual).toEqual(expected);
  });

  it("summary 三档之和等于 block 规则总数", () => {
    const { stdout } = run(["--json"]);
    const report = JSON.parse(stdout) as FpReport;
    const { red, orange, green, total } = report.summary;
    expect(red + orange + green).toBe(total);
  });

  it("#1 block-write-system-backdoor 已降 warn，不在 block 集合中", () => {
    const { stdout } = run(["--json"]);
    const report = JSON.parse(stdout) as FpReport;
    expect(report.findings.map((f) => f.id)).not.toContain("block-write-system-backdoor");
  });
});
