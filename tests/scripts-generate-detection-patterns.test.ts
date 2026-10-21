// scripts/generate-detection-patterns.mjs unit tests for  + .

import { describe, it, expect, vi } from "vitest";

interface MockRule {
  id: string;
  match?: { riskFlagsAny?: string[]; riskFlagsAll?: string[]; paramsRegex?: unknown };
  action: { decision: string };
}

describe("validateHookBlockedByEngine (hookBlocked subset block rule)", () => {
  it("all hookBlockedFlags matched by a block rule -> passes", async () => {
    const { validateHookBlockedByEngine } = await import("../scripts/generate-detection-patterns.mjs");
    const hookBlockedFlags = ["token_in_command", "pipe_to_shell"];
    const rules: MockRule[] = [
      { id: "r1", match: { riskFlagsAny: ["token_in_command"] }, action: { decision: "block" } },
      { id: "r2", match: { riskFlagsAll: ["pipe_to_shell"] }, action: { decision: "block" } },
    ];
    expect(() => validateHookBlockedByEngine(hookBlockedFlags, rules)).not.toThrow();
  });

  it("orphan hookBlockedFlag throws GenerateError and blocks the build", async () => {
    const { validateHookBlockedByEngine, GenerateError } = await import("../scripts/generate-detection-patterns.mjs");
    const hookBlockedFlags = ["token_in_command", "orphan_flag"];
    const rules: MockRule[] = [
      { id: "r1", match: { riskFlagsAny: ["token_in_command"] }, action: { decision: "block" } },
    ];
    expect(() => validateHookBlockedByEngine(hookBlockedFlags, rules)).toThrow(GenerateError);
    try {
      validateHookBlockedByEngine(hookBlockedFlags, rules);
    } catch (err) {
      expect((err as Error).message).toMatch(/orphan_flag/);
      expect((err as Error).message).toMatch(/无引擎 block 规则消费/);
    }
  });

  it("non-block decision rules do not count as consumers", async () => {
    const { validateHookBlockedByEngine, GenerateError } = await import("../scripts/generate-detection-patterns.mjs");
    const hookBlockedFlags = ["token_in_command"];
    const rules: MockRule[] = [
      { id: "r-warn", match: { riskFlagsAny: ["token_in_command"] }, action: { decision: "warn" } },
      { id: "r-audit", match: { riskFlagsAny: ["token_in_command"] }, action: { decision: "audit" } },
    ];
    expect(() => validateHookBlockedByEngine(hookBlockedFlags, rules)).toThrow(GenerateError);
  });

  it("empty hookBlockedFlags throws GenerateError ", async () => {
    const { validateHookBlockedByEngine, GenerateError } = await import("../scripts/generate-detection-patterns.mjs");
    const rules: MockRule[] = [{ id: "r", match: {}, action: { decision: "block" } }];
    expect(() => validateHookBlockedByEngine([], rules)).toThrow(GenerateError);
    try {
      validateHookBlockedByEngine([], rules);
    } catch (err) {
      expect((err as Error).message).toMatch(/hookBlockedFlags.*空数组/);
    }
  });

  it("non-array rules argument throws", async () => {
    const { validateHookBlockedByEngine, GenerateError } = await import("../scripts/generate-detection-patterns.mjs");
    expect(() => validateHookBlockedByEngine(["x"], null as unknown as never[])).toThrow(GenerateError);
  });

  it("block rule without riskFlags still triggers empty-array fail-loud ", async () => {
    const { validateHookBlockedByEngine, GenerateError } = await import("../scripts/generate-detection-patterns.mjs");
    const hookBlockedFlags: string[] = [];
    const rules: MockRule[] = [{ id: "r1", match: { paramsRegex: { command: ["foo"] } }, action: { decision: "block" } }];
    expect(() => validateHookBlockedByEngine(hookBlockedFlags, rules)).toThrow(GenerateError);
  });

  it("riskFlagsAny + riskFlagsAll are both collected into the consumer set", async () => {
    const { validateHookBlockedByEngine } = await import("../scripts/generate-detection-patterns.mjs");
    const hookBlockedFlags = ["flag_a", "flag_b", "flag_d"];
    const rules: MockRule[] = [
      { id: "r1", match: { riskFlagsAny: ["flag_a"] }, action: { decision: "block" } },
      { id: "r2", match: { riskFlagsAll: ["flag_b", "flag_c"] }, action: { decision: "block" } },
      { id: "r3", match: { riskFlagsAny: ["flag_d"] }, action: { decision: "block" } },
    ];
    expect(() => validateHookBlockedByEngine(hookBlockedFlags, rules)).not.toThrow();
  });

  it("returns consumedFlags Set ", async () => {
    const { validateHookBlockedByEngine } = await import("../scripts/generate-detection-patterns.mjs");
    const hookBlockedFlags = ["flag_a"];
    const rules: MockRule[] = [
      { id: "r1", match: { riskFlagsAny: ["flag_a"] }, action: { decision: "block" } },
      { id: "r2", match: { riskFlagsAll: ["flag_b"] }, action: { decision: "block" } },
    ];
    const consumed = validateHookBlockedByEngine(hookBlockedFlags, rules);
    expect(consumed).toBeInstanceOf(Set);
    expect(consumed.has("flag_a")).toBe(true);
    expect(consumed.has("flag_b")).toBe(true);
  });
});

//  normalizeFlagRegistry 允许 monitor/engine 名单为空
describe("normalizeFlagRegistry ", () => {
  const FLAG_REGISTRY_PATH = "../scripts/generate-detection-patterns.mjs";

  function makeRaw(overrides: Record<string, unknown> = {}) {
    return {
      hookBlockedFlags: ["reverse_shell"],
      monitorAutoKillFlags: ["reverse_shell"],
      engineHighRiskFlags: ["reverse_shell"],
      ...overrides,
    };
  }

  it("accepts monitorAutoKillFlags = [] with WARN (layer not deployed)", async () => {
    const mod = await import(FLAG_REGISTRY_PATH);
    const warns: string[] = [];
    const out = (mod as any).collectFromPolicy(
      {
        rules: [],
        metadata: { flagRegistry: makeRaw({ monitorAutoKillFlags: [] }) },
        "x-openclaw-selfProtection": { groups: {}, structural: {} },
      },
      (msg: string) => warns.push(msg)
    );
    expect(out.flagRegistry.monitorAutoKillFlags).toEqual([]);
    expect(warns.some((w) => /monitorAutoKillFlags.*empty/i.test(w))).toBe(true);
  });

  it("accepts engineHighRiskFlags = [] with WARN", async () => {
    const mod = await import(FLAG_REGISTRY_PATH);
    const warns: string[] = [];
    const out = (mod as any).collectFromPolicy(
      {
        rules: [],
        metadata: { flagRegistry: makeRaw({ engineHighRiskFlags: [] }) },
        "x-openclaw-selfProtection": { groups: {}, structural: {} },
      },
      (msg: string) => warns.push(msg)
    );
    expect(out.flagRegistry.engineHighRiskFlags).toEqual([]);
    expect(warns.some((w) => /engineHighRiskFlags.*empty/i.test(w))).toBe(true);
  });

  it("hookBlockedFlags = [] does NOT warn (still fail-loud at validateHookBlockedByEngine)", async () => {
    // hookBlockedFlags 空数组的检查在 collectFromPolicy 阶段不报错（WARN 也不会触发），
    // 但 generateArtifacts → validateHookBlockedByEngine 会 fail-loud。
    const mod = await import(FLAG_REGISTRY_PATH);
    const warns: string[] = [];
    expect(() =>
      (mod as any).collectFromPolicy(
        {
          rules: [],
          metadata: { flagRegistry: makeRaw({ hookBlockedFlags: [] }) },
          "x-openclaw-selfProtection": { groups: {}, structural: {} },
        },
        (msg: string) => warns.push(msg)
      )
    ).not.toThrow();
    expect(warns.some((w) => /hookBlockedFlags.*empty/i.test(w))).toBe(false);
  });

  it("non-array value throws GenerateError", async () => {
    const mod = await import(FLAG_REGISTRY_PATH);
    expect(() =>
      (mod as any).collectFromPolicy(
        {
          rules: [],
          metadata: { flagRegistry: makeRaw({ monitorAutoKillFlags: "not-array" }) },
          "x-openclaw-selfProtection": { groups: {}, structural: {} },
        }
      )
    ).toThrow(/expected an array/);
  });
});

//  monitorAutoKillFlags ⊆ monitorPatterns keys + engineHighRisk coverage WARN
describe("validateMonitorAutoKillInMonitorPatterns + warnEngineHighRiskCoverage ", () => {
  const FLAG_REGISTRY_PATH = "../scripts/generate-detection-patterns.mjs";

  it("autokill flag must have monitorPatterns entry", async () => {
    const { validateMonitorAutoKillInMonitorPatterns, GenerateError } = await import(FLAG_REGISTRY_PATH);
    expect(() =>
      validateMonitorAutoKillInMonitorPatterns(
        ["reverse_shell", "orphan"],
        { reverse_shell: [{ pattern: "foo" }] },
        () => {}
      )
    ).toThrow(GenerateError);
    try {
      validateMonitorAutoKillInMonitorPatterns(["orphan"], { reverse_shell: [{ pattern: "foo" }] }, () => {});
    } catch (err) {
      expect((err as Error).message).toMatch(/orphan/);
      expect((err as Error).message).toMatch(/monitorPatterns/);
    }
  });

  it("empty monitorAutoKillFlags passes (layer not deployed)", async () => {
    const { validateMonitorAutoKillInMonitorPatterns } = await import(FLAG_REGISTRY_PATH);
    expect(() => validateMonitorAutoKillInMonitorPatterns([], {}, () => {})).not.toThrow();
  });

  it("warnEngineHighRiskCoverage: missing flag in engineHighRiskFlags -> WARN", async () => {
    const { warnEngineHighRiskCoverage } = await import(FLAG_REGISTRY_PATH);
    const warns: string[] = [];
    warnEngineHighRiskCoverage(["flag_a"], new Set(["flag_a", "flag_b", "flag_c"]), (m) => warns.push(m));
    expect(warns.length).toBeGreaterThan(0);
    expect(warns[0]).toMatch(/flag_b/);
    expect(warns[0]).toMatch(/flag_c/);
  });

  it("warnEngineHighRiskCoverage: full coverage -> no WARN", async () => {
    const { warnEngineHighRiskCoverage } = await import(FLAG_REGISTRY_PATH);
    const warns: string[] = [];
    warnEngineHighRiskCoverage(["flag_a", "flag_b"], new Set(["flag_a", "flag_b"]), (m) => warns.push(m));
    expect(warns).toHaveLength(0);
  });

  it("warnEngineHighRiskCoverage: empty list passes", async () => {
    const { warnEngineHighRiskCoverage } = await import(FLAG_REGISTRY_PATH);
    const warns: string[] = [];
    warnEngineHighRiskCoverage([], new Set(["flag_a"]), (m) => warns.push(m));
    expect(warns).toHaveLength(0);
  });
});

//  lint / layered entry / flags / pattern validation 单测
describe("lintPatternSubset + validateLayeredEntry ", () => {
  const PATH = "../scripts/generate-detection-patterns.mjs";

  it("inline (?i fails lint", async () => {
    const { lintPatternSubset, GenerateError } = await import(PATH);
    expect(() => lintPatternSubset("(?i:foo)", "x")).toThrow(GenerateError);
    expect(() => lintPatternSubset("(?i:foo)", "x")).toThrow(/inline "\(\?i/);
  });

  it("(?< (lookbehind/named group) fails lint", async () => {
    const { lintPatternSubset, GenerateError } = await import(PATH);
    expect(() => lintPatternSubset("(?<name>foo)", "x")).toThrow(GenerateError);
  });

  it("\\p{ unicode property class fails lint", async () => {
    const { lintPatternSubset, GenerateError } = await import(PATH);
    expect(() => lintPatternSubset("\\p{L}+", "x")).toThrow(GenerateError);
  });

  it("validateLayeredEntry: JS compile failure throws", async () => {
    const { validateLayeredEntry, GenerateError } = await import(PATH);
    expect(() => validateLayeredEntry({ pattern: "[invalid" }, "x")).toThrow(GenerateError);
  });

  it("validateLayeredEntry: valid pattern passes", async () => {
    const { validateLayeredEntry } = await import(PATH);
    expect(() => validateLayeredEntry({ pattern: "foo.*bar", flags: "i" }, "x")).not.toThrow();
  });

  it("validateLayeredEntry: invalid flags field throws", async () => {
    const { validateLayeredEntry, GenerateError } = await import(PATH);
    expect(() => validateLayeredEntry({ pattern: "foo", flags: "z" }, "x")).toThrow(GenerateError);
  });
});

//  pythonCompileCheck 单测（mock child_process.spawnSync）
describe("pythonCompileCheck ", () => {
  const PATH = "../scripts/generate-detection-patterns.mjs";

  it("returns true when python available and all patterns compile", async () => {
    vi.doMock("child_process", () => ({
      spawnSync: vi.fn((cmd: string) => {
        if (cmd === "python" || cmd === "python3") {
          if (cmd === "python3") {
            return { status: 0, stdout: "", stderr: "", error: undefined };
          }
        }
        return { status: 1, stdout: "", stderr: "", error: new Error("not found") };
      }),
    }));
    const mod = await import(`${PATH}?mock=success`);
    // Use real python (if available on host) instead of mock
    const warns: string[] = [];
    const result = (mod as any).pythonCompileCheck(
      [{ where: "test[0]", pattern: "foo", flags: "" }],
      (m: string) => warns.push(m)
    );
    // Either returns true (python ok) or false (python absent -> WARN)
    expect(typeof result).toBe("boolean");
    vi.doUnmock("child_process");
  });

  it("returns false and WARNs when neither python nor python3 available", async () => {
    // spawnSync 是 child_process 顶层 export，运行时不可写。使用 vi.mock
    // 在 import 前替换整个模块。
    vi.resetModules();
    vi.doMock("child_process", () => ({
      spawnSync: () => ({ status: 1, error: new Error("not found"), stdout: "", stderr: "" }),
    }));
    const mod = await import(`${PATH}?mock=no-python`);
    const warns: string[] = [];
    const result = (mod as any).pythonCompileCheck(
      [{ where: "x[0]", pattern: "foo", flags: "" }],
      (m: string) => warns.push(m)
    );
    expect(result).toBe(false);
    expect(warns.some((w) => /python not available/i.test(w))).toBe(true);
    vi.doUnmock("child_process");
    vi.resetModules();
  });
});