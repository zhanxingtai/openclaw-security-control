import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, readdirSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { renameSync } from "fs";
import { PLUGIN_ID, ensureHostPluginEntryDefaults } from "./initialize.js";

// renameSync is overridden per-test to simulate an atomic-rename failure;
// every other export stays the real builtin.
vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return { ...actual, renameSync: vi.fn(actual.renameSync) };
});

/**
 * When the host has only written
 * `plugins.entries[PLUGIN_ID] = { enabled: true }` (the shape produced on a
 * brand-new install), the bootstrap must still create the
 * `hooks` / `llm` / `subagent` sub-objects and land the four permission
 * defaults inside them. Earlier the helper treated undefined intermediates
 * as "skip" and silently wrote nothing, leaving the UI showing blocked.
 */
describe("ensureHostPluginEntryDefaults", () => {
  let dir: string;
  let target: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "openclaw-bootstrap-"));
    target = path.join(dir, "openclaw.json");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("seeds all four defaults when only enabled:true is present (brand-new install)", () => {
    writeFileSync(
      target,
      JSON.stringify({ plugins: { entries: { [PLUGIN_ID]: { enabled: true } } } })
    );
    const written = ensureHostPluginEntryDefaults(target);
    expect(written).toBe(true);
    const next = JSON.parse(readFileSync(target, "utf8"));
    const entry = next.plugins.entries[PLUGIN_ID];
    expect(entry.enabled).toBe(true);
    expect(entry.hooks.allowConversationAccess).toBe(true);
    expect(entry.hooks.allowPromptInjection).toBe(true);
    expect(entry.llm.allowModelOverride).toBe(true);
    expect(entry.subagent.allowModelOverride).toBe(true);
  });

  it("is idempotent on a second invocation", () => {
    writeFileSync(
      target,
      JSON.stringify({ plugins: { entries: { [PLUGIN_ID]: { enabled: true } } } })
    );
    expect(ensureHostPluginEntryDefaults(target)).toBe(true);
    expect(ensureHostPluginEntryDefaults(target)).toBe(false);
  });

  it("preserves user-supplied false values (does not overwrite)", () => {
    writeFileSync(
      target,
      JSON.stringify({
        plugins: {
          entries: {
            [PLUGIN_ID]: {
              enabled: true,
              hooks: { allowConversationAccess: false },
            },
          },
        },
      })
    );
    expect(ensureHostPluginEntryDefaults(target)).toBe(true);
    const next = JSON.parse(readFileSync(target, "utf8"));
    expect(next.plugins.entries[PLUGIN_ID].hooks.allowConversationAccess).toBe(false);
    // the other three still default to true
    expect(next.plugins.entries[PLUGIN_ID].hooks.allowPromptInjection).toBe(true);
    expect(next.plugins.entries[PLUGIN_ID].llm.allowModelOverride).toBe(true);
    expect(next.plugins.entries[PLUGIN_ID].subagent.allowModelOverride).toBe(true);
  });

  it("skips a slot that is a non-object (user-shaped config)", () => {
    writeFileSync(
      target,
      JSON.stringify({
        plugins: {
          entries: {
            [PLUGIN_ID]: { enabled: true, hooks: "custom-string" },
          },
        },
      })
    );
    expect(ensureHostPluginEntryDefaults(target)).toBe(true);
    const next = JSON.parse(readFileSync(target, "utf8"));
    // hooks preserved as the user's scalar string
    expect(next.plugins.entries[PLUGIN_ID].hooks).toBe("custom-string");
    // but llm / subagent still seeded
    expect(next.plugins.entries[PLUGIN_ID].llm.allowModelOverride).toBe(true);
    expect(next.plugins.entries[PLUGIN_ID].subagent.allowModelOverride).toBe(true);
  });

  it("returns false and writes nothing when config file is missing JSON object", () => {
    writeFileSync(target, "[1, 2, 3]");
    expect(ensureHostPluginEntryDefaults(target)).toBe(false);
  });

  it("creates the file from scratch when it does not exist", () => {
    const result = ensureHostPluginEntryDefaults(target);
    expect(result).toBe(true);
    const next = JSON.parse(readFileSync(target, "utf8"));
    expect(next.plugins.entries[PLUGIN_ID].hooks.allowConversationAccess).toBe(true);
  });

  it("cleans up the tmp file when atomic rename fails", () => {
    writeFileSync(
      target,
      JSON.stringify({ plugins: { entries: { [PLUGIN_ID]: { enabled: true } } } })
    );
    vi.mocked(renameSync).mockImplementationOnce(() => {
      throw new Error("EACCES: simulated rename failure");
    });
    const result = ensureHostPluginEntryDefaults(target);
    expect(result).toBe(false);
    // the stale `${target}.${pid}.${ts}.tmp` must not linger next to the config
    const leftovers = readdirSync(dir).filter((f) => f.endsWith(".tmp"));
    expect(leftovers).toEqual([]);
  });
});
