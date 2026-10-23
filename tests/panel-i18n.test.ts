import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "http";
import path from "path";
import vm from "node:vm";
import { mkdtempSync, rmSync, copyFileSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import type { AddressInfo } from "net";
import plugin, { CONFIG_SCHEMA, PLUGIN_ID } from "../index.js";
import {
  HTML_LANG,
  LOCALES,
  PANEL_DICT,
  RAW_FALLBACK_PREFIXES,
  normalizePanelLocalePreference,
  parseLocale,
  serializeDictionary,
  translate,
  type Locale,
} from "../src/panel-i18n.js";

/**
 * 面板 i18n 回归。
 *
 * 覆盖四类验收：
 *   1. 两种语言的词典 key 集合完全相等、无空值、占位符两边一致；
 *   2. locale 解析（?lang= → 已保存偏好 → Accept-Language → 默认 en）表驱动；
 *   3. `?lang=en` 的可见文案零 CJK；
 *   4. 未知枚举值回落到原始标识符（后端新增 decision/severity 时既不显示空白，
 *      也不显示 `decision.degrade` 这种带前缀的内部键）。
 *
 * 另外钉住三件容易悄悄回归的事：CONFIG_SCHEMA 每个字段都在词典里有词条
 * （否则 Config 页会直接把 `cfg.label.…` 显示给用户）、服务端 translate() 与面板
 * `<script>` 里的 T() 对每个键结果一致（那本来就是两份实现）、以及面板内联的回落
 * 前缀表与 src/panel-i18n.ts 的常量一致。
 *
 * 右上角那对 EN / 中文 开关另有一段：它在两种语言下形状必须一致（endonym，
 * 语言名不翻译），aria-pressed 必须跟着实际解析出的语言走，写下的偏好必须
 * **不重启 gateway** 就生效，而且必须**不写宿主 openclaw.json** —— 写它会让
 * gateway 重载全部插件，实测一次语言切换要 8.4 秒才看得见效果。
 */

interface RouteRec {
  auth: string;
  handler: (req: unknown, res: unknown) => void;
}

function createFakeApi() {
  const httpRoutes = new Map<string, RouteRec>();
  const gatewayMethods = new Map<string, (params: unknown) => unknown>();
  const api = {
    pluginConfig: {},
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    on: () => {},
    registerHook: () => {},
    registerGatewayMethod: (name: string, handler: (params: unknown) => unknown) =>
      gatewayMethods.set(name, handler),
    registerHttpRoute: (route: RouteRec & { path: string }) => httpRoutes.set(route.path, route),
    runtime: { registerRuntimeLifecycle: () => {} },
  };
  return { api, httpRoutes, gatewayMethods };
}

/** Unlike the harness in panel-auth-rce.test.ts this keeps the query string —
 *  `?lang=` is the whole point of this file. */
function request(
  base: string,
  opts: { method?: string; path?: string; headers?: Record<string, string> } = {}
) {
  return new Promise<{ status: number; body: string; headers: Record<string, unknown> }>((resolve, reject) => {
    const u = new URL(base);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: opts.path ?? "/openclaw-security-monitor/panel",
        method: opts.method ?? "GET",
        headers: opts.headers ?? {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: res.headers as Record<string, unknown>,
          })
        );
      }
    );
    req.on("error", reject);
    req.end();
  });
}

/** The text an operator can actually see.
 *
 *  Drops <script> (code + the inlined dictionary), <style> (CSS, including its
 *  Chinese *comments*) and HTML comments (also Chinese, also never rendered).
 *  Those three are source text, not copy — no browser paints them. Leaving them
 *  in would turn this assertion into a proxy for "have the maintainers finished
 *  translating code comments", which is a different task. */
function visibleCopy(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/g, "")
    .replace(/<style[\s\S]*?<\/style>/g, "")
    // 语言切换控件整体剔除后再查 CJK。控件里的 "中文" 是语言 endonym，不是
    // 未翻译的中文文案——Chrome / VS Code / macOS 的语言选择器在英文界面下
    // 同样显示本族语言名。要盯的是"英文界面漏了中文句子"，不是语言名本身。
    // 控件自身由 "the header language switcher renders identically in both
    // locales" 一条单独钉住。
    .replace(/<div class="langswitch"[\s\S]*?<\/div>/g, "")
    .replace(/<!--[\s\S]*?-->/g, "");
}

const CJK_RE = /[一-鿿]/g;
const cjkIn = (s: string): string[] => s.match(CJK_RE) ?? [];

describe("panel i18n dictionary", () => {
  it("both locales carry the exact same key set", () => {
    const en = Object.keys(PANEL_DICT.en).sort();
    const zh = Object.keys(PANEL_DICT.zh).sort();
    expect(zh).toEqual(en);
    // Guard against the suite passing on an empty dictionary.
    expect(en.length).toBeGreaterThan(100);
  });

  it("no locale has an empty or whitespace-only value", () => {
    for (const locale of LOCALES) {
      const empty = Object.entries(PANEL_DICT[locale])
        .filter(([, v]) => typeof v !== "string" || v.trim() === "")
        .map(([k]) => k);
      expect(empty, `${locale} has empty values`).toEqual([]);
    }
  });

  it("the en dictionary contains no CJK", () => {
    expect(cjkIn(Object.values(PANEL_DICT.en).join(""))).toEqual([]);
  });

  it("every {placeholder} is one the panel actually interpolates", () => {
    // An unfilled token renders literally as "Showing {shown} of {total}", so
    // the allowed set is pinned rather than wildcarded.
    //
    // preloadTarget comes from src/hook-locations.ts and reaches the prose
    // through ConfigField.helpVars (see withRuntimeHelpVars); hookPath rides on
    // security.status. They are listed here because the panel render path is
    // covered by the security.config.get test below — that one asserts every
    // placeholder the help text uses actually has a value bound to it.
    const allowed = new Set([
      "shown", "total", "mark", "unit", "n", "version", "deps", "path", "time", "url",
      "preloadTarget", "hookPath",
    ]);
    for (const locale of LOCALES) {
      for (const [key, value] of Object.entries(PANEL_DICT[locale])) {
        for (const token of value.matchAll(/\{(\w+)\}/g)) {
          expect(allowed.has(token[1]), `${locale} ${key} has unknown placeholder {${token[1]}}`).toBe(true);
        }
      }
    }
  });

  it("both locales fill the same placeholders for the same key", () => {
    // If zh and en disagreed about which tokens a key takes, one side would
    // leak a literal brace at runtime.
    const tokensOf = (dict: Record<string, string>, key: string) =>
      [...dict[key].matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const key of Object.keys(PANEL_DICT.en)) {
      expect(tokensOf(PANEL_DICT.zh, key), `${key} placeholder mismatch`).toEqual(tokensOf(PANEL_DICT.en, key));
    }
  });

  it("CONFIG_SCHEMA stores dictionary keys and every one resolves in both locales", () => {
    for (const f of CONFIG_SCHEMA) {
      expect(f.label, `${f.section}.${f.key}: label must be a cfg.label.* key`).toBe(
        `cfg.label.${f.section}.${f.key}`
      );
      // `danger` is the boolean flag; the localized text lives in dangerReason.
      for (const kind of ["help", "dangerReason"] as const) {
        const value = f[kind];
        if (value === undefined) continue;
        const family = kind === "help" ? "help" : "danger";
        expect(value, `${f.section}.${f.key} ${kind} must be cfg.${family}.${f.section}.${f.key}`).toBe(
          `cfg.${family}.${f.section}.${f.key}`
        );
      }
      for (const key of [f.label, f.help, f.dangerReason]) {
        if (!key) continue;
        for (const locale of LOCALES) {
          const resolved = translate(locale, key);
          expect(resolved.trim(), `${locale} ${key} resolved to nothing`).not.toBe("");
          expect(resolved, `${locale} ${key} fell through to the raw key`).not.toBe(key);
        }
      }
    }
  });

  it("the three cfg text families keep the documented counts", () => {
    const keys = Object.keys(PANEL_DICT.en);
    // 34/13/16 为既定基线；application.panelLocale（label + help）各 +1。
    expect(keys.filter((k) => k.startsWith("cfg.label."))).toHaveLength(35);
    expect(keys.filter((k) => k.startsWith("cfg.help."))).toHaveLength(14);
    expect(keys.filter((k) => k.startsWith("cfg.danger."))).toHaveLength(16);
  });

  it("serializeDictionary neutralises '<' so a value cannot close the script tag", () => {
    for (const locale of LOCALES) {
      expect(serializeDictionary(locale)).not.toContain("<");
      expect(JSON.parse(serializeDictionary(locale))).toEqual(PANEL_DICT[locale]);
    }
  });
});

describe("parseLocale", () => {
  const cases: Array<[string, string | undefined, string | undefined, Locale]> = [
    ["no query, no header → en", undefined, undefined, "en"],
    ["?lang=zh", "/p?lang=zh", undefined, "zh"],
    ["?lang=en", "/p?lang=en", undefined, "en"],
    ["?lang=zh-CN collapses to zh", "/p?lang=zh-CN", undefined, "zh"],
    ["?lang=zh-Hans collapses to zh", "/p?lang=zh-Hans", undefined, "zh"],
    ["?lang is case-insensitive", "/p?lang=ZH-hans", undefined, "zh"],
    ["?lang is not the only query param", "/p?a=1&lang=zh-CN&b=2", undefined, "zh"],
    ["unsupported ?lang=fr → en", "/p?lang=fr", undefined, "en"],
    ["empty ?lang= → en", "/p?lang=", undefined, "en"],
    ["unsupported ?lang does NOT defer to Accept-Language", "/p?lang=fr", "zh-CN,zh;q=0.9", "en"],
    ["?lang wins over Accept-Language", "/p?lang=en", "zh-CN,zh;q=0.9", "en"],
    ["Accept-Language zh-CN,zh;q=0.9", "/p", "zh-CN,zh;q=0.9", "zh"],
    ["Accept-Language zh", "/p", "zh", "zh"],
    ["Accept-Language en-GB,en;q=0.9", "/p", "en-GB,en;q=0.9", "en"],
    ["Accept-Language fr → en", "/p", "fr", "en"],
    ["Accept-Language skips q=0 entries", "/p", "fr;q=0, zh;q=0.8", "zh"],
    ["Accept-Language empty string → en", "/p", "", "en"],
    ["Accept-Language prefers the highest-weighted tag", "/p", "de;q=0.9, zh;q=0.8", "zh"],
  ];

  it.each(cases)("%s", (_name, url, acceptLanguage, expected) => {
    expect(parseLocale(url, acceptLanguage)).toBe(expected);
  });

  // 面板右上角的语言开关把选择写进 application.panelLocale。三段的顺序不能
  // 随便挪：?lang= 必须仍然独占（书签 / 外链要能钉住语言），已保存的偏好必须
  // 压过 Accept-Language（否则点了"中文"却因为浏览器首选 en 又弹回英文），
  // 而 "auto" 必须真的什么都不做，否则等于给"跟随浏览器"关掉了后门。
  const saved: Array<[string, string | undefined, string | undefined, unknown, Locale]> = [
    ["saved zh pins a French browser to zh", "/p", "fr", "zh", "zh"],
    ["saved en pins a Chinese browser to en", "/p", "zh-CN,zh;q=0.9", "en", "en"],
    ["saved auto keeps Accept-Language negotiation", "/p", "zh-CN,zh;q=0.9", "auto", "zh"],
    ["saved auto with no header → en", "/p", undefined, "auto", "en"],
    ["?lang= still beats a saved zh", "/p?lang=en", "zh-CN,zh;q=0.9", "zh", "en"],
    ["?lang= still beats a saved en", "/p?lang=zh", "en-GB,en;q=0.9", "en", "zh"],
    ["unsupported ?lang= falls back to en, not to the saved value", "/p?lang=fr", "zh-CN", "zh", "en"],
    ["garbage saved value degrades to auto", "/p", "zh-CN", "zh-CN", "zh"],
    ["non-string saved value degrades to auto", "/p", "zh-CN", { zh: true }, "zh"],
    ["undefined saved value is auto", "/p", "zh-CN", undefined, "zh"],
  ];

  it.each(saved)("%s", (_name, url, acceptLanguage, preference, expected) => {
    expect(parseLocale(url, acceptLanguage, preference)).toBe(expected);
  });
});

describe("normalizePanelLocalePreference", () => {
  it.each([
    ["auto", "auto"],
    ["en", "en"],
    ["zh", "zh"],
  ])("passes %s through", (input, expected) => {
    expect(normalizePanelLocalePreference(input)).toBe(expected);
  });

  // openclaw.json 是手改的：写错成 "zh-CN" / "EN" / 漏引号都会到这层。与其把
  // 非法值透传给 parseLocale 让它悄悄回落到 en（表现为"我明明选了中文"），
  // 不如统一折成 auto——至少和从没配过是同一种行为。
  it.each([
    ["uppercase EN", "EN"],
    ["region-qualified zh-CN", "zh-CN"],
    ["empty string", ""],
    ["null", null],
    ["undefined", undefined],
    ["number", 3],
    ["boolean", true],
    ["object", { locale: "zh" }],
    ["array", ["zh"]],
  ])("folds %s to auto", (_name, input) => {
    expect(normalizePanelLocalePreference(input)).toBe("auto");
  });
});

describe("panel HTML served per locale", () => {
  let tmpDir: string;
  let server: http.Server;
  let base: string;
  /** Captured from createFakeApi so the switcher test can drive the real RPC
   *  instead of a mock — the client-side test only proves the envelope shape. */
  let gatewayMethods: Map<string, (params: unknown) => unknown>;
  const savedEnv = process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;

  beforeAll(async () => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "panel-i18n-"));
    const hostConfigPath = path.join(tmpDir, "openclaw.json");
    writeFileSync(hostConfigPath, "{}", "utf8");
    process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = hostConfigPath;

    const policyPath = path.join(tmpDir, "security-policy.yaml");
    copyFileSync(path.join(process.cwd(), "policies", "security-policy.spl.yaml"), policyPath);

    const { api, httpRoutes, gatewayMethods: methods } = createFakeApi();
    gatewayMethods = methods;
    (api as { pluginConfig: Record<string, unknown> }).pluginConfig = {
      collector: { ndjsonPath: path.join(tmpDir, "events.jsonl") },
      application: { enabled: false },
      network: { enabled: false },
      system: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: true, policyPath },
    };
    plugin.register(api as never);

    server = http.createServer((req, res) => {
      const route = httpRoutes.get((req.url ?? "").split("?")[0]);
      if (!route) {
        res.statusCode = 404;
        res.end("not found");
        return;
      }
      route.handler(req, res as never);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 30000);

  afterAll(async () => {
    server?.close();
    if (savedEnv === undefined) delete process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
    else process.env.OPENCLAW_EXTERNAL_CONFIG_PATH = savedEnv;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  const getPanel = (opts: { path?: string; headers?: Record<string, string> } = {}) => request(base, opts);

  function makeEl(id: string, handlers: Map<string, (e: unknown) => void>) {
    return {
      id,
      style: {} as Record<string, string>,
      dataset: {} as Record<string, string>,
      innerHTML: "",
      textContent: "",
      className: "",
      disabled: false,
      checked: false,
      value: "",
      onclick: undefined as unknown,
      addEventListener(type: string, fn: (e: unknown) => void) {
        handlers.set(`${id}:${type}`, fn);
      },
      appendChild(child: { innerHTML: string }) {
        this.innerHTML += child.innerHTML;
      },
      // Collapse the append positions to a plain innerHTML append so the
      // skeleton+rows split (Events / Policy Hits) is observable.
      insertAdjacentHTML(_pos: string, html: string) {
        this.innerHTML += html;
      },
      setAttribute() {},
      getAttribute() {
        return null;
      },
      closest() {
        return null;
      },
      querySelector() {
        return null;
      },
      querySelectorAll() {
        return [];
      },
      focus() {},
    };
  }

  /** Just the i18n prologue of the panel script — enough to exercise the
   *  client-side translator without booting the whole UI. The slice starts at
   *  `var I18N` (not at byte 0, which would open the panel's IIFE and never
   *  close it) and ends where the rest of the panel begins. */
  function i18nContext(html: string): vm.Context {
    const scriptSrc = html.match(/<script>([\s\S]*?)<\/script>/)![1];
    const start = scriptSrc.indexOf("var I18N =");
    const cut = scriptSrc.indexOf("// OpenClaw 9.4 hosts this panel inside a sandboxed iframe");
    expect(start, "i18n block not found in the panel script").toBeGreaterThan(0);
    expect(cut, "end-of-i18n marker not found in the panel script").toBeGreaterThan(start);
    const ctx = vm.createContext({});
    vm.runInContext(scriptSrc.slice(start, cut), ctx);
    return ctx;
  }

  function runPanel(
    html: string,
    respond: (method: string) => unknown,
    opts: {
      /** Boot the header language switcher as if it were on screen. Omitted →
       *  #langswitch stays an ordinary stub and the widget stays inert, which
       *  is what every other test in this file wants. */
      langSwitch?: { current: string; search?: string };
      /** Reject this RPC the way a CORS-blocked response does: fetch() itself
       *  throws TypeError("Failed to fetch") and the caller never sees a
       *  status. That is the shape of the real failure. */
      failRpc?: string;
      /** With failRpc: succeed the first call, then fail. */
      failAfterFirst?: boolean;
      /** Hand this RPC back as {ok:false,...} with HTTP 200 — a server-side
       *  refusal (bad argument, unwritable file), not a transport failure. */
      refuseRpc?: { method: string; message: string };
    } = {},
  ) {
    const handlers = new Map<string, (e: unknown) => void>();
    const els = new Map<string, ReturnType<typeof makeEl>>();
    const calls: string[] = [];
    let rpcCallsSoFar = 0;
    /** Full rpc() envelopes, not just method names — the switcher's patch
     *  shape is the thing under test. */
    const rpcBodies: Array<Record<string, unknown>> = [];
    /** Every fetch init the panel issued, with the AbortSignal it carried. */
    const fetchInits: Array<{ method: string; signal: unknown }> = [];
    let reloads = 0;
    let replaceUrl: string | null = null;

    // The switcher's buttons are the only nodes in the panel whose *identity*
    // matters: wireLangSwitch reads data-lang off them and the click handler
    // writes .disabled back. The uniform stub's getAttribute() returns null for
    // everything, which would make querySelectorAll("button") look empty and
    // the widget silently no-op — so it gets hand-built nodes.
    const langButtons: Array<{
      lang: string;
      disabled: boolean;
      handler?: (e: unknown) => void;
      node: unknown;
    }> = opts.langSwitch
      ? (["en", "zh"] as const).map((lang) => {
          const rec: { lang: string; disabled: boolean; handler?: (e: unknown) => void; node?: unknown } = {
            lang,
            disabled: false,
          };
          rec.node = {
            getAttribute: (name: string) => (name === "data-lang" ? rec.lang : null),
            addEventListener: (_type: string, fn: (e: unknown) => void) => {
              rec.handler = fn;
            },
            get disabled() {
              return rec.disabled;
            },
            set disabled(v: boolean) {
              rec.disabled = v;
            },
          };
          return rec as { lang: string; disabled: boolean; handler?: (e: unknown) => void; node: unknown };
        })
      : [];
    const langSwitchEl = opts.langSwitch
      ? {
          id: "langswitch",
          getAttribute: (name: string) => (name === "data-current" ? opts.langSwitch!.current : null),
          querySelectorAll: () => langButtons.map((b) => b.node),
        }
      : null;

    const getEl = (id: string) => {
      if (id === "langswitch" && langSwitchEl) return langSwitchEl as unknown as ReturnType<typeof makeEl>;
      if (!els.has(id)) els.set(id, makeEl(id, handlers));
      return els.get(id)!;
    };
    const sandbox: Record<string, unknown> = {
      console,
      setTimeout,
      clearTimeout,
      setInterval: () => 0,
      clearInterval: () => {},
      fetch: async (_url: string, fetchOpts: { body: string; signal?: unknown }) => {
        const parsed = JSON.parse(fetchOpts.body) as { method: string };
        calls.push(parsed.method);
        rpcBodies.push(parsed as unknown as Record<string, unknown>);
        // 每一次 fetch 的 init 都要留下：RELOAD_SETTLE 的探询与普通 rpc() 走
        // 同一个 fetch，靠 signal 是否存在就能断言"探询自带超时"。
        fetchInits.push({ method: parsed.method, signal: fetchOpts.signal });
        if (opts.failRpc === parsed.method || opts.failRpc === "*") {
          // failAfterFirst：先成功一次、再失败。用来模拟"用着用着 session 过期"
          // ——面板 rpc() 里 rpcEverOk 判的就是这个信号。
          if (!(opts.failAfterFirst && rpcCallsSoFar++ > 0)) throw new TypeError("Failed to fetch");
        }
        const refusal = opts.refuseRpc?.method === parsed.method ? opts.refuseRpc.message : null;
        return {
          ok: true,
          status: 200,
          json: async () => ({ ok: true, payload: refusal ? { ok: false, error: { message: refusal } } : respond(parsed.method) }),
          text: async () => "",
        };
      },
      alert: () => {},
      AbortController,
      document: undefined as unknown,
      navigator: {},
      // `search` matters to the switcher: it strips ?lang= before reloading so
      // the URL can't out-rank the choice the user just made.
      location: {
        search: opts.langSwitch?.search ?? "",
        pathname: "/openclaw-security-monitor/panel",
        hash: "",
        reload: () => {
          reloads += 1;
        },
      },
      history: {
        replaceState: (_a: unknown, _b: unknown, url: string) => {
          replaceUrl = url;
        },
      },
    };
    sandbox.window = sandbox;
    sandbox.top = sandbox;
    sandbox.self = sandbox;
    sandbox.document = {
      readyState: "complete",
      body: makeEl("body", handlers),
      getElementById: getEl,
      querySelector: (sel: string) => (sel.includes("ocm-panel-nonce") ? { content: "NONCE" } : null),
      querySelectorAll: () => [],
      addEventListener: (type: string, fn: (e: unknown) => void) => handlers.set(`doc:${type}`, fn),
      createElement: () => makeEl(`dyn-${calls.length}`, handlers),
    };
    vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)![1], vm.createContext(sandbox));
    return {
      els,
      calls,
      rpcBodies,
      fetchInits,
      langButtons,
      reloadCount: () => reloads,
      replacedUrl: () => replaceUrl,
      /** Wait out the post-save settle window.
       *
       *  A language click writes the *host's* openclaw.json, after which the
       *  host reloads plugin config: for a few seconds every plugin route
       *  answers 500 with no CORS headers, so the panel cannot tell "the
       *  gateway is mid-reload" from "the request failed". Navigating inside
       *  that window lands the operator on a raw 500 page, so the switcher
       *  polls the route until it answers readably and *then* reloads. Poll
       *  for the reload here instead of hardcoding the streak length. */
      waitForReload: async (timeoutMs = 12000) => {
        const deadline = Date.now() + timeoutMs;
        while (reloads === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      },
      clickLang: async (lang: string) => {
        const btn = langButtons.find((b) => b.lang === lang);
        expect(btn, `no ${lang} button — did the switcher render two?`).toBeTruthy();
        expect(btn!.handler, `${lang} button never registered a click handler`).toBeTruthy();
        // 事件对象在派发结束后 currentTarget 被浏览器置空（规范如此）。这里照做，
        // 否则 mock 会让 event.currentTarget 在异步回调里仍然有值，把真实
        // 浏览器里的那个 TypeError 悄悄放过去——那条 bug 就是靠这个空值
        // 把"恢复可点"吃掉的。
        const ev: { currentTarget: unknown } = { currentTarget: btn!.node };
        btn!.handler!(ev);
        ev.currentTarget = null;
        // rpc() is a promise chain; the reload lands in its .then().
        await new Promise((r) => setTimeout(r, 40));
      },
      clickTab: async (tab: string) => {
        // Let the load-time Metrics render settle first. Its .then() writes
        // #panel.innerHTML, and a tab click issued before it lands would be
        // silently overwritten (the mock uses plain string assignment, so the
        // race shows up as the previous tab's HTML).
        await new Promise((r) => setTimeout(r, 40));
        handlers.get("tabs:click")!({
          target: {
            closest: (sel: string) =>
              sel === ".tab" ? { classList: { add() {}, remove() {} }, dataset: { tab } } : null,
          },
        });
        await new Promise((r) => setTimeout(r, 40));
      },
    };
  }

  // ── Locale negotiation over real HTTP ────────────────────────────────

  it('defaults to English: <html lang="en"> and zero CJK in visible copy', async () => {
    const res = await getPanel();
    expect(res.status).toBe(200);
    expect(res.body).toContain('<html lang="en">');
    expect(cjkIn(visibleCopy(res.body)), "the default panel must render no CJK").toEqual([]);
  });

  it('?lang=zh yields <html lang="zh-CN"> and the four Chinese tab labels', async () => {
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    expect(res.status).toBe(200);
    expect(res.body).toContain('<html lang="zh-CN">');
    for (const [tab, label] of [
      ["metrics", "统计"],
      ["events", "事件"],
      ["blocks", "威胁"],
      ["config", "配置"],
    ] as const) {
      expect(res.body, `zh tab ${tab}`).toContain(`data-tab="${tab}">${label}<`);
    }
    expect(visibleCopy(res.body), "English tab labels must be gone").not.toContain(">Policy Hits</button>");
  });

  it("Accept-Language: zh-CN,zh;q=0.9 with no ?lang= yields the Chinese panel", async () => {
    const res = await getPanel({ headers: { "Accept-Language": "zh-CN,zh;q=0.9" } });
    expect(res.body).toContain('<html lang="zh-CN">');
    expect(res.body).toContain('data-tab="metrics">统计<');
  });

  it("?lang=fr and Accept-Language: fr both yield the English panel", async () => {
    const explicit = await getPanel({ path: "/openclaw-security-monitor/panel?lang=fr" });
    expect(explicit.status).toBe(200);
    expect(explicit.body).toContain('<html lang="en">');
    expect(cjkIn(visibleCopy(explicit.body))).toEqual([]);
    const header = await getPanel({ headers: { "Accept-Language": "fr" } });
    expect(header.body).toContain('<html lang="en">');
  });

  it("HTML_LANG agrees with the lang attribute on the page it is asked for", async () => {
    for (const locale of LOCALES) {
      const res = await getPanel({ path: `/openclaw-security-monitor/panel?lang=${locale}` });
      expect(res.body).toContain(`<html lang="${HTML_LANG[locale]}">`);
    }
  });

  it("ships only the active locale's dictionary", async () => {
    const en = await getPanel();
    const zh = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    // Inlining both would double the page weight and leave an unused copy of
    // the other language sitting in every response.
    expect(en.body).not.toContain("捕获用户 Prompt");
    expect(zh.body).not.toContain("Capture user prompts");
  });

  it("inlines the same raw-fallback prefix list as src/panel-i18n.ts", async () => {
    const res = await getPanel();
    const inlined = res.body.match(/var RAW_PREFIXES = (\[.*?\]);/)?.[1];
    expect(inlined).toBeTruthy();
    expect(JSON.parse(inlined!)).toEqual([...RAW_FALLBACK_PREFIXES]);
  });

  it("runtimeHooks help text carries the real preload path, not a hard-coded one", async () => {
    // 回归：帮助文案曾把 NODE_OPTIONS 路径写死成
    // `.../extensions/<id>/runtime.js` —— 那条路径既不在安装包清单里（是插件
    // 每次启动现拷进去的），在宿主机直装下也压根不是那个 home。改由
    // src/hook-locations.ts 在请求时解析并经 helpVars 下发。
    const result = (await gatewayMethods.get("security.config.get")?.({})) as {
      schema: Array<{ section: string; key: string; help?: string; helpVars?: Record<string, string> }>;
    };
    const field = result.schema.find(
      (f) => f.section === "application" && f.key === "runtimeHooks.enabled"
    );
    expect(field).toBeDefined();
    expect(field!.help).toBe("cfg.help.application.runtimeHooks.enabled");

    // 文案里用到的每个占位符都必须有值，否则面板会把它原样印出来。
    const placeholders = new Set(
      [...PANEL_DICT.en[field!.help!].matchAll(/\{(\w+)\}/g)].map((m) => m[1])
    );
    expect(placeholders.size).toBeGreaterThan(0);
    for (const name of placeholders) {
      expect(field!.helpVars?.[name], `helpVars 缺 ${name}`).toBeTruthy();
    }

    // 两种 locale 都不得残留未填充的占位符，且必须包含当前机器解析出的路径。
    for (const locale of LOCALES) {
      const rendered = translate(locale, field!.help!, field!.helpVars);
      expect(rendered, `${locale} 残留未填充占位符`).not.toMatch(/\{\w+\}/);
      expect(rendered, `${locale} 未包含预加载路径`).toContain(field!.helpVars!.preloadTarget);
    }
  });

  it("keeps exactly one script block, and it parses", async () => {
    // panel-auth-rce.test.ts extracts the panel with a non-greedy first-match
    // regex. A second inline block would be the one picked up and the panel
    // logic would silently stop executing under the vm harness.
    const res = await getPanel();
    expect(res.body.match(/<script>/g)).toHaveLength(1);
    const scriptSrc = res.body.match(/<script>([\s\S]*?)<\/script>/)![1];
    expect(scriptSrc).toContain("var I18N =");
    expect(scriptSrc).toContain("function T(key, vars)");
    expect(() => new vm.Script(scriptSrc)).not.toThrow();
  });

  // ── Client-side T(): the browser half of the same dictionary ──────────

  it("client T() agrees with the server-side translate() on every key", async () => {
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const ctx = i18nContext(res.body);
    for (const key of Object.keys(PANEL_DICT.zh)) {
      expect(vm.runInContext(`T(${JSON.stringify(key)})`, ctx), `zh ${key} diverges`).toBe(
        translate("zh", key)
      );
    }
  });

  it("client T() interpolates placeholders the same way", async () => {
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const ctx = i18nContext(res.body);
    const vars = { shown: 1, total: 9, mark: "+", unit: "events" };
    const client = vm.runInContext(`T("pager.showing", ${JSON.stringify(vars)})`, ctx);
    expect(client).toBe(translate("zh", "pager.showing", vars));
    expect(client).not.toContain("{");
  });

  it("client T() falls back to the raw identifier for unknown enum values", async () => {
    const ctx = i18nContext((await getPanel()).body);
    for (const [key, raw] of [
      ["decision.degrade", "degrade"],
      ["sev.catastrophic", "catastrophic"],
      ["layer.kube", "kube"],
      ["capsule.quarantine", "quarantine"],
      ["sec.newsection", "newsection"],
    ] as const) {
      const out = vm.runInContext(`T(${JSON.stringify(key)})`, ctx);
      // Not the prefixed key (ugly), not blank (useless) — the identifier.
      expect(out, key).toBe(raw);
      expect(out).not.toContain(".");
    }
    // A genuinely unknown key is echoed so a missing entry stays loud.
    expect(vm.runInContext('T("cfg.label.nope.nope")', ctx)).toBe("cfg.label.nope.nope");
  });

  // ── Rendering, driven through the panel's own code ────────────────────

  const eventsFixture = {
    total: 2,
    truncated: false,
    events: [
      {
        ts: 1_700_000_000_000,
        event_type: "agent_tool_call",
        layer: "system",
        agent_id: "a1",
        intervention: { decision: "block", risk_level: "critical" },
      },
      {
        ts: 1_700_000_001_000,
        event_type: "process_exec",
        layer: "application",
        agent_id: "a2",
        intervention: { decision: "warn", risk_level: "medium" },
      },
    ],
  };

  it("zh renders Chinese decision / severity / layer badges and headers", async () => {
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const panel = runPanel(res.body, (method) => (method === "security.events.list" ? eventsFixture : {}));
    await panel.clickTab("events");
    const rows = panel.els.get("events-body").innerHTML;
    expect(rows).toContain('<span class="badge block">阻断</span>');
    expect(rows).toContain('<span class="badge warn">警告</span>');
    expect(rows).toContain('<span class="badge block">严重</span>');
    expect(rows).toContain('<span class="badge change">中</span>');
    expect(rows).toContain("<td>系统层</td>");
    expect(rows).toContain("<td>应用层</td>");
    const head = panel.els.get("events-table").innerHTML;
    for (const th of ["时间", "类型", "层级", "严重度", "智能体", "工具 / 会话", "状态"]) {
      expect(head, `zh events header ${th}`).toContain(`<th>${th}</th>`);
    }
  });

  it("en keeps the raw identifiers for decision / severity / layer", async () => {
    const res = await getPanel();
    const panel = runPanel(res.body, (method) => (method === "security.events.list" ? eventsFixture : {}));
    await panel.clickTab("events");
    const rows = panel.els.get("events-body").innerHTML;
    expect(rows).toContain('<span class="badge block">block</span>');
    expect(rows).toContain('<span class="badge warn">warn</span>');
    expect(rows).toContain('<span class="badge block">critical</span>');
    expect(rows).toContain("<td>system</td>");
    expect(rows).toContain("<td>application</td>");
    const head = panel.els.get("events-table").innerHTML;
    for (const th of ["Time", "Type", "Layer", "Severity", "Agent", "Tool/Session", "Status"]) {
      expect(head, `en events header ${th}`).toContain(`<th>${th}</th>`);
    }
  });

  it("an unrecognised decision degrades to its identifier in both locales", async () => {
    const events = {
      total: 1,
      truncated: false,
      events: [
        {
          ts: 1_700_000_000_000,
          event_type: "agent_tool_call",
          layer: "system",
          intervention: { decision: "degrade", risk_level: "extreme" },
        },
      ],
    };
    for (const locale of LOCALES) {
      const res = await getPanel({ path: `/openclaw-security-monitor/panel?lang=${locale}` });
      const panel = runPanel(res.body, (method) => (method === "security.events.list" ? events : {}));
      await panel.clickTab("events");
      const rows = panel.els.get("events-body").innerHTML;
      expect(rows, `${locale}: unknown decision must read "degrade"`).toContain(">degrade</span>");
      expect(rows, `${locale}: never show the prefixed key`).not.toContain("decision.degrade");
      // A *known* severity in the same row still gets its own translation.
      expect(rows, `${locale}: sev.extreme is known`).toContain(
        `<span class="badge block">${locale === "zh" ? "极高" : "extreme"}</span>`
      );
    }
  });

  it("zh Policy Hits capsules are localized, en keeps the identifiers", async () => {
    const hits = { hits: [], total: 0, byDecision: { block: 1, warn: 2 } };
    const zhRes = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const zhPanel = runPanel(zhRes.body, (method) => (method === "security.policy.hits" ? hits : {}));
    await zhPanel.clickTab("blocks");
    const zhOut = zhPanel.els.get("blocks-table").innerHTML;
    for (const [label, key] of [
      ["全部", "all"],
      ["阻断", "block"],
      ["警告", "warn"],
      ["修改", "modify"],
      ["审计", "audit"],
    ] as const) {
      expect(zhOut, `zh capsule ${label}`).toContain(`data-capsule="${key}">${label} <span class="count">`);
    }
    expect(zhOut).toContain("<th>原因</th>");

    const enRes = await getPanel();
    const enPanel = runPanel(enRes.body, (method) => (method === "security.policy.hits" ? hits : {}));
    await enPanel.clickTab("blocks");
    const enOut = enPanel.els.get("blocks-table").innerHTML;
    for (const key of ["all", "block", "warn", "modify", "audit"]) {
      expect(enOut, `en capsule ${key}`).toContain(`data-capsule="${key}">${key} <span class="count">`);
    }
    expect(enOut).toContain("<th>Reason</th>");
  });

  it("localizes the event-type dropdown's placeholder option only", async () => {
    for (const [locale, placeholder] of [
      ["zh", "全部事件类型"],
      ["en", "All event types"],
    ] as const) {
      const res = await getPanel({ path: `/openclaw-security-monitor/panel?lang=${locale}` });
      const panel = runPanel(res.body, () => ({}));
      await panel.clickTab("events");
      const out = panel.els.get("panel").innerHTML;
      // The placeholder option is the current filter (eventsState.eventType
      // defaults to ""), so its tag carries `selected` — match the text.
      expect(out, `${locale} placeholder option`).toContain(`>${placeholder}</option>`);
      expect(out).toMatch(/<option value=""[^>]*>.*<\/option>/);
      // Event type identifiers are wire values, not copy — they stay as-is.
      expect(out).toContain('<option value="agent_tool_call">agent_tool_call</option>');
    }
  });

  it("zh Config page renders Chinese labels, help and dangerReason; en renders English", async () => {
    // 用真实的 config.get 返回值（含 withRuntimeHelpVars 注入的 helpVars），
    // 而不是裸 CONFIG_SCHEMA —— 后者没有占位符取值，会把 {preloadTarget}
    // 原样印出来，而这正是本用例要守住的那类回归。
    const real = (await gatewayMethods.get("security.config.get")?.({})) as { schema: unknown };
    const payload = {
      config: {
        collector: { ndjsonPath: "/tmp/events.jsonl" },
        application: { runtimeHooks: { enabled: false } },
        system: { enabled: false },
      },
      schema: real.schema,
    };
    const zhRes = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const zhPanel = runPanel(zhRes.body, (method) => (method === "security.config.get" ? payload : {}));
    await zhPanel.clickTab("config");
    const zhOut = zhPanel.els.get("panel").innerHTML;
    expect(zhOut, "label").toContain('<span class="tool">本地 NDJSON 路径');
    expect(zhOut, "section title").toContain(">采集器</h2>");
    expect(zhOut, "dangerReason").toContain("⚠ 改路径后下次启动会在新位置创建文件");
    expect(zhOut, "help text").toContain("打开本开关，然后把 NODE_OPTIONS 指向：");
    // 帮助文案里的运行时占位符必须全部被 helpVars 填掉，不能原样漏给用户。
    expect(zhOut, "help text 未填充的占位符").not.toMatch(/\{\w+\}/);
    expect(zhOut, "danger modal title").toContain(">⚠ 危险操作确认</h3>");
    expect(zhOut, "save button").toContain(">保存</button>");
    // The Config page is built entirely from dictionary keys; a missing entry
    // would render the raw key in the operator's face.
    expect(zhOut, "dictionary keys leaked into the Config page").not.toMatch(/cfg\.(label|help|danger)\./);

    const enRes = await getPanel();
    const enPanel = runPanel(enRes.body, (method) => (method === "security.config.get" ? payload : {}));
    await enPanel.clickTab("config");
    const enOut = enPanel.els.get("panel").innerHTML;
    expect(enOut, "label").toContain('<span class="tool">Local NDJSON path');
    expect(enOut, "section title").toContain(">Collector</h2>");
    expect(enOut, "dangerReason").toContain("⚠ Changing the path creates the file at the new location");
    expect(enOut, "help text").toContain("Turn this on, then point NODE_OPTIONS at:");
    expect(enOut, "help text unfilled placeholder").not.toMatch(/\{\w+\}/);
    expect(enOut, "danger modal title").toContain(">⚠ Confirm dangerous change</h3>");
    expect(cjkIn(enOut), "the en Config page must be CJK-free").toEqual([]);
  });

  it("carries the localized dangerReason onto the danger inputs", async () => {
    // The confirm modal re-reads data-danger-reason off the inputs, so the
    // localized string has to survive the escAttr() round-trip.
    for (const [locale, expected] of [
      ["zh", "改路径后下次启动会在新位置创建文件"],
      ["en", "Changing the path creates the file at the new location"],
    ] as const) {
      const res = await getPanel({ path: `/openclaw-security-monitor/panel?lang=${locale}` });
      const panel = runPanel(res.body, (method) =>
        method === "security.config.get"
          ? { config: { collector: { ndjsonPath: "/tmp/events.jsonl" } }, schema: CONFIG_SCHEMA }
          : {}
      );
      await panel.clickTab("config");
      const out = panel.els.get("panel").innerHTML;
      const attr = out.match(/data-danger-reason="([^"]*)"/)?.[1];
      expect(attr, `${locale}: danger inputs lost data-danger-reason`).toBeTruthy();
      expect(attr, `${locale}: danger attribute not localized`).toContain(expected);
    }
  });

  // ── Header language switcher (panel-state.json) ─────────────────────
  //
  // 四条不能松的线：
  //   1. 控件在两种语言下形状完全一致（语言名用 endonym，不翻译），只有
  //      aria-pressed 跟着实际语言走——否则用户不知道当前看到的是哪种；
  //   2. 点一下写的是 security.panel.locale.set（插件自己的状态文件），**不是**
  //      security.config.save：写宿主 openclaw.json 会让 gateway 重载全部插件，
  //      实测一次语言切换要 8.4 秒才看得见效果（现场实测，见 index.ts 的
  //      RELOAD_SETTLE_* 注释）；当前语言再点一次必须是空操作；
  //   3. 偏好在**不重启 gateway** 的情况下生效——每次 GET 现读落盘文件，不是
  //      middleware.getConfig() 的启动快照；
  //   4. 服务端拒绝（ok:false）不能被当成保存成功：否则按钮卡在"切换中"、
  //      页面永远不变，又是一个"看起来坏了"的失败。

  /** Rewrite the host config the harness is pointed at, in place. */
  function setHostPanelLocale(value: string | undefined) {
    writeFileSync(
      path.join(tmpDir, "openclaw.json"),
      JSON.stringify({
        plugins: {
          entries: {
            [PLUGIN_ID]: { config: value === undefined ? {} : { application: { panelLocale: value } } },
          },
        },
      }),
      "utf8",
    );
  }

  /** The switcher's own state file (auto = "never touched"). */
  function setPanelStateLocale(value: string | undefined) {
    const p = path.join(tmpDir, "panel-state.json");
    if (value === undefined) rmSync(p, { force: true });
    else writeFileSync(p, JSON.stringify({ panelLocale: value }), "utf8");
  }

  const readPanelStateLocale = () => {
    try {
      return (JSON.parse(readFileSync(path.join(tmpDir, "panel-state.json"), "utf8")) as { panelLocale?: unknown })
        .panelLocale;
    } catch {
      return undefined;
    }
  };

  const switcherOf = (html: string) => {
    const box = html.match(/<div class="langswitch"[^>]*>[\s\S]*?<\/div>/)?.[0] ?? "";
    return {
      box,
      current: box.match(/data-current="([^"]*)"/)?.[1],
      ariaLabel: box.match(/aria-label="([^"]*)"/)?.[1],
      buttons: [...box.matchAll(/<button ([^>]*)>([^<]*)<\/button>/g)].map((m) => ({
        lang: m[1].match(/data-lang="([^"]*)"/)?.[1],
        pressed: m[1].match(/aria-pressed="([^"]*)"/)?.[1],
        label: m[2],
      })),
    };
  };

  it("renders the same two endonym segments in both locales, pressed state following the served language", async () => {
    for (const [locale, htmlLang] of [
      ["en", "en"],
      ["zh", "zh-CN"],
    ] as const) {
      const res = await getPanel({ path: `/openclaw-security-monitor/panel?lang=${locale}` });
      const sw = switcherOf(res.body);

      // 语言名不翻译：英文界面里的 "中文" 是语言本身的写法，不是漏翻的文案。
      // visibleCopy() 因此把整个控件剔除后再查 CJK。
      expect(sw.buttons.map((b) => b.label), `${locale}: endonym labels`).toEqual(["EN", "中文"]);
      expect(sw.buttons.map((b) => b.lang), `${locale}: data-lang order`).toEqual(["en", "zh"]);
      expect(sw.current, `${locale}: data-current must mirror the resolved locale`).toBe(locale);
      expect(
        sw.buttons.find((b) => b.pressed === "true")?.lang,
        `${locale}: exactly the active language must be aria-pressed`,
      ).toBe(locale);
      expect(sw.ariaLabel, `${locale}: the group needs a label for screen readers`).toBeTruthy();
      // aria-label 随界面语言走，控件形状不变。
      expect(sw.ariaLabel, `${locale}: group label not localized`).not.toBe(
        locale === "en" ? "切换面板语言" : "Switch panel language",
      );
      expect(res.body, `${locale}: <html lang> and data-current disagree`).toContain(`<html lang="${htmlLang}">`);
    }
  });

  it("a saved preference pins the panel with no gateway restart", async () => {
    // Accept-Language 故意与偏好相反：偏好必须压过浏览器，否则点了"中文"
    // 却因为系统首选 en 又弹回英文，看起来就是按钮坏了。
    const fr = { "Accept-Language": "fr" };
    try {
      for (const [saved, expectLang, expectHtmlLang] of [
        ["zh", "zh", "zh-CN"],
        ["en", "en", "en"],
      ] as const) {
        setPanelStateLocale(saved);
        const res = await getPanel({ headers: fr });
        expect(res.body, `saved ${saved} under Accept-Language: fr`).toContain(`<html lang="${expectHtmlLang}">`);
        expect(switcherOf(res.body).current, `saved ${saved}: switcher must agree`).toBe(expectLang);
      }

      // ?lang= 仍然独占——书签 / 外链要能钉住语言。
      setPanelStateLocale("zh");
      const pinned = await getPanel({ path: "/openclaw-security-monitor/panel?lang=en" });
      expect(pinned.body, "?lang= must out-rank the saved preference").toContain('<html lang="en">');

      // 回落：没存过 / 值非法都不该让面板报错或空白。
      setPanelStateLocale(undefined);
      const missing = await getPanel({ headers: { "Accept-Language": "zh-CN,zh;q=0.9" } });
      expect(missing.status).toBe(200);
      expect(missing.body, "no stored choice must behave like auto").toContain('<html lang="zh-CN">');

      setPanelStateLocale("zh-CN");
      const garbage = await getPanel({ headers: { "Accept-Language": "en" } });
      expect(garbage.status, "an illegal value must not 500").toBe(200);
      expect(garbage.body, "an illegal value must degrade to auto").toContain('<html lang="en">');
    } finally {
      // 还原，别把语言偏好漏给同文件里的后续用例。
      setPanelStateLocale(undefined);
      setHostPanelLocale(undefined);
      writeFileSync(path.join(tmpDir, "openclaw.json"), "{}", "utf8");
    }
  });

  it("the switcher outranks application.panelLocale, which stays the default", async () => {
    // 两个落盘处是有意并存的分层：开关（panel-state.json）代表"这个人在面板上
    // 按过"，配置键代表"这台机器默认长这样"。优先级写反的话，手工钉死的配置会被
    // 一次随手点击悄悄盖掉；合并成一处则又退回 8 秒等待。
    try {
      setHostPanelLocale("zh");
      setPanelStateLocale("en");
      const overridden = await getPanel({ headers: { "Accept-Language": "zh-CN" } });
      expect(overridden.body, "the switcher must win over the config key").toContain('<html lang="en">');
      expect(switcherOf(overridden.body).current).toBe("en");

      // 开关回到 auto（= 没人碰过）后，配置键重新说话。
      setPanelStateLocale("auto");
      const defaulted = await getPanel({ headers: { "Accept-Language": "en" } });
      expect(defaulted.body, "application.panelLocale must still pin when the switcher is auto").toContain(
        '<html lang="zh-CN">',
      );

      // 两边都是 auto → 交回浏览器协商。
      setHostPanelLocale(undefined);
      const negotiated = await getPanel({ headers: { "Accept-Language": "zh-CN,zh;q=0.9" } });
      expect(negotiated.body).toContain('<html lang="zh-CN">');
    } finally {
      setPanelStateLocale(undefined);
      setHostPanelLocale(undefined);
      writeFileSync(path.join(tmpDir, "openclaw.json"), "{}", "utf8");
    }
  });

  it("clicking a language saves the choice, strips ?lang= and reloads", async () => {
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=en&tab=config" });
    const panel = runPanel(
      res.body,
      (method) => (method === "security.config.get" ? { config: {}, schema: CONFIG_SCHEMA } : {}),
      { langSwitch: { current: "en", search: "?lang=en&tab=config" } },
    );

    await panel.clickLang("zh");

    const saves = panel.rpcBodies.filter((b) => b.method === "security.panel.locale.set");
    expect(saves, "the switcher must persist the choice, not just reload").toHaveLength(1);
    expect(saves[0].params, "the choice must travel as the target locale").toEqual({ locale: "zh" });
    // 写宿主 openclaw.json 会让 gateway 重载全部插件（实测一次切换 8.4 秒）。
    // 开关因此只写插件自己的状态文件，这条断言就是那个决定的守卫。
    expect(
      panel.rpcBodies.filter((b) => b.method === "security.config.save"),
      "the switcher must never touch the host config — that restarts every plugin",
    ).toHaveLength(0);
    await panel.waitForReload();
    expect(panel.reloadCount(), "the page must reload or the switcher looks inert").toBe(1);
    // 不摘掉 ?lang= 的话刷新后又被 URL 盖回原语言——按钮看起来就是坏的。
    expect(panel.replacedUrl(), "?lang= must be dropped before reloading").toBe(
      "/openclaw-security-monitor/panel?tab=config",
    );
    // 保存期间按钮要禁用，否则连点两下就是两次写入。
    expect(panel.langButtons.find((b) => b.lang === "zh")?.disabled).toBe(true);
  });

  it("the switcher does not sit on a dead button while it waits for the reload", async () => {
    // 回归：文案写成"已保存"而页面 8 秒不动，就是被当成"按钮坏了"的那一版。
    // 等待期必须说"切换中"，且这次等待必须是秒级而不是把上限跑满。
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=en" });
    const panel = runPanel(res.body, () => ({}), { langSwitch: { current: "en", search: "?lang=en" } });

    await panel.clickLang("zh");
    const btn = panel.langButtons.find((b) => b.lang === "zh");
    const pendingLabel = (btn?.node as { textContent?: string }).textContent;
    expect(pendingLabel, "the wait must be announced, not shown as a finished save").toBe(
      translate("en", "lang.switching"),
    );
    expect(pendingLabel, "a button that says 'Saved' while nothing changed is the bug").not.toBe(
      translate("en", "save.saved"),
    );

    // 路由一直可读 → 两次探询就导航，不该把 12s 上限跑满。
    const started = Date.now();
    await panel.waitForReload();
    expect(panel.reloadCount()).toBe(1);
    expect(Date.now() - started, "a no-window switch must not wait out the settle cap").toBeLessThan(4000);
  });

  it("the settle probe carries its own timeout", async () => {
    // 上限判断写在 probe 的 .then 里：fetch 永不返回（隧道挂住、宿主收下连接
    // 不吐响应）时上限永远轮不到，页面就此钉在"切换中"再也不会导航。唯一的
    // 防线是探询自带 AbortSignal。
    const res = await getPanel();
    const panel = runPanel(res.body, () => ({}), { langSwitch: { current: "en", search: "" } });

    await panel.clickLang("zh");
    await panel.waitForReload(3000);

    const probes = panel.fetchInits.filter((f) => f.method === "security.status");
    expect(probes.length, "the switcher must probe the route before navigating").toBeGreaterThan(0);
    expect(
      probes.every((f) => f.signal),
      "every settle probe must be abortable, or one hung request strands the page",
    ).toBe(true);
  });

  it("a server-side refusal is not reported as a successful switch", async () => {
    // 回归：rpc() 把 payload 原样交回来，服务端拒绝是 {ok:false,error} 而不是抛。
    // 不看 ok 的话"字段校验失败"也会被当成保存成功——按钮卡在切换中、页面不变，
    // 和网络失败长得一模一样，却连错误提示都没有。
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const panel = runPanel(res.body, () => ({}), {
      langSwitch: { current: "zh", search: "?lang=zh" },
      refuseRpc: { method: "security.panel.locale.set", message: "写入面板语言偏好失败: EACCES" },
    });

    await panel.clickLang("en");

    const btn = panel.langButtons.find((b) => b.lang === "en");
    expect(btn?.disabled, "a refused switch must never leave the button greyed out").toBe(false);
    expect((btn?.node as { textContent?: string }).textContent, "the label must go back to the language").toBe("EN");
    expect(panel.reloadCount(), "a refused switch must not reload").toBe(0);
    expect(panel.els.get("toast")?.textContent, "the reason must reach the operator").toContain("EACCES");
  });

  it("clicking the language already on screen is a no-op", async () => {
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const panel = runPanel(res.body, () => ({}), { langSwitch: { current: "zh", search: "?lang=zh" } });

    await panel.clickLang("zh");

    expect(panel.rpcBodies.filter((b) => b.method === "security.panel.locale.set")).toHaveLength(0);
    expect(panel.reloadCount()).toBe(0);
    expect(panel.replacedUrl()).toBeNull();
  });

  it("the switcher survives a page with no ?lang= (search stays clean)", async () => {
    const res = await getPanel();
    const panel = runPanel(res.body, () => ({}), { langSwitch: { current: "en", search: "" } });

    await panel.clickLang("zh");

    expect(panel.rpcBodies.some((b) => b.method === "security.panel.locale.set")).toBe(true);
    // 没有 ?lang= 时不该去改地址栏——replaceState 只在确实有 lang 参数时才有意义。
    expect(panel.replacedUrl(), "a clean URL must not be rewritten").toBeNull();
    await panel.waitForReload();
    expect(panel.reloadCount()).toBe(1);
  });

  it("a failed save hands the button back and says why", async () => {
    // 回归：event.currentTarget 只在派发期间有效，一进 promise 回调就是 null。
    // 写成 ev.currentTarget.disabled = false 会在 catch 里抛
    // "Cannot set properties of null"，而这个异常恰好把"恢复可点"这一步吃掉
    // ——控件就此永久变灰，表现为"从中文切不回英文，也不报错"。
    // 这条断言盯的是失败后按钮必须可点，别的都随它去。
    const res = await getPanel({ path: "/openclaw-security-monitor/panel?lang=zh" });
    const panel = runPanel(res.body, () => ({}), {
      langSwitch: { current: "zh", search: "?lang=zh" },
      failRpc: "security.panel.locale.set",
    });

    await panel.clickLang("en");

    const btn = panel.langButtons.find((b) => b.lang === "en");
    expect(btn?.disabled, "a failed switch must never leave the button greyed out").toBe(false);
    // 失败不刷新：地址栏和页面都不动，用户还能直接再点一次。
    expect(panel.reloadCount(), "a failed save must not reload").toBe(0);
    // 至少要把原因说出来，静默失败比报错更难排查。
    expect(panel.els.get("toast")?.textContent, "the failure must reach the operator").toContain("Failed to fetch");
  });

  it("a CORS-blocked RPC after a good session self-heals by reloading", async () => {
    // 长挂面板 → 宿主 session 过期 → 宿主回 401 但不带 ACAO → fetch reject 成
    // TypeError。rpc() 过去只在 `r.status === 401/403` 上认这件事，而这条路在
    // sandboxed iframe 里根本走不到，于是自动刷新永远把内容换成
    // "⚠ Failed to fetch" 且不自愈，只能手动 F5。
    //
    // 读不到响应与"宿主正在重载插件配置"在浏览器眼里是同一个信号，所以自愈要
    // 先确认路由能给出**可读**响应再导航。这里 failRpc:"*" 让它一直读不到，
    // 断言的是上限兜底：必须重载（不能永远卡在 Failed to fetch），且只重载
    // 一次；正常情况下它会提前在路由恢复可读时就走。
    const res = await getPanel();
    const panel = runPanel(res.body, () => ({}), { failRpc: "*", failAfterFirst: true });

    // 首个 RPC 成功 → rpcEverOk 置位；随后的失败必须换来一次自动重载。
    await new Promise((r) => setTimeout(r, 60));
    expect(panel.rpcBodies.length, "the panel should have issued RPCs").toBeGreaterThan(1);
    expect(panel.reloadCount(), "nothing may navigate while the route is unreadable").toBe(0);
    await panel.waitForReload();
    expect(panel.reloadCount(), "an expired session must self-heal without user action").toBe(1);
  }, 25000);

  it("a page that never had a working session does not reload itself", async () => {
    // 反向：不许变成"每 30s 刷新一次、永远加载不出来"的死循环。授权本来就发
    // 不下来时重载没有意义——判据是本页有没有成功过一次（rpcEverOk）。
    const res = await getPanel();
    const panel = runPanel(res.body, () => ({}), { failRpc: "*" });

    await new Promise((r) => setTimeout(r, 60));
    expect(panel.rpcBodies.length, "the panel should have issued RPCs").toBeGreaterThan(0);
    expect(panel.reloadCount(), "a never-working session must not trigger a reload loop").toBe(0);
  });

  it("the real security.panel.locale.set persists the choice and the next GET already speaks it", async () => {
    // 上面几条用 mock fetch，只证明了客户端发对了信封。这一条把整条链走完：
    // 点开关 → RPC → panel-state.json → 刷新 → 新语言，全程不重启 gateway。
    // 断点最可能落在两处：写入路径与面板 GET 读的不是同一个文件，或者写入
    // 顺手碰了宿主 openclaw.json（那会让 gateway 重载全部插件）。
    const setLocale = gatewayMethods.get("security.panel.locale.set");
    expect(setLocale, "security.panel.locale.set not registered").toBeTruthy();

    try {
      const hostConfigBefore = readFileSync(path.join(tmpDir, "openclaw.json"), "utf8");
      const saved = (await setLocale!({ locale: "zh" })) as { ok: boolean; locale?: string; error?: { message?: string } };
      expect(saved.ok, `switch refused: ${saved.error?.message ?? ""}`).toBe(true);
      expect(saved.locale, "the handler must hand back what it actually stored").toBe("zh");

      expect(readPanelStateLocale(), "the choice must land on the file the panel GET reads").toBe("zh");
      expect(
        readFileSync(path.join(tmpDir, "openclaw.json"), "utf8"),
        "writing a language must not rewrite the host config (that restarts every plugin)",
      ).toBe(hostConfigBefore);

      // Accept-Language 故意相反：保存的值必须压过浏览器。
      const after = await getPanel({ headers: { "Accept-Language": "en-GB,en;q=0.9" } });
      expect(after.body, "the reload after a switch must come back Chinese").toContain('<html lang="zh-CN">');
      expect(switcherOf(after.body).current).toBe("zh");
    } finally {
      setPanelStateLocale(undefined);
      setHostPanelLocale(undefined);
      writeFileSync(path.join(tmpDir, "openclaw.json"), "{}", "utf8");
    }
  });

  it("security.panel.locale.get reports both saved layers, not just the winner", async () => {
    // 只回一个解析结果的话，"面板是中文"分不清是开关按过、配置键钉死、还是
    // 浏览器协商出来的 —— 排查时看不出该去改哪一处。
    const get = gatewayMethods.get("security.panel.locale.get");
    try {
      setHostPanelLocale("zh");
      setPanelStateLocale("en");
      expect(await get!({})).toEqual({ saved: "en", configDefault: "zh", effective: "en" });

      setPanelStateLocale(undefined);
      setHostPanelLocale(undefined);
      expect(await get!({}), "no stored choice anywhere means 'auto', not 'en'").toEqual({
        saved: "auto",
        configDefault: "auto",
        effective: "auto",
      });
    } finally {
      setPanelStateLocale(undefined);
      setHostPanelLocale(undefined);
      writeFileSync(path.join(tmpDir, "openclaw.json"), "{}", "utf8");
    }
  });

  it("security.panel.locale.set rejects an unsupported locale instead of storing auto", async () => {
    const setLocale = gatewayMethods.get("security.panel.locale.set");
    try {
      for (const bad of ["fr", "", "zh-CN", 3, null, undefined]) {
        const res = (await setLocale!({ locale: bad })) as { ok: boolean; error?: { message?: string } };
        expect(res.ok, `${JSON.stringify(bad)} must not be accepted`).toBe(false);
        expect(res.error?.message, "the refusal must say what is allowed").toBeTruthy();
      }
      expect(readPanelStateLocale(), "a rejected locale must not touch the stored preference").toBeUndefined();

      const good = (await setLocale!({ locale: "auto" })) as { ok: boolean; locale?: string };
      expect(good.ok, "auto is a legal choice — it hands the panel back to negotiation").toBe(true);
      expect(readPanelStateLocale()).toBe("auto");
    } finally {
      setPanelStateLocale(undefined);
    }
  });

  it("a corrupt panel-state.json degrades to negotiation, never to a blank panel", async () => {
    try {
      writeFileSync(path.join(tmpDir, "panel-state.json"), "{not json", "utf8");
      const res = await getPanel({ headers: { "Accept-Language": "zh-CN,zh;q=0.9" } });
      expect(res.status, "a hand-mangled state file must not 500").toBe(200);
      expect(res.body).toContain('<html lang="zh-CN">');

      // auto（= 没人按过开关）等于没有选择，交回协商。
      writeFileSync(path.join(tmpDir, "panel-state.json"), JSON.stringify({ panelLocale: "auto" }), "utf8");
      const auto = await getPanel({ headers: { "Accept-Language": "en-GB" } });
      expect(auto.body, "auto must behave as if the switcher had never been touched").toContain('<html lang="en">');
    } finally {
      setPanelStateLocale(undefined);
    }
  });
});