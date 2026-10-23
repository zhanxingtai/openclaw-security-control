#!/usr/bin/env node
/**
 * Real OpenClaw panel end-to-end test.
 *
 * Drives the actual OpenClaw 9.4 instance on http://127.0.0.1:28789 the same
 * way a browser tab would: GET the panel HTML, parse out the embedded JS RPC
 * endpoints, then POST each RPC and verify the JSON payload. Also probes the
 * NDJSON sidecar pull. Surfaces any HTTP status / CORS / CSP issues.
 *
 * Usage:  node scripts/verify-panel-browser-flow.mjs [baseUrl]
 */

import http from "node:http";

const baseUrl = process.argv[2] || "http://127.0.0.1:28789";

function request(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: opts.method || "GET",
        headers: {
          "User-Agent": "verify-panel/1.0",
          "Accept": "application/json, text/html, */*",
          ...(opts.body ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(opts.body) } : {}),
          ...(opts.headers || {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

const failures = [];
function check(name, ok, detail = "") {
  console.log(`  ${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures.push(name);
}

console.log(`[verify-panel-browser-flow] target: ${baseUrl}`);

// Step 1: GET the panel HTML
console.log("\n[verify-panel-browser-flow] step 1: GET panel HTML");
const get = await request(`${baseUrl}/openclaw-security-monitor/panel`);
check("GET panel → 200", get.status === 200, `status=${get.status}`);
check("Content-Type text/html", (get.headers["content-type"] || "").includes("text/html"));
check("CSP includes connect-src 'self'", (get.headers["content-security-policy"] || "").includes("connect-src 'self'"));
check("response body has <html>", get.body.includes("<html"));
// Structural assertions. The old checks looked for the literal "Security
// Monitor" (a title the header has not carried for some time — it is
// "SST Security Control") and for "5 tabs" while only testing two of them, so
// they could only ever fail or pass without testing anything. Assert the real
// shape instead: the header title, exactly four tabs, and their labels.
check("response body has the panel header", get.body.includes("<h1>SST Security Control</h1>"));
const tabCount = (get.body.match(/data-tab="/g) || []).length;
check("response body has 4 tabs", tabCount === 4, `data-tab count=${tabCount}`);
check(
  "default locale is English",
  get.body.includes('<html lang="en">'),
  get.body.match(/<html lang="[^"]*">/)?.[0] || "no lang attribute"
);
check("English tab labels render", get.body.includes(">Policy Hits</button>"));
check("Cache-Control is no-store", (get.headers["cache-control"] || "") === "no-store");

// Step 2: POST each RPC the panel calls
console.log("\n[verify-panel-browser-flow] step 2: POST panel RPCs");
const RPCS = [
  { method: "security.status", params: {} },
  { method: "security.metrics", params: {} },
  { method: "security.events.list", params: { limit: 5 } },
  { method: "security.events.stats", params: {} },
  { method: "security.assets.list", params: {} },
  { method: "security.policy.hits", params: {} },
  { method: "security.config.get", params: {} },
];
for (const rpc of RPCS) {
  const res = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
    method: "POST",
    body: JSON.stringify(rpc),
  });
  let ok = res.status === 200;
  let payload = null;
  try {
    payload = JSON.parse(res.body);
    ok = ok && payload.ok === true;
  } catch {}
  check(`POST ${rpc.method} → 200 ok=true`, ok, `status=${res.status} body=${res.body.slice(0, 100)}`);
}

// Step 3: OPTIONS preflight (mimics what browser does for cross-origin)
console.log("\n[verify-panel-browser-flow] step 3: OPTIONS preflight");
const preflight = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
  method: "OPTIONS",
  headers: {
    Origin: baseUrl,
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "Content-Type",
  },
});
check("OPTIONS → 204", preflight.status === 204, `status=${preflight.status}`);
check("cross-origin preflight NOT approved (no ACAO echo)", preflight.headers["access-control-allow-origin"] === undefined);
const sandboxPreflight = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
  method: "OPTIONS",
  headers: {
    Origin: "null",
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "Content-Type",
  },
});
check("sandbox OPTIONS → 204 with ACAO null", sandboxPreflight.status === 204 && sandboxPreflight.headers["access-control-allow-origin"] === "null", `status=${sandboxPreflight.status}`);
check("no Access-Control-Allow-Credentials", sandboxPreflight.headers["access-control-allow-credentials"] === undefined && get.headers["access-control-allow-credentials"] === undefined);

// Step 4: panel language negotiation
console.log("\n[verify-panel-browser-flow] step 4: panel locale negotiation");
const zh = await request(`${baseUrl}/openclaw-security-monitor/panel?lang=zh`);
check("?lang=zh → 200", zh.status === 200, `status=${zh.status}`);
check("?lang=zh renders zh-CN", zh.body.includes('<html lang="zh-CN">'));
check("?lang=zh localizes the tabs", zh.body.includes(">威胁</button>"));
const fr = await request(`${baseUrl}/openclaw-security-monitor/panel?lang=fr`);
check("?lang=fr falls back to English", fr.body.includes('<html lang="en">'), `status=${fr.status}`);

// Step 4b: the header switcher round trip.
//
// The switcher writes the plugin's own panel-state.json, NOT the host
// openclaw.json — a host-config write makes the gateway reload every plugin,
// and a language switch used to take 8.4s to show up (you watched a greyed
// "已保存 ✓" the whole time). This step exercises the whole loop over HTTP and
// restores whatever preference the instance started with, so running it never
// leaves somebody's panel in a language they didn't pick.
console.log("\n[verify-panel-browser-flow] step 4b: locale switcher round trip");
const rpcPost = async (method, params) => {
  const res = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
    method: "POST",
    body: JSON.stringify({ method, params }),
  });
  let payload = null;
  try {
    payload = JSON.parse(res.body);
  } catch {}
  return { status: res.status, payload };
};

const before = await rpcPost("security.panel.locale.get", {});
const savedBefore = before.payload?.payload?.saved;
check("security.panel.locale.get is registered", typeof savedBefore === "string", JSON.stringify(before.payload));

if (typeof savedBefore === "string") {
  const refused = await rpcPost("security.panel.locale.set", { locale: "fr" });
  check(
    "an unsupported locale is refused, not stored",
    refused.payload?.payload?.ok === false,
    JSON.stringify(refused.payload)
  );

  const switchTo = savedBefore === "zh" ? "en" : "zh";
  const set = await rpcPost("security.panel.locale.set", { locale: switchTo });
  check(`switching to ${switchTo} succeeds`, set.payload?.payload?.ok === true, JSON.stringify(set.payload));

  // Header deliberately opposite: the stored choice must win.
  const oppositeHeader = switchTo === "zh" ? "en-GB,en;q=0.9" : "zh-CN,zh;q=0.9";
  const afterSwitch = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
    headers: { "Accept-Language": oppositeHeader },
  });
  const expectHtmlLang = switchTo === "zh" ? "zh-CN" : "en";
  check(
    `the stored choice beats Accept-Language (${oppositeHeader})`,
    afterSwitch.body.includes(`<html lang="${expectHtmlLang}">`),
    `data-current=${afterSwitch.body.match(/data-current="([^"]*)"/)?.[1]}`
  );

  const afterGet = await rpcPost("security.panel.locale.get", {});
  check(
    "the switcher outranks application.panelLocale",
    afterGet.payload?.payload?.saved === switchTo && afterGet.payload?.payload?.effective === switchTo,
    JSON.stringify(afterGet.payload?.payload)
  );

  const restore = await rpcPost("security.panel.locale.set", { locale: savedBefore });
  check(
    `restored the instance's original preference (${savedBefore})`,
    restore.payload?.payload?.ok === true,
    JSON.stringify(restore.payload)
  );

  // Only meaningful once nothing is pinned: auto hands the panel back to the
  // browser. Asserted after the restore, and skipped if the operator had a
  // preference of their own (restoring it is the whole point of the step above).
  if (savedBefore === "auto") {
    const zhHeader = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
      headers: { "Accept-Language": "zh-CN,zh;q=0.9" },
    });
    check("Accept-Language: zh yields the Chinese panel", zhHeader.body.includes('<html lang="zh-CN">'));
  } else {
    console.log(
      `  – Accept-Language negotiation skipped: this instance pins ${savedBefore} (restored, not reset)`
    );
  }
}

// Step 5: NDJSON sidecar pull
console.log("\n[verify-panel-browser-flow] step 5: events.ndjson pull");
const events = await request(`${baseUrl}/openclaw-security-monitor/events.ndjson`);
// That route is declared `auth: "gateway"` on purpose (external scrapers tail
// it via operator scope; "plugin" would gate it to internal calls only), and
// this script carries no gateway credentials — so 401 is the correct answer
// here, and demanding 200 was asserting the wrong contract.
check(
  "GET events.ndjson → 200 (credentials) or 401 (none supplied)",
  events.status === 200 || events.status === 401,
  `status=${events.status} body=${events.body.slice(0, 60)}`
);

// Step 6: POST without Origin header (non-browser client — still accepted)
console.log("\n[verify-panel-browser-flow] step 6: POST with no Origin header");
const cross = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
  method: "POST",
  body: JSON.stringify({ method: "security.metrics", params: {} }),
});
check("no-Origin POST → 200", cross.status === 200, `status=${cross.status}`);

// Step 7: POST with Origin: null (sandboxed iframe)
console.log("\n[verify-panel-browser-flow] step 7: POST with Origin: null (sandboxed iframe)");
const sandboxedNoNonce = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
  method: "POST",
  headers: { Origin: "null" },
  body: JSON.stringify({ method: "security.metrics", params: {} }),
});
check("sandboxed POST without nonce → 403", sandboxedNoNonce.status === 403, `status=${sandboxedNoNonce.status}`);
const nonce = get.body.match(/ocm-panel-nonce" content="([^"]+)"/)?.[1];
check("panel HTML embeds a nonce", !!nonce);
const sandboxed = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
  method: "POST",
  headers: { Origin: "null", "X-Panel-Nonce": nonce || "" },
  body: JSON.stringify({ method: "security.metrics", params: {} }),
});
check("sandboxed POST with nonce → 200", sandboxed.status === 200, `status=${sandboxed.status}`);
check("sandbox response ACAO null, no credentials", sandboxed.headers["access-control-allow-origin"] === "null" && sandboxed.headers["access-control-allow-credentials"] === undefined);

if (failures.length > 0) {
  console.error(`\n[verify-panel-browser-flow] ${failures.length} FAIL`);
  process.exit(1);
}
console.log("\n[verify-panel-browser-flow] all checks passed");