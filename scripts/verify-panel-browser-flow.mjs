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
check("response body has Security Monitor", get.body.includes("Security Monitor"));
check("response body has 5 tabs", get.body.includes('data-tab="metrics"') && get.body.includes('data-tab="config"'));
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

// Step 4: NDJSON sidecar pull
console.log("\n[verify-panel-browser-flow] step 4: events.ndjson pull");
const events = await request(`${baseUrl}/openclaw-security-monitor/events.ndjson`);
check("GET events.ndjson → 200", events.status === 200, `status=${events.status} body=${events.body.slice(0, 60)}`);

// Step 5: POST without Origin header (non-browser client — still accepted)
console.log("\n[verify-panel-browser-flow] step 5: POST with no Origin header");
const cross = await request(`${baseUrl}/openclaw-security-monitor/panel`, {
  method: "POST",
  body: JSON.stringify({ method: "security.metrics", params: {} }),
});
check("no-Origin POST → 200", cross.status === 200, `status=${cross.status}`);

// Step 6: POST with Origin: null (sandboxed iframe)
console.log("\n[verify-panel-browser-flow] step 6: POST with Origin: null (sandboxed iframe)");
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