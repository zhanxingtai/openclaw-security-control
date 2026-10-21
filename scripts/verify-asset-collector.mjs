#!/usr/bin/env node
/**
 * AssetCollector end-to-end verification script (asset baseline/change/remove acceptance).
 *
 * Usage:
 *   npm run build && node scripts/verify-asset-collector.mjs
 *
 * Builds a throwaway fixture (agent config with an embedded MCP server +
 * token, one skill directory) in a temp dir, then drives the AssetCollector
 * through four phases and asserts on the local NDJSON output:
 *
 *   1. first run        → full baseline (3 'added' events)
 *   2. second run       → zero new events (state restored, nothing changed)
 *   3. token modified   → exactly 2 'changed' events (config + mcp_server),
 *                         and the obfuscated token decodes to the new value
 *   4. skill deleted    → exactly 1 'removed' event
 *
 * The key property under test: periodic scans do NOT repeat reports — only
 * real content changes produce events.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const pluginEntry = path.join(rootDir, 'dist', 'index.js');

if (!fs.existsSync(pluginEntry)) {
  console.error('Could not find dist/index.js. Run `npm run build` first.');
  process.exit(1);
}

const { AssetCollector, obfDecode } = await import(
  pathToFileURL(pluginEntry).href
);

// Minimal NDJSON-only collector. SDK-decoupled: the plugin no longer ships a
// public EventCollector class; verification scripts that just want events
// appended to a file can roll their own 4-method stub.
function makeLocalCollector(ndjsonPath) {
  return {
    initialize: async () => {},
    async report(event) {
      fs.appendFileSync(ndjsonPath, JSON.stringify(event) + '\n', 'utf8');
    },
    flush: async () => {},
    getStats: () => ({ queueSize: 0, totalFailed: 0, totalReported: 0 }),
    shutdown: async () => {},
  };
}

const TOKEN_V1 = 'ghp_verify_token_v1';
const TOKEN_V2 = 'ghp_verify_token_v2';

// Fixture
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-verify-'));
const configPath = path.join(work, 'openclaw.json');
const mcpPath = path.join(work, 'mcp.json');
const skillsRoot = path.join(work, 'skills');
const outputPath = path.join(work, 'asset-events.jsonl');
const statePath = path.join(work, 'asset-state.json');

function writeConfig(token) {
  fs.writeFileSync(
    configPath,
    JSON.stringify(
      {
        plugins: { 'sst-security-control-openclaw': { enabled: true } },
        mcpServers: {
          github: { command: 'npx', args: ['-y', 'server-github'], env: { GITHUB_TOKEN: token } },
        },
      },
      null,
      2
    ),
    'utf8'
  );
}

writeConfig(TOKEN_V1);
fs.mkdirSync(path.join(skillsRoot, 'alpha'), { recursive: true });
fs.writeFileSync(
  path.join(skillsRoot, 'alpha', 'SKILL.md'),
  '---\nname: alpha\nversion: 1.0.0\n---\n# Alpha\n',
  'utf8'
);

// Driver
function readEvents() {
  if (!fs.existsSync(outputPath)) return [];
  return fs
    .readFileSync(outputPath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function runOnce(action) {
  const collector = makeLocalCollector(outputPath);
  await collector.initialize();
  const asset = new AssetCollector(
    collector,
    {
      enabled: true,
      scanIntervalMs: 60000,
      fullSnapshotIntervalMs: 0,
      statePersistencePath: statePath,
      collectSkillPackage: true,
    },
    { hostId: 'verify-host' },
    { configPaths: [configPath], skillDirs: [skillsRoot], mcpPaths: [mcpPath] }
  );
  await asset.initialize();
  if (action) await action(asset);
  await asset.shutdown();
  await collector.shutdown();
}

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

// Phase 1: baseline
await runOnce();
let events = readEvents();
check(
  'phase1: first run reports full baseline (3 added)',
  events.length === 3 && events.every((e) => e.event_type === 'asset_add' && e.layer === 'asset'),
  `got ${events.length} events`
);

// Phase 1b: the skill event must carry a decodable ZIP package of the full dir.
const skillEvent = events.find((e) => e.asset_type === 'skill');
let packageOk = false;
if (skillEvent?.asset_package?.format === 'zip') {
  const zip = Buffer.from(skillEvent.asset_package.data, 'base64');
  packageOk =
    zip.readUInt32LE(0) === 0x04034b50 &&
    zip.includes(Buffer.from('SKILL.md')) &&
    skillEvent.asset_package.file_count === 1;
}
check('phase1b: skill event carries ZIP package of the full directory', packageOk);

// Restart, nothing changed
await runOnce();
events = readEvents();
check(
  'phase2: restart + rescan emits zero new events',
  events.length === 3,
  `total ${events.length} events`
);

// Modify the token
writeConfig(TOKEN_V2);
await runOnce();
events = readEvents();
const changed = events.filter((e) => e.event_type === 'asset_change');
const mcpChanged = changed.find((e) => e.asset_type === 'mcp_server');
check(
  'phase3: token change emits exactly 2 changed events',
  changed.length === 2,
  `got ${changed.length}`
);
check(
  'phase3: obfuscated token decodes to the new value',
  !!mcpChanged && obfDecode(mcpChanged.parsed.env.GITHUB_TOKEN) === TOKEN_V2
);
check(
  'phase3: no plaintext token anywhere in NDJSON',
  !fs.readFileSync(outputPath, 'utf8').includes(TOKEN_V1) &&
    !fs.readFileSync(outputPath, 'utf8').includes(TOKEN_V2)
);

// Phase 4: delete the skill
fs.rmSync(path.join(skillsRoot, 'alpha'), { recursive: true, force: true });
await runOnce();
events = readEvents();
const removed = events.filter((e) => e.event_type === 'asset_remove');
check(
  'phase4: skill deletion emits exactly 1 removed event',
  removed.length === 1 && removed[0].asset_type === 'skill',
  `got ${removed.length}`
);

console.log(`\nNDJSON output: ${outputPath}`);
const failed = results.filter((r) => !r.ok);
console.log(failed.length === 0 ? '\nAll checks passed.' : `\n${failed.length} check(s) FAILED.`);
process.exit(failed.length === 0 ? 0 : 1);
