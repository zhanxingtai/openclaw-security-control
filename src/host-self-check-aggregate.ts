/**
 * 宿主自检命令的聚合识别名单。
 *
 * ## 与 host-internal-probe 的分工
 *
 * `host-internal-probe` 管**排除**（逐字命中已知只读探针形态 ⇒ 整个事件
 * 丢弃，如 lsof 端口探活 / systemctl is-system-running）；本模块管**压缩**
 * —— 刻意保留在 probe 排除面之外的那批自检命令（probe 注释里写明
 * 「都可能带凭据或拓扑信息，一律保留」）：
 *
 * - `gh auth token [--hostname …]`：可能吐出令牌；
 * - `claude auth status --json`；
 * - `openclaw plugins list --json` / `openclaw skills list --json`；
 * - spawn-broker / state-ownership / schema-inspection 宿主 worker 轮询
 *   （cmdline 无标记参数，含 process_exit）。
 *
 * 这些是**宿主自身的维护心跳**，不是 agent 动作；逐条落盘会把真正的子
 * 进程信号淹没在事件流里（实测采样窗口里这一类约占 process 事件的一半）。
 *
 * ## 为什么是聚合而不是排除
 *
 * 排除会让「宿主今天自检过多少次」这个事实完全消失，且这批命令里有的
 * 真带凭据/拓扑信息（gh auth token 的输出就是令牌），值得保留首条实例。
 * 聚合的语义：同一分钟内重复命中只落**一条** `x_openclaw_self_traffic_aggregate`
 * 计数事件（含 count / 首末时间戳），**首个实例仍即时原样落盘**（保延迟
 * 可见性），后续同窗口内折叠进计数。
 *
 * ## 安全边界（与采集层共同保证，见 runtime-hook-collector）
 *
 * - 有 agent 归属（tool_call_id 非空）的调用**不走聚合**——agent 行为
 *   必须逐条留痕；
 * - blocked / 带 risk_flags 的进程事件**永不聚合**；
 * - worker 匹配依赖内部模块路径（攻击者可仿造 `*.worker.js` 命名），
 *   仿造进程 worst-case 是被计进宿主自检计数——但它的首个实例仍即时
 *   落盘、计数异常激增反而更醒目，且带 risk_flags/blocked/归属时整套
 *   折叠逻辑绕行。失配方向是可接受的。
 */

/** 自检形态名（落在聚合计数事件的 `aggregate.pattern` 上）。 */
export type HostSelfCheckPatternName =
  | 'gh_auth_token'
  | 'claude_auth_status'
  | 'openclaw_plugins_list'
  | 'openclaw_skills_list'
  | 'spawn_broker_worker'
  | 'state_ownership_worker'
  | 'schema_inspection_worker';

type ArgvMatcher = (argv: string[]) => boolean;

/** 把命令行拆成 argv：宿主自检都是直接 spawn（不经 shell），空白分隔即参数。 */
function splitArgv(command: string): string[] {
  return command.trim().split(/\s+/).filter((token) => token.length > 0);
}

/** 取可执行文件名（忽略路径前缀）。 */
function basename(token: string | undefined): string {
  if (!token) return '';
  const idx = token.lastIndexOf('/');
  return idx === -1 ? token : token.slice(idx + 1);
}

/** `gh auth token [任意后缀]`（如 --hostname github.com）。 */
const matchGhAuthToken: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'gh' && argv[1] === 'auth' && argv[2] === 'token';

/** `claude auth status [--json]`。 */
const matchClaudeAuthStatus: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'claude' && argv[1] === 'auth' && argv[2] === 'status';

/**
 * `openclaw plugins list [--json]`（两种已观测形态：
 * `node …/openclaw.mjs plugins list --json` 与 `node …/openclaw plugins list --json`）。
 * `list` 之后只允许开关型参数（`--xxx`），任何位置参数都不匹配。
 */
const matchOpenclawPluginsList: ArgvMatcher = (argv) => {
  const idx = argv.indexOf('plugins');
  if (idx === -1 || argv[idx + 1] !== 'list') return false;
  const rest = argv.slice(idx + 2);
  if (!rest.every((token) => token.startsWith('-'))) return false;
  // 前缀必须是宿主 CLI 形态（node 或直接 openclaw），不接受任意包装器。
  const bin = basename(argv[0]);
  return bin === 'node' || bin === 'openclaw' || bin === 'openclaw.mjs' || bin.startsWith('openclaw');
};

/** `openclaw skills list [--json]`，形态约束同 plugins list。 */
const matchOpenclawSkillsList: ArgvMatcher = (argv) => {
  const idx = argv.indexOf('skills');
  if (idx === -1 || argv[idx + 1] !== 'list') return false;
  const rest = argv.slice(idx + 2);
  if (!rest.every((token) => token.startsWith('-'))) return false;
  const bin = basename(argv[0]);
  return bin === 'node' || bin === 'openclaw' || bin === 'openclaw.mjs' || bin.startsWith('openclaw');
};

/** spawn-broker 宿主 worker：`node …/process/spawn-broker/worker.js`。 */
const matchSpawnBrokerWorker: ArgvMatcher = (argv) =>
  argv.some((token) => token.endsWith('/process/spawn-broker/worker.js') || token === 'spawn-broker/worker.js');

/** state-ownership 宿主 worker（argv 尾部带 state sqlite 路径）。 */
const matchStateOwnershipWorker: ArgvMatcher = (argv) =>
  argv.some(
    (token) =>
      token.endsWith('/openclaw-state-ownership.worker.js') ||
      token === 'openclaw-state-ownership.worker.js'
  );

/**
 * schema-inspection 宿主 worker。已观测形态 argv[0] 直接是
 * `file:///app/dist/state/openclaw-agent-schema-inspection.worker.js`（worker
 * 以脚本 URL 自启动），所以按**任意 token 包含**匹配。
 */
const matchSchemaInspectionWorker: ArgvMatcher = (argv) =>
  argv.some((token) => token.includes('openclaw-agent-schema-inspection.worker.js'));

const PATTERN_MATCHERS: Array<{ name: HostSelfCheckPatternName; match: ArgvMatcher }> = [
  { name: 'gh_auth_token', match: matchGhAuthToken },
  { name: 'claude_auth_status', match: matchClaudeAuthStatus },
  { name: 'openclaw_plugins_list', match: matchOpenclawPluginsList },
  { name: 'openclaw_skills_list', match: matchOpenclawSkillsList },
  { name: 'spawn_broker_worker', match: matchSpawnBrokerWorker },
  { name: 'state_ownership_worker', match: matchStateOwnershipWorker },
  { name: 'schema_inspection_worker', match: matchSchemaInspectionWorker },
];

/**
 * 判断一条命令行是否属于宿主自检聚合名单。
 *
 * @param command 采集到的命令行（未经 shell 解析）
 * @returns 命中的自检形态名；不命中返回 null
 */
export function matchHostSelfCheckPattern(command: string): HostSelfCheckPatternName | null {
  if (!command) return null;
  const argv = splitArgv(command);
  if (argv.length === 0) return null;
  for (const pattern of PATTERN_MATCHERS) {
    if (pattern.match(argv)) return pattern.name;
  }
  return null;
}
