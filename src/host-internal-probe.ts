/**
 * 宿主内部只读探针的识别（1.1.0 起）。
 *
 * 宿主网关在空闲期会周期性拉起一批**只读**的自身维护命令：端口探活
 * （lsof）、systemd 状态查询、busctl 版本查询、全局包根目录查询、
 * git 工作区状态查询、用户/路由/磁盘查询。实测一份 105 分钟的采样里
 * 1139 条 process_start 有约 560 条属于这一类——它们逐字重复（lsof
 * 一条命令就重复了 203 次），其中 360 条还带着 `self_protection_bypass`
 * 误标（宿主自己派生的进程本来就不该被 hook 覆盖），把真正的子进程信号
 * 淹没在事件流里。
 *
 * ## 判据：命令模式（argv 级精确匹配）
 *
 * 识别只看命令行本身，且要求**逐字命中**下表里的一条已知只读探针形态：
 * 不是正则模糊匹配，而是把命令行拆成 argv 后逐项比对。这样做的取舍是
 * 宿主改版换掉探针写法时规则失配——表现是噪声回来，而不是误杀别的进程。
 * 失配方向始终是安全的一侧。
 *
 * 宿主内部 worker（`node …/xxx.worker.js`）**不在**本表里：它们靠内部
 * 模块路径识别，而路径是攻击者可以仿造的（把文件命名成 `*.worker.js`
 * 就能让自己的进程被当成宿主内部进程消失），那会把失配方向翻到不安全
 * 的那一侧。宿主 worker 由另一条基于**子进程标记**的规则处理
 * （见 runtime-hook-collector 的 HOST_INTERNAL_COMMAND_MARKERS）。
 *
 * ## 明确不覆盖的形态（即使看起来无害也一律保留）
 *
 * - 任何 shell 包装的命令（argv[0] 是 `sh`/`bash`…，不是探针本体）；
 * - `ps` 不带 `-p <pid>`、`lsof` 不带具体端口、`getent passwd` 不带用户名、
 *   `ip route` 不带 `default`、`df` 不带 `-kP / /etc/hosts`；
 * - `git config` / `git remote`（远端地址可能带凭据）、`git fetch`/`push`；
 * - `gh auth token`、`crontab -l`、`npm config list`、`claude auth status`、
 *   `tailscale serve status`（都可能带凭据或拓扑信息）。
 */

/** 探针类别名（用于统计与留痕）。 */
export type HostInternalProbeName =
  | 'lsof_port_probe'
  | 'ps_single_pid_probe'
  | 'systemctl_state_probe'
  | 'busctl_version_probe'
  | 'global_package_root'
  | 'npm_config_globalconfig'
  | 'getent_passwd_user'
  | 'ip_default_route'
  | 'df_disk_usage'
  | 'git_workspace_probe';

type ArgvMatcher = (argv: string[]) => boolean;

/** 把命令行拆成 argv：宿主探针都是直接 spawn（不经 shell），空白分隔即参数。 */
function splitArgv(command: string): string[] {
  return command.trim().split(/\s+/).filter((token) => token.length > 0);
}

/** 取可执行文件名（忽略路径前缀）。 */
function basename(token: string | undefined): string {
  if (!token) return '';
  const idx = token.lastIndexOf('/');
  return idx === -1 ? token : token.slice(idx + 1);
}

/** lsof 端口探活：必须是「只看 LISTEN 端口 + 具体端口号」的形态。 */
const matchLsof: ArgvMatcher = (argv) => {
  if (basename(argv[0]) !== 'lsof') return false;
  let portSeen = false;
  let listenOnly = false;
  let noTcp = false;
  for (const token of argv.slice(1)) {
    if (token === '-nP') {
      noTcp = true;
      continue;
    }
    if (token === '-sTCP:LISTEN') {
      listenOnly = true;
      continue;
    }
    if (/^-iTCP:\d+$/.test(token)) {
      portSeen = true;
      continue;
    }
    // 只允许字段选择开关（-FpFcn / -Fpc 这类输出格式控制）。
    if (/^-F[A-Za-z0-9]+$/.test(token)) continue;
    return false;
  }
  // 少了 -sTCP:LISTEN 就是「列举该端口的全部连接」——那是侦察，不该被排除。
  return portSeen && listenOnly && noTcp;
};

/** ps 单进程探活：必须带 -p <pid> 且输出格式只到 -o <field>=。 */
const matchPs: ArgvMatcher = (argv) => {
  if (basename(argv[0]) !== 'ps') return false;
  if (argv[1] !== '-p') return false;
  if (!/^\d+$/.test(argv[2] || '')) return false;
  let i = 3;
  if (argv[i] === '-ww' || argv[i] === '-w') i += 1;
  let specs = 0;
  while (i < argv.length) {
    if (argv[i] !== '-o') return false;
    if (!/^[A-Za-z_][A-Za-z0-9_]*=$/.test(argv[i + 1] || '')) return false;
    specs += 1;
    i += 2;
  }
  return specs > 0;
};

/** systemd 状态探活。 */
const matchSystemctl: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'systemctl' &&
  argv.length === 3 &&
  argv[1] === '--system' &&
  argv[2] === 'is-system-running';

/** busctl 查询 systemd Manager 版本。 */
const matchBusctl: ArgvMatcher = (argv) => {
  if (basename(argv[0]) !== 'busctl') return false;
  const idx = argv.indexOf('get-property');
  if (idx === -1) return false;
  if (argv[idx + 1] !== 'org.freedesktop.systemd1') return false;
  return argv[argv.length - 1] === 'Version';
};

/** 全局包根目录查询（npm/pnpm/yarn）。 */
const matchGlobalPackageRoot: ArgvMatcher = (argv) => {
  const bin = basename(argv[0]);
  if (bin !== 'npm' && bin !== 'pnpm' && bin !== 'pnpm-native' && bin !== 'yarn') return false;
  return argv.length === 3 && argv[1] === 'root' && argv[2] === '-g';
};

/** npm 全局配置文件路径查询（只取单个已知键，不含凭据）。 */
const matchNpmConfigGlobalconfig: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'npm' &&
  argv.length === 4 &&
  argv[1] === 'config' &&
  argv[2] === 'get' &&
  argv[3] === 'globalconfig';

/** 单用户 passwd 解析（不带用户名时会枚举全部用户，不在此列）。 */
const matchGetentPasswd: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'getent' &&
  argv.length === 3 &&
  argv[1] === 'passwd' &&
  /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(argv[2] || '');

/** 默认路由查询。 */
const matchIpDefaultRoute: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'ip' &&
  argv.length === 5 &&
  argv[1] === '-4' &&
  argv[2] === 'route' &&
  argv[3] === 'show' &&
  argv[4] === 'default';

/** 磁盘占用探活。 */
const matchDf: ArgvMatcher = (argv) =>
  basename(argv[0]) === 'df' &&
  argv.length === 4 &&
  argv[1] === '-kP' &&
  argv[2] === '/' &&
  argv[3] === '/etc/hosts';

/** git 全局选项（不带子命令的那部分）。 */
const GIT_GLOBAL_FLAG_ONE = new Set([
  '--no-pager',
  '--paginate',
  '--literal-pathspecs',
  '--no-optional-locks',
  '--no-recurse-submodules',
]);
const GIT_GLOBAL_FLAG_TWO = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--exec-path',
]);

/** 剥掉 git 的全局选项，返回子命令部分。 */
function stripGitGlobalOptions(argv: string[]): string[] {
  let i = 1;
  while (i < argv.length) {
    const token = argv[i];
    if (GIT_GLOBAL_FLAG_TWO.has(token)) {
      i += 2;
      continue;
    }
    if (GIT_GLOBAL_FLAG_ONE.has(token)) {
      i += 1;
      continue;
    }
    if (
      token.startsWith('--git-dir=') ||
      token.startsWith('--work-tree=') ||
      token.startsWith('--namespace=') ||
      token.startsWith('--exec-path=')
    ) {
      i += 1;
      continue;
    }
    break;
  }
  return argv.slice(i);
}

/**
 * 允许的 git 只读形态。每一项都要求子命令与参数**完全**落在白名单里，
 * 任何多余参数（含 `config`/`remote`/`fetch`/`push`）都不匹配。
 */
const GIT_SAFE_FORMS: Array<(rest: string[]) => boolean> = [
  // rev-parse --show-toplevel [--verify HEAD^{commit}] [--verify --quiet HEAD]
  (rest) =>
    rest[0] === 'rev-parse' &&
    rest.includes('--show-toplevel') &&
    rest
      .slice(1)
      .every(
        (token) =>
          token === '--show-toplevel' ||
          token === '--verify' ||
          token === '--quiet' ||
          token === 'HEAD' ||
          token === 'HEAD^{commit}'
      ),
  // rev-parse --verify HEAD^{commit}
  (rest) =>
    rest.length === 3 && rest[0] === 'rev-parse' && rest[1] === '--verify' && rest[2] === 'HEAD^{commit}',
  // rev-parse --abbrev-ref HEAD
  (rest) =>
    rest.length === 3 && rest[0] === 'rev-parse' && rest[1] === '--abbrev-ref' && rest[2] === 'HEAD',
  // symbolic-ref --quiet HEAD
  (rest) =>
    rest.length === 3 && rest[0] === 'symbolic-ref' && rest[1] === '--quiet' && rest[2] === 'HEAD',
  // show-ref --verify --quiet refs/heads/<branch>
  (rest) =>
    rest.length === 4 &&
    rest[0] === 'show-ref' &&
    rest[1] === '--verify' &&
    rest[2] === '--quiet' &&
    rest[3].startsWith('refs/heads/'),
  // hash-object -t tree --stdin（无 -w：只算哈希、不写对象库）
  (rest) =>
    rest.length === 4 &&
    rest[0] === 'hash-object' &&
    rest[1] === '-t' &&
    rest[2] === 'tree' &&
    rest[3] === '--stdin',
  // diff -M <sha> --name-status -z
  (rest) =>
    rest.length === 5 &&
    rest[0] === 'diff' &&
    rest[1] === '-M' &&
    /^[0-9a-f]{40}$/.test(rest[2] || '') &&
    rest[3] === '--name-status' &&
    rest[4] === '-z',
  // ls-files --others --exclude-standard -z
  (rest) =>
    rest.length === 4 &&
    rest[0] === 'ls-files' &&
    rest[1] === '--others' &&
    rest[2] === '--exclude-standard' &&
    rest[3] === '-z',
];

/** git 工作区状态探针。 */
const matchGit: ArgvMatcher = (argv) => {
  if (basename(argv[0]) !== 'git') return false;
  const rest = stripGitGlobalOptions(argv);
  if (rest.length === 0) return false;
  return GIT_SAFE_FORMS.some((form) => form(rest));
};

const PROBE_MATCHERS: Array<{ name: HostInternalProbeName; match: ArgvMatcher }> = [
  { name: 'lsof_port_probe', match: matchLsof },
  { name: 'ps_single_pid_probe', match: matchPs },
  { name: 'systemctl_state_probe', match: matchSystemctl },
  { name: 'busctl_version_probe', match: matchBusctl },
  { name: 'global_package_root', match: matchGlobalPackageRoot },
  { name: 'npm_config_globalconfig', match: matchNpmConfigGlobalconfig },
  { name: 'getent_passwd_user', match: matchGetentPasswd },
  { name: 'ip_default_route', match: matchIpDefaultRoute },
  { name: 'df_disk_usage', match: matchDf },
  { name: 'git_workspace_probe', match: matchGit },
];

/**
 * 判断一条命令行是否属于宿主内部只读探针。
 *
 * @param command 采集到的命令行（未经 shell 解析）
 * @returns 命中的探针类别；不是宿主探针时返回 null
 */
export function matchHostInternalProbe(command: string): HostInternalProbeName | null {
  if (!command) return null;
  const argv = splitArgv(command);
  if (argv.length === 0) return null;
  for (const probe of PROBE_MATCHERS) {
    if (probe.match(argv)) return probe.name;
  }
  return null;
}

/** 带 agent 归属信息的字段（runtime hook 事件的子集）。 */
export interface AgentAttribution {
  session_id?: string;
  run_id?: string;
  agent_id?: string;
  tool_call_id?: string;
  tool_name?: string;
}

/**
 * 事件是否带有 agent 归属。
 *
 * 归属来自插件在 tool call 前后写入的运行时上下文（会话/工具调用 id）。
 * 带归属的事件一定是**某个 agent 动作的直接产物**，永远保留；没有归属
 * 的事件只可能是宿主自身的维护动作或无主进程——这是"能不能排除"的第一
 * 道闸门。
 */
export function hasAgentAttribution(event: AgentAttribution): boolean {
  return Boolean(
    event.session_id || event.run_id || event.agent_id || event.tool_call_id || event.tool_name
  );
}
