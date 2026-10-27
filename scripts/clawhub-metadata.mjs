/**
 * ClawHub 发布元数据的搬运与断言。
 *
 * 为什么单独成文件：ClawHub 的 publish 校验读的是**发布归档根的
 * package.json**（本仓 tgz 里即 `package/package.json`），不是仓库根那份。
 * build.js 生成 install 端清单时是白名单式挑选字段的，历史上只搬了
 * `openclaw.extensions`，把宿主兼容元数据全丢了——仓库根看着齐全，上架照样报
 * `package.json / Package manifest / Missing metadata`。搬字段这件事必须与
 * "该搬哪些"分开，且能被单测钉住，所以走纯函数模块（本仓既有先例：
 * version-check.mjs 同为 build 前置断言 + 对应单测）。
 *
 * 字段分工（同一份事实不允许出现在两处）：
 *   - compat / build / install / plugin
 *     权威全在 package.json#openclaw。install 规格（clawhubSpec / minHostVersion）
 *     曾经写在 openclaw.plugin.json#openclaw.install，但宿主清单里根本没有
 *     `openclaw` 这个顶层字段——ClawHub 的 `manifest-unknown-fields` 校验会把
 *     它判成非法字段。规格属于"包/安装元数据"，宿主认的位置是
 *     package.json#openclaw.install，所以搬家到那里，本模块只做搬运。
 */

/**
 * ClawHub code-plugin 上架要求的 package.json 字段。做成数据而不是散在
 * if 里，是为了让报错一次性列全所有缺口——逐个修、逐个重传是这类校验最费时
 * 的地方。
 * @type {ReadonlyArray<{ path: string, label: string }>}
 */
export const REQUIRED_PUBLISH_FIELDS = [
  { path: 'description', label: 'description' },
  { path: 'license', label: 'license' },
  { path: 'author', label: 'author' },
  { path: 'repository', label: 'repository' },
  { path: 'openclaw.extensions', label: 'openclaw.extensions（运行入口声明）' },
  {
    path: 'openclaw.compat.pluginApi',
    label: 'openclaw.compat.pluginApi（宿主 Plugin API 兼容区间）',
  },
  {
    path: 'openclaw.build.openclawVersion',
    label: 'openclaw.build.openclawVersion（构建时的宿主版本）',
  },
  { path: 'openclaw.install.clawhubSpec', label: 'openclaw.install.clawhubSpec（上架规格）' },
];

/**
 * @param {Record<string, any>} obj
 * @param {string} dotted
 * @returns {any}
 */
function readPath(obj, dotted) {
  return dotted.split('.').reduce((acc, key) => (acc == null ? acc : acc[key]), obj);
}

/**
 * 生成 install 端 package.json 的 `openclaw` 块。
 *
 * entryRel 是给 extensions 用的相对路径：仓库根是 TS 源码 `./index.ts`，
 * tgz 里是编译产物 `./index.js`（见 build.js 的 installPkg）。compat/build/
 * install/plugin 四块原样搬运——它们描述的是"我支持哪个宿主、从哪装"，
 * 与入口是 TS 还是 JS 无关。
 *
 * @param {Record<string, any>} rootPkg 仓库根 package.json
 * @param {string} entryRel 该清单自己的运行入口（相对包根）
 * @returns {Record<string, any>}
 */
export function buildInstallOpenClawMeta(rootPkg, entryRel) {
  const rootOpenClaw = rootPkg.openclaw ?? {};

  /** @type {Record<string, any>} */
  const meta = { extensions: [entryRel] };

  // 搬运而非复制：权威在 package.json#openclaw 那边。
  if (rootOpenClaw.compat !== undefined) meta.compat = rootOpenClaw.compat;
  if (rootOpenClaw.build !== undefined) meta.build = rootOpenClaw.build;
  if (rootOpenClaw.install !== undefined) meta.install = rootOpenClaw.install;
  if (rootOpenClaw.plugin !== undefined) meta.plugin = rootOpenClaw.plugin;

  return meta;
}

/**
 * 上架前断言：归档根 package.json 必须自带 ClawHub 要读的全部元数据。
 *
 * 在 npm pack **之前**抛错——错误 tgz 一旦进了 install/，就会一路传到用户的
 * 上传动作上，而报错现场离根因（build.js 的字段白名单）隔着一整条发布链路。
 *
 * @param {Record<string, any>} pkg 待写入 / 已写入的 package.json 内容
 * @param {string} source 出处，写进报错信息便于定位
 * @returns {{ checked: string[], pluginApi: string }}
 */
export function assertPublishMetadata(pkg, source) {
  const missing = REQUIRED_PUBLISH_FIELDS.filter(
    (field) => readPath(pkg, field.path) === undefined
  ).map((field) => field.label);

  if (missing.length > 0) {
    throw new Error(
      `${source} 缺少 ${missing.length} 项 ClawHub 上架必需的元数据：\n` +
        missing.map((label) => `  - ${label}`).join('\n') +
        `\n  提示：ClawHub 校验读的是**发布归档根**的 package.json（本仓 tgz 里即 ` +
        `package/package.json，由 build.js 生成），不是仓库根那份。仓库根齐全但 ` +
        `build.js 没搬进 install/ 端清单，正是本断言要拦的漂移。`
    );
  }

  const pluginApi = pkg.openclaw.compat.pluginApi;
  // OpenClaw 安装侧的兼容检查按空白切 token 并 AND 求值，`||` 会被当成一个字面
  // token 静默判否——发布校验放行、安装时报"requires plugin API X but host is
  // Y"。这里直接拦在构建期，别等用户装不上。
  if (/\s|\|\|/.test(pluginApi)) {
    throw new Error(
      `${source} 的 openclaw.compat.pluginApi = ${JSON.stringify(pluginApi)} 含有空白或 ` +
        `|| 。宿主安装侧按空白切 token 后 AND 求值，多段比较符（含 || 列表）会被 ` +
        `读成字面 token 从而静默判否——请写成单个比较符（如 ">=2026.9.4"）。`
    );
  }

  // clawhubSpec 必须是字符串（"clawhub:<包名>" 或 "clawhub:<包名>@<版本>"）。
  // 历史上它被写成对象（{ owner, package, category, ... }），宿主把这种形状
  // 当成非法字段拒收——那正是 ClawHub 上架报 manifest-unknown-fields 的根因之一。
  // 对象形状在这里直接拦在构建期。
  const clawhubSpec = pkg.openclaw.install?.clawhubSpec;
  if (typeof clawhubSpec !== 'string' || !clawhubSpec.startsWith('clawhub:')) {
    throw new Error(
      `${source} 的 openclaw.install.clawhubSpec = ${JSON.stringify(clawhubSpec)} 不是合法字符串。` +
        `宿主只认 "clawhub:<包名>" / "clawhub:<包名>@<版本>" 形状的字符串规格` +
        `（写成一个带 owner/category 的对象会被宿主当成非法字段拒收）。`
    );
  }

  return { checked: REQUIRED_PUBLISH_FIELDS.map((f) => f.path), pluginApi };
}