/**
 * 宿主清单（openclaw.plugin.json）的合法字段集。
 *
 * 为什么要有这个文件：ClawHub 上架校验（`clawhub package validate`）会把
 * 清单里"宿主不认识的顶层字段"和"宿主不认识的 contracts 键"判成硬错误
 * （manifest-unknown-fields / manifest-unknown-contracts）。宿主清单的
 * 合法字段集是**两个宿主版本**的交集：
 *
 *   - openclaw@2026.9.4 —— 本插件声明的最低宿主版本（compat.pluginApi 的下限）
 *   - openclaw@main     —— 校验时用户实际装着的宿主
 *
 * 两个版本的字段集并不互相包含（2026.9.4 有 embeddedExtensionFactories，
 * main 把它删了；main 又有 themes / decisionModels / uiCapabilities /
 * configGroups 等新字段）。取交集意味着"在最低版本上合法的清单，在新版本上
 * 也合法"——这正是宿主加载器（loadPluginManifest）逐版本读取字段的方式所
 * 要求的保守边界。
 *
 * 字段清单来自宿主的类型定义（openclaw 源码 src/plugins/manifest-types.ts 的
 * `export type PluginManifest = {`），契约键来自同目录的
 * manifest-contract-keys.ts 的 `PLUGIN_MANIFEST_CONTRACT_KEYS`。
 *
 * 单一事实源：scripts/verify-tarball.mjs（对打好的 tgz）与
 * tests/manifest-fields.test.ts（对仓库里的清单）都从这里取清单，
 * 两边不许各抄一份——抄两份必然漂移，而漂移的方向正好是"本地绿的、上架红的"。
 */

/** 宿主清单合法的顶层字段（2026.9.4 与 main 的交集）。 */
export const SUPPORTED_MANIFEST_FIELDS = Object.freeze([
  'id',
  'configSchema',
  'categories',
  'backupResources',
  'requiresPlugins',
  'enabledByDefault',
  'enabledByDefaultOnPlatforms',
  'legacyPluginIds',
  'autoEnableWhenConfiguredProviders',
  'kind',
  'channels',
  'providers',
  'providerCatalogEntry',
  'capabilityCatalogEntry',
  'modelSupport',
  'modelCatalog',
  'modelPricing',
  'modelIdNormalization',
  'providerEndpoints',
  'providerRequest',
  'secretProviderIntegrations',
  'cliBackends',
  'syntheticAuthRefs',
  'nonSecretAuthMarkers',
  'commandAliases',
  'cliCommands',
  'providerUsageAuthEnvVars',
  'providerAuthAliases',
  'providerAuthChoices',
  'activation',
  'setup',
  'doctorContract',
  'doctorHealthChecks',
  'sessionRouteStateOwners',
  'qaRunners',
  'dashboard',
  'controlUi',
  'mcpServers',
  'skills',
  'name',
  'description',
  'catalog',
  'version',
  'uiHints',
  'contracts',
  'transcriptSources',
  'mediaUnderstandingProviderMetadata',
  'imageGenerationProviderMetadata',
  'videoGenerationProviderMetadata',
  'musicGenerationProviderMetadata',
  'toolMetadata',
  'configContracts',
  'channelConfigs',
]);

/** `contracts` 下合法的键（2026.9.4 与 main 的交集）。 */
export const SUPPORTED_CONTRACT_KEYS = Object.freeze([
  'agentToolResultMiddleware',
  'trustedToolPolicies',
  'externalAuthProviders',
  'embeddingProviders',
  'speechProviders',
  'realtimeTranscriptionProviders',
  'realtimeVoiceProviders',
  'mediaUnderstandingProviders',
  'transcriptSourceProviders',
  'documentExtractors',
  'imageGenerationProviders',
  'videoGenerationProviders',
  'musicGenerationProviders',
  'webContentExtractors',
  'webFetchProviders',
  'webSearchProviders',
  'workerProviders',
  'usageProviders',
  'migrationProviders',
  'gatewayMethodDispatch',
  'tools',
]);

/** 宿主认的目录分类 slug（2026.9.4 与 main 的交集）。 */
export const SUPPORTED_CATEGORY_SLUGS = Object.freeze([
  'channels',
  'models',
  'memory',
  'context',
  'voice',
  'media',
  'web',
  'tools',
  'runtime',
  'gateway',
  'security',
  'other',
]);

/**
 * 找出清单里宿主不认识的顶层字段。
 *
 * @param {Record<string, any>} manifest
 * @returns {string[]} 非法字段名（按清单里的出现顺序）
 */
export function findUnknownManifestFields(manifest) {
  if (!manifest || typeof manifest !== 'object') return [];
  const known = new Set(SUPPORTED_MANIFEST_FIELDS);
  return Object.keys(manifest).filter((key) => !known.has(key));
}

/**
 * 找出 `contracts` 里宿主不认识的键。
 *
 * @param {Record<string, any>} manifest
 * @returns {string[]} 非法键名
 */
export function findUnknownContractKeys(manifest) {
  const contracts = manifest?.contracts;
  if (!contracts || typeof contracts !== 'object' || Array.isArray(contracts)) return [];
  const known = new Set(SUPPORTED_CONTRACT_KEYS);
  return Object.keys(contracts).filter((key) => !known.has(key));
}

/**
 * 找出宿主不认识的分类 slug。
 *
 * @param {Record<string, any>} manifest
 * @returns {string[]} 非法 slug
 */
export function findUnknownCategories(manifest) {
  const categories = manifest?.categories;
  if (!Array.isArray(categories)) return [];
  const known = new Set(SUPPORTED_CATEGORY_SLUGS);
  return categories.filter((slug) => !known.has(slug));
}
