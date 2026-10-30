/**
 * 「操作目标路径」参数名别名表 —— 单源。
 *
 * 宿主各框架对「写文件 / 读文件的目标路径」的命名不统一（`file_path` /
 * `path` / `filePath` / `filepath`，移动复制类的 `src` / `source` /
 * `target` / `destination`）。两处消费方语义不同但**必须看到同一组键**：
 * `src/store.ts` 的 `normalizeFilePathParams` 把别名归一到同一组键；
 * `src/intervention/SelfProtection.ts` 按目标路径判定是否写入插件自有资产。
 * 两边不一致会让某一侧看不到目标 ⇒ 只能单源。
 */
export const FILE_PATH_PARAM_ALIASES: readonly string[] = [
  'file_path',
  'filepath',
  'filePath',
  'path',
  'file',
  'src',
  'source',
  'target',
  'destination',
];
