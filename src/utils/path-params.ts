/**
 * 路径参数别名归一（落盘侧收敛）。
 *
 * 策略引擎在**内存里**把一个路径参数展开成全部别名（path / file_path /
 * filepath / filePath / file / src / source / target / destination），
 * 这样任何一条按别名写的规则都能命中同一个路径。展开是必要的。
 *
 * 但这份展开结果会被原样落盘：`intervention.modified_params` 与
 * `previous_actions[].params` 里，同一个路径因此出现 9 份，一条约 423
 * 字节的纯噪声；而且展开后的形态对下游没有意义——数据标准里的规范名是
 * `path`。
 *
 * 本模块负责在**落盘边界**把别名收回成一个规范名。规则匹配仍在内存里
 * 用展开形态进行，收敛只发生在写出去的那一刻。
 */

/** 数据标准里的规范路径参数名。 */
export const CANONICAL_PATH_KEY = 'path';

/** 宿主与各类 wrapper 使用过的路径参数别名。 */
export const PATH_PARAM_ALIASES = [
  'file_path',
  'filepath',
  'filePath',
  'path',
  'file',
  'src',
  'source',
  'target',
  'destination',
] as const;

/**
 * 把路径参数别名收敛成单个规范名 `path`。
 *
 * 只在**所有已出现的别名指向同一个值**时才收敛。多路径工具
 * （复制/移动的 src + destination）各别名值不同，收敛会丢掉语义，
 * 这种情况下原样返回。
 *
 * 非字符串路径（数组、对象）不参与别名判定，原样保留。
 */
export function canonicalizePathParams<T extends Record<string, unknown> | undefined>(
  params: T
): T {
  if (!params || typeof params !== 'object') return params;

  const present: string[] = [];
  for (const alias of PATH_PARAM_ALIASES) {
    const value = params[alias];
    if (typeof value === 'string' && value.length > 0) {
      present.push(alias);
    }
  }
  if (present.length === 0) {
    return params;
  }

  const distinct = new Set(present.map((alias) => params[alias]));
  if (distinct.size !== 1) {
    // 多路径语义（src/destination 不同），收敛会丢信息——保持原样。
    return params;
  }

  const resolved = params[present[0]] as string;
  const result = { ...params } as Record<string, unknown>;
  for (const alias of PATH_PARAM_ALIASES) {
    delete result[alias];
  }
  result[CANONICAL_PATH_KEY] = resolved;
  return result as T;
}
