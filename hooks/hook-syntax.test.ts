/**
 * hook 三件套（hook-mounter.js / runtime.js / network.js）通过
 * NODE_OPTIONS --require 注入任意版本的 Node 子进程，语法超出目标
 * 兼容面会直接崩掉子进程。本测试用 acorn 按固定 ecmaVersion 解析三件套，
 * 形成语法上限棘轮：任何人引入更新的语法都会失败。
 *
 * 兼容面：三件套最高用到 ES2020（可选链 ?./空值合并
 * ??），hooks/package.json 声明 engines node>=18；棘轮定 ES2020 比 engines
 * 下限更严，给未来留出余量。
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
// acorn 是 devDependency（仅测试用，不进运行时/安装包）。
const acorn = require('acorn') as typeof import('acorn');

const HOOK_FILES = ['hook-mounter.js', 'runtime.js', 'network.js'];
const SYNTAX_CEILING = 2020;

function stripShebang(code: string): string {
  // acorn 不接受 #! 行；替换为等长注释，保持行列号可定位。
  return code.startsWith('#!') ? '//' + code.slice(2) : code;
}

describe('hook 文件语法兼容棘轮', () => {
  for (const name of HOOK_FILES) {
    it(`${name} 不含 ES${SYNTAX_CEILING + 1}+ 语法（按 ES${SYNTAX_CEILING} 解析）`, () => {
      const file = path.resolve(process.cwd(), 'hooks', name);
      const code = stripShebang(fs.readFileSync(file, 'utf8'));
      expect(() => acorn.parse(code, { ecmaVersion: SYNTAX_CEILING })).not.toThrow();
    });
  }
});
