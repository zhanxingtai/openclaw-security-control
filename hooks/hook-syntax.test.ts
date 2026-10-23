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

  it('三件套不含 shebang —— `#!` 只能出现在文件最开头，否则整份文件语法错', () => {
    // 棘轮：`#!` 是 JavaScript 里唯一"必须在字节 0"的语法，Node 只认字节 0
    // 处的 shebang。只要有任何东西被插到它前面（BOM、宿主安装器改写、
    // 编辑器、license header 注入），文件就变成 SyntaxError —— 而这三个
    // 文件正是 NODE_OPTIONS 的预加载目标，语法错 = 宿主进程在加载任何
    // 插件之前就退出，插件连把副本修回去的机会都没有。
    // 被 require 的模块不需要 shebang（只有直接 execve 才需要），所以这里
    // 直接钉死"不许有"。
    for (const name of HOOK_FILES) {
      const file = path.resolve(process.cwd(), 'hooks', name);
      const code = fs.readFileSync(file, 'utf8');
      expect(code.startsWith('#!')).toBe(false);
      expect(code).not.toMatch(/^\s*#!/m);
    }
  });

  it('三件套不往 stdout 写任何东西 —— 预加载不能占用别人的数据通道', () => {
    // NODE_OPTIONS=--require 扩散到宿主里每一个 node 进程，包括把 stdout
    // 当数据通道解析的机器进程（OpenClaw CLI 的 SQLite 只读 worker 就是：
    // 它的 stdout 是一段 JSON）。预加载在别人进程最早期抢到的 stdout 等于
    // 替别人改协议，一行非 JSON 日志就能让下游解析失败。2026-10-23 实测
    // 命中：`hooks mounter: loaded=2 …` 走 console.log → CLI 报
    // `SQLite read-only worker returned invalid JSON`。
    //
    // 白名单式检查只覆盖 stdout 写入点；提示/错误一律 console.error/warn。
    for (const name of HOOK_FILES) {
      const file = path.resolve(process.cwd(), 'hooks', name);
      const code = fs.readFileSync(file, 'utf8').replace(/^\s*\/\*[\s\S]*?\*\//g, '');
      expect(code, `${name} 不得写 stdout`).not.toMatch(
        /console\.(log|info|debug|dir|table|trace)\s*\(|process\.stdout\.write\s*\(/
      );
    }
  });
});
