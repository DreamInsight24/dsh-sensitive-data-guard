// 保护目录模式（.gitignore 风格）单元测试。
// 运行：node test/protect.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { compileProtectPatterns, isProtectedByPatterns, patternCoversTarget } from '../lib/paths.js';
import { GateCore } from '../lib/gate.js';

// 设置文件必须隔离：仓库里的 data/settings.json 不能影响单元测试。
const SETTINGS_DIR = path.join('D:\\dsh-workspaces', '_dg-run', 'protect-settings', `${process.pid}`);

test('protect: User/* 保护、!User/WorkSpace 放行', () => {
  const p = compileProtectPatterns(['User/*', '!User/WorkSpace']);
  assert.equal(isProtectedByPatterns(p, 'C:\\User\\Other\\file.txt'), true);
  assert.equal(isProtectedByPatterns(p, 'C:\\User\\WorkSpace\\project\\a.txt'), false);
  assert.equal(isProtectedByPatterns(p, 'D:\\User\\Other'), true);
  assert.equal(patternCoversTarget(p, 'C:\\'), true);
  assert.equal(patternCoversTarget(p, 'D:\\dsh-workspaces'), false);
});

test('protect: 盘符锚定与任意层级', () => {
  const p = compileProtectPatterns(['D:/work/secret', '*.tmp']);
  assert.equal(isProtectedByPatterns(p, 'D:\\work\\secret\\a.txt'), true);
  assert.equal(isProtectedByPatterns(p, 'C:\\work\\secret\\a.txt'), false);
  assert.equal(isProtectedByPatterns(p, 'D:\\a\\b\\c.tmp'), true);
  assert.equal(isProtectedByPatterns(p, 'D:\\a\\b\\c.txt'), false);
});

test('protect: ** 跨段与后写覆盖', () => {
  const p = compileProtectPatterns(['**/node_modules/**', '!**/keep/**']);
  assert.equal(isProtectedByPatterns(p, 'D:\\a\\node_modules\\x\\y.js'), true);
  assert.equal(isProtectedByPatterns(p, 'D:\\a\\node_modules\\keep\\y.js'), false);
});

test('protect: 空列表 / 注释 / 反斜杠写法', () => {
  assert.equal(isProtectedByPatterns(compileProtectPatterns([]), 'D:\\a'), false);
  const p = compileProtectPatterns(['# 注释', '', 'User\\*']);
  assert.equal(isProtectedByPatterns(p, 'C:\\User\\A\\b'), true);
});

test('gate: 配置 protectedPaths 后，命中模式的删除目标被阻断', () => {
  const core = new GateCore(
    { logger: { info() {}, warn() {}, error() {} }, workingDirectory: null },
    { policy: { protectedPaths: ['**/_dg-protect/*'] } },
    { settingsDir: SETTINGS_DIR },
  );
  assert.throws(() => core.assertNotProtected('D:\\dsh-workspaces\\_dg-protect\\victim', 'targets'), /protectedPaths/);
  assert.throws(() => core.assertNotProtected('D:\\dsh-workspaces\\_dg-protect\\victim', 'scope'), /protectedPaths/);
  assert.doesNotThrow(() => core.assertNotProtected('D:\\dsh-workspaces\\_dg-ok', 'targets'));
  core.dispose();
});
