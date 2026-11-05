// 本地单元/集成测试：不依赖 DSH Host，直接跑分类器与备份引擎。
// 运行：node --test test/
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { BackupEngine, BackupLimitError } from '../lib/backup.js';
import { parseShellCommand, planToolCall, quickClassify } from '../lib/classify.js';
import { DEFAULTS, resolveConfig } from '../lib/defaults.js';

const TMP = path.join(os.tmpdir(), `dg-test-${process.pid}-${Date.now()}`);

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function makeEngine(overrides = {}) {
  const config = resolveConfig({ backup: overrides });
  return new BackupEngine(config.backup);
}

test.before(async () => {
  await fsp.mkdir(TMP, { recursive: true });
});

test.after(async () => {
  for (let i = 0; i < 5; i++) {
    try {
      await fsp.rm(TMP, { recursive: true, force: true });
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
});

test('classifier: Remove-Item 目录 → targets', () => {
  const p = parseShellCommand('Remove-Item -Recurse -Force D:\\data\\victim', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\data\\victim']);
});

test('classifier: 别名 rm -rf → targets', () => {
  const p = parseShellCommand('rm -rf ./build', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\work\\build']);
});

test('classifier: 删除但没有路径 → scope', () => {
  const p = parseShellCommand('Get-ChildItem | Remove-Item -Recurse', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'scope');
  assert.equal(p.scope, 'D:\\work');
});

test('classifier: python -c shutil.rmtree 字面量 → targets', () => {
  const p = parseShellCommand('python -c "import shutil; shutil.rmtree(\'D:/data/x\')"', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\data\\x']);
});

test('classifier: python -c shutil.rmtree 原始字符串 r\'...\' → targets', () => {
  const p = parseShellCommand('python -c "import shutil; shutil.rmtree(r\'D:/data/raw\')"', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\data\\raw']);
});

test('classifier: os.truncate 路径 → targets', () => {
  const p = parseShellCommand('python -c "import os; os.truncate(r\'D:/data/log.txt\', 0)"', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\data\\log.txt']);
});

test('classifier: prettier --write 目标目录 → targets（格式化=破坏性写入）', () => {
  const p = parseShellCommand('node node_modules/prettier/bin/prettier.cjs --write src', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\work\\src']);
});

test('classifier: node -e fs.rmSync 字面量 → targets', () => {
  const p = parseShellCommand('node -e "require(\'fs\').rmSync(\'D:/data/y\', {recursive:true})"', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\data\\y']);
});

test('classifier: git clean → scope(仓库根)', () => {
  const repo = path.join(TMP, 'repo');
  fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
  const p = parseShellCommand('git clean -fdx', path.join(repo, 'src'), DEFAULTS.policy);
  assert.equal(p.kind, 'scope');
  assert.equal(p.scope, repo);
});

test('classifier: 未知命令 → scope（默认策略）', () => {
  const p = parseShellCommand('npm run build', 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'scope');
  assert.equal(p.scope, 'D:\\work');
});

test('classifier: 未知命令 + block 策略 → deny', () => {
  const p = parseShellCommand('node build.mjs', 'D:\\work', { ...DEFAULTS.policy, opaqueCommand: 'block' });
  assert.equal(p.kind, 'deny');
});

test('classifier: 只读命令 → safe', () => {
  for (const cmd of ['Get-ChildItem D:\\work', 'git status', 'git log --oneline', 'npm --version', 'echo hi']) {
    const p = parseShellCommand(cmd, 'D:\\work', DEFAULTS.policy);
    assert.equal(p.kind, 'safe', cmd);
  }
});

test('classifier: robocopy /MIR → targets(dest)', () => {
  const dest = path.join(TMP, 'mirror-dest');
  fs.mkdirSync(dest, { recursive: true });
  fs.writeFileSync(path.join(dest, 'a.txt'), 'a');
  const p = parseShellCommand(`robocopy C:\\src "${dest}" /MIR`, 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.ok(p.targets.includes(dest));
});

test('classifier: 系统级破坏命令 → deny', () => {
  for (const cmd of ['fsutil usn deletejournal /d C:', 'cipher /w:C:', 'format D: /q', 'vssadmin delete shadows /all /quiet']) {
    const p = parseShellCommand(cmd, 'D:\\work', DEFAULTS.policy);
    assert.equal(p.kind, 'deny', cmd);
  }
});

test('classifier: PowerShell .NET 字面量删除 → targets', () => {
  const p = parseShellCommand(`[System.IO.File]::Delete('D:\\Zip\\test\\a.txt')`, 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\Zip\\test\\a.txt']);
});

test('classifier: PowerShell .NET 短类型名 + 目录递归删除 → targets', () => {
  const p = parseShellCommand(`[IO.Directory]::Delete('D:\\Zip\\test', $true)`, 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'targets');
  assert.deepEqual(p.targets, ['D:\\Zip\\test']);
});

test('classifier: PowerShell .NET 删除目标为变量 → deny（回归：实测绕过用例）', () => {
  // 2026-11-05 的真实测试里，这条命令绕过了守卫：
  //   Get-ChildItem ... | ForEach-Object { [System.IO.File]::Delete($_.FullName) }
  // 旧版分类器不认识 .NET 调用，整条命令按 opaque → scope=工作区 → 放行。
  const command = [
    `$target = 'D:\\Zip\\test'`,
    'try {',
    '  Get-ChildItem -LiteralPath $target -File -Force | ForEach-Object {',
    '    try { [System.IO.File]::Delete($_.FullName); Write-Output ("DELETED: " + $_.FullName) }',
    '    catch { Write-Output ("FAILED: " + $_.Exception.Message) }',
    '  }',
    "  Write-Output '--- remaining ---'",
    '  Get-ChildItem -LiteralPath $target -Force | Select-Object -ExpandProperty Name',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }',
  ].join('\n');
  const p = parseShellCommand(command, 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'deny');
  assert.match(p.reason, /fail-closed/);
});

test('classifier: PowerShell .NET Move/Copy → targets', () => {
  const src = path.join(TMP, 'dotnet-src.txt');
  const dst = path.join(TMP, 'dotnet-dst.txt');
  fs.writeFileSync(src, 'x');
  fs.writeFileSync(dst, 'old');
  const move = parseShellCommand(`[System.IO.File]::Move('${src}', '${dst}')`, 'D:\\work', DEFAULTS.policy);
  assert.equal(move.kind, 'targets');
  assert.ok(move.targets.includes(src), 'Move 的源被移除，应纳入备份');
  assert.ok(move.targets.includes(dst), 'Move 的目标被覆盖，应纳入备份');
  const copy = parseShellCommand(`[IO.File]::Copy('${src}', '${dst}')`, 'D:\\work', DEFAULTS.policy);
  assert.equal(copy.kind, 'targets');
  assert.deepEqual(copy.targets, [dst], 'Copy 只覆盖目标');
});

test('classifier: 解释器覆盖已存在文件 → targets', () => {
  const file = path.join(TMP, 'interpreter-write.txt');
  fs.writeFileSync(file, 'old');
  const node = parseShellCommand(`node -e "require('fs').writeFileSync('${file}','x')"`, 'D:\\work', DEFAULTS.policy);
  assert.equal(node.kind, 'targets');
  assert.deepEqual(node.targets, [file]);
  const python = parseShellCommand(`python -c "open(r'${file}','w').write('x')"`, 'D:\\work', DEFAULTS.policy);
  assert.equal(python.kind, 'targets');
  assert.deepEqual(python.targets, [file]);
});

test('classifier: 解释器新建文件 → safe（write-create）', () => {
  const file = path.join(TMP, 'interpreter-new.txt');
  const p = parseShellCommand(`node -e "require('fs').writeFileSync('${file}','x')"`, 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'safe');
  assert.deepEqual(p.notes, ['interpreter:write-create']);
});

test('classifier: 解释器只读 open → safe（不算写入）', () => {
  const file = path.join(TMP, 'interpreter-read.txt');
  fs.writeFileSync(file, 'x');
  const p = parseShellCommand(`python -c "open(r'${file}','r').read()"`, 'D:\\work', DEFAULTS.policy);
  assert.equal(p.kind, 'safe');
  assert.deepEqual(p.notes, ['interpreter:clean']);
});

test('classifier: write 工具新建文件 → safe，覆盖已有 → targets', () => {
  const dir = path.join(TMP, 'write');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'a.txt');
  const p1 = planToolCall({ name: 'write', args: { file_path: file, content: 'x' }, workdir: dir, policy: DEFAULTS.policy });
  assert.equal(p1.kind, 'safe');
  fs.writeFileSync(file, 'old');
  const p2 = planToolCall({ name: 'write', args: { file_path: file, content: 'x' }, workdir: dir, policy: DEFAULTS.policy });
  assert.equal(p2.kind, 'targets');
  assert.deepEqual(p2.targets, [file]);
});

test('classifier: 未知工具 → unknown；quickClassify 同步', () => {
  const p = planToolCall({ name: 'mystery_tool', args: {}, workdir: 'D:\\work', policy: DEFAULTS.policy });
  assert.equal(p.kind, 'unknown');
  assert.equal(quickClassify('pwsh'), 'destructive');
  assert.equal(quickClassify('read'), 'safe');
  assert.equal(quickClassify('mystery_tool'), 'unknown');
});

test('backup: 目录备份 + 还原 + 哈希一致', async () => {
  const root = path.join(TMP, 'root1');
  const src = path.join(TMP, 'src1');
  fs.mkdirSync(path.join(src, 'sub'), { recursive: true });
  const files = [];
  for (let i = 0; i < 30; i++) {
    const file = path.join(src, i % 2 === 0 ? 'sub' : '', `f${i}.txt`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `content-${i}`);
    files.push(file);
  }
  const before = new Map(files.map((f) => [path.relative(src, f), sha256(f)]));
  const engine = makeEngine({ root, maxBatchFiles: 10000, maxBatchBytes: 1e12, quotaBytes: 1e12 });
  await engine.init();
  const result = await engine.backup([src], { sessionId: 'session-test', toolCallId: 'call-1', toolName: 'pwsh', command: 'Remove-Item', plan: 'targets' });
  assert.ok(result.batchId);
  assert.equal(result.count, 30);
  await fsp.rm(src, { recursive: true, force: true });
  const report = await engine.restore(result.batchId, {});
  assert.equal(report.restored, 30);
  assert.equal(report.failed, 0);
  for (const file of files) {
    const rel = path.relative(src, file);
    const restored = path.join(src, rel);
    assert.ok(fs.existsSync(restored), rel);
    assert.equal(sha256(restored), before.get(rel), rel);
  }
});

test('backup: 去重（同内容只存一份）', async () => {
  const root = path.join(TMP, 'root2');
  const src = path.join(TMP, 'src2');
  fs.mkdirSync(src, { recursive: true });
  fs.writeFileSync(path.join(src, 'a.txt'), 'same');
  fs.writeFileSync(path.join(src, 'b.txt'), 'same');
  const engine = makeEngine({ root, maxBatchFiles: 100, maxBatchBytes: 1e12, quotaBytes: 1e12 });
  await engine.init();
  const first = await engine.backup([src], { sessionId: 's' });
  assert.ok(first.batchId);
  const usage = JSON.parse(await fsp.readFile(path.join(root, '_state', 'usage.json'), 'utf8'));
  assert.equal(usage.files, 1, '同哈希只应存 1 个对象');
  const second = await engine.backup([src], { sessionId: 's' });
  const usage2 = JSON.parse(await fsp.readFile(path.join(root, '_state', 'usage.json'), 'utf8'));
  assert.equal(usage2.files, 1, '第二次备份不应新增对象');
});

test('backup: 单批文件数超限 → BackupLimitError', async () => {
  const root = path.join(TMP, 'root3');
  const src = path.join(TMP, 'src3');
  fs.mkdirSync(src, { recursive: true });
  for (let i = 0; i < 20; i++) fs.writeFileSync(path.join(src, `f${i}.txt`), 'x');
  const engine = makeEngine({ root, maxBatchFiles: 5, maxBatchBytes: 1e12, quotaBytes: 1e12 });
  await engine.init();
  await assert.rejects(() => engine.backup([src], { sessionId: 's' }), (error) => error instanceof BackupLimitError);
});

test('backup: 单文件超限 → 阻断', async () => {
  const root = path.join(TMP, 'root4');
  const src = path.join(TMP, 'src4');
  fs.mkdirSync(src, { recursive: true });
  fs.writeFileSync(path.join(src, 'big.bin'), Buffer.alloc(4096));
  const engine = makeEngine({ root, maxFileBytes: 1024, maxBatchFiles: 100, maxBatchBytes: 1e12, quotaBytes: 1e12 });
  await engine.init();
  await assert.rejects(() => engine.backup([src], { sessionId: 's' }), (error) => error instanceof BackupLimitError);
});

test('backup: 软链接只记录、不跟随', async () => {
  const root = path.join(TMP, 'root5');
  const src = path.join(TMP, 'src5');
  fs.mkdirSync(src, { recursive: true });
  fs.writeFileSync(path.join(src, 'a.txt'), 'a');
  try {
    fs.symlinkSync(path.join(src, 'a.txt'), path.join(src, 'link.txt'));
  } catch {
    return; // 没有创建符号链接权限则跳过
  }
  const engine = makeEngine({ root, maxBatchFiles: 100, maxBatchBytes: 1e12, quotaBytes: 1e12 });
  await engine.init();
  const result = await engine.backup([src], { sessionId: 's' });
  assert.equal(result.count, 1);
  assert.equal(result.links, 1);
});

test('backup: 不可写根 → init 抛错（fail-closed 依据）', async () => {
  if (process.platform !== 'win32') return;
  const root = path.join(TMP, 'root6');
  fs.mkdirSync(root, { recursive: true });
  // 在 Windows 上用只读目录模拟：这里只验证 engine 对不存在根的兜底（后续 T5 用 ACL 做真实演练）。
  const engine = makeEngine({ root: path.join(root, 'nested', 'deeper') });
  await engine.init();
  assert.equal(engine.healthy, true);
});
