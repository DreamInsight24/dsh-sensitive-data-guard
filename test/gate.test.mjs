// GateCore 级别的集成测试：不起 DSH Host，用假 ctx 验证
// 分类 → 备份 → 令牌 → shell 深度层 → Python/Node 运行时钩子。
// 运行：node test/gate.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { GateCore } from '../lib/gate.js';

// 插件根目录：临时目录放在它的兄弟目录 _dg-run 下，跟着插件走，不绑机器。
const PLUGIN_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const TMP = path.join(PLUGIN_DIR, '..', '_dg-run', 'gate-tmp', `${process.pid}-${Date.now()}`);

function fakeCtx() {
  return {
    logger: { info() {}, warn() {}, error() {} },
    workingDirectory: null,
  };
}

function execFor(command, workdir, callId = 'call-1') {
  return {
    name: 'pwsh',
    callId,
    arguments: { command, workdir, description: 'test' },
    agent: { id: 'session-test' },
    signal: new AbortController().signal,
  };
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

test('端到端：令牌 → guard → shell 钩子（python/node）', async () => {
  const root = path.join(TMP, 'backup-root');
  const work = path.join(TMP, 'work');
  const victim = path.join(work, 'victim');
  // 工作区内部现在完全不设防，所以“越界”必须用工作区之外的路径来验证。
  const outside = path.join(TMP, 'outside');
  fs.mkdirSync(victim, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(victim, 'a.txt'), 'a');
  fs.writeFileSync(path.join(victim, 'b.txt'), 'b');
  fs.writeFileSync(path.join(outside, 'keep.txt'), 'keep');

  const core = new GateCore(fakeCtx(), {
    backup: { root, maxBatchFiles: 1000, maxBatchBytes: 1e12, quotaBytes: 1e12 },
  });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  const exec = execFor(`Remove-Item -Recurse -Force "${victim}"`, work);
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'allow');
  assert.ok(core.tokens.has(exec.callId), '应签发令牌');
  assert.equal(core.guard(exec), undefined);

  // shell 深度层：用同一个 command/workdir/session 应复用令牌，不重复备份
  const spec = {
    command: `Remove-Item -Recurse -Force "${victim}"`,
    workdir: work,
    sandboxPolicy: { mode: 'danger-full-access', workspaceRoot: work, sessionId: 'session-test' },
    env: {},
  };
  const prepared = await core.prepareShell(spec);
  assert.ok(prepared.env.DSH_DELETE_GUARD_ALLOW, '应注入允许清单');
  assert.ok(prepared.env.PYTHONPATH.includes('hooks'), '应注入 PYTHONPATH');
  assert.ok(prepared.env.NODE_OPTIONS.includes('--require'), '应注入 NODE_OPTIONS');
  assert.equal(core.shellTokens.size, 0, '令牌应被消费');

  const baseEnv = { ...process.env, ...prepared.env };

  // Python 钩子：批准范围内删除 → 允许
  const pyAllowed = spawnSync('python', ['-c', `import os; os.remove(r"${path.join(victim, 'a.txt')}")`], {
    env: baseEnv,
    stdio: 'ignore',
    windowsHide: true,
  });
  assert.equal(pyAllowed.status, 0, '批准范围内的 python 删除应成功');

  // Python 钩子：范围外删除 → 拒绝且文件还在
  const pyDenied = spawnSync('python', ['-c', `import os; os.remove(r"${path.join(outside, 'keep.txt')}")`], {
    env: baseEnv,
    stdio: 'ignore',
    windowsHide: true,
  });
  assert.notEqual(pyDenied.status, 0, '范围外的 python 删除应被拒绝');
  assert.ok(fs.existsSync(path.join(outside, 'keep.txt')), '被拒绝的文件应保留');

  // Node 钩子：批准范围内删除 → 允许
  const nodeAllowed = spawnSync(process.execPath, ['-e', `require('fs').rmSync(${JSON.stringify(path.join(victim, 'b.txt'))})`], {
    env: baseEnv,
    stdio: 'ignore',
    windowsHide: true,
  });
  assert.equal(nodeAllowed.status, 0, '批准范围内的 node 删除应成功');

  // Node 钩子：范围外删除 → 拒绝
  const nodeDenied = spawnSync(process.execPath, ['-e', `require('fs').rmSync(${JSON.stringify(path.join(outside, 'keep.txt'))})`], {
    env: baseEnv,
    stdio: 'ignore',
    windowsHide: true,
  });
  assert.notEqual(nodeDenied.status, 0, '范围外的 node 删除应被拒绝');
  assert.ok(fs.existsSync(path.join(outside, 'keep.txt')));

  // 没有令牌的破坏性调用 → guard 阻断
  const fresh = { name: 'pwsh', callId: 'call-unknown', arguments: { command: 'Get-ChildItem', workdir: work }, agent: { id: 's' } };
  assert.ok(typeof core.guard(fresh) === 'string');

  core.dispose();
});

test('区域模型：工作区不备份、敏感区备份并要求确认码', async () => {
  const root = path.join(TMP, 'root-zone');
  const work = path.join(TMP, 'zone-work');
  const victim = path.join(work, 'victim');
  const sensitive = path.join(TMP, 'zone-sensitive');
  fs.mkdirSync(victim, { recursive: true });
  fs.mkdirSync(sensitive, { recursive: true });
  fs.writeFileSync(path.join(victim, 'w.txt'), 'w');
  fs.writeFileSync(path.join(sensitive, 's.txt'), 's');

  const core = new GateCore(fakeCtx(), {
    backup: { root, maxBatchFiles: 1000, maxBatchBytes: 1e12, quotaBytes: 1e12 },
    policy: { triggerLevel: 'hard' },
  });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  // 工作区：放行且不产生批次
  const wsExec = execFor(`Remove-Item -Recurse -Force "${victim}"`, work, 'call-ws');
  const wsDecision = await core.onPreExecute(wsExec, async () => ({ kind: 'allow' }));
  assert.equal(wsDecision.kind, 'allow');
  assert.equal(core.tokens.get('call-ws').batchId, null, '工作区不应备份');

  // 敏感区：拦下来，并给出备份 + 确认码
  const seExec = execFor(`Remove-Item -Recurse -Force "${sensitive}"`, work, 'call-se');
  const seDecision = await core.onPreExecute(seExec, async () => ({ kind: 'allow' }));
  assert.equal(seDecision.kind, 'deny');
  assert.match(String(seDecision.reason), /确认码：\d{4}/);
  assert.match(String(seDecision.reason), /已经提前备份/);

  const firstBatch = core.tokens.get('call-se');
  // 未拿到令牌（被拦），所以这里应没有令牌
  assert.equal(firstBatch, undefined, '被拦截的调用不应签发令牌');

  // 取出确认码，带码重发 → 放行且复用同一批次
  const code = /确认码：(\d{4})/.exec(String(seDecision.reason))[1];
  const retry = execFor(`$env:DSH_GUARD_CONFIRM='${code}'; Remove-Item -Recurse -Force "${sensitive}"`, work, 'call-se-2');
  const retryDecision = await core.onPreExecute(retry, async () => ({ kind: 'allow' }));
  assert.equal(retryDecision.kind, 'allow');
  assert.ok(core.tokens.get('call-se-2').batchId, '带码放行应复用备份批次');

  core.dispose();
});

test('回归：PowerShell .NET 删除（变量路径）现在能定位目标 → 备份 + 确认码', async () => {
  const root = path.join(TMP, 'root-dotnet');
  const work = path.join(TMP, 'dotnet-work');
  const target = path.join(TMP, 'dotnet-target');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'a.txt'), 'a');
  fs.writeFileSync(path.join(target, 'b.txt'), 'b');

  const core = new GateCore(fakeCtx(), {
    backup: { root, maxBatchFiles: 1000, maxBatchBytes: 1e12, quotaBytes: 1e12 },
    policy: { triggerLevel: 'hard' },
  });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  // 2026-11-05 实测里被放行的那条命令形态：删的是变量路径。
  // 0.2.3 起变量表 + 管道回溯能还原出 $target，于是走正常的「备份 + 确认码」。
  const command = [
    `$target = '${target}'`,
    'Get-ChildItem -LiteralPath $target -File -Force | ForEach-Object {',
    '  try { [System.IO.File]::Delete($_.FullName); Write-Output ("DELETED: " + $_.FullName) }',
    '  catch { Write-Output ("FAILED: " + $_.Exception.Message) }',
    '}',
  ].join('\n');
  const exec = execFor(command, work, 'call-dotnet');
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny', '敏感区删除仍然要拦下来要确认码');
  assert.match(String(decision.reason), /确认码：\d{4}/);
  assert.match(String(decision.reason), /已经提前备份/, '能定位目标就应该先备份');
  assert.ok(fs.existsSync(path.join(target, 'a.txt')), '被拦截时不应删除任何文件');

  const variableCode = /确认码：(\d{4})/.exec(String(decision.reason))[1];
  const variableRetry = execFor(`$env:DSH_GUARD_CONFIRM='${variableCode}'; ${command}`, work, 'call-dotnet-1b');
  const variableDecision = await core.onPreExecute(variableRetry, async () => ({ kind: 'allow' }));
  assert.equal(variableDecision.kind, 'allow');
  assert.ok(core.tokens.get('call-dotnet-1b').batchId, '带码放行应复用备份批次');

  // 字面量路径的 .NET 删除：敏感区 → 备份 + 确认码。
  const literalPath = path.join(target, 'a.txt');
  const literal = execFor(`[System.IO.File]::Delete('${literalPath}')`, work, 'call-dotnet-2');
  const literalDecision = await core.onPreExecute(literal, async () => ({ kind: 'allow' }));
  assert.equal(literalDecision.kind, 'deny');
  assert.match(String(literalDecision.reason), /确认码：\d{4}/);
  assert.match(String(literalDecision.reason), /已经提前备份/);

  const code = /确认码：(\d{4})/.exec(String(literalDecision.reason))[1];
  const retry = execFor(`$env:DSH_GUARD_CONFIRM='${code}'; [System.IO.File]::Delete('${literalPath}')`, work, 'call-dotnet-3');
  const retryDecision = await core.onPreExecute(retry, async () => ({ kind: 'allow' }));
  assert.equal(retryDecision.kind, 'allow');
  assert.ok(core.tokens.get('call-dotnet-3').batchId, '带码放行应复用备份批次');

  core.dispose();
});

test('目标解析不出：走确认码放行（无备份），报告必须写明', async () => {
  const root = path.join(TMP, 'root-unresolved');
  const work = path.join(TMP, 'unresolved-work');
  fs.mkdirSync(work, { recursive: true });

  const core = new GateCore(fakeCtx(), {
    backup: { root, maxBatchFiles: 1000, maxBatchBytes: 1e12, quotaBytes: 1e12 },
    policy: { triggerLevel: 'hard' },
  });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  const command = 'Remove-Item -LiteralPath $env:DSH_SOMETHING_UNDEFINED -Recurse -Force';
  const first = await core.onPreExecute(execFor(command, work, 'call-unresolved-1'), async () => ({ kind: 'allow' }));
  assert.equal(first.kind, 'deny', '第一次必须拦下来要确认码');
  assert.match(String(first.reason), /目标无法静态确定/);
  assert.match(String(first.reason), /没有备份/, '报告必须明确告知没有备份');
  assert.match(String(first.reason), /确认码：\d{4}/);

  // 错误确认码：拒绝。
  const wrong = await core.onPreExecute(
    execFor(`$env:DSH_GUARD_CONFIRM='9999'; ${command}`, work, 'call-unresolved-2'),
    async () => ({ kind: 'allow' }),
  );
  assert.equal(wrong.kind, 'deny');
  assert.match(String(wrong.reason), /确认码不正确/);

  // 正确确认码：放行，且签发的令牌允许整条命令（含派生的 python/node 子进程）。
  const code = /确认码：(\d{4})/.exec(String(first.reason))[1];
  const retry = execFor(`$env:DSH_GUARD_CONFIRM='${code}'; ${command}`, work, 'call-unresolved-3');
  const decision = await core.onPreExecute(retry, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'allow');
  const token = core.tokens.get('call-unresolved-3');
  assert.equal(token.allowAll, true, '确认过的未解析命令需要 allowAll，否则子进程钩子会全部拒掉');
  assert.equal(token.batchId, null, '这种情况本来就没有备份');

  // shell 深度层：同一个 seam 里先拦一次拿到“shell 指纹”的码，带码重发应放行，
  // 且允许清单里必须写出 allowAll（否则派生的子进程会被钩子全部拒掉）。
  const baseSpec = {
    workdir: work,
    sandboxPolicy: { mode: 'danger-full-access', workspaceRoot: work, sessionId: 'session-test' },
    env: {},
  };
  let seamCode = null;
  try {
    await core.prepareShell({ ...baseSpec, command });
  } catch (error) {
    seamCode = /确认码：(\d{4})/.exec(String(error.message))?.[1] ?? null;
  }
  assert.ok(seamCode, 'shell 深度层也应该给出确认码');
  const prepared = await core.prepareShell({ ...baseSpec, command: `$env:DSH_GUARD_CONFIRM='${seamCode}'; ${command}` });
  const allow = JSON.parse(fs.readFileSync(prepared.env.DSH_DELETE_GUARD_ALLOW, 'utf8'));
  assert.equal(allow.allowAll, true);
  assert.deepEqual(allow.roots, []);

  core.dispose();
});

test('受保护目录优先于「工作区不保护」的短路', async () => {
  const root = path.join(TMP, 'root-prot');
  const work = path.join(TMP, 'prot-work');
  const secret = path.join(work, 'secret');
  fs.mkdirSync(secret, { recursive: true });
  fs.writeFileSync(path.join(secret, 'x.txt'), 'x');

  const core = new GateCore(fakeCtx(), {
    backup: { root },
    policy: { protectedPaths: ['**/prot-work/secret'] },
  }, { settingsDir: path.join(TMP, 'settings-prot') });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  const exec = execFor(`Remove-Item -Recurse -Force "${secret}"`, work, 'call-prot');
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny', '工作区内的受保护目录也必须被拒绝');
  core.dispose();
});

test('设置文件里的空 protectedPaths 不能清空配置里的保护目录', async () => {
  const settingsDir = path.join(TMP, 'settings-empty');
  fs.mkdirSync(path.join(settingsDir, 'data'), { recursive: true });
  fs.writeFileSync(
    path.join(settingsDir, 'data', 'settings.json'),
    JSON.stringify({
      triggerLevel: 'hard', mediumMinFiles: 10, mediumMinBytes: 67108864, protectedPaths: [],
    }),
  );
  const core = new GateCore(fakeCtx(), {
    backup: { root: path.join(TMP, 'root-overlay') },
    policy: { protectedPaths: ['**/overlay-secret/*'] },
  }, { settingsDir });

  // 配置底线不会被设置文件里的空数组覆盖。
  assert.throws(
    () => core.assertNotProtected(path.join(TMP, 'overlay-secret', 'x.txt'), 'targets'),
    /protectedPaths/,
    '空 settings.json 不应清空配置里的保护目录',
  );

  // UI 追加的项与配置底线合并，两边都生效。
  core.applySettings({ protectedPaths: ['**/ui-extra/*'] });
  assert.throws(() => core.assertNotProtected(path.join(TMP, 'ui-extra', 'y.txt'), 'targets'), /protectedPaths/);
  assert.throws(() => core.assertNotProtected(path.join(TMP, 'overlay-secret', 'x.txt'), 'targets'), /protectedPaths/);

  // UI 清空只删掉追加项，底线还在。
  core.applySettings({ protectedPaths: [] });
  assert.throws(() => core.assertNotProtected(path.join(TMP, 'overlay-secret', 'x.txt'), 'targets'), /protectedPaths/);
  assert.doesNotThrow(() => core.assertNotProtected(path.join(TMP, 'ui-extra', 'y.txt'), 'targets'));
  core.dispose();
});

test('cwdFor：服务缺失时回落到 Session 头里的 cwd', async () => {
  const core = new GateCore(fakeCtx(), { backup: { root: path.join(TMP, 'root-cwd') } });
  const cwdFixture = path.join(PLUGIN_DIR, '..', '_dg-run', 'cwd-fixture');
  const exec = { agent: { id: 's', session: { header: { cwd: cwdFixture } } } };
  assert.equal(await core.cwdFor(exec), cwdFixture);
  core.dispose();
});

test('cwd 落在 .dsh 里时，不能把工作区目标误判成「工作区」', async () => {
  const fakeDsh = path.join(TMP, 'fake-dsh');
  const core = new GateCore(fakeCtx(), { backup: { root: path.join(TMP, 'root-cwd2') } });
  core.dshHome = fakeDsh;
  // process.cwd() 在桌面版里就是 profile 目录；这种基准必须被丢弃。
  const zone = core.zoneForRoots([path.join(TMP, 'somewhere')], path.join(fakeDsh, 'profiles', 'desktop'));
  assert.equal(zone, 'sensitive', '无效的工作区基准必须回落成敏感区，而不是放行');
  core.dispose();
});

test('fail-closed：未知工具默认拒绝；备份根不可用时拒绝', async () => {
  const root = path.join(TMP, 'root2');
  const core = new GateCore(fakeCtx(), { backup: { root } });
  await core.start();
  const unknown = { name: 'mystery_tool', callId: 'u1', arguments: {}, agent: { id: 's' } };
  const decision = await core.onPreExecute(unknown, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.ok(String(decision.reason).includes('未知工具'));
  assert.ok(typeof core.guard(unknown) === 'string');
  core.dispose();
});
