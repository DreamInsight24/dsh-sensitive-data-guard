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
    policy: { triggerLevel: 'hard', confirmVia: 'code' },
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
    policy: { triggerLevel: 'hard', confirmVia: 'code' },
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
    policy: { triggerLevel: 'hard', confirmVia: 'code' },
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

/**
 * 带「用户问答服务」的假 ctx：模拟 DSH 把问题弹到用户界面上。
 * choice 决定用户点了什么：allow（允许执行）/ deny（拦截）/ 抛错（模拟没有 UI 客户端）。
 */
function fakeCtxWithUser(choice) {
  const agent = { id: 'session-test' };
  const seen = [];
  const LABEL = {
    allow: '允许执行',
    deny: '拦截',
    trust: '信任并加入白名单',
    once: '仅本次允许',
  };
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    workingDirectory: null,
    seen,
    get(name) {
      if (name === 'agents') {
        return { get: (id) => (id === 'session-test' ? agent : undefined), roots: () => [agent] };
      }
      if (name === 'tools') {
        return {
          get: (toolName) => (toolName === 'config2ds'
            ? {
                name: 'config2ds',
                description: '把配置转换成 DS 格式（只读）',
                parameters: { type: 'object', properties: { action: { type: 'string', enum: ['doc', 'json'] } } },
              }
            : undefined),
        };
      }
      if (name === 'userQuestions') {
        return {
          async ask(request) {
            seen.push(request);
            if (choice === 'throw') {
              const error = new Error('no user-questions answerer accepted the request');
              error.code = 'NO_PROVIDER';
              throw error;
            }
            return {
              answers: [{
                id: request.questions[0].id,
                selected: [LABEL[choice] ?? '拦截'],
              }],
            };
          },
        };
      }
      return undefined;
    },
  };
  return ctx;
}

test('弹窗确认：用户点「允许执行」就直接放行，全程没有确认码', async () => {
  const root = path.join(TMP, 'root-popup-allow');
  const work = path.join(TMP, 'popup-work');
  const target = path.join(TMP, 'popup-target');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'a.txt'), 'a');

  const ctx = fakeCtxWithUser('allow');
  const core = new GateCore(ctx, { backup: { root } });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  const exec = execFor(`Remove-Item -Recurse -Force "${target}"`, work, 'call-popup-allow');
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'allow', '用户在弹窗里点了允许，这一次就应该放行');
  assert.equal(core.tokens.get('call-popup-allow').batchId !== null, true, '放行前必须已经备份');
  assert.equal(core.guard(exec), undefined);

  // 问题确实发给了用户，正文里带目标与备份信息；且**没有任何确认码**留给模型。
  assert.equal(ctx.seen.length, 1, '应该只问一次');
  const question = ctx.seen[0].questions[0];
  assert.match(question.detail, /popup-target/, '弹窗里要写清楚删的是哪儿');
  assert.match(question.detail, /已经提前备份/);
  assert.doesNotMatch(JSON.stringify(question), /确认码：\d{4}/);
  assert.deepEqual(question.options.map((o) => o.label), ['允许执行', '拦截']);

  core.dispose();
});

test('弹窗确认：用户点「拦截」→ 阻断，且不给确认码', async () => {
  const root = path.join(TMP, 'root-popup-deny');
  const work = path.join(TMP, 'popup-work2');
  const target = path.join(TMP, 'popup-target2');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'a.txt'), 'a');

  const core = new GateCore(fakeCtxWithUser('deny'), { backup: { root } });
  await core.start();
  const exec = execFor(`Remove-Item -Recurse -Force "${target}"`, work, 'call-popup-deny');
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.match(String(decision.reason), /拦截/);
  assert.doesNotMatch(String(decision.reason), /确认码：\d{4}/, '弹窗模式下不应该再出现 4 位确认码');
  assert.equal(core.tokens.has('call-popup-deny'), false);
  core.dispose();
});

test('弹窗确认：问不到用户（没有 UI 客户端）→ fail-closed 阻断', async () => {
  const root = path.join(TMP, 'root-popup-none');
  const work = path.join(TMP, 'popup-work3');
  const target = path.join(TMP, 'popup-target3');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'a.txt'), 'a');

  const core = new GateCore(fakeCtxWithUser('throw'), { backup: { root } });
  await core.start();
  const exec = execFor(`Remove-Item -Recurse -Force "${target}"`, work, 'call-popup-none');
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.match(String(decision.reason), /fail-closed/);
  assert.doesNotMatch(String(decision.reason), /确认码：\d{4}/);
  core.dispose();
});

test('弹窗确认：目标解析不出时同样弹窗，并写明没有备份', async () => {
  const root = path.join(TMP, 'root-popup-unresolved');
  const work = path.join(TMP, 'popup-work4');
  fs.mkdirSync(work, { recursive: true });

  const ctx = fakeCtxWithUser('allow');
  const core = new GateCore(ctx, { backup: { root } });
  await core.start();
  const command = 'Remove-Item -LiteralPath $env:DSH_NOPE -Recurse -Force';
  const exec = execFor(command, work, 'call-popup-unres');
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'allow');
  assert.equal(core.tokens.get('call-popup-unres').allowAll, true);
  assert.match(ctx.seen[0].questions[0].detail, /没有备份/);
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

test('fail-closed：未知工具默认弹窗；问不到人时阻断', async () => {
  const root = path.join(TMP, 'root2');
  const core = new GateCore(fakeCtx(), { backup: { root } }, { settingsDir: path.join(TMP, 'settings-failclosed') });
  await core.start();
  const unknown = { name: 'mystery_tool', callId: 'u1', arguments: {}, agent: { id: 's' } };
  const decision = await core.onPreExecute(unknown, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.match(String(decision.reason), /mystery_tool/);
  assert.match(String(decision.reason), /fail-closed/);
  // prompt 模式下异步路径已经处理过，同步 guard 不应再重复阻断。
  assert.equal(core.guard(unknown), undefined);
  core.dispose();
});

test('unknownTool=deny：未知工具直接阻断，不弹窗', async () => {
  const ctx = fakeCtxWithUser('allow');
  const core = new GateCore(ctx, {
    backup: { root: path.join(TMP, 'root-unknown-deny') },
    policy: { unknownTool: 'deny' },
  }, { settingsDir: path.join(TMP, 'settings-unknown-deny') });
  await core.start();
  const unknown = { name: 'mystery_tool', callId: 'u2', arguments: {}, agent: { id: 'session-test' } };
  const decision = await core.onPreExecute(unknown, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.match(String(decision.reason), /未知工具/);
  assert.equal(ctx.seen.length, 0, 'deny 模式不应弹窗');
  assert.ok(typeof core.guard(unknown) === 'string');
  core.dispose();
});

test('未知工具：弹窗摊开工具信息与本次参数，信任后加入白名单并放行', async () => {
  const settingsDir = path.join(TMP, 'settings-trust');
  const ctx = fakeCtxWithUser('trust');
  const core = new GateCore(ctx, {
    backup: { root: path.join(TMP, 'root-trust') },
    policy: { unknownTool: 'prompt' },
  }, { settingsDir });
  await core.start();
  assert.equal(core.ready, true, core.initError ?? '');

  const exec = {
    name: 'config2ds', callId: 'u3', arguments: { action: 'doc' },
    agent: { id: 'session-test' }, signal: new AbortController().signal,
  };
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'allow');
  assert.ok(core.policy.safeTools.includes('config2ds'), '信任后应立刻生效');
  assert.equal(core.guard(exec), undefined);

  // 设置文件已持久化，重启后仍然受信任。
  const saved = JSON.parse(fs.readFileSync(path.join(settingsDir, 'data', 'settings.json'), 'utf8'));
  assert.ok(saved.safeTools.includes('config2ds'));

  // 弹窗内容必须摊开工具说明与本次调用参数。
  assert.equal(ctx.seen.length, 1);
  const question = ctx.seen[0].questions[0];
  assert.match(question.detail, /config2ds/);
  assert.match(question.detail, /把配置转换成 DS 格式/);
  assert.match(question.detail, /"action"\s*:\s*"doc"/);
  assert.match(question.detail, /不在守卫的安全清单里/);
  assert.deepEqual(
    question.options.map((o) => o.label),
    ['信任并加入白名单', '仅本次允许', '拦截'],
  );

  // 第二次调用同一工具：不再弹窗，直接放行。
  const exec2 = { ...exec, callId: 'u4' };
  const decision2 = await core.onPreExecute(exec2, async () => ({ kind: 'allow' }));
  assert.equal(decision2.kind, 'allow');
  assert.equal(ctx.seen.length, 1, '已信任的工具不应再弹窗');
  core.dispose();
});

test('未知工具：仅本次允许 → 放行但不加白，下次仍问', async () => {
  const ctx = fakeCtxWithUser('once');
  const core = new GateCore(ctx, {
    backup: { root: path.join(TMP, 'root-once') },
    policy: { unknownTool: 'prompt' },
  }, { settingsDir: path.join(TMP, 'settings-once') });
  await core.start();

  const exec = {
    name: 'config2ds', callId: 'u5', arguments: { action: 'doc' },
    agent: { id: 'session-test' }, signal: new AbortController().signal,
  };
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'allow');
  assert.ok(!core.policy.safeTools.includes('config2ds'), '仅本次允许不应写入白名单');

  const exec2 = { ...exec, callId: 'u6' };
  const decision2 = await core.onPreExecute(exec2, async () => ({ kind: 'allow' }));
  assert.equal(decision2.kind, 'allow');
  assert.equal(ctx.seen.length, 2, '仅本次允许之后，下次调用仍应弹窗');
  core.dispose();
});

test('未知工具：用户拦截 → 阻断', async () => {
  const ctx = fakeCtxWithUser('deny');
  const core = new GateCore(ctx, {
    backup: { root: path.join(TMP, 'root-unknown-deny-user') },
    policy: { unknownTool: 'prompt' },
  }, { settingsDir: path.join(TMP, 'settings-unknown-deny-user') });
  await core.start();
  const exec = {
    name: 'config2ds', callId: 'u7', arguments: { action: 'doc' },
    agent: { id: 'session-test' }, signal: new AbortController().signal,
  };
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.match(String(decision.reason), /config2ds/);
  assert.ok(!core.policy.safeTools.includes('config2ds'));
  core.dispose();
});

test('未知工具：弹窗不可达 → fail-closed 阻断，并提示手工加白', async () => {
  const ctx = fakeCtxWithUser('throw');
  const core = new GateCore(ctx, {
    backup: { root: path.join(TMP, 'root-unknown-none') },
    policy: { unknownTool: 'prompt' },
  }, { settingsDir: path.join(TMP, 'settings-unknown-none') });
  await core.start();
  const exec = {
    name: 'config2ds', callId: 'u8', arguments: { action: 'doc' },
    agent: { id: 'session-test' }, signal: new AbortController().signal,
  };
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny');
  assert.match(String(decision.reason), /fail-closed/);
  assert.match(String(decision.reason), /policy\.safeTools/);
  core.dispose();
});

test('受信任工具：已知破坏性工具不能加白', () => {
  const core = new GateCore(fakeCtx(), { backup: { root: path.join(TMP, 'root-trust-deny') } }, { settingsDir: path.join(TMP, 'settings-trust-deny') });
  assert.equal(core.trustTool('delete'), false);
  assert.equal(core.trustTool('pwsh'), false);
  assert.equal(core.trustTool('plugin_manager'), false);
  assert.equal(core.trustTool(''), false);
  assert.equal(core.trustTool('config2ds'), true);
  assert.ok(core.policy.safeTools.includes('config2ds'));
  core.dispose();
});

test('受信任工具：仍然不能碰受保护目录', async () => {
  const core = new GateCore(fakeCtx(), {
    backup: { root: path.join(TMP, 'root-trust-prot') },
    policy: { safeTools: ['config2ds'], protectedPaths: ['**/trust-secret/*'] },
  }, { settingsDir: path.join(TMP, 'settings-trust-prot') });
  await core.start();
  const target = path.join(TMP, 'trust-secret', 'x.txt');
  const exec = { name: 'config2ds', callId: 'u9', arguments: { file_path: target }, agent: { id: 's' } };
  const decision = await core.onPreExecute(exec, async () => ({ kind: 'allow' }));
  assert.equal(decision.kind, 'deny', '受信任工具也不能写受保护目录');
  core.dispose();
});

test('设置页 safeTools：空数组不能清空配置底线', async () => {
  const settingsDir = path.join(TMP, 'settings-safetools');
  fs.mkdirSync(path.join(settingsDir, 'data'), { recursive: true });
  fs.writeFileSync(
    path.join(settingsDir, 'data', 'settings.json'),
    JSON.stringify({ safeTools: [] }),
  );
  const core = new GateCore(fakeCtx(), {
    backup: { root: path.join(TMP, 'root-safetools') },
    policy: { safeTools: ['config-base'] },
  }, { settingsDir });
  assert.ok(core.policy.safeTools.includes('config-base'), '配置底线不会被设置文件清空');

  core.applySettings({ safeTools: ['config-ui'] });
  assert.ok(core.policy.safeTools.includes('config-base'));
  assert.ok(core.policy.safeTools.includes('config-ui'));

  // 破坏性工具名会被 sanitizePatch 过滤掉。
  core.applySettings({ safeTools: ['delete', 'config-ui'] });
  assert.ok(!core.policy.safeTools.includes('delete'));
  assert.ok(core.policy.safeTools.includes('config-ui'));
  core.dispose();
});
