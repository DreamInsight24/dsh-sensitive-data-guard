#!/usr/bin/env node
// 敏感数据守卫 CLI：status / restore / dry-run / gc。
// 运行示例：
//   node bin/delete-guard.mjs status
//   node bin/delete-guard.mjs restore latest --force
//   node bin/delete-guard.mjs dry-run -- Remove-Item -Recurse -Force D:\tmp\victim
//   node bin/delete-guard.mjs dry-run --tool write --path D:\work\a.txt
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { DEFAULTS, resolveConfig } from '../lib/defaults.js';
import { BackupEngine, formatBytes } from '../lib/backup.js';
import { AuditLog } from '../lib/audit.js';
import { parseShellCommand, planToolCall } from '../lib/classify.js';
import { toAbsolute } from '../lib/paths.js';

const PLUGIN_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

function usage() {
  console.log(`敏感数据守卫 CLI

用法：
  delete-guard status [--root DIR] [--json]
  delete-guard restore <批次|latest> [--root DIR] [--to DIR] [--force] [--dry-run]
  delete-guard dry-run -- <shell 命令...> [--workdir DIR] [--root DIR]
  delete-guard dry-run --tool write --path FILE [--workdir DIR] [--root DIR]
  delete-guard gc [--root DIR]

批次 id 形如 2026-11-05/session-xxx/0001。
`);
}

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  let command = null;
  let rest = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      rest = argv.slice(i + 1);
      break;
    }
    if (arg.startsWith('--')) {
      const [key, inline] = arg.slice(2).split('=', 2);
      if (inline !== undefined) {
        flags[key] = inline;
      } else if (['json', 'force', 'dry-run', 'help'].includes(key)) {
        flags[key] = true;
      } else {
        flags[key] = argv[++i];
      }
      continue;
    }
    if (command === null) command = arg;
    else positional.push(arg);
  }
  return { command, positional, flags, rest };
}

function makeEngine(flags) {
  const config = resolveConfig({ backup: { root: flags.root ?? DEFAULTS.backup.root } });
  return { config, engine: new BackupEngine(config.backup) };
}

async function printStatus(flags) {
  const { config, engine } = makeEngine(flags);
  await engine.init();
  const status = await engine.status();
  const audit = new AuditLog(engine.root);
  const recent = await audit.recent(300);
  const sysmon = [...recent].reverse().find((e) => e.event === 'sysmon') ?? null;
  const gateEvents = recent.filter((e) => e.event === 'gate' || e.event === 'bypass' || e.event === 'backup').slice(-5);
  if (flags.json) {
    console.log(JSON.stringify({ status, sysmon, recent: gateEvents }, null, 2));
    return 0;
  }
  console.log('== 敏感数据守卫 状态 ==');
  console.log(`备份根：${status.root}`);
  console.log(`健康：${status.healthy ? '正常' : `异常（${status.healthError}）`}`);
  console.log(`占用：${formatBytes(status.usage.bytes)} / ${formatBytes(status.limits.quotaBytes)}（对象 ${status.usage.files} 个）`);
  console.log(`批次：${status.batches} 个；最近：${status.latestBatch ?? '无'}`);
  console.log(`限额：单文件 ${formatBytes(status.limits.maxFileBytes)}；单批 ${formatBytes(status.limits.maxBatchBytes)} / ${status.limits.maxBatchFiles} 个文件；保留 ${status.limits.retentionDays} 天`);
  if (sysmon) {
    console.log(`Sysmon（最近一次检测 ${sysmon.at}）：${sysmon.ok ? '运行中' : '未运行/异常'}`);
    for (const service of sysmon.services ?? []) {
      console.log(`  - ${service.name}: ${service.ok ? 'Running' : 'Stopped/不可用'} ${service.detail ?? ''}`.trimEnd());
    }
  } else {
    console.log('Sysmon：Host 尚未记录检测结果（启动后由插件检测并写审计）');
  }
  const hooks = ['python/sitecustomize.py', 'node/delete-guard.cjs'].map((rel) => ({ rel, ok: fs.existsSync(path.join(PLUGIN_DIR, 'hooks', rel)) }));
  console.log(`钩子文件：${hooks.map((h) => `${h.rel}=${h.ok ? 'ok' : '缺失'}`).join('；')}`);
  if (gateEvents.length > 0) {
    console.log('最近事件：');
    for (const event of gateEvents) {
      const decision = event.decision ?? event.event;
      console.log(`  ${event.time}  ${event.event}/${decision}  tool=${event.tool ?? '?'}  ${event.reason ?? ''}`.trimEnd());
    }
  }
  return 0;
}

async function doRestore(flags, positional) {
  const batch = positional[0];
  if (!batch) {
    console.error('缺少批次 id（或 latest）');
    return 2;
  }
  const { engine } = makeEngine(flags);
  await engine.init();
  const report = await engine.restore(batch, {
    to: flags.to ?? null,
    force: flags.force === true,
    dryRun: flags['dry-run'] === true,
  });
  console.log(JSON.stringify(report, null, 2));
  if (report.failed > 0) {
    console.error(`有 ${report.failed} 个文件还原失败`);
    return 1;
  }
  console.log(`还原完成：${report.restored} 个文件，${report.dirs} 个目录，${formatBytes(report.bytes)}${report.dryRun ? '（dry-run）' : ''}`);
  return 0;
}

async function doDryRun(flags, rest) {
  const workdir = path.resolve(flags.workdir ?? process.cwd());
  let plan;
  if (flags.tool) {
    const tool = String(flags.tool);
    const file = flags.path ? toAbsolute(flags.path, workdir) : undefined;
    const args = tool === 'write' || tool === 'edit' ? { file_path: file, content: 'x' } : { file_path: file };
    plan = planToolCall({ name: tool, args, workdir, policy: DEFAULTS.policy });
  } else {
    const command = rest.join(' ').trim();
    if (!command) {
      console.error('dry-run 需要命令：delete-guard dry-run -- <shell 命令...>');
      return 2;
    }
    plan = parseShellCommand(command, workdir, DEFAULTS.policy, 0);
  }
  if (plan.kind === 'safe') {
    console.log('判定：明确安全，无需备份。');
    return 0;
  }
  if (plan.kind === 'deny') {
    console.log(`判定：阻断 —— ${plan.reason}`);
    return 2;
  }
  if (plan.kind === 'confirm') {
    // 解析不出目标：真实门禁会弹窗确认（不备份）。dry-run 只如实报告。
    console.log('判定：目标无法静态确定 —— 门禁会拦下来弹窗确认，且**不会备份**');
    console.log(`原因：${plan.reason}`);
    console.log(`处置：policy.unresolvedAction = ${(DEFAULTS.policy.unresolvedAction)}`);
    return 0;
  }
  const roots = plan.kind === 'targets' ? plan.targets : [plan.scope];
  const { config, engine } = makeEngine(flags);
  await engine.init();
  const result = await engine.plan(roots, { quotaCheck: false });
  console.log('判定：需要备份（未执行删除、未写备份）');
  console.log(`目标/范围：${roots.join('；')}`);
  console.log(`将备份：${result.files.length} 个文件，${formatBytes(result.bytes)}；目录 ${result.dirs.length} 个；链接 ${result.links.length} 个；缺失 ${result.missing.length} 个`);
  const limits = config.backup;
  if (result.files.length > limits.maxBatchFiles) console.log(`!! 文件数超过单批上限 ${limits.maxBatchFiles}`);
  if (result.bytes > limits.maxBatchBytes) console.log(`!! 总量超过单批上限 ${formatBytes(limits.maxBatchBytes)}`);
  if (result.bytes > limits.quotaBytes - engine.usage.bytes) console.log(`!! 超过剩余配额 ${formatBytes(Math.max(0, limits.quotaBytes - engine.usage.bytes))}`);
  const huge = result.files.filter((f) => f.size > limits.maxFileBytes);
  if (huge.length > 0) console.log(`!! ${huge.length} 个文件超过单文件上限 ${formatBytes(limits.maxFileBytes)}：${huge.slice(0, 5).map((f) => f.path).join(', ')}`);
  if (result.missing.length > 0) console.log(`（缺失、无需备份：${result.missing.slice(0, 5).join(', ')}）`);
  return 0;
}

async function main() {
  const { command, positional, flags, rest } = parseArgs(process.argv.slice(2));
  if (!command || flags.help) {
    usage();
    return command ? 0 : 2;
  }
  if (command === 'status') return printStatus(flags);
  if (command === 'restore') return doRestore(flags, positional);
  if (command === 'dry-run') return doDryRun(flags, rest);
  if (command === 'gc') {
    const { engine } = makeEngine(flags);
    await engine.init();
    const result = await engine.cleanup();
    console.log(`清理完成：批次 ${result.removedBatches} 个，对象 ${result.removedObjects} 个`);
    return 0;
  }
  console.error(`未知命令：${command}`);
  usage();
  return 2;
}

main().then((code) => process.exit(code)).catch((error) => {
  console.error(`delete-guard: ${error.message}`);
  process.exit(1);
});
