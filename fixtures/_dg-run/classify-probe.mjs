// 分类器演练：迁移期用过的命令形态（robocopy /MOVE、Copy-Item 覆盖、Move-Item）。
// 目标端一律用「插件自己的目录」（由 import.meta.url 推导，不写死任何盘符），
// 这样「目标已存在」的分支会被真正走到。直接跑：
//   node fixtures/_dg-run/classify-probe.mjs
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseShellCommand } from '../../lib/classify.js';

const PLUGIN_DIR = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));

const commands = [
  `robocopy D:\\old\\backup ${PLUGIN_DIR}\\backup /E /MOVE`,
  `Copy-Item D:\\old\\package.json ${PLUGIN_DIR}\\package.json`,
  `Move-Item D:\\old\\docs ${PLUGIN_DIR}\\docs`,
];

for (const command of commands) {
  const plan = parseShellCommand(command, path.join(PLUGIN_DIR, '..'), {}, 0);
  console.log('CMD:', command);
  console.log('  ->', plan.kind, '| targets:', JSON.stringify(plan.targets), '| scope:', plan.scope, '| notes:', JSON.stringify(plan.notes), '| reason:', plan.reason);
  console.log();
}
