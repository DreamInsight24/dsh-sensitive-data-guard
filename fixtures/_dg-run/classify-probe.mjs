import { parseShellCommand } from '../delete-guard/lib/classify.js';

const commands = [
  'robocopy D:\\dsh-workspaces\\delete-guard D:\\dsh-workspaces\\local\\delete-guard /E /MOVE',
  'robocopy D:\\dsh-workspaces\\_delete-backup D:\\dsh-workspaces\\local\\delete-guard\\backup /E /MOVE',
  'Copy-Item -Recurse D:\\dsh-workspaces\\delete-guard D:\\dsh-workspaces\\local\\delete-guard',
  'Move-Item D:\\dsh-workspaces\\delete-guard-docs D:\\dsh-workspaces\\local\\delete-guard\\docs',
];

for (const command of commands) {
  const plan = parseShellCommand(command, 'D:\\dsh-workspaces', {}, 0);
  console.log('CMD:', command);
  console.log('  ->', plan.kind, '| targets:', JSON.stringify(plan.targets), '| scope:', plan.scope, '| notes:', JSON.stringify(plan.notes), '| reason:', plan.reason);
  console.log();
}
