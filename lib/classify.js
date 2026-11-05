// 工具 / 命令分类器（纯 Node，CLI 与 Host 共用）。
//
// 原则：宁可保守。能确定"明确安全"才返回 safe；能确定目标就返回 targets；
// 只能确定范围就返回 scope；解析失败按 policy.opaqueCommand 处理（默认 scope）；
// 系统级破坏（format/diskpart/vssadmin delete 等）直接 deny。
import fs from 'node:fs';
import path from 'node:path';
import { toAbsolute, isInside } from './paths.js';

// 插件自身标识：用于禁止模型通过 plugin_manager 卸载/替换守卫。
export const SELF_NAME_RE = /delete-guard|sensitive-data-guard|dsh-guard/i;
// 守卫自己的管理 CLI（bin/dsh-guard.mjs，旧名 bin/delete-guard.mjs 仍然接受）。
export const ADMIN_CLI_RE = /(?:dsh-guard|delete-guard)\.mjs$/i;

// ── 已知工具 ────────────────────────────────────────────────────────────────

export const SAFE_TOOLS = new Set([
  'read', 'glob', 'grep', 'read_image', 'working_directory', 'load_workspace_dependencies',
  'job_output', 'job_list', 'job_kill', 'skill', 'web_search', 'web_fetch', 'present',
  'cordis_inspect_list', 'cordis_inspect_query', 'send_message', 'interrupt_agent', 'list_agents',
  'todo_write', 'workflow', 'get_goal', 'create_goal', 'update_goal', 'ask_user_question',
  'exit_plan_mode', 'subagent', 'subagent_fork', 'schedule_create', 'schedule_list',
  'schedule_delete', 'schedule_update', 'delete_guard_status', 'delete_guard_dry_run',
]);

export const SHELL_TOOLS = new Set(['pwsh', 'bash', 'powershell', 'terminal', 'shell']);
export const WRITE_TOOLS = new Set(['write', 'edit', 'str_replace_editor', 'replace_editor']);
export const MOVE_TOOLS = new Set(['move', 'move_file', 'rename', 'rename_file']);
export const DELETE_TOOLS = new Set([
  'delete', 'delete_file', 'remove', 'remove_file', 'rm', 'unlink',
  'rmdir', 'delete_directory', 'remove_directory',
]);

export const DESTRUCTIVE_TOOLS = new Set([
  ...SHELL_TOOLS, ...WRITE_TOOLS, ...MOVE_TOOLS, ...DELETE_TOOLS,
]);

/** guard 用的同步、廉价分类：只按工具名判断，不做任何 I/O。 */
export function quickClassify(name) {
  if (SAFE_TOOLS.has(name)) return 'safe';
  if (DESTRUCTIVE_TOOLS.has(name)) return 'destructive';
  if (name === 'plugin_manager') return 'plugin-manager';
  return 'unknown';
}

// ── Plan ────────────────────────────────────────────────────────────────────

function planSafe(notes = []) {
  return { kind: 'safe', targets: [], scope: null, reason: '', notes };
}
function planTargets(targets, notes = []) {
  return { kind: 'targets', targets: [...new Set(targets)], scope: null, reason: '', notes };
}
function planScope(scope, notes = []) {
  return { kind: 'scope', targets: [], scope, reason: '', notes };
}
function planDeny(reason, notes = []) {
  return { kind: 'deny', targets: [], scope: null, reason, notes };
}

// ── 工具入口 ────────────────────────────────────────────────────────────────

/**
 * @param {{name: string, args: any, workdir: string, policy: any}} input
 */
export function planToolCall({ name, args, workdir, policy }) {
  if (SAFE_TOOLS.has(name)) {
    if (name === 'plugin_manager') return classifyPluginManager(args);
    return planSafe();
  }
  if (name === 'plugin_manager') return classifyPluginManager(args);
  if (WRITE_TOOLS.has(name)) return classifyWriteTool(name, args, workdir);
  if (MOVE_TOOLS.has(name)) return classifyMoveTool(name, args, workdir);
  if (DELETE_TOOLS.has(name)) return classifyDeleteTool(name, args, workdir);
  if (SHELL_TOOLS.has(name)) {
    const command = typeof args?.command === 'string' ? args.command : '';
    if (!command.trim()) return planDeny('delete-guard: shell 工具缺少 command，无法检查');
    return parseShellCommand(command, workdir, policy, 0);
  }
  return { kind: 'unknown', targets: [], scope: null, reason: '', notes: [] };
}

function classifyPluginManager(args) {
  const action = String(args?.action ?? '');
  const text = JSON.stringify(args ?? {}).toLowerCase();
  const mutating = new Set(['install_bundle', 'remove_bundle', 'set_bundle', 'set_plugin']);
  if (mutating.has(action) && SELF_NAME_RE.test(text)) {
    return planDeny('delete-guard: 禁止通过 plugin_manager 移除/替换敏感数据守卫自身');
  }
  return planSafe(['plugin_manager:' + action]);
}

function pathFromArgs(args, workdir, keys) {
  for (const key of keys) {
    const value = args?.[key];
    if (typeof value === 'string' && value.trim()) return toAbsolute(value, workdir);
    if (Array.isArray(value) && value.length > 0) {
      return value.filter((v) => typeof v === 'string').map((v) => toAbsolute(v, workdir));
    }
  }
  return null;
}

function existsOrDir(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

function existsFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function classifyWriteTool(name, args, workdir) {
  const found = pathFromArgs(args, workdir, ['file_path', 'path', 'target', 'file']);
  if (!found) return planDeny(`delete-guard: ${name} 未提供目标路径，无法检查`);
  const paths = Array.isArray(found) ? found : [found];
  const targets = [];
  for (const p of paths) {
    if (existsFile(p)) targets.push(p);
  }
  return targets.length > 0 ? planTargets(targets, [`${name}:overwrite`]) : planSafe([`${name}:create`]);
}

function classifyMoveTool(name, args, workdir) {
  const src = pathFromArgs(args, workdir, ['source', 'from', 'src', 'file_path', 'path', 'paths']);
  const dst = pathFromArgs(args, workdir, ['destination', 'to', 'dst', 'target']);
  const sources = src ? (Array.isArray(src) ? src : [src]) : [];
  const target = Array.isArray(dst) ? dst[0] : dst;
  if (sources.length === 0 && !target) return planDeny(`delete-guard: ${name} 未提供路径`);
  const targets = [...sources];
  if (target && existsFile(target)) targets.push(target);
  return targets.length > 0 ? planTargets(targets, [`${name}:move`]) : planSafe([`${name}:move`]);
}

function classifyDeleteTool(name, args, workdir) {
  const found = pathFromArgs(args, workdir, ['path', 'file_path', 'target', 'file', 'paths']);
  if (!found) return planDeny(`delete-guard: ${name} 未提供目标路径，无法检查`);
  const paths = Array.isArray(found) ? found : [found];
  if (paths.length === 0) return planDeny(`delete-guard: ${name} 未提供目标路径，无法检查`);
  return planTargets(paths, [`${name}:delete`]);
}

// ── shell 解析 ──────────────────────────────────────────────────────────────

const DELETE_CMDS = new Set(['remove-item', 'rm', 'ri', 'del', 'erase', 'rd', 'rmdir', 'rmi', 'unlink', 'sdelete']);
const MOVE_CMDS = new Set(['move-item', 'mv', 'move', 'ren', 'rename-item', 'rni', 'rename', 'mvitem']);
const TRUNCATE_CMDS = new Set(['clear-content', 'clc', 'set-content', 'sc', 'out-file', 'export-csv', 'export-clixml', 'tee-object', 'set-item']);
const COPY_CMDS = new Set(['copy-item', 'cp', 'copy', 'cpi', 'xcopy', 'robocopy']);
const INTERPRETERS = new Set(['python', 'python3', 'py', 'node', 'nodejs', 'deno', 'bun']);
const NESTED_SHELLS = new Set(['powershell', 'pwsh', 'cmd', 'bash', 'sh', 'zsh']);

const SAFE_COMMAND_RE = [
  /^(get-|select-|where-|measure-|sort-|group-|format-|convertto-|convertfrom-|write-output|write-host|test-path|resolve-path|split-path|join-path|add-content|add-history|clear-host|out-host|out-string|out-null|set-location|push-location|pop-location|findstr|select-string|start-sleep|test-connection|dir|ls|cat|type|gc|echo|pwd|cd|where|which|whoami|hostname|ver|date|time|env|printenv|uname|stat|du|df|head|tail|less|more|file|man|help)\b/i,
  /^(git\s+(status|log|diff|show|blame|describe|rev-parse|ls-files|remote|config|fetch|pull|push|add|commit|merge|rebase|cherry-pick|revert|bisect|shortlog|reflog)\b)/i,
  /^(node|python|python3|py)\s+(--version|-v|-V)\s*$/i,
  /^(npm|pnpm|yarn)\s+(--version|-v|ls|list|view|info)\b/i,
  /^(tsc|eslint|prettier|vitest|jest|mocha|pytest|ruff|black|flake8|mypy)\s+--version\b/i,
  /^(cargo|rustc|go|dotnet|java|javac)\s+(--version|-V)\s*$/i,
  /^(robocopy)\s+\/help\b/i,
];

function isSafeCommandText(stmt) {
  for (const re of SAFE_COMMAND_RE) if (re.test(stmt)) return true;
  return false;
}

/**
 * 纯变量赋值（$x = 1 / $x = 'abc' / $x = $y / $x = D:\path）不触碰文件，视为安全。
 * 右侧只接受字面量/变量/绝对路径，避免把 $x = Remove-Item ... 这类命令赋值当成安全。
 */
function isPureAssignment(stmt) {
  const m = /^\s*\$[A-Za-z_][\w:]*\s*=\s*(.*)$/.exec(stmt);
  if (!m) return false;
  const rhs = m[1].trim();
  if (!rhs) return false;
  return /^(?:'[^']*'|"[^"]*"|\d+(?:\.\d+)?|\$[A-Za-z_][\w:]*|[A-Za-z]:[\\/].*|\\.*|\/.*)$/.test(rhs);
}

/** 直接调用的格式化/自动修复工具（prettier/eslint/black/gofmt...）。 */
const FORMATTERS = new Set([
  'prettier', 'eslint', 'stylelint', 'biome', 'dprint', 'black', 'autopep8', 'yapf',
  'gofmt', 'rustfmt', 'dart', 'ktlint', 'clang-format', 'phpcbf', 'rubocop',
]);
const FORMAT_WRITE_FLAGS = new Set(['--write', '-w', '--fix', '-F', '-i', '--in-place', '--write-out', '--rewrite']);

/** 格式化工具带写入开关时，返回会被原地覆盖的目标（目录则取目录本身）。 */
function formatterWritePlan(cmd, args, workdir) {
  if (!FORMATTERS.has(cmd) || !args.some((a) => FORMAT_WRITE_FLAGS.has(a.text))) return null;
  const scriptExtensions = /\.(py|js|mjs|cjs|ps1|sh)$/i;
  const targets = [];
  for (const a of args) {
    if (a.text.startsWith('-')) continue;
    if (scriptExtensions.test(a.text)) continue;
    const r = resolveMaybe(a.text, workdir);
    if (r) targets.push(r.path);
  }
  if (targets.length > 0) return planTargets(targets, ['formatter:write-flag']);
  return planScope(workdir, ['formatter:write-flag-no-path']);
}

/** 按行/分号/管道拆分语句（引号内不拆）。 */
function splitStatements(text) {
  const parts = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      cur += ch;
      if (ch === '`' && quote === '"' && i + 1 < text.length) {
        cur += text[++i];
        continue;
      }
      if (ch === quote) {
        if (quote === "'" && text[i + 1] === "'") {
          cur += text[++i];
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === '`' && i + 1 < text.length) {
      cur += ch + text[++i];
      continue;
    }
    if (ch === ';' || ch === '\n' || ch === '\r') {
      parts.push(cur);
      cur = '';
      continue;
    }
    if (ch === '|') {
      parts.push(cur);
      cur = '';
      continue;
    }
    if (ch === '&' && text[i + 1] === '&') {
      parts.push(cur);
      cur = '';
      i++;
      continue;
    }
    cur += ch;
  }
  parts.push(cur);
  return parts.filter((p) => p.trim().length > 0);
}

/** 引号感知的 tokenizer；保留 quote 标记。 */
function tokenize(segment) {
  const tokens = [];
  let i = 0;
  while (i < segment.length) {
    if (/\s/.test(segment[i])) {
      i++;
      continue;
    }
    let text = '';
    let quoted = false;
    while (i < segment.length && !/\s/.test(segment[i])) {
      const ch = segment[i];
      if (ch === "'") {
        quoted = true;
        i++;
        while (i < segment.length) {
          if (segment[i] === "'" && segment[i + 1] === "'") {
            text += "'";
            i += 2;
            continue;
          }
          if (segment[i] === "'") {
            i++;
            break;
          }
          text += segment[i++];
        }
      } else if (ch === '"') {
        quoted = true;
        i++;
        while (i < segment.length) {
          if (segment[i] === '`' && i + 1 < segment.length) {
            text += segment[i + 1];
            i += 2;
            continue;
          }
          if (segment[i] === '"') {
            i++;
            break;
          }
          text += segment[i++];
        }
      } else if (ch === '`' && i + 1 < segment.length) {
        text += segment[i + 1];
        i += 2;
      } else {
        text += ch;
        i++;
      }
    }
    tokens.push({ text, quoted });
  }
  return tokens;
}

function normalizeCommand(token) {
  let t = token.text;
  if (t.startsWith('&') && t.length > 1) t = t.slice(1);
  const base = t.split(/[\\/]/).pop().toLowerCase();
  return base.replace(/\.(exe|cmd|bat|ps1)$/i, '');
}

function resolveMaybe(raw, workdir) {
  const expanded = String(raw).replace(/%([^%]+)%/g, (m) => m);
  if (expanded.includes('$') || /%[^%]+%/.test(expanded)) return null; // 变量，无法确定
  if (/[*?]/.test(expanded)) {
    const abs = toAbsolute(expanded, workdir);
    return { path: path.dirname(abs), wildcard: true };
  }
  return { path: toAbsolute(expanded, workdir), wildcard: false };
}

function extractPathArgs(tokens, workdir) {
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const text = t.text;
    const inline = /^-(path|literalpath|destination|dest|file|filepath|source|target):(.+)$/i.exec(text);
    if (inline) {
      const r = resolveMaybe(inline[2], workdir);
      if (r) out.push(r.path);
      continue;
    }
    if (/^-(path|literalpath|destination|dest|file|filepath|source|target)$/i.test(text)) {
      const next = tokens[i + 1];
      if (next) {
        const r = resolveMaybe(next.text, workdir);
        if (r) out.push(r.path);
        i++;
      }
      continue;
    }
    if (text.startsWith('-')) continue;
    if (text.startsWith('/') && !/^[A-Za-z]:/.test(text)) continue; // 开关
    if (text === '>' || text === '>>' || /^[12]?>$/.test(text)) continue;
    const r = resolveMaybe(text, workdir);
    if (r) out.push(r.path);
  }
  return out;
}

function scanCode(text) {
  const deleteRe = /(shutil\s*\.\s*rmtree|os\s*\.\s*(remove|unlink|rmdir|removedirs|truncate)|pathlib\s*\.\s*Path\b[\s\S]{0,80}?\.\s*(unlink|rmdir)|\.\s*(rmSync|rmdirSync|unlinkSync|truncateSync|rmdir|unlink|rm|truncate)\s*\(|fs\s*\.\s*promises\s*\.\s*(rm|rmdir|unlink|truncate)\s*\()/i;
  const dynamicRe = /\b(eval\s*\(|exec\s*\(|subprocess|os\s*\.\s*system|popen|child_process|spawnSync|execSync|spawn\s*\(|Invoke-Expression|\biex\b|Start-Process)\b/i;
  const hasDelete = deleteRe.test(text);
  const dynamic = dynamicRe.test(text);
  const paths = [];
  // 允许 Python 字符串前缀：r'...'、f'...'、rb'...' 等。
  const prefixes = "(?:[rRbBuUfF]{1,2})?";
  const patterns = [
    new RegExp(`shutil\\s*\\.\\s*rmtree\\s*\\(\\s*${prefixes}(['"\`])([^'"\`]+)\\1`, 'gi'),
    new RegExp(`os\\s*\\.\\s*(?:remove|unlink|rmdir|removedirs|truncate)\\s*\\(\\s*${prefixes}(['"\`])([^'"\`]+)\\1`, 'gi'),
    new RegExp(`\\.\\s*(?:rmSync|rmdirSync|unlinkSync|truncateSync|rmdir|unlink|rm|truncate)\\s*\\(\\s*${prefixes}(['"\`])([^'"\`]+)\\1`, 'gi'),
    new RegExp(`fs\\s*\\.\\s*promises\\s*\\.\\s*(?:rm|rmdir|unlink|truncate)\\s*\\(\\s*${prefixes}(['"\`])([^'"\`]+)\\1`, 'gi'),
  ];
  for (const re of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const candidate = m[2];
      if (/[{}]/.test(candidate) || candidate.includes('$') || /%[^%]+%/.test(candidate)) continue; // 插值路径无法确定
      paths.push(candidate);
    }
  }
  return { hasDelete, dynamic, paths };
}

function scanScriptFile(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > 2 * 1024 * 1024) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function interpreterPlan(cmd, args, workdir, policy, depth) {
  const flags = args.filter((a) => a.text.startsWith('-'));
  const codeFlag = args.find((a) => ['-c', '--command', '-e', '--eval', '/c', '-Command'].includes(a.text));
  let code = null;
  if (codeFlag) {
    const idx = args.indexOf(codeFlag);
    const rest = args.slice(idx + 1);
    if (rest.length > 0) code = rest.map((t) => t.text).join(' ');
  }
  let file = null;
  if (!code) {
    const candidate = args.find((a) => !a.text.startsWith('-') && /\.(py|js|mjs|cjs|ps1|sh)$/i.test(a.text));
    if (candidate) file = toAbsolute(candidate.text, workdir);
  }
  // 格式化/自动修复类写入：prettier --write、eslint --fix、gofmt -w、rustfmt 等。
  // 这些命令会原地覆盖文件，按破坏性写入处理（先备份目标，再放行）。
  const writeFlags = new Set(['--write', '-w', '--fix', '-i', '--in-place', '--write-out']);
  if (!code && args.some((a) => writeFlags.has(a.text))) {
    const scriptExtensions = /\.(py|js|mjs|cjs|ps1|sh)$/i;
    const writeTargets = args
      .filter((a) => !a.text.startsWith('-') && !scriptExtensions.test(a.text))
      .map((a) => toAbsolute(a.text, workdir));
    return writeTargets.length > 0
      ? planTargets(writeTargets, ['interpreter:write-flag'])
      : planScope(workdir, ['interpreter:write-flag-no-path']);
  }
  const source = code ?? (file ? scanScriptFile(file) : null);
  if (source === null) {
    return policy?.opaqueCommand === 'block'
      ? planDeny(`delete-guard: 无法读取/静态分析 ${cmd} 的目标，已按策略阻断`)
      : planScope(workdir, ['interpreter:opaque']);
  }
  const scan = scanCode(source);
  if (scan.hasDelete) {
    if (scan.paths.length > 0) {
      return planTargets(scan.paths.map((p) => toAbsolute(p, workdir)), ['interpreter:delete']);
    }
    return planScope(workdir, ['interpreter:delete-no-path']);
  }
  if (scan.dynamic) return planScope(workdir, ['interpreter:dynamic']);
  return planSafe(['interpreter:clean']);
}

function gitPlan(args, workdir) {
  const sub = (args[0]?.text ?? '').toLowerCase();
  const repo = findRepoRoot(workdir) ?? workdir;
  const rest = args.slice(1).map((a) => a.text);
  if (!sub) return planScope(workdir, ['git:no-subcommand']);
  const safe = new Set(['status', 'log', 'diff', 'show', 'blame', 'describe', 'rev-parse', 'ls-files', 'remote', 'config', 'fetch', 'pull', 'push', 'add', 'commit', 'shortlog', 'reflog', 'version', 'help']);
  if (safe.has(sub)) return planSafe([`git:${sub}`]);
  if (sub === 'branch' || sub === 'tag') {
    if (rest.some((r) => /^(-D|-d|--delete)$/.test(r))) return planScope(repo, [`git:${sub}-delete`]);
    return planSafe([`git:${sub}`]);
  }
  if (sub === 'reset') {
    return rest.some((r) => r === '--hard' || r === '--merge') ? planScope(repo, ['git:reset-hard']) : planSafe(['git:reset']);
  }
  if (sub === 'clean') return planScope(repo, ['git:clean']);
  if (sub === 'checkout' || sub === 'switch' || sub === 'restore') {
    const dash = rest.indexOf('--');
    if (dash >= 0 && rest.length > dash + 1) {
      return planTargets(rest.slice(dash + 1).map((p) => toAbsolute(p, repo)), ['git:restore-path']);
    }
    return planScope(repo, [`git:${sub}`]);
  }
  if (sub === 'rm') {
    const paths = rest.filter((r) => !r.startsWith('-')).map((p) => toAbsolute(p, repo));
    return paths.length > 0 ? planTargets(paths, ['git:rm']) : planScope(repo, ['git:rm']);
  }
  if (sub === 'mv') {
    const paths = rest.filter((r) => !r.startsWith('-')).map((p) => toAbsolute(p, repo));
    return paths.length > 0 ? planTargets(paths, ['git:mv']) : planScope(repo, ['git:mv']);
  }
  if (['stash', 'gc', 'prune', 'filter-branch', 'update-ref'].includes(sub)) {
    return planScope(path.join(repo, '.git'), [`git:${sub}`]);
  }
  return planScope(workdir, [`git:${sub}`]);
}

function robocopyPlan(args, workdir) {
  const rest = args.map((a) => a.text);
  const mirror = rest.some((r) => /^\/(mir|purge|move|mov)$/i.test(r));
  const paths = rest.filter((r) => !r.startsWith('/'));
  if (paths.length < 2) return planScope(workdir, ['robocopy:no-dest']);
  const dest = toAbsolute(paths[paths.length - 1], workdir);
  if (!existsOrDir(dest)) return planSafe(['robocopy:new-dest']);
  return planTargets([dest], [mirror ? 'robocopy:mirror' : 'robocopy:overwrite']);
}

function systemDeny(cmd, args) {
  const text = args.map((a) => a.text.toLowerCase()).join(' ');
  if (cmd === 'fsutil' && text.includes('deletejournal')) return 'fsutil usn deletejournal 会删除卷 USN 日志';
  if (cmd === 'cipher' && /\/w\b/.test(text)) return 'cipher /w 会擦除卷空闲空间';
  if (cmd === 'format' || cmd === 'diskpart') return '格式化/分区工具会破坏整个卷';
  if (cmd === 'vssadmin' && /delete\s+shadows/.test(text)) return 'vssadmin delete shadows 会删除卷影副本';
  if (cmd === 'wbadmin' && /delete\b/.test(text)) return 'wbadmin delete 会删除备份';
  return null;
}

/**
 * 解析一条 shell 命令。
 * @returns {{kind: 'safe'|'targets'|'scope'|'deny', targets: string[], scope: string|null, reason: string, notes: string[]}}
 */
export function parseShellCommand(command, workdir, policy = {}, depth = 0) {
  if (depth > 3) return planScope(workdir, ['nested-too-deep']);
  const statements = splitStatements(String(command));
  const targets = [];
  const notes = [];
  let needsScope = false;
  let scope = null;

  for (const stmt of statements) {
    const tokens = tokenize(stmt);
    if (tokens.length === 0) continue;

    // 重定向：> 覆盖写
    const gt = tokens.findIndex((t) => t.text === '>' || t.text === '1>' || t.text === '2>');
    if (gt >= 0 && tokens[gt + 1]) {
      const r = resolveMaybe(tokens[gt + 1].text, workdir);
      if (r && existsFile(r.path)) targets.push(r.path);
      notes.push('redirect:overwrite');
      continue;
    }

    // 前导符号/包装
    let idx = 0;
    while (idx < tokens.length && ['&', '.', 'sudo', 'env', 'command', 'time'].includes(tokens[idx].text.toLowerCase())) idx++;
    if (idx >= tokens.length) continue;

    const cmdToken = tokens[idx];
    let cmd = normalizeCommand(cmdToken);
    const args = tokens.slice(idx + 1);

    // 本插件自己的 CLI：status/dry-run 只读，允许；restore/gc 会改用户数据，
    // 只允许用户在 DSH 之外的终端执行（避免模型用“还原”覆盖用户的新数据）。
    if ((cmd === 'node' || cmd === 'nodejs') && args.some((a) => ADMIN_CLI_RE.test(a.text))) {
      const scriptIndex = args.findIndex((a) => ADMIN_CLI_RE.test(a.text));
      const sub = (args[scriptIndex + 1]?.text ?? '').toLowerCase();
      if (sub === 'restore' && args.some((a) => a.text === '--dry-run')) {
        notes.push('admin-cli:restore-dry-run');
        continue;
      }
      if (['status', 'dry-run', ''].includes(sub)) {
        notes.push(`admin-cli:${sub || 'help'}`);
        continue;
      }
      return planDeny('delete-guard: restore/gc 属于用户操作，禁止由 DSH 工具链执行；请在普通终端里运行');
    }

    // 别名/包装：start-process 等
    if (cmd === 'start-process') return planScope(workdir, ['start-process']);

    const sys = systemDeny(cmd, args);
    if (sys) return planDeny(`delete-guard: ${sys}，已阻断`);

    // 语句切分后第二条起可能带前导空格，先 trim 再匹配行首锚定的安全正则。
    if (isSafeCommandText(stmt.trim()) && !DELETE_CMDS.has(cmd) && !MOVE_CMDS.has(cmd)) {
      notes.push(`safe:${cmd}`);
      continue;
    }

    // 纯变量赋值不触碰文件。
    if (isPureAssignment(stmt)) {
      notes.push('assign');
      continue;
    }

    // 格式化/自动修复工具直接调用（prettier --write src 等）。
    const formatterPlan = formatterWritePlan(cmd, args, workdir);
    if (formatterPlan) {
      if (formatterPlan.kind === 'targets') targets.push(...formatterPlan.targets);
      else if (formatterPlan.kind === 'scope') {
        needsScope = true;
        scope = scope ?? formatterPlan.scope;
      }
      notes.push(...formatterPlan.notes);
      continue;
    }

    if (DELETE_CMDS.has(cmd)) {
      const paths = extractPathArgs(args, workdir);
      if (paths.length > 0) targets.push(...paths);
      else {
        needsScope = true;
        scope = scope ?? workdir;
      }
      notes.push(`delete:${cmd}`);
      continue;
    }

    if (MOVE_CMDS.has(cmd)) {
      const paths = extractPathArgs(args, workdir);
      if (paths.length === 0) {
        needsScope = true;
        scope = scope ?? workdir;
      } else {
        const dest = paths[paths.length - 1];
        targets.push(...paths.slice(0, -1));
        if (existsFile(dest)) targets.push(dest);
      }
      notes.push(`move:${cmd}`);
      continue;
    }

    if (TRUNCATE_CMDS.has(cmd)) {
      const paths = extractPathArgs(args, workdir);
      const existing = paths.filter((p) => existsFile(p));
      if (existing.length > 0) targets.push(...existing);
      else if (paths.length === 0) {
        needsScope = true;
        scope = scope ?? workdir;
      }
      notes.push(`write:${cmd}`);
      continue;
    }

    if (COPY_CMDS.has(cmd)) {
      if (cmd === 'robocopy') {
        const p = robocopyPlan(args, workdir);
        if (p.kind === 'targets') targets.push(...p.targets);
        else if (p.kind === 'scope') {
          needsScope = true;
          scope = scope ?? p.scope;
        }
        notes.push('robocopy');
        continue;
      }
      const paths = extractPathArgs(args, workdir);
      if (paths.length >= 2) {
        const dest = paths[paths.length - 1];
        if (existsFile(dest)) targets.push(dest);
      } else if (paths.length === 0) {
        needsScope = true;
        scope = scope ?? workdir;
      }
      notes.push(`copy:${cmd}`);
      continue;
    }

    if (cmd === 'new-item' || cmd === 'ni' || cmd === 'mkdir' || cmd === 'md') {
      const paths = extractPathArgs(args, workdir);
      const existing = paths.filter((p) => existsFile(p));
      if (existing.length > 0) targets.push(...existing);
      notes.push('new-item');
      continue;
    }

    if (cmd === 'git') {
      const p = gitPlan(args, workdir);
      if (p.kind === 'targets') targets.push(...p.targets);
      else if (p.kind === 'scope') {
        needsScope = true;
        scope = scope ?? p.scope;
      }
      notes.push(...p.notes);
      continue;
    }

    if (INTERPRETERS.has(cmd)) {
      const p = interpreterPlan(cmd, args, workdir, policy, depth + 1);
      if (p.kind === 'targets') targets.push(...p.targets);
      else if (p.kind === 'scope') {
        needsScope = true;
        scope = scope ?? p.scope;
      } else if (p.kind === 'deny') return p;
      notes.push(...p.notes);
      continue;
    }

    if (NESTED_SHELLS.has(cmd)) {
      const flag = args.find((a) => ['-c', '/c', '-command', '--command'].includes(a.text.toLowerCase()));
      if (flag) {
        const idx2 = args.indexOf(flag);
        const inner = args.slice(idx2 + 1).map((t) => t.text).join(' ');
        if (inner.trim()) {
          const p = parseShellCommand(inner, workdir, policy, depth + 1);
          if (p.kind === 'targets') targets.push(...p.targets);
          else if (p.kind === 'scope') {
            needsScope = true;
            scope = scope ?? p.scope;
          } else if (p.kind === 'deny') return p;
          notes.push(...p.notes);
          continue;
        }
      }
      needsScope = true;
      scope = scope ?? workdir;
      notes.push(`nested:${cmd}`);
      continue;
    }

    // 其它常见但无文件破坏的命令
    if (['takeown', 'icacls', 'attrib', 'reg', 'schtasks', 'netsh', 'sc', 'sc.exe', 'taskkill', 'stop-process', 'kill', 'get-acl', 'set-acl'].includes(cmd)) {
      notes.push(`allow:${cmd}`);
      continue;
    }

    // 未知命令：按策略
    if (policy?.opaqueCommand === 'block') {
      return planDeny(`delete-guard: 无法静态确认这条命令的安全性，已按策略阻断：${stmt.trim().slice(0, 200)}`);
    }
    needsScope = true;
    scope = scope ?? workdir;
    notes.push(`opaque:${cmd}`);
  }

  if (targets.length > 0) return planTargets(targets, notes);
  if (needsScope) return planScope(scope ?? workdir, notes);
  return planSafe(notes);
}

/** 向上找 git 仓库根（最多 12 层）。 */
export function findRepoRoot(start) {
  let dir = path.resolve(start);
  for (let i = 0; i < 12; i++) {
    try {
      if (fs.existsSync(path.join(dir, '.git'))) return dir;
    } catch {
      return null;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/** 供外部复用的内部工具。 */
export const _internal = { splitStatements, tokenize, scanCode, isInside };
