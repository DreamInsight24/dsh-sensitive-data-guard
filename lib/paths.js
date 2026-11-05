// 路径工具（纯 Node，CLI 与 Host 共用）。
import path from 'node:path';
import os from 'node:os';

const IS_WIN = process.platform === 'win32';

/** 把 %TEMP% 这类环境变量展开；展开不了的原样返回。 */
export function expandEnv(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/%([^%]+)%/g, (match, name) => {
    const v = process.env[name] ?? process.env[name.toUpperCase()] ?? process.env[name.toLowerCase()];
    return v === undefined ? match : v;
  });
}

/** 绝对化并规范化（不解析符号链接）。 */
export function toAbsolute(value, base = process.cwd()) {
  const expanded = expandEnv(String(value ?? ''));
  return path.resolve(base, expanded);
}

export function normKey(value) {
  const abs = path.resolve(value);
  return IS_WIN ? abs.toLowerCase() : abs;
}

/** child 是否等于 parent 或位于 parent 之内（大小写不敏感，Windows）。 */
export function isInside(parent, child) {
  const p = normKey(parent);
  const c = normKey(child);
  if (p === c) return true;
  const withSep = p.endsWith(path.sep) ? p : p + path.sep;
  return c.startsWith(withSep);
}

/** 两个路径是否存在包含关系（任一方向）。 */
export function overlaps(a, b) {
  return isInside(a, b) || isInside(b, a);
}

/** 把绝对路径映射成备份树中的相对键：D:\a\b -> D/a/b。 */
export function treeKey(absPath) {
  const resolved = path.resolve(absPath);
  const root = path.parse(resolved).root; // 'D:\' or '/'
  const rest = resolved.slice(root.length).split(/[\\/]+/).filter(Boolean);
  const drive = root.replace(/[\\/:]+/g, '').toUpperCase() || 'ROOT';
  const safe = rest.map((part) => part.replace(/[<>:"|?*\x00-\x1f]/g, '_').replace(/^\.+$/, '_'));
  return path.join(drive, ...safe);
}

/** 批次 id 只允许 <date>/<session>/<seq> 形状。 */
export function parseBatchId(batchId) {
  if (typeof batchId !== 'string') return null;
  const parts = batchId.replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.length !== 3) return null;
  const [date, session, seq] = parts;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
  if (!/^[A-Za-z0-9_.-]+$/.test(session)) return null;
  if (!/^\d{1,6}$/.test(seq)) return null;
  return { date, session, seq };
}

export function homeDir() {
  return os.homedir();
}

// ── .gitignore 风格的保护目录模式 ─────────────────────────────────────────────
//
// 语义（与 .gitignore 类似，用于 policy.protectedPaths）：
//   - 模式用 / 分隔、大小写不敏感；可带盘符（D:/xxx），不带盘符则匹配任意盘。
//   - '*' 匹配一段内的任意字符，'**' 跨段匹配，'?' 匹配单个字符。
//   - 以 '!' 开头表示“排除/放行”；后写的模式覆盖先写的。
//   - 不含 '/' 的模式匹配任意层级（如 '*.tmp' 匹配 a/b.tmp）。
//   - 含 '/' 的模式从根开始锚定（如 'User/*' 只匹配根下的 User）。
//   - 目录一旦被保护，其下所有内容一并受保护，除非被更具体的 '!' 模式放行。
//
// 示例：保护 User 下所有内容，但放行 User/WorkSpace
//   protectedPaths:
//     - 'User/*'
//     - '!User/WorkSpace'

function globToSource(glob) {
  let out = '';
  let i = 0;
  while (i < glob.length) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i += 2;
        if (glob[i] === '/') {
          i += 1;
          out += '(?:.*/)?';
        } else {
          out += '.*';
        }
      } else {
        i += 1;
        out += '[^/]*';
      }
    } else if (ch === '?') {
      i += 1;
      out += '[^/]';
    } else {
      i += 1;
      out += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  return out;
}

/** 模式里第一个通配符之前的字面前缀（用于“连根删”检查）。 */
function literalPrefixOf(p) {
  const out = [];
  for (const part of p.split('/')) {
    if (/[*?]/.test(part)) break;
    out.push(part);
  }
  return out.join('/');
}

export function compileProtectPatterns(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    if (typeof raw !== 'string') continue;
    let p = raw.trim();
    if (!p || p.startsWith('#')) continue;
    let negate = false;
    if (p.startsWith('!')) {
      negate = true;
      p = p.slice(1).trim();
    }
    let drive = null;
    const dm = /^([a-zA-Z]):[\\/]?(.*)$/.exec(p);
    if (dm) {
      drive = dm[1].toLowerCase();
      p = dm[2];
    }
    p = p.replace(/\\/g, '/');
    let anchored = false;
    if (p.startsWith('/')) {
      anchored = true;
      p = p.slice(1);
    }
    p = p.replace(/\/+$/, '');
    if (!p) continue;
    p = p.toLowerCase();
    const hasSlash = p.includes('/');
    const source = globToSource(p);
    out.push({
      raw,
      negate,
      drive,
      regex: new RegExp(`^${source}$`),
      anyLevelRegex: !anchored && !hasSlash ? new RegExp(`^(?:.*/)?${source}$`) : null,
      literalPrefix: literalPrefixOf(p),
    });
  }
  return out;
}

function splitTargetPath(target) {
  const abs = path.resolve(String(target));
  const parsed = path.parse(abs);
  const drive = parsed.root.replace(/[\\/:]/g, '').toLowerCase();
  const parts = abs
    .slice(parsed.root.length)
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
    .map((s) => s.toLowerCase());
  return { drive, parts };
}

function protectDecisionAt(compiled, prefix, drive) {
  let decision = null;
  for (const c of compiled) {
    if (c.drive && c.drive !== drive) continue;
    const hit = c.anyLevelRegex ? c.anyLevelRegex.test(prefix) : c.regex.test(prefix);
    if (hit) decision = c.negate ? false : true;
  }
  return decision;
}

/** 目标路径是否命中保护模式（含其所有祖先层级，后者可覆盖前者）。 */
export function isProtectedByPatterns(compiled, target) {
  if (!Array.isArray(compiled) || compiled.length === 0) return false;
  const { drive, parts } = splitTargetPath(target);
  let result = false;
  for (let i = 1; i <= parts.length; i += 1) {
    const d = protectDecisionAt(compiled, parts.slice(0, i).join('/'), drive);
    if (d !== null) result = d;
  }
  return result;
}

/** targets 类删除：目标是否覆盖了某个受保护模式的字面前缀（防止“连根删”绕过）。 */
export function patternCoversTarget(compiled, target) {
  if (!Array.isArray(compiled) || compiled.length === 0) return false;
  const { drive, parts } = splitTargetPath(target);
  const prefix = parts.join('/');
  for (const c of compiled) {
    if (!c.literalPrefix) continue;
    if (c.drive && c.drive !== drive) continue;
    if (prefix === '' || c.literalPrefix === prefix || c.literalPrefix.startsWith(`${prefix}/`)) return true;
  }
  return false;
}
