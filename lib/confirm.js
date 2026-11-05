// 确认码：敏感区删除先备份，再要求用户输入 4 位随机确认码。
//
// 通道（用户选定）：环境变量前缀。模型在重新发起命令前加
//   $env:DSH_GUARD_CONFIRM='1234';
// 插件从命令文本里取出确认码，校验「同会话 + 同命令指纹 + 未过期」后放行，
// 并复用第一次已经做好的备份。

import { formatBytes } from './backup.js';

export const CONFIRM_ENV = 'DSH_GUARD_CONFIRM';
export const CONFIRM_TTL_MS = 10 * 60 * 1000;

// $env:DSH_GUARD_CONFIRM='1234';  /  DSH_GUARD_CONFIRM=1234  /  set DSH_GUARD_CONFIRM=1234
const CODE_PATTERNS = [
  new RegExp(`\\$env:${CONFIRM_ENV}\\s*=\\s*['"]?(\\d{4})['"]?\\s*;?`, 'i'),
  new RegExp(`${CONFIRM_ENV}\\s*=\\s*['"]?(\\d{4})['"]?`, 'i'),
];

/** 从命令文本里取出确认码（没有则 null），并返回剥离后的命令。 */
export function extractConfirmCode(command) {
  const text = typeof command === 'string' ? command : '';
  for (const pattern of CODE_PATTERNS) {
    const match = pattern.exec(text);
    if (match) {
      const stripped = text.replace(pattern, ' ').replace(/\s+/g, ' ').trim();
      return { code: match[1], command: stripped };
    }
  }
  return { code: null, command: text.trim() };
}

/** 命令/工具调用的稳定指纹：剥离确认码、压缩空白，保证两次发起能对上。 */
export function fingerprintOf({ toolName, command, args }) {
  const base = typeof command === 'string'
    ? extractConfirmCode(command).command
    : JSON.stringify(args ?? {});
  return `${toolName}|${base.replace(/\s+/g, ' ').trim()}`;
}

function randomCode() {
  return String(Math.floor(Math.random() * 10000)).padStart(4, '0');
}

export class ConfirmStore {
  constructor() {
    this.entries = new Map();
  }

  prune(now = Date.now()) {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  key(sessionId, fingerprint) {
    return `${sessionId}|${fingerprint}`;
  }

  /** 登记一次待确认的删除，返回确认码。 */
  issue({ sessionId, fingerprint, batchId, batchDir, zone, stats, targets }) {
    this.prune();
    const code = randomCode();
    const entry = {
      code,
      createdAt: Date.now(),
      expiresAt: Date.now() + CONFIRM_TTL_MS,
      sessionId,
      fingerprint,
      batchId,
      batchDir,
      zone,
      stats,
      targets,
    };
    this.entries.set(this.key(sessionId, fingerprint), entry);
    return entry;
  }

  /** 校验；命中返回条目并作废（一次性），否则返回 null。 */
  verify(sessionId, fingerprint, code) {
    this.prune();
    const key = this.key(sessionId, fingerprint);
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.code !== String(code)) return null;
    this.entries.delete(key);
    return entry;
  }

  peek(sessionId, fingerprint) {
    this.prune();
    return this.entries.get(this.key(sessionId, fingerprint)) ?? null;
  }

  clear() {
    this.entries.clear();
  }
}

function describeTargets(targets) {
  const lines = [];
  for (const item of targets ?? []) {
    const files = item.files ?? 0;
    const bytes = item.bytes ?? 0;
    lines.push(`  • ${item.root}\n      ${files} 个文件，${formatBytes(bytes)}`);
  }
  return lines.join('\n');
}

/** 生成给用户看的拦截报告。确认码放在最后。 */
export function buildReport({ zone, level, targets, stats, batchId, batchDir, code, command, unresolvedReason, knownTargets }) {
  if (unresolvedReason) return buildUnresolvedReport({ level, command, unresolvedReason, code, knownTargets });
  const list = describeTargets(targets);
  const total = `合计：${stats.files} 个文件，${formatBytes(stats.bytes)}`;
  return [
    '🛑 敏感区删除已拦截（未执行）',
    '',
    `区域：${zone}`,
    `级别：${level}`,
    '',
    '拟删除的内容：',
    list || '  •（无法列出明细）',
    '',
    total,
    '',
    `已经提前备份：${batchId}`,
    `备份目录：${batchDir}`,
    `还原命令：node bin/delete-guard.mjs restore ${batchId}`,
    '',
    '如确实要删除，请把下面的确认码发给我，我会带着它重新发起（备份已就绪，不会重复备份）：',
    '',
    `确认码：${code}`,
  ].join('\n');
}

/**
 * 目标解析不出时的报告。与敏感区拦截的关键差别必须摆在最前面：
 * 这一次**没有备份**，确认之后删掉的东西是找不回来的。
 */
function buildUnresolvedReport({ level, command, unresolvedReason, code, knownTargets }) {
  const lines = [
    '⚠️ 破坏性命令的目标无法静态确定（未执行）',
    '',
    `原因：${unresolvedReason}`,
  ];
  if (Array.isArray(knownTargets) && knownTargets.length > 0) {
    lines.push(`能确定的部分目标：${knownTargets.join('、')}`);
  }
  lines.push(
    '',
    '命令原文：',
    '```',
    String(command ?? '').trim() || '(无)',
    '```',
    '',
    '❗ 本次没有备份：目标要到运行时才确定，守卫无法在放行前保存副本。',
    '   确认之后执行删除，被删掉的内容无法用 delete-guard restore 还原。',
    '   守卫同样无法校验目标是否落在受保护目录（插件自身、备份根）里。',
    '',
    `级别：${level}`,
    '',
    '请你替我确认：上面的命令是不是真的只删你想删的东西？',
    '如果确认无误，请把下面的确认码发给我，我会带着它重新发起这条命令：',
    '',
    `确认码：${code}`,
  );
  return lines.join('\n');
}
