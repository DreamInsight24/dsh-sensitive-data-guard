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
 * 弹窗确认时展示在 detail 里的说明文本（**不含确认码**）。
 * 用户是在 DSH 的交互卡片里直接点选放行/拦截的，答案由本插件自己收，
 * 模型看不到这次问答，也就没有「模型自己把码填回去」这条捷径。
 */
export function buildPromptDetail({ zone, level, stats, targets, batchId, batchDir, command, unresolvedReason }) {
  if (unresolvedReason) {
    return [
      '命令原文：',
      String(command ?? '').trim() || '(无)',
      '',
      `为什么问你：${unresolvedReason}`,
      '',
      '❗ 这次没有备份。目标要到运行时才确定，守卫无法在放行前保存副本：',
      '   · 执行后删掉的内容无法用 delete-guard restore 还原；',
      '   · 也无法校验目标是否落在受保护目录（插件自身、备份根）里。',
    ].join('\n');
  }
  const list = describeTargets(targets);
  return [
    `区域：${zone}`,
    `级别：${level}`,
    '',
    '拟删除的内容：',
    list || '  •（无法列出明细）',
    '',
    `合计：${stats.files} 个文件，${formatBytes(stats.bytes)}`,
    '',
    `已经提前备份：${batchId}`,
    `备份目录：${batchDir}`,
    `还原命令：node bin/delete-guard.mjs restore ${batchId}`,
  ].join('\n');
}

/** 用户点了拦截时回给模型的话（不含任何可用于放行的信息）。 */
export function buildDeclinedText() {
  return [
    '❌ 用户已在确认弹窗里拦截这次删除，命令没有执行。',
    '',
    '不要重复发起同一条命令，也不要换个写法绕过去。',
    '如果确实需要删除，请让用户自己操作，或者先问清楚他想要什么。',
  ].join('\n');
}

/** 弹窗发不出去（没有 UI 客户端、子代理、超时等）时回给模型的话。 */
export function buildUnavailableText(reason) {
  return [
    '❌ 需要用户确认，但确认弹窗没能送达用户，已按 fail-closed 阻断。',
    '',
    `原因：${reason}`,
    '',
    '请把你要删除的内容直接用自然语言告诉用户，让他自己在 DSH 界面里操作；',
    '或者把 policy.confirmVia 改成 "code" 走文本确认码流程。',
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
