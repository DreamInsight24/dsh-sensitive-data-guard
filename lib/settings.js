// 运行时设置：DSH 设置页里改的「提醒级别」与「保护目录」。
//
// 优先级：DEFAULTS < bundle 的 cordis.patch.yml config < 本文件（UI 保存的覆盖）。
// 本文件放在插件目录下的 data/settings.json，由 Host 进程读写；
// 插件目录本身是受保护路径，模型无法通过工具改写它。
import fs from 'node:fs';
import path from 'node:path';

export const LEVELS = Object.freeze(['soft', 'medium', 'hard']);

export const LEVEL_SCOPE = Object.freeze({
  soft: '仅备份，不提醒也不阻断：敏感区删除照常执行，事后可从备份还原。',
  medium: '达到阈值才提醒：文件数或体积任一超过阈值，才要求输入 4 位确认码。',
  hard: '一律提醒：敏感区（.dsh 与工作区之外）的任何删除/覆盖都先备份再要确认码。',
});

export function settingsPath(pluginDir) {
  return path.join(pluginDir, 'data', 'settings.json');
}

export function loadSettings(pluginDir) {
  try {
    const text = fs.readFileSync(settingsPath(pluginDir), 'utf8');
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

export function saveSettings(pluginDir, settings) {
  const file = settingsPath(pluginDir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(settings, null, 2), 'utf8');
  return file;
}

/** 只接受已知字段并做范围校验；非法值直接拒绝（不静默纠正）。 */
export function sanitizePatch(input) {
  if (!input || typeof input !== 'object') throw new Error('设置必须是对象');
  const out = {};
  if (input.triggerLevel !== undefined) {
    const level = String(input.triggerLevel);
    if (!LEVELS.includes(level)) throw new Error(`triggerLevel 只能是 ${LEVELS.join(' / ')}`);
    out.triggerLevel = level;
  }
  if (input.mediumMinFiles !== undefined) {
    const n = Number(input.mediumMinFiles);
    if (!Number.isFinite(n) || n < 0) throw new Error('mediumMinFiles 必须是非负数字');
    out.mediumMinFiles = Math.floor(n);
  }
  if (input.mediumMinBytes !== undefined) {
    const n = Number(input.mediumMinBytes);
    if (!Number.isFinite(n) || n < 0) throw new Error('mediumMinBytes 必须是非负数字');
    out.mediumMinBytes = Math.floor(n);
  }
  if (input.protectedPaths !== undefined) {
    const list = input.protectedPaths;
    if (!Array.isArray(list)) throw new Error('protectedPaths 必须是字符串数组');
    out.protectedPaths = list
      .map((item) => String(item ?? '').trim())
      .filter((item) => item.length > 0);
  }
  return out;
}

/** 级别收紧/放宽的判定：hard > medium > soft。 */
export function levelRank(level) {
  const at = LEVELS.indexOf(level);
  return at === -1 ? LEVELS.length : at;
}

export function isLoosening(from, to) {
  return levelRank(to) < levelRank(from);
}
