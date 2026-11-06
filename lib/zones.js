// 区域模型：把每个操作目标归入三个区域之一，并给出该区域的处理策略。
//
//   workspace  当前会话工作区           → 不做任何保护（不备份、不提醒、不阻断）
//   dsh        本机 .dsh 配置目录        → 静默自动备份一次（LLM 主动修改时），不提醒
//   sensitive  .dsh 与工作区之外的路径   → 备份 + 弹窗确认，按级别定阈值
//
// 本插件的存在目的：防止 DSH 在获得最高权限时，静默删除/修改工作区之外的目录。
// 因此工作区内部故意完全不设防。

import path from 'node:path';
import os from 'node:os';
import { isInside } from './paths.js';
import { expandEnv } from './paths.js';

export const ZONE = Object.freeze({
  WORKSPACE: 'workspace',
  DSH: 'dsh',
  SENSITIVE: 'sensitive',
});

export const ZONE_LABEL = Object.freeze({
  workspace: '工作区',
  dsh: '.dsh 配置目录',
  sensitive: '敏感区（.dsh 与工作区之外）',
});

const RANK = { workspace: 0, dsh: 1, sensitive: 2 };

/** 本机 .dsh 根目录；可用配置覆盖。 */
export function dshHomeOf(explicit) {
  if (explicit) {
    const expanded = expandEnv(explicit);
    if (expanded) return path.resolve(expanded);
  }
  if (process.env.DSH_HOME) return path.resolve(process.env.DSH_HOME);
  const profileDir = process.env.DSH_PROFILE_DIR;
  if (profileDir) return path.dirname(path.resolve(profileDir));
  return path.join(os.homedir(), '.dsh');
}

/** 单个路径属于哪个区域。 */
export function classifyZone(target, { workspaceRoot, dshHome }) {
  if (!target) return ZONE.SENSITIVE;
  const resolved = path.resolve(target);
  if (workspaceRoot && isInside(path.resolve(workspaceRoot), resolved)) return ZONE.WORKSPACE;
  if (dshHome && isInside(path.resolve(dshHome), resolved)) return ZONE.DSH;
  return ZONE.SENSITIVE;
}

/** 多目标取最严格的区域。 */
export function strictestZoneOf(targets, ctx) {
  let zone = ZONE.WORKSPACE;
  for (const target of targets) {
    const current = classifyZone(target, ctx);
    if (RANK[current] > RANK[zone]) zone = current;
  }
  return zone;
}

export function zoneRank(zone) {
  return RANK[zone] ?? RANK.sensitive;
}
