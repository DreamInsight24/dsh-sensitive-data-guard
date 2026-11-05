// Host 侧 Config schema（schemastery）。默认值与 lib/defaults.js 保持一致；
// apply() 里还会用 resolveConfig() 做一次深合并，保证用户只覆盖部分字段时也安全。
import z from '@deepseek-ai/schemastery';
import { DEFAULTS } from './defaults.js';

export const Config = z.object({
  enabled: z.boolean().default(DEFAULTS.enabled),
  emergencyBypass: z.boolean().default(DEFAULTS.emergencyBypass),
  failClosed: z.boolean().default(DEFAULTS.failClosed),
  shellSeam: z.boolean().default(DEFAULTS.shellSeam),
  hooks: z.object({
    python: z.boolean().default(DEFAULTS.hooks.python),
    node: z.boolean().default(DEFAULTS.hooks.node),
  }).default(DEFAULTS.hooks),
  sysmon: z.object({
    warnOnly: z.boolean().default(DEFAULTS.sysmon.warnOnly),
  }).default(DEFAULTS.sysmon),
  backup: z.object({
    root: z.string().default(DEFAULTS.backup.root),
    maxFileBytes: z.number().default(DEFAULTS.backup.maxFileBytes),
    overFileLimit: z.string().default(DEFAULTS.backup.overFileLimit),
    maxBatchBytes: z.number().default(DEFAULTS.backup.maxBatchBytes),
    maxBatchFiles: z.number().default(DEFAULTS.backup.maxBatchFiles),
    quotaBytes: z.number().default(DEFAULTS.backup.quotaBytes),
    retentionDays: z.number().default(DEFAULTS.backup.retentionDays),
    autoCleanup: z.boolean().default(DEFAULTS.backup.autoCleanup),
    dedupe: z.boolean().default(DEFAULTS.backup.dedupe),
    verify: z.boolean().default(DEFAULTS.backup.verify),
    followSymlinks: z.boolean().default(DEFAULTS.backup.followSymlinks),
    exclusions: z.array(z.string()).default(DEFAULTS.backup.exclusions),
    concurrency: z.number().default(DEFAULTS.backup.concurrency),
    mirrorTree: z.boolean().default(DEFAULTS.backup.mirrorTree),
  }).default(DEFAULTS.backup),
  policy: z.object({
    unknownTool: z.string().default(DEFAULTS.policy.unknownTool),
    opaqueCommand: z.string().default(DEFAULTS.policy.opaqueCommand),
    scopeRoots: z.array(z.string()).default(DEFAULTS.policy.scopeRoots),
    safeTools: z.array(z.string()).default(DEFAULTS.policy.safeTools),
    safeCommands: z.array(z.string()).default(DEFAULTS.policy.safeCommands),
    volatileRoots: z.array(z.string()).default(DEFAULTS.policy.volatileRoots),
    protectedPaths: z.array(z.string()).default(DEFAULTS.policy.protectedPaths),
  }).default(DEFAULTS.policy),
});
