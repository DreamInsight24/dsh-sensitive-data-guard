// 敏感数据守卫默认配置（纯数据，CLI 与 Host 插件共用；不依赖 DSH 包）。
// 这份默认值同时是 cordis.patch.yml 里 config 的说明基准。
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// 插件根目录：所有「指向本插件」的默认路径都从这里推导，
// 换机器、换安装位置都不用改任何绝对路径。
export const PLUGIN_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

// 备份根默认就是插件目录下的 backup/。
// 配置里写相对路径（例如 'backup'）时，resolveConfig 会按 PLUGIN_DIR 解析。
export const DEFAULT_BACKUP_ROOT = path.join(PLUGIN_DIR, 'backup');

/** 深合并：对象逐层合并，数组/标量直接覆盖。 */
export function mergeConfig(base, override) {
  if (override === undefined || override === null) return clone(base);
  if (Array.isArray(base) || Array.isArray(override)) return clone(override);
  if (typeof base === 'object' && typeof override === 'object') {
    const out = {};
    for (const key of Object.keys(base)) out[key] = mergeConfig(base[key], override[key]);
    for (const key of Object.keys(override)) if (!(key in out)) out[key] = clone(override[key]);
    return out;
  }
  return clone(override);
}

function clone(value) {
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) out[key] = clone(value[key]);
    return out;
  }
  return value;
}

export const DEFAULTS = {
  // 总开关：只有手工改配置才能关掉。
  enabled: true,
  // 逃生开关：默认关；打开后所有删除直接放行（仅审计），只允许用户手工改。
  emergencyBypass: false,
  // 插件内部异常时是否阻断（硬性要求：保持 true）。
  failClosed: true,
  // 是否启用 ctx.shell 深度层（覆盖所有 shell 命令与 python/node 孙进程）。
  shellSeam: true,
  hooks: {
    python: true,
    node: true,
  },
  sysmon: {
    warnOnly: true,
  },
  backup: {
    // 备份根：必须与删除目标不同树；默认放在工作区内、C: 用户配置目录之外。
    root: DEFAULT_BACKUP_ROOT,
    // 单文件上限：超过则按 overFileLimit 处理（默认阻断）。
    maxFileBytes: 268435456, // 256 MiB
    overFileLimit: 'block', // block | record-only
    // 单批上限：一次删除/覆盖最多备份多少字节、多少个文件。
    maxBatchBytes: 10737418240, // 10 GiB
    maxBatchFiles: 50000,
    // 备份总配额：超过后新的备份直接阻断，绝不把磁盘打满。
    quotaBytes: 53687091200, // 50 GiB
    // 敏感区保留天数：到期批次会被自动清理（审计日志不删）。
    retentionDays: 30,
    // .dsh 区域：只保留最新 N 个批次，且不超过 N 天。
    dshRetentionCount: 10,
    dshRetentionDays: 30,
    autoCleanup: true,
    // 内容寻址去重：相同哈希只存一份。
    dedupe: true,
    // 复制后校验大小；还原时校验 SHA-256。
    verify: true,
    // 是否跟随软链接/junction：默认不跟随，只记录。
    followSymlinks: false,
    // 显式排除表（白名单式）：默认不排除任何路径。
    exclusions: [],
    // 并行复制数。
    concurrency: 4,
    // 是否在批次目录里建立硬链接镜像（便于人工查看；跨卷时退化为复制）。
    mirrorTree: true,
  },
  policy: {
    // 提醒级别（可在 DSH 设置页里改）：
    //   soft   = 仅备份，不提醒、不阻断
    //   medium = 达到阈值才提醒（文件数 ≥ mediumMinFiles 或 体积 ≥ mediumMinBytes）
    //   hard   = 敏感区删除一律提醒（默认）
    triggerLevel: 'hard',
    mediumMinFiles: 10,
    mediumMinBytes: 67108864, // 64 MiB
    // .dsh 根目录覆盖；留空则用 $DSH_HOME，再退回 %USERPROFILE%\.dsh。
    dshHome: '',
    // 工作区内部的处理方式：none = 完全不保护（默认，且不建议改）。
    workspaceMode: 'none',
    // 不认识的工具：prompt（默认，弹窗问用户是否信任）| deny | allow-audit。
    // prompt 里用户可以「信任并加入白名单」（写 data/settings.json，以后不再询问）
    // 或「仅本次允许」；弹窗送不到就 fail-closed 阻断。
    unknownTool: 'prompt',
    // shell 命令解析不出目标时：scope（备份整个工作目录，默认）| block。
    opaqueCommand: 'scope',
    // 确认通道：
    //   popup = 直接弹窗问用户（默认）。答案只回本插件，模型看不到、也拿不到码。
    //   code  = 旧的文本确认码：报告里给 4 位数字，模型带回命令重发。
    //           ⚠ 确认码写在工具返回值里，模型自己就能填回去，等于没有「人在环路」。
    confirmVia: 'popup',
    // 弹窗等待上限（毫秒）：超时按 fail-closed 阻断，绝不自动放行。
    confirmTimeoutMs: 300000,
    // 破坏性命令的目标「解析不出」（变量/运行时表达式）时怎么办：
    //   confirm = 弹窗确认后放行（默认；没有备份，正文里会写明）
    //   deny    = 直接阻断（最严，但正常操作容易被卡死）
    //   scope   = 回落到工作目录 scope（0.2.2 及以前的行为，等于放行）
    // 注意 confirm/scope 两种情况都**没有备份**：目标在运行时才确定。
    unresolvedAction: 'confirm',
    // 额外保护根（绝对路径）：其中的删除/覆盖一律拒绝。
    scopeRoots: [],
    // 追加的安全工具名（只读）。
    safeTools: [],
    // 追加的只读命令正则（字符串）。
    safeCommands: [],
    // 运行时钩子允许删除的易失目录（临时目录、包管理器缓存等）。
    // 这些目录本来就可以随时删除；不放开会让 npm/pnpm 安装直接失败。
    volatileRoots: [
      '%TEMP%',
      '%LOCALAPPDATA%\\Temp',
      '%LOCALAPPDATA%\\npm-cache',
      '%APPDATA%\\npm-cache',
      '%LOCALAPPDATA%\\pnpm',
      '%LOCALAPPDATA%\\pnpm-cache',
      '%APPDATA%\\pnpm',
      '%LOCALAPPDATA%\\Yarn',
      '%USERPROFILE%\\.npm',
      '%USERPROFILE%\\.cache',
    ],
    // 额外保护路径（.gitignore 风格模式，支持 ! 排除；插件目录、备份根、审计日志自动加入）。
    protectedPaths: [],
  },
};

export function resolveConfig(input) {
  const merged = mergeConfig(DEFAULTS, input);
  // 备份根支持相对写法：相对路径一律按插件目录解析（见 PLUGIN_DIR）。
  const root = merged.backup?.root;
  if (typeof root === 'string' && root.length > 0 && !path.isAbsolute(root)) {
    merged.backup.root = path.resolve(PLUGIN_DIR, root);
  }
  return merged;
}
