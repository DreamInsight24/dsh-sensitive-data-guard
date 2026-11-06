// 门禁核心：工具 pre-execute / guard / post-execute 与 shell 深度层。
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveConfig } from './defaults.js';
import { BackupEngine, formatBytes } from './backup.js';
import { AuditLog } from './audit.js';
import {
  planToolCall, quickClassify, parseShellCommand, SHELL_TOOLS, WRITE_TOOLS, MOVE_TOOLS, DELETE_TOOLS,
  SELF_NAME_RE, isWhitelistableTool, unknownToolAction,
} from './classify.js';
import {
  isInside, toAbsolute, expandEnv, compileProtectPatterns, isProtectedByPatterns, patternCoversTarget,
} from './paths.js';
import { ZONE, ZONE_LABEL, classifyZone, strictestZoneOf, dshHomeOf } from './zones.js';
import {
  ConfirmStore, extractConfirmCode, fingerprintOf, buildReport,
  buildPromptDetail, buildDeclinedText, buildUnavailableText,
  buildUnknownToolDetail, buildUnknownDeclinedText, buildUnknownUnavailableText,
} from './confirm.js';
import {
  LEVELS, LEVEL_SCOPE, loadSettings, saveSettings, settingsPath, sanitizePatch, isLoosening,
} from './settings.js';

const PLUGIN_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

const ALLOW_TTL_MS = 30 * 60 * 1000;

// 弹窗确认的固定标识：问题 id 与两个选项文案。只有「允许执行」这一个选项会放行，
// 其余（拦截、自定义回答、超时、没有 UI）一律阻断。
const CONFIRM_QUESTION_ID = 'delete-guard-confirm';
const ALLOW_LABEL = '允许执行';
const DENY_LABEL = '拦截';

// 未知工具的信任弹窗：三个选项，只有明确选中其中一个才生效。
//   「信任并加入白名单」= 持久信任（写 data/settings.json，以后不再询问）
//   「仅本次允许」       = 只放行这一次，下次仍问
//   「拦截」             = 阻断
const UNKNOWN_TOOL_QUESTION_ID = 'delete-guard-unknown-tool';
const TRUST_LABEL = '信任并加入白名单';
const ONCE_LABEL = '仅本次允许';

function nowIso() {
  return new Date().toISOString();
}

/** 尽可能取真实路径（穿透符号链接/junction）；不存在时取父目录真实路径 + 文件名。 */
function realpathOr(target) {
  const resolved = path.resolve(target);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    try {
      const parent = fs.realpathSync.native(path.dirname(resolved));
      return path.join(parent, path.basename(resolved));
    } catch {
      return resolved;
    }
  }
}

/** 从工具参数里取可能被写入/移动/删除的路径（用于受保护路径检查）。 */
function toolPaths(name, args, workdir) {
  const keys = ['file_path', 'path', 'target', 'file', 'source', 'destination', 'from', 'to'];
  const out = [];
  for (const key of keys) {
    const value = args?.[key];
    if (typeof value === 'string' && value.trim()) out.push(toAbsolute(value, workdir));
    if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item.trim()) out.push(toAbsolute(item, workdir));
    }
  }
  return out;
}

export class GateCore {
  constructor(ctx, rawConfig, options = {}) {
    this.ctx = ctx;
    this.config = resolveConfig(rawConfig);
    this.policy = this.config.policy;
    // 设置文件的位置：默认插件目录下 data/settings.json（测试可注入临时目录）。
    this.settingsDir = options.settingsDir ? path.resolve(options.settingsDir) : PLUGIN_DIR;
    // 配置文件里声明的保护目录是**底线**：UI 只能往上追加，不能把它删掉。
    // （曾经写成「settings.json 里的数组直接覆盖」，结果用户在设置页点一次保存，
    //   把配置里写好的保护目录永久清空——这是 0.2.1 修掉的 bug。）
    this.baseProtectedPaths = [...(this.policy.protectedPaths ?? [])];
    this.uiProtectedPaths = [];
    this.protectPatterns = [];
    // 受信任工具同理：配置里声明的是底线，UI/弹窗追加的单独存 data/settings.json。
    this.baseSafeTools = [...(this.policy.safeTools ?? [])];
    this.uiSafeTools = [];
    // DSH 设置页保存的覆盖（级别 / 阈值 / 追加的保护目录）。
    this.applySettingsOverlay();
    this.engine = new BackupEngine(this.config.backup);
    this.audit = new AuditLog(this.engine.root, ctx.logger);
    this.tokens = new Map();
    this.shellTokens = new Map();
    this.ready = false;
    this.initError = null;
    this.disposed = false;
    this.timers = [];
    this.sysmon = { checked: false, ok: false, detail: '尚未检测' };
    this.hookFiles = { python: false, node: false, pythonDir: '', nodePath: '' };
    this.pluginDir = PLUGIN_DIR;
    this.protectedRoots = this.buildProtectedRoots();
    // 区域模型：工作区 / .dsh / 敏感区
    this.dshHome = dshHomeOf(this.policy.dshHome);
    this.confirm = new ConfirmStore();
  }

  /** 生效的保护目录 = 配置底线 ∪ UI 追加（去重，保持顺序）。 */
  refreshProtectedPaths() {
    const seen = new Set();
    const merged = [];
    for (const item of [...this.baseProtectedPaths, ...this.uiProtectedPaths]) {
      const pattern = String(item ?? '').trim();
      if (!pattern || seen.has(pattern)) continue;
      seen.add(pattern);
      merged.push(pattern);
    }
    this.policy.protectedPaths = merged;
    // policy.protectedPaths 现在是 .gitignore 风格的可管理模式列表（支持 ! 排除）。
    this.protectPatterns = compileProtectPatterns(merged);
  }

  /**
   * 生效的受信任工具 = 配置底线 ∪ UI/弹窗追加（去重，保持顺序）。
   * 已知的删除/覆盖类工具与 plugin_manager 不能加白（底线，见 classify.isWhitelistableTool）。
   */
  refreshSafeTools() {
    const merged = [];
    for (const item of [...this.baseSafeTools, ...this.uiSafeTools]) {
      const name = String(item ?? '').trim();
      if (!name || merged.includes(name)) continue;
      if (!isWhitelistableTool(name)) continue;
      merged.push(name);
    }
    this.policy.safeTools = merged;
  }

  /** 把 data/settings.json 里的覆盖套到当前配置上。 */
  applySettingsOverlay() {
    let overlay;
    try {
      overlay = loadSettings(this.settingsDir);
    } catch {
      return;
    }
    if (!overlay || typeof overlay !== 'object') {
      this.refreshProtectedPaths();
      return;
    }
    if (LEVELS.includes(overlay.triggerLevel)) this.policy.triggerLevel = overlay.triggerLevel;
    if (Number.isFinite(overlay.mediumMinFiles)) this.policy.mediumMinFiles = overlay.mediumMinFiles;
    if (Number.isFinite(overlay.mediumMinBytes)) this.policy.mediumMinBytes = overlay.mediumMinBytes;
    if (Array.isArray(overlay.protectedPaths)) {
      this.uiProtectedPaths = overlay.protectedPaths
        .map((item) => String(item ?? '').trim())
        .filter((item) => item.length > 0);
    }
    if (Array.isArray(overlay.safeTools)) {
      this.uiSafeTools = overlay.safeTools
        .map((item) => String(item ?? '').trim())
        .filter((item) => item.length > 0);
    }
    this.refreshProtectedPaths();
    this.refreshSafeTools();
  }

  /** 当前生效的设置（给设置页读）。 */
  settingsSnapshot() {
    return {
      triggerLevel: this.policy.triggerLevel,
      levelScope: LEVEL_SCOPE,
      levels: [...LEVELS],
      mediumMinFiles: this.policy.mediumMinFiles,
      mediumMinBytes: this.policy.mediumMinBytes,
      // 文本框里编辑的是「UI 追加」这一份；配置底线单独给出来只读展示。
      protectedPaths: [...this.uiProtectedPaths],
      configProtectedPaths: [...this.baseProtectedPaths],
      safeTools: [...this.uiSafeTools],
      configSafeTools: [...this.baseSafeTools],
      effectiveSafeTools: [...this.policy.safeTools],
      dshHome: this.dshHome,
      workspaceMode: this.policy.workspaceMode,
      retention: {
        sensitiveDays: this.config.backup.retentionDays,
        dshCount: this.config.backup.dshRetentionCount,
        dshDays: this.config.backup.dshRetentionDays,
      },
      settingsFile: settingsPath(this.settingsDir),
    };
  }

  /**
   * 保存设置并立即生效（无需重启）。
   * 返回 { ok, loosened, from, to, settings } —— loosened=true 表示这次是放宽，界面需要红字警告。
   */
  applySettings(input) {
    const patch = sanitizePatch(input);
    const before = this.policy.triggerLevel;
    const merged = { ...loadSettings(this.settingsDir), ...patch };
    saveSettings(this.settingsDir, merged);

    if (patch.triggerLevel !== undefined) this.policy.triggerLevel = patch.triggerLevel;
    if (patch.mediumMinFiles !== undefined) this.policy.mediumMinFiles = patch.mediumMinFiles;
    if (patch.mediumMinBytes !== undefined) this.policy.mediumMinBytes = patch.mediumMinBytes;
    if (patch.protectedPaths !== undefined) {
      // 只替换「UI 追加」这一份；配置底线始终保留。
      this.uiProtectedPaths = patch.protectedPaths;
      // 保护目录立即重新编译：放宽也要等下一次工具调用才生效。
      this.refreshProtectedPaths();
    }
    if (patch.safeTools !== undefined) {
      this.uiSafeTools = [...patch.safeTools];
      this.refreshSafeTools();
    }
    const loosened = patch.triggerLevel !== undefined && isLoosening(before, patch.triggerLevel);
    this.audit.write({
      event: 'settings', by: 'ui', before, after: this.policy.triggerLevel, loosened, patch,
    });
    return {
      ok: true,
      loosened,
      from: before,
      to: this.policy.triggerLevel,
      settings: this.settingsSnapshot(),
    };
  }

  buildProtectedRoots() {
    const roots = [realpathOr(this.engine.root), realpathOr(this.pluginDir)];
    const profileDir = process.env.DSH_PROFILE_DIR;
    if (profileDir) {
      for (const file of ['cordis.patch.yml', 'cordis.yml', 'package.json']) {
        roots.push(realpathOr(path.join(profileDir, file)));
      }
    }
    return [...new Set(roots)];
  }

  async start() {
    try {
      await this.audit.init();
      await this.engine.init();
      await this.engine.cleanIpc();
      this.checkHookFiles();
      this.ready = true;
      this.audit.write({ event: 'startup', root: this.engine.root, pid: process.pid, platform: process.platform });
      this.ctx.logger?.info?.(`[delete-guard] 已就绪：备份根 ${this.engine.root}`);
      this.checkSysmon();
      if (this.config.backup.autoCleanup) {
        const timer = setTimeout(() => {
          this.engine.cleanup().catch((error) => this.ctx.logger?.warn?.(`[delete-guard] 清理失败：${error.message}`));
        }, 3000);
        this.timers.push(timer);
      }
    } catch (error) {
      this.initError = error.message;
      this.ready = false;
      this.ctx.logger?.warn?.(`[delete-guard] 初始化失败（破坏性操作将保持阻断）：${error.message}`);
      this.audit.write({ event: 'error', phase: 'startup', message: error.message });
    }
  }

  dispose() {
    this.disposed = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.length = 0;
    this.audit.write({ event: 'shutdown' });
    this.audit.flush().catch(() => {});
  }

  checkHookFiles() {
    const pythonDir = path.join(PLUGIN_DIR, 'hooks', 'python');
    const pythonFile = path.join(pythonDir, 'sitecustomize.py');
    const nodePath = path.join(PLUGIN_DIR, 'hooks', 'node', 'delete-guard.cjs');
    this.hookFiles = {
      pythonDir,
      nodePath,
      python: fs.existsSync(pythonFile),
      node: fs.existsSync(nodePath),
    };
    if (this.config.hooks.python && !this.hookFiles.python) {
      this.config.hooks.python = false;
      this.ctx.logger?.warn?.(`[delete-guard] 缺少 Python 钩子文件：${pythonFile}，已禁用 python 钩子`);
    }
    if (this.config.hooks.node && !this.hookFiles.node) {
      this.config.hooks.node = false;
      this.ctx.logger?.warn?.(`[delete-guard] 缺少 Node 钩子文件：${nodePath}，已禁用 node 钩子`);
    }
  }

  async checkSysmon() {
    const query = (name) => new Promise((resolve) => {
      execFile('sc.exe', ['query', name], { windowsHide: true, timeout: 5000 }, (error, stdout) => {
        if (error) {
          resolve({ name, ok: false, detail: error.message });
          return;
        }
        resolve({ name, ok: /RUNNING/i.test(String(stdout)), detail: String(stdout).split(/\r?\n/).find((l) => /STATE/.test(l)) ?? '' });
      });
    });
    try {
      const services = await Promise.all([query('Sysmon64'), query('SysmonDrv')]);
      this.sysmon = {
        checked: true,
        at: nowIso(),
        ok: services.every((s) => s.ok),
        services,
      };
      this.audit.write({ event: 'sysmon', ...this.sysmon });
      if (!this.sysmon.ok) {
        this.ctx.logger?.warn?.('[delete-guard] Sysmon 未在运行：OS 层删除取证可能缺失');
      }
    } catch (error) {
      this.sysmon = { checked: true, at: nowIso(), ok: false, detail: error.message };
    }
  }

  // ── 工具关卡 ──────────────────────────────────────────────────────────────

  async onPreExecute(exec, next) {
    if (this.disposed) return next();
    const decision = await next();
    if (decision.kind === 'deny' || decision.kind === 'cancel') return decision;
    try {
      const outcome = await this.evaluate(exec);
      if (outcome.kind === 'deny') return { kind: 'deny', reason: outcome.reason };
      return decision;
    } catch (error) {
      this.audit.write({ event: 'error', tool: exec.name, callId: exec.callId, message: error.message });
      return { kind: 'deny', reason: `delete-guard: 内部异常，已按 fail-closed 阻断：${error.message}` };
    }
  }

  guard(exec) {
    if (this.disposed || !this.config.enabled || this.config.emergencyBypass) return undefined;
    this.pruneTokens();
    const kind = quickClassify(exec.name, this.policy);
    if (kind === 'safe') return undefined;
    if (kind === 'destructive') {
      if (!this.tokens.has(exec.callId)) {
        return 'delete-guard: 该调用没有完成备份检查，已阻断（fail-closed）';
      }
      return undefined;
    }
    if (kind === 'plugin-manager') {
      const action = String(exec.arguments?.action ?? '');
      const text = JSON.stringify(exec.arguments ?? {}).toLowerCase();
      const mutating = ['install_bundle', 'remove_bundle', 'set_bundle', 'set_plugin'];
      if (mutating.includes(action) && SELF_NAME_RE.test(text)) {
        return 'delete-guard: 禁止通过 plugin_manager 改动敏感数据守卫自身';
      }
      return undefined;
    }
    if (kind === 'unknown') {
      // prompt / allow-audit：异步 pre-execute 已经处理过（弹窗或审计），这里不再重复阻断。
      if (unknownToolAction(this.policy) === 'deny') {
        return `delete-guard: 未知工具 "${exec.name}" 不在安全清单中，已阻断（如只读请加入 policy.safeTools）`;
      }
    }
    return undefined;
  }

  async onPostExecute(exec, result, next) {
    if (this.disposed) return next();
    const decision = await next();
    const token = this.tokens.get(exec.callId);
    if (!token || !token.summary || token.summaryShown) return decision;
    token.summaryShown = true;
    if (decision.kind !== 'accept' || !Array.isArray(decision.content)) return decision;
    return {
      ...decision,
      content: [...decision.content, { type: 'text', text: token.summary }],
    };
  }

  async evaluate(exec) {
    if (this.disposed || !this.config.enabled) return { kind: 'allow' };
    if (this.config.emergencyBypass) {
      this.audit.write({ event: 'bypass', tool: exec.name, callId: exec.callId });
      return { kind: 'allow' };
    }
    const name = String(exec.name ?? '');
    const args = exec.arguments ?? {};
    const workdir = await this.computeWorkdir(exec, name, args);
    const plan = planToolCall({ name, args, workdir, policy: this.policy });
    if (plan.kind === 'unknown') {
      const action = unknownToolAction(this.policy);
      if (action === 'allow-audit') {
        this.auditGate(exec, plan, 'allow');
        return { kind: 'allow' };
      }
      if (action === 'prompt') {
        // 信任弹窗只能走 popup 通道；用户显式选了 code（旧文本码）时没有弹窗可发，
        // 直接 fail-closed 阻断，并告诉模型怎么手工加白。
        if (this.confirmVia() !== 'popup') {
          this.auditGate(exec, plan, 'deny', null, 'confirmVia=code，无法弹窗');
          return {
            kind: 'deny',
            reason: `delete-guard: 未知工具 "${name}"，当前确认通道是 code，无法弹窗确认；请把它加入 policy.safeTools 或把 confirmVia 改成 popup。`,
          };
        }
        const outcome = await this.guardUnknownTool({
          exec, plan, args, workdir, toolName: name, agent: exec.agent, signal: exec.signal,
        });
        if (outcome.kind === 'deny') {
          this.auditGate(exec, plan, 'deny', null, outcome.reason, null);
          return { kind: 'deny', reason: outcome.reason };
        }
        this.issueToken(exec, outcome.entry);
        this.auditGate(exec, plan, 'allow', outcome.entry, null, null);
        return { kind: 'allow' };
      }
      this.auditGate(exec, plan, 'deny');
      return { kind: 'deny', reason: `delete-guard: 未知工具 "${name}" 不在安全清单中，已阻断（如只读请加入 policy.safeTools）` };
    }
    if (plan.kind === 'deny') {
      this.auditGate(exec, plan, 'deny');
      return { kind: 'deny', reason: plan.reason };
    }
    if (plan.kind === 'confirm') {
      // 目标解析不出：不硬拒，改走确认码流程（由模型用自然语言向用户申请）。
      // 但「门禁本身不健康」时仍然 fail-closed——那时候连审计都不可信。
      if (this.initError) {
        return { kind: 'deny', reason: `delete-guard: 备份不可用，已阻断：${this.initError}` };
      }
      if (!this.ready) {
        return { kind: 'deny', reason: 'delete-guard: 门禁尚未就绪，已阻断（fail-closed）' };
      }
      const outcome = await this.guardUnresolved({
        exec, plan, args, workdir, toolName: name, agent: exec.agent, signal: exec.signal,
      });
      if (outcome.kind === 'deny') {
        this.auditGate(exec, plan, 'deny', null, outcome.reason, 'unresolved');
        return { kind: 'deny', reason: outcome.reason };
      }
      this.issueToken(exec, outcome.entry);
      this.auditGate(exec, plan, 'allow', outcome.entry, null, 'unresolved');
      return { kind: 'allow' };
    }
    if (plan.kind === 'safe') {
      // 新建文件本身不需要备份，但不允许在受保护目录里新建（防止往插件目录注入文件）。
      // 受信任的白名单工具同样过这一层：信任的是「只读」，不是「可以碰插件目录/备份根」。
      const whitelisted = Array.isArray(plan.notes) && plan.notes.includes('policy:safeTools');
      if (whitelisted || WRITE_TOOLS.has(name) || MOVE_TOOLS.has(name) || DELETE_TOOLS.has(name)) {
        for (const candidate of toolPaths(name, args, workdir)) {
          try {
            this.assertNotProtected(candidate, 'targets');
          } catch (error) {
            this.auditGate(exec, plan, 'deny', null, error.message);
            return { kind: 'deny', reason: `delete-guard: ${error.message}` };
          }
        }
      }
      this.issueToken(exec, { roots: [], batchId: null, summary: null, planKind: 'safe', workdir });
      this.auditGate(exec, plan, 'allow');
      return { kind: 'allow' };
    }
    // targets / scope：按区域分流。
    const roots = plan.kind === 'targets' ? [...plan.targets] : [plan.scope];
    const zone = this.zoneForRoots(roots, workdir);
    const sessionId = exec.agent?.id ?? 'no-agent';
    const command = typeof args?.command === 'string' ? args.command : null;

    // 受保护目录优先于区域判定：插件目录、备份根、protectedPaths 命中项即使在
    // 工作区内也一律拒绝（工作区短路不能绕过这一层）。
    try {
      for (const root of roots) this.assertNotProtected(root, plan.kind);
    } catch (error) {
      this.auditGate(exec, plan, 'deny', null, error.message, zone);
      return { kind: 'deny', reason: `delete-guard: ${error.message}` };
    }

    // 工作区：完全不保护（不备份、不提醒、不阻断）。
    // 仍然把授权范围写进钩子允许清单，否则 python/node 子进程会自己把工作区删除拦掉。
    if (zone === ZONE.WORKSPACE && this.policy.workspaceMode === 'none') {
      const entry = {
        roots: [...new Set([...roots, workdir ?? process.cwd()])],
        workdir, batchId: null, summary: null, planKind: plan.kind, zone,
      };
      this.issueToken(exec, entry);
      this.auditGate(exec, plan, 'allow', entry, null, zone);
      return { kind: 'allow' };
    }
    if (this.initError) {
      return { kind: 'deny', reason: `delete-guard: 备份不可用，已阻断：${this.initError}` };
    }
    if (!this.ready) {
      return { kind: 'deny', reason: 'delete-guard: 门禁尚未就绪，已阻断（fail-closed）' };
    }
    try {
      const outcome = await this.guardSensitive({
        exec, plan, args, workdir, zone, command, sessionId, toolName: name,
        agent: exec.agent, signal: exec.signal,
      });
      if (outcome.kind === 'deny') {
        this.auditGate(exec, plan, 'deny', outcome.entry ?? null, outcome.reason, zone);
        return { kind: 'deny', reason: outcome.reason };
      }
      this.issueToken(exec, outcome.entry);
      this.auditGate(exec, plan, 'allow', outcome.entry, null, zone);
      return { kind: 'allow' };
    } catch (error) {
      this.auditGate(exec, plan, 'deny', null, error.message, zone);
      return { kind: 'deny', reason: `delete-guard: 备份未完成，已阻断：${error.message}` };
    }
  }

  /** 目标根所属区域（多目标取最严格）。 */
  zoneForRoots(roots, workdir) {
    let workspaceRoot = workdir ?? process.cwd();
    // 工作区不可能落在 .dsh 里面。cwd 回落取错时（桌面版的 process.cwd() 就是
    // profile 目录），宁可把目标当敏感区处理，也不能误判成「工作区、无需保护」。
    if (this.dshHome && isInside(this.dshHome, workspaceRoot)) workspaceRoot = null;
    return strictestZoneOf(roots, { workspaceRoot, dshHome: this.dshHome });
  }

  /** 敏感区是否需要用户确认。 */
  needsConfirm(zone, stats) {
    if (zone !== ZONE.SENSITIVE) return false;
    const level = this.policy.triggerLevel;
    if (level === 'soft') return false;
    if (level === 'medium') {
      const files = stats?.count ?? 0;
      const bytes = stats?.bytes ?? 0;
      return files >= (Number(this.policy.mediumMinFiles) || Infinity)
        || bytes >= (Number(this.policy.mediumMinBytes) || Infinity);
    }
    return true; // hard：一律确认
  }

  /** 确认通道：popup（默认，直接问用户）/ code（旧的 4 位确认码）。 */
  confirmVia() {
    return String(this.policy?.confirmVia ?? 'popup').toLowerCase() === 'code' ? 'code' : 'popup';
  }

  confirmTimeoutMs() {
    const value = Number(this.policy?.confirmTimeoutMs);
    return Number.isFinite(value) && value >= 1000 ? value : 300000;
  }

  /**
   * 直接问用户要授权。
   *
   * 走 ctx.userQuestions.ask()——和 ask_user_question 工具同一个通道，卡片直接出现在
   * 用户界面上，答案**只回到本插件**，模型看不到也拿不到。这是 0.2.4 换掉确认码的原因：
   * 确认码写在工具返回值里，模型自己就能把它填回去，「人在环路里」等于没生效。
   *
   * 拿不到答案（没有 UI 客户端 / 子代理 / 超时 / 用户拒绝）一律不放行。
   */
  async askHuman({ agent, header, question, detail, options, questionId = CONFIRM_QUESTION_ID, signal: outer }) {
    let service;
    try {
      service = typeof this.ctx.get === 'function' ? this.ctx.get('userQuestions') : undefined;
    } catch {
      service = undefined;
    }
    if (!service || typeof service.ask !== 'function') {
      return { ok: false, code: 'NO_SERVICE', message: '当前运行环境没有用户问答服务' };
    }
    const target = agent ?? null;
    if (!target) {
      return { ok: false, code: 'NO_AGENT', message: '没有可用的会话代理（子代理无法代替用户确认）' };
    }
    const timeoutMs = this.confirmTimeoutMs();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    const combined = outer ? AbortSignal.any([controller.signal, outer]) : controller.signal;
    try {
      const answer = await service.ask({
        questions: [{ id: questionId, header, question, detail, options }],
        agent: target,
        signal: combined,
      });
      const item = (answer?.answers ?? []).find((entry) => entry.id === questionId);
      const selected = Array.isArray(item?.selected) ? item.selected : [];
      // 成功拿到答案就返回选中项，由调用方解释（不同场景的选项含义不同）。
      return { ok: true, selected };
    } catch (error) {
      if (outer?.aborted) return { ok: false, code: 'CANCELLED', message: '调用被取消' };
      if (controller.signal.aborted) {
        return { ok: false, code: 'TIMEOUT', message: `等待用户确认超时（${Math.round(timeoutMs / 1000)} 秒）` };
      }
      return { ok: false, code: error?.code ?? 'ASK_FAILED', message: error?.message ?? String(error) };
    } finally {
      clearTimeout(timer);
    }
  }

  /** 弹窗确认：用户点了「允许执行」就放行，其余情况一律阻断。 */
  async promptUser({ exec, entry, sessionId, toolName, header, question, detail, allowDescription, agent, signal }) {
    const verdict = await this.askHuman({
      agent, header, question, detail, signal,
      options: [
        { label: ALLOW_LABEL, description: allowDescription },
        { label: DENY_LABEL, description: '不执行；已经做过的备份会保留' },
      ],
    });
    if (verdict.ok) {
      const selected = Array.isArray(verdict.selected) ? verdict.selected : [];
      if (selected.length === 1 && selected[0] === ALLOW_LABEL) {
        this.audit.write({
          event: 'confirm', tool: toolName, callId: exec?.callId ?? null, sessionId,
          result: 'popup-allowed', zone: entry?.zone ?? null, batchId: entry?.batchId ?? null,
        });
        return { kind: 'allow', entry };
      }
      this.audit.write({
        event: 'confirm', tool: toolName, callId: exec?.callId ?? null, sessionId,
        result: 'popup-rejected', zone: entry?.zone ?? null,
      });
      return { kind: 'deny', entry, reason: buildDeclinedText() };
    }
    this.audit.write({
      event: 'confirm', tool: toolName, callId: exec?.callId ?? null, sessionId,
      result: 'popup-unavailable', code: verdict.code, zone: entry?.zone ?? null,
    });
    return { kind: 'deny', entry, reason: buildUnavailableText(verdict.message ?? verdict.code) };
  }

  /**
   * 未认识的工具：把工具信息与本次调用参数摊开，让用户决定。
   *
   * 三种结果：
   *   信任并加入白名单 → 写 data/settings.json，本次与以后都放行（已知破坏性工具除外）
   *   仅本次允许       → 本次放行，下次仍问
   *   拦截 / 问不到人  → 阻断（fail-closed）
   */
  async guardUnknownTool({ exec, plan, args, workdir, toolName, agent, signal }) {
    const sessionId = exec.agent?.id ?? 'no-agent';
    const info = this.toolInfo(toolName, exec);
    const verdict = await this.askHuman({
      agent: agent ?? exec.agent,
      signal,
      questionId: UNKNOWN_TOOL_QUESTION_ID,
      header: '删除守卫 · 未认识的工具',
      question: `允许工具「${toolName}」执行吗？`,
      detail: buildUnknownToolDetail({ toolName, info, args }),
      options: [
        { label: TRUST_LABEL, description: '加入白名单：以后该工具的所有调用都不再询问；本次立即执行' },
        { label: ONCE_LABEL, description: '只执行这一次；下次调用仍会询问' },
        { label: DENY_LABEL, description: '不执行；工具调用被阻断' },
      ],
    });
    const entry = {
      roots: [], workdir, batchId: null, summary: null,
      planKind: 'unknown', zone: null, toolName,
    };
    if (verdict.ok) {
      const selected = Array.isArray(verdict.selected) ? verdict.selected : [];
      const choice = selected.length === 1 ? selected[0] : null;
      if (choice === TRUST_LABEL) {
        if (!this.trustTool(toolName, exec)) {
          return {
            kind: 'deny', entry,
            reason: `delete-guard: 工具 "${toolName}" 不能加入白名单（已知的删除/覆盖类工具或插件管理操作）。`,
          };
        }
        this.audit.write({
          event: 'confirm', tool: toolName, callId: exec.callId, sessionId,
          result: 'popup-trusted', zone: null,
        });
        return { kind: 'allow', entry: { ...entry, trusted: true } };
      }
      if (choice === ONCE_LABEL) {
        this.audit.write({
          event: 'confirm', tool: toolName, callId: exec.callId, sessionId,
          result: 'popup-allowed-once', zone: null,
        });
        return { kind: 'allow', entry: { ...entry, trusted: false } };
      }
      this.audit.write({
        event: 'confirm', tool: toolName, callId: exec.callId, sessionId,
        result: 'popup-rejected', zone: null,
      });
      return { kind: 'deny', entry, reason: buildUnknownDeclinedText(toolName) };
    }
    this.audit.write({
      event: 'confirm', tool: toolName, callId: exec.callId, sessionId,
      result: 'popup-unavailable', code: verdict.code, zone: null,
    });
    return { kind: 'deny', entry, reason: buildUnknownUnavailableText(toolName, verdict.message ?? verdict.code) };
  }

  /** 从 DSH 工具注册表取这个工具的说明与参数结构（拿不到返回 null）。 */
  toolInfo(name, exec) {
    try {
      const tools = this.ctx.tools ?? (typeof this.ctx.get === 'function' ? this.ctx.get('tools') : undefined);
      if (tools && typeof tools.get === 'function') {
        return tools.get(name, exec?.agent ?? undefined, exec?.toolSet) ?? null;
      }
    } catch {
      /* 注册表不可用时省略说明 */
    }
    return null;
  }

  /**
   * 把一个工具加入受信任白名单（用户刚在弹窗里点了「信任并加入白名单」）。
   * 写 data/settings.json，立刻生效，也不用重启。
   */
  trustTool(name, exec = null) {
    const tool = String(name ?? '').trim();
    if (!tool || !isWhitelistableTool(tool)) return false;
    if (!this.uiSafeTools.includes(tool)) this.uiSafeTools = [...this.uiSafeTools, tool];
    this.refreshSafeTools();
    try {
      const settings = loadSettings(this.settingsDir);
      settings.safeTools = [...this.uiSafeTools];
      saveSettings(this.settingsDir, settings);
    } catch (error) {
      this.ctx.logger?.warn?.(`[delete-guard] 写入受信任工具失败：${error.message}`);
    }
    this.audit.write({
      event: 'trust-tool', tool, callId: exec?.callId ?? null,
      sessionId: exec?.agent?.id ?? null,
    });
    return true;
  }

  /**
   * 敏感区/`.dsh` 区处理：先备份，再决定是放行还是要用户确认。
   * 已经带正确确认码的重发命令不会再备份一次，直接复用上次批次。
   */
  async guardSensitive({ exec, plan, args, workdir, zone, command, sessionId, toolName, agent, signal }) {
    const fingerprint = fingerprintOf({ toolName, command, args });
    const resolved = extractConfirmCode(command ?? '');
    if (resolved.code) {
      const hit = this.confirm.verify(sessionId, fingerprint, resolved.code);
      if (hit) {
        this.audit.write({ event: 'confirm', tool: toolName, callId: exec.callId, sessionId, result: 'ok', batchId: hit.batchId });
        return {
          kind: 'allow',
          entry: { roots: (hit.targets ?? []).map((t) => t.root), workdir, batchId: hit.batchId, summary: null, planKind: plan.kind, zone, confirmed: true },
        };
      }
      if (this.confirm.peek(sessionId, fingerprint)) {
        this.audit.write({ event: 'confirm', tool: toolName, callId: exec.callId, sessionId, result: 'wrong-code' });
        return { kind: 'deny', reason: 'delete-guard: 确认码不正确。请使用上一次拦截报告里给出的 4 位数字。' };
      }
      // 已过期：继续走下面，重新备份并生成新的确认码。
    }

    const entry = await this.backupPlan({
      plan, args, workdir, sessionId, toolCallId: exec.callId, toolName, zone,
    });

    if (!this.needsConfirm(zone, entry.stats)) {
      if (zone === ZONE.DSH) entry.summary = entry.summary ? `${entry.summary}（.dsh 静默备份）` : null;
      return { kind: 'allow', entry };
    }

    const level = this.policy.triggerLevel;
    if (this.confirmVia() === 'popup') {
      return this.promptUser({
        exec,
        entry,
        sessionId,
        toolName,
        agent: agent ?? exec.agent,
        signal,
        header: '删除守卫 · 敏感区删除',
        question: '允许执行这次删除吗？',
        detail: buildPromptDetail({
          zone: ZONE_LABEL[zone] ?? zone,
          level,
          targets: entry.perRoot,
          stats: entry.stats,
          batchId: entry.batchId ?? '(无可备份文件)',
          batchDir: entry.batchDir ?? this.engine.root,
        }),
        allowDescription: '执行这一次；已提前备份，可用 restore 还原',
      });
    }

    const pending = this.confirm.issue({
      sessionId,
      fingerprint,
      batchId: entry.batchId,
      batchDir: entry.batchDir,
      zone: ZONE_LABEL[zone] ?? zone,
      stats: entry.stats,
      targets: entry.perRoot,
    });
    this.audit.write({
      event: 'confirm-required', tool: toolName, callId: exec.callId, sessionId,
      batchId: entry.batchId, files: entry.stats.files, bytes: entry.stats.bytes, zone,
    });
    return {
      kind: 'deny',
      entry,
      reason: buildReport({
        zone: ZONE_LABEL[zone] ?? zone,
        level,
        targets: entry.perRoot,
        stats: entry.stats,
        batchId: entry.batchId ?? '(无可备份文件)',
        batchDir: entry.batchDir ?? this.engine.root,
        code: pending.code,
      }),
    };
  }

  /**
   * 目标无法静态确定（变量 / 运行时表达式）时的处理。
   *
   * 不硬拒，也不静默放行：直接弹窗问用户（和敏感区同一套确认通道）。
   * 与 guardSensitive 的差别只有两点：
   *   1. 不做备份（目标运行时才确定，此时无法备份）——弹窗正文里必须写明；
   *   2. 放行时需要 allowAll，否则命令派生出来的 python/node 子进程会被钩子全部拒掉。
   */
  async guardUnresolved({ exec, plan, args, workdir, toolName, agent, signal }) {
    const sessionId = exec.agent?.id ?? 'no-agent';
    const command = typeof args?.command === 'string' ? args.command : null;
    const fingerprint = fingerprintOf({ toolName, command, args });
    const resolved = extractConfirmCode(command ?? '');

    if (resolved.code) {
      const hit = this.confirm.verify(sessionId, fingerprint, resolved.code);
      if (hit) {
        this.audit.write({
          event: 'confirm', tool: toolName, callId: exec.callId, sessionId, result: 'ok-unresolved', zone: 'unresolved',
        });
        return {
          kind: 'allow',
          entry: {
            roots: [], workdir, batchId: null, summary: null,
            planKind: 'confirm', zone: 'unresolved', confirmed: true, allowAll: true,
          },
        };
      }
      if (this.confirm.peek(sessionId, fingerprint)) {
        this.audit.write({ event: 'confirm', tool: toolName, callId: exec.callId, sessionId, result: 'wrong-code' });
        return { kind: 'deny', reason: 'delete-guard: 确认码不正确。请使用上一次拦截报告里给出的 4 位数字。' };
      }
      // 已过期：继续走下面，重新生成确认码。
    }

    const entry = {
      roots: [], workdir, batchId: null, summary: null,
      planKind: 'confirm', zone: 'unresolved', allowAll: true,
    };

    if (this.confirmVia() === 'popup') {
      return this.promptUser({
        exec,
        entry,
        sessionId,
        toolName,
        agent: agent ?? exec.agent,
        signal,
        header: '删除守卫 · 目标未确定',
        question: '这条命令的删除目标无法静态确定，仍然要执行吗？',
        detail: buildPromptDetail({
          command,
          unresolvedReason: plan.reason || '无法静态确定目标路径',
        }),
        allowDescription: '执行这一次；没有备份，删掉的内容无法还原',
      });
    }

    const pending = this.confirm.issue({
      sessionId,
      fingerprint,
      batchId: null,
      batchDir: null,
      zone: 'unresolved',
      stats: { files: 0, bytes: 0, dirs: 0, missing: 0 },
      targets: [],
    });
    this.audit.write({
      event: 'confirm-required', tool: toolName, callId: exec.callId, sessionId,
      zone: 'unresolved', batchId: null, reason: plan.reason,
    });
    return {
      kind: 'deny',
      reason: buildReport({
        level: this.policy.triggerLevel,
        command,
        unresolvedReason: plan.reason || '无法静态确定目标路径',
        code: pending.code,
      }),
    };
  }

  /** 当前会话真实存活的根代理（用户问答只认它）。拿不到返回 null。 */
  liveAgentOf(sessionId) {
    if (!sessionId) return null;
    try {
      const agents = typeof this.ctx.get === 'function' ? this.ctx.get('agents') : this.ctx.agents;
      if (!agents || typeof agents.get !== 'function') return null;
      return agents.get(sessionId) ?? null;
    } catch {
      return null;
    }
  }

  async computeWorkdir(exec, name, args) {
    const cwd = await this.cwdFor(exec);
    if (SHELL_TOOLS.has(name) && typeof args?.workdir === 'string' && args.workdir.trim().length > 0) {
      return toAbsolute(args.workdir, cwd);
    }
    return cwd;
  }

  /**
   * 会话当前工作目录。这是「工作区」的判定基准，因此必须尽可能拿到真实值：
   * 退回 process.cwd() 在桌面版里是 profile 目录（.dsh 里面），
   * 会把工作区目标误判成敏感区。这里按可信度逐层回落。
   */
  async cwdFor(exec) {
    const agent = exec.agent;
    if (!agent) return process.cwd();

    // workingDirectory 是可选服务：用 ctx.get 取（未注册时为 undefined）。
    let wd = null;
    try {
      wd = typeof this.ctx.get === 'function' ? this.ctx.get('workingDirectory') : this.ctx.workingDirectory;
    } catch {
      wd = null;
    }
    if (!wd) {
      try {
        wd = this.ctx.workingDirectory;
      } catch {
        wd = null;
      }
    }

    if (wd) {
      try {
        if (typeof wd.ensure === 'function') {
          const ensured = await wd.ensure(agent, exec.signal);
          if (typeof ensured === 'string' && ensured.length > 0) return ensured;
        }
        const session = agent.session ?? this.ctx.sessions?.get?.(agent.id);
        if (session && typeof wd.get === 'function') {
          const cwd = wd.get(session);
          if (typeof cwd === 'string' && cwd.length > 0) return cwd;
        }
        if (typeof wd.defaultDirectory === 'string' && wd.defaultDirectory.length > 0) {
          return wd.defaultDirectory;
        }
      } catch {
        /* 继续下面的回落 */
      }
    }

    // 服务不可用：Session 头里记录的 cwd 同样可信。
    const headerCwd = agent.session?.header?.cwd;
    if (typeof headerCwd === 'string' && headerCwd.length > 0) return headerCwd;
    return process.cwd();
  }

  issueToken(exec, entry) {
    const record = { time: Date.now(), ...entry };
    this.tokens.set(exec.callId, record);
    if (SHELL_TOOLS.has(exec.name)) {
      const workdir = entry.workdir;
      const command = typeof exec.arguments?.command === 'string' ? exec.arguments.command : '';
      const sessionId = exec.agent?.id ?? 'no-agent';
      if (workdir && command) {
        this.shellTokens.set(`${sessionId}|${workdir}|${command}`, record);
      }
    }
  }

  pruneTokens() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [key, token] of this.tokens) {
      if (token.time < cutoff) this.tokens.delete(key);
    }
    for (const [key, token] of this.shellTokens) {
      if (token.time < cutoff) this.shellTokens.delete(key);
    }
  }

  async backupPlan({ plan, args, workdir, sessionId, toolCallId, toolName, zone = ZONE.SENSITIVE }) {
    const roots = plan.kind === 'targets' ? [...plan.targets] : [plan.scope];
    for (const extra of this.policy.scopeRoots ?? []) {
      const resolved = path.resolve(expandEnv(extra));
      if (plan.kind === 'scope' && resolved) roots.push(resolved);
    }
    for (const root of roots) this.assertNotProtected(root, plan.kind);
    const command = typeof args?.command === 'string' ? args.command : null;
    const result = await this.engine.backup(roots, {
      sessionId,
      toolCallId,
      toolName,
      command,
      plan: plan.kind,
      cwd: workdir,
      zone,
      policy: { opaqueCommand: this.policy.opaqueCommand, unknownTool: this.policy.unknownTool },
    });
    let summary = null;
    if (result.count > 0) {
      summary = `[delete-guard] 已备份 ${result.count} 个文件（${formatBytes(result.bytes)}）→ 批次 ${result.batchId}；还原：delete-guard restore ${result.batchId}`;
    } else if (result.batchId) {
      summary = `[delete-guard] 已记录 ${result.dirs} 个目录 / ${result.links} 个链接（无可备份文件）→ 批次 ${result.batchId}`;
    }
    this.audit.write({
      event: 'backup', tool: toolName, callId: toolCallId, sessionId, plan: plan.kind,
      batchId: result.batchId, count: result.count, bytes: result.bytes, zone,
      missing: result.missing?.length ?? 0, durationMs: result.durationMs,
    });
    return {
      roots,
      workdir,
      zone,
      batchId: result.batchId,
      batchDir: result.dir,
      summary,
      planKind: plan.kind,
      stats: { files: result.count ?? 0, bytes: result.bytes ?? 0, dirs: result.dirs ?? 0, missing: result.missing?.length ?? 0 },
      perRoot: result.perRoot ?? roots.map((root) => ({ root, files: 0, bytes: 0 })),
    };
  }

  assertNotProtected(target, planKind) {
    const resolved = realpathOr(target);
    for (const protectedPath of this.protectedRoots) {
      const guard = realpathOr(protectedPath);
      if (isInside(guard, resolved)) {
        throw new Error(`目标 ${target} 位于受保护路径 ${protectedPath} 内`);
      }
      if (planKind === 'targets' && isInside(resolved, guard)) {
        throw new Error(`目标 ${target} 会连同受保护路径 ${protectedPath} 一起删除`);
      }
    }
    if (this.protectPatterns.length > 0) {
      if (isProtectedByPatterns(this.protectPatterns, resolved)) {
        throw new Error(`目标 ${target} 命中 policy.protectedPaths 里的受保护目录模式`);
      }
      if (planKind === 'targets' && patternCoversTarget(this.protectPatterns, resolved)) {
        throw new Error(`目标 ${target} 会连同 policy.protectedPaths 覆盖的受保护目录一起删除`);
      }
    }
  }

  auditGate(exec, plan, decision, entry = null, reason = null, zone = null) {
    this.audit.write({
      event: 'gate',
      tool: exec.name,
      callId: exec.callId,
      sessionId: exec.agent?.id ?? null,
      plan: plan.kind,
      zone,
      targets: plan.kind === 'targets' ? plan.targets : plan.scope ? [plan.scope] : [],
      decision,
      batchId: entry?.batchId ?? null,
      reason,
      notes: plan.notes,
    });
  }

  // ── shell 深度层 ──────────────────────────────────────────────────────────

  /** 在 ctx.shell.execute 之前调用；返回注入了钩子环境变量的 spec，或抛错阻断。 */
  async prepareShell(spec) {
    if (this.disposed || !this.config.enabled || this.config.emergencyBypass || !this.config.shellSeam) return spec;
    try {
      if (this.initError) throw new Error(`备份不可用：${this.initError}`);
      if (!this.ready) throw new Error('门禁尚未就绪（fail-closed）');
      const sessionId = spec.sandboxPolicy?.sessionId ?? 'no-agent';
      const key = `${sessionId}|${spec.workdir}|${spec.command}`;
      let entry = this.shellTokens.get(key) ?? null;
      if (entry) this.shellTokens.delete(key);
      if (!entry) {
        const plan = parseShellCommand(spec.command, spec.workdir, this.policy, 0);
        const shellExec = { name: 'shell', callId: null, agent: { id: sessionId }, arguments: { command: spec.command } };
        // 弹窗确认要求「当前会话真实存活的根代理」；这里按 sessionId 把它找回来，
        // 否则 shell 深度层自己撞上需要确认的命令时无法问用户，只能阻断。
        const liveAgent = this.liveAgentOf(sessionId);
        if (plan.kind === 'deny') throw new Error(plan.reason);
        if (plan.kind === 'unknown') throw new Error('命令无法分类');
        if (plan.kind === 'confirm') {
          const outcome = await this.guardUnresolved({
            exec: shellExec,
            plan,
            args: { command: spec.command },
            workdir: spec.workdir,
            toolName: 'shell',
            agent: liveAgent,
          });
          if (outcome.kind === 'deny') throw new Error(outcome.reason);
          entry = outcome.entry;
          this.auditGate(shellExec, plan, 'allow', entry, null, 'unresolved');
        } else if (plan.kind === 'safe') {
          entry = { roots: [], batchId: null, summary: null, planKind: 'safe', zone: null };
        } else {
          const roots = plan.kind === 'targets' ? [...plan.targets] : [plan.scope];
          const zone = this.zoneForRoots(roots, spec.workdir);
          // 受保护目录优先于区域判定。
          for (const root of roots) this.assertNotProtected(root, plan.kind);
          if (zone === ZONE.WORKSPACE && this.policy.workspaceMode === 'none') {
            entry = {
              roots: [...new Set([...roots, spec.workdir])],
              batchId: null, summary: null, planKind: plan.kind, zone,
            };
          } else {
            const outcome = await this.guardSensitive({
              exec: shellExec,
              plan,
              args: { command: spec.command },
              workdir: spec.workdir,
              zone,
              command: spec.command,
              sessionId,
              toolName: 'shell',
              agent: liveAgent,
            });
            if (outcome.kind === 'deny') throw new Error(outcome.reason);
            entry = outcome.entry;
          }
        }
        if (plan.kind !== 'confirm') {
          this.auditGate(shellExec, plan, 'allow', entry, null, entry.zone ?? null);
        }
      }
      const allowFile = await this.writeAllowFile(entry, spec);
      return {
        ...spec,
        env: {
          ...(spec.env ?? {}),
          ...this.hookEnv(spec, allowFile),
        },
      };
    } catch (error) {
      this.audit.write({ event: 'gate', tool: 'shell', decision: 'deny', reason: error.message, command: spec.command });
      throw new Error(`delete-guard: ${error.message}`);
    }
  }

  hookEnv(spec, allowFile) {
    const env = {};
    if (this.config.hooks.python && this.hookFiles.python) {
      const existing = spec.env?.PYTHONPATH ?? process.env.PYTHONPATH ?? '';
      env.PYTHONPATH = existing ? `${this.hookFiles.pythonDir};${existing}` : this.hookFiles.pythonDir;
    }
    if (this.config.hooks.node && this.hookFiles.node) {
      const existing = spec.env?.NODE_OPTIONS ?? process.env.NODE_OPTIONS ?? '';
      // NODE_OPTIONS 里反斜杠会被当转义吃掉，统一用正斜杠；带空格时用引号包裹。
      const nodePath = this.hookFiles.nodePath.replace(/\\/g, '/');
      const requires = `--require "${nodePath}"`;
      env.NODE_OPTIONS = existing ? `${existing} ${requires}` : requires;
    }
    env.DSH_DELETE_GUARD_ALLOW = allowFile;
    env.DSH_DELETE_GUARD_BACKUP = this.engine.root;
    return env;
  }

  async writeAllowFile(entry, spec) {
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    const file = path.join(this.engine.root, '_ipc', `${id}.json`);
    const allow = {
      id,
      createdAt: Date.now(),
      expiresAt: Date.now() + ALLOW_TTL_MS,
      sessionId: spec.sandboxPolicy?.sessionId ?? null,
      command: spec.command,
      cwd: spec.workdir,
      roots: entry.roots ?? [],
      // 用户对「解析不出的命令」确认过：派生出的 python/node 子进程放行，
      // 否则确认了也执行不了（钩子会对子进程里的每一次删除 fail-closed）。
      allowAll: entry.allowAll === true,
      volatile: this.volatileRoots(),
    };
    await fsp.writeFile(file, JSON.stringify(allow, null, 2), 'utf8');
    return file;
  }

  volatileRoots() {
    const roots = new Set();
    // 内置易失目录：系统临时目录 + 常见包管理器缓存（它们本来就可以随时删除，
    // 不允许它们被删会让 npm/pnpm 安装直接失败）。用户配置在此之上追加。
    const builtin = [
      '%TEMP%', '%TMP%', '%LOCALAPPDATA%\\Temp',
      '%LOCALAPPDATA%\\npm-cache', '%APPDATA%\\npm-cache',
      '%LOCALAPPDATA%\\pnpm', '%LOCALAPPDATA%\\pnpm-cache', '%APPDATA%\\pnpm',
      '%LOCALAPPDATA%\\Yarn', '%USERPROFILE%\\.npm', '%USERPROFILE%\\.cache',
    ];
    for (const item of builtin) {
      const expanded = expandEnv(item);
      if (expanded) roots.add(path.resolve(expanded));
    }
    for (const item of this.policy.volatileRoots ?? []) {
      const expanded = expandEnv(item);
      if (expanded) roots.add(path.resolve(expanded));
    }
    roots.add(path.resolve(os.tmpdir()));
    return [...roots];
  }

  /** CLI/调试用快照。 */
  snapshot() {
    return {
      enabled: this.config.enabled,
      emergencyBypass: this.config.emergencyBypass,
      shellSeam: this.config.shellSeam,
      ready: this.ready,
      initError: this.initError,
      backupRoot: this.engine.root,
      sysmon: this.sysmon,
      hooks: { ...this.hookFiles, enabled: { ...this.config.hooks } },
      protectedRoots: this.protectedRoots,
      zones: {
        workspaceMode: this.policy.workspaceMode,
        dshHome: this.dshHome,
        triggerLevel: this.policy.triggerLevel,
        mediumMinFiles: this.policy.mediumMinFiles,
        mediumMinBytes: this.policy.mediumMinBytes,
        unresolvedAction: this.policy.unresolvedAction,
      },
      unknownTool: this.policy.unknownTool,
      safeTools: [...this.policy.safeTools],
      retention: {
        sensitiveDays: this.config.backup.retentionDays,
        dshCount: this.config.backup.dshRetentionCount,
        dshDays: this.config.backup.dshRetentionDays,
      },
      protectedPatterns: this.policy.protectedPaths,
    };
  }
}
