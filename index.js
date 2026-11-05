// 敏感数据守卫（核心行）：统一工具门禁 + 同步 guard 兜底 + 结果摘要 + shell 实例包装。
//
// 注意：本机 profile 里的本地 bundle 无法 import 随 dsh 发行的包，因此这里
// 不依赖任何 @deepseek-ai/* 模块：
//   - 不在导出里写 Config（配置由 lib/defaults.js 深合并 + 运行时校验）；
//   - shell 深度层不替换 ctx.shell 行，而是包装当前 ctx.shell 实例的 execute
//     （不修改任何 DSH 文件、不依赖内部类）。包装以“原始方法”为基准，
//     热重载时不会叠加多层包装。
import { resolveConfig } from './lib/defaults.js';
import { GateCore } from './lib/gate.js';
import { getSharedState } from './lib/state.js';
import { SETTINGS_ROUTE, handleSettingsRequest } from './lib/http-settings.js';

export const inject = ['tools'];

const SHELL_ORIGINAL = Symbol.for('dsh.delete-guard.shell-original');

export function apply(ctx, config) {
  const core = new GateCore(ctx, config ?? {});
  const shared = getSharedState();
  shared.core = core;
  let shellCleanup = null;

  // 插件卸载：先恢复 ctx.shell.execute，再清理门禁。
  ctx.effect(() => () => {
    try {
      shellCleanup?.();
    } catch {
      /* 还原失败只影响卸载 */
    }
    core.dispose();
    if (shared.core === core) shared.core = null;
  });

  // 异步检查 + 备份 + allow/deny；ask 决策由后面的 guard 再兜底。
  ctx.effect(() => ctx.on('tools/pre-execute', (exec, next) => core.onPreExecute(exec, next)));

  // 同步、单向否决：任何破坏性调用没有备份令牌就阻断。
  ctx.effect(() => ctx.tools.guard((exec) => core.guard(exec)));

  // 结果摘要：谁、删了什么、备份在哪、怎么还原。
  ctx.effect(() => ctx.on('tools/post-execute', (exec, result, next) => core.onPostExecute(exec, result, next)));

  // shell 深度层：包装当前 ctx.shell 实例的 execute（spawn 前检查 + 备份 + 注入钩子环境变量）。
  ctx.inject(['shell'], (shellCtx) => {
    const shell = shellCtx.shell;
    if (!shell || typeof shell.execute !== 'function') return;
    // 清理非本插件留下的 execute 包装（例如禁用/重载前的旧版本）：直接落回原型方法。
    if (Object.prototype.hasOwnProperty.call(shell, 'execute') && typeof shell[SHELL_ORIGINAL] !== 'function') {
      try {
        delete shell.execute;
      } catch {
        /* 删不掉就继续，热重载可能多包一层 */
      }
    }
    let original = shell[SHELL_ORIGINAL];
    if (typeof original !== 'function') {
      original = shell.execute;
      try {
        Object.defineProperty(shell, SHELL_ORIGINAL, { value: original, configurable: true });
      } catch {
        /* 冻结实例：仍然继续，只是热重载可能多包一层 */
      }
    }
    const wrapped = async function deleteGuardShellExecute(spec) {
      const prepared = await core.prepareShell(spec);
      return original.call(shell, prepared);
    };
    try {
      shell.execute = wrapped;
    } catch (error) {
      ctx.logger?.warn?.(`[delete-guard] 无法包装 ctx.shell.execute，shell 深度层不可用：${error.message}`);
      return;
    }
    const cleanup = () => {
      if (shell.execute === wrapped) shell.execute = original;
    };
    shellCleanup = cleanup;
    shellCtx.effect(() => cleanup);
  });

  // 设置页的数据通道（同源 + JSON）。webServer 不存在时静默跳过，门禁照常工作。
  ctx.inject(['webServer'], (webCtx) => {
    const webServer = webCtx.webServer;
    if (!webServer || typeof webServer.register !== 'function') return;
    const handler = (req, res) => handleSettingsRequest(core, req, res);
    try {
      webCtx.effect(() => webServer.register({ kind: 'exact', path: SETTINGS_ROUTE, handler }));
    } catch (error) {
      ctx.logger?.warn?.(`[敏感数据守卫] 设置路由注册失败：${error.message}`);
    }
  });

  core.start();
}
