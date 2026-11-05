// 跨模块/跨行共享的运行时状态。
// 用 globalThis + Symbol 兜住 HMR 重新加载模块的情况：同进程内始终拿到同一份状态。
const KEY = Symbol.for('dsh.delete-guard.state');

export function getSharedState() {
  if (!globalThis[KEY]) {
    globalThis[KEY] = {
      core: null,
      installedAt: Date.now(),
    };
  }
  return globalThis[KEY];
}
