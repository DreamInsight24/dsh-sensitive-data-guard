// Delete Guard 运行时钩子（Node.js / CommonJS）。
// 由 shell 深度层通过 NODE_OPTIONS=--require 注入，在用户代码之前加载。
// 规则与 Python 钩子相同：删除目标必须在本次命令已备份的根内或易失目录内。
'use strict';

const fs = require('node:fs');
const path = require('node:path');

let state = { mode: 'deny', roots: [], volatile: [], allowAll: false, reason: '缺少允许清单（fail-closed）' };
try {
  const allowFile = process.env.DSH_DELETE_GUARD_ALLOW;
  if (allowFile) {
    const data = JSON.parse(fs.readFileSync(allowFile, 'utf8'));
    const norm = (value) => {
      try {
        return path.resolve(String(value)).toLowerCase();
      } catch {
        return '';
      }
    };
    state = {
      mode: 'allow',
      roots: (Array.isArray(data.roots) ? data.roots : []).map(norm).filter(Boolean),
      volatile: (Array.isArray(data.volatile) ? data.volatile : []).map(norm).filter(Boolean),
      // 用户对「目标解析不出」的命令输入过确认码：整条命令放行。
      allowAll: data.allowAll === true,
      reason: null,
    };
  }
} catch (error) {
  state = { mode: 'deny', roots: [], volatile: [], reason: error.message };
}

function isInside(parent, child) {
  if (parent === child) return true;
  return child.startsWith(parent.endsWith(path.sep) ? parent : parent + path.sep);
}

function check(target, operation) {
  if (state.mode === 'deny') {
    throw new Error(`delete-guard: 拒绝删除 ${String(target)}（${state.reason}）`);
  }
  if (state.allowAll === true) return; // 用户已对这条「目标无法解析」的命令确认放行
  let resolved;
  try {
    resolved = path.resolve(String(target)).toLowerCase();
  } catch {
    throw new Error('delete-guard: 无法解析删除目标');
  }
  if (state.roots.some((root) => isInside(root, resolved))) return;
  if (state.volatile.some((root) => isInside(root, resolved))) return;
  throw new Error(
    `delete-guard: 未审批的删除操作已阻断：${resolved}（操作：${operation}）。` +
      '目标不在本次命令已备份的范围内；如确需删除，请通过 DSH 工具重新发起，让 Delete Guard 先备份。',
  );
}

function patchSync(name, operation) {
  const original = fs[name];
  if (typeof original !== 'function' || original.__deleteGuardWrapped) return;
  const wrapped = function wrappedFsOp(...args) {
    check(args[0], operation);
    if ((name === 'rename' || name === 'renameSync') && args[1] != null) {
      try {
        if (fs.existsSync(args[1])) check(args[1], `${operation}-overwrite`);
      } catch {
        /* 目标不存在时无需检查 */
      }
    }
    return original.apply(this, args);
  };
  wrapped.__deleteGuardWrapped = true;
  fs[name] = wrapped;
}

function patchPromise(name, operation) {
  const holder = fs.promises;
  const original = holder[name];
  if (typeof original !== 'function' || original.__deleteGuardWrapped) return;
  const wrapped = async function wrappedPromiseOp(...args) {
    check(args[0], operation);
    if (name === 'rename' && args[1] != null) {
      try {
        await fs.promises.access(args[1]);
        check(args[1], `${operation}-overwrite`);
      } catch {
        /* 目标不存在时无需检查 */
      }
    }
    return original.apply(this, args);
  };
  wrapped.__deleteGuardWrapped = true;
  holder[name] = wrapped;
}

for (const name of ['rm', 'rmSync', 'rmdir', 'rmdirSync', 'unlink', 'unlinkSync', 'rename', 'renameSync']) {
  patchSync(name, name);
}
for (const name of ['rm', 'rmdir', 'unlink', 'rename']) {
  patchPromise(name, name);
}
