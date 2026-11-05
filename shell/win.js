// Windows shell 深度层：替换 dsh-pwsh-sandbox 的默认执行器，
// 在真正 spawn 之前做检查 + 备份，并把 Python/Node 钩子的环境变量注入子进程。
import Base from '@deepseek-ai/dsh-pwsh-sandbox';
import { getSharedState } from '../lib/state.js';

export default class DeleteGuardPwshShell extends Base {
  async execute(spec) {
    const core = getSharedState().core;
    if (!core) throw new Error('delete-guard: 门禁未就绪，命令未执行（fail-closed）');
    const prepared = await core.prepareShell(spec);
    return super.execute(prepared);
  }
}
