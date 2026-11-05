// 审计日志：<root>/_audit/YYYY-MM-DD.jsonl，一行一个事件。
import fs from 'node:fs/promises';
import path from 'node:path';

function today() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export class AuditLog {
  constructor(root, logger = null) {
    this.dir = path.join(root, '_audit');
    this.logger = logger;
    this.chain = Promise.resolve();
    this.enabled = true;
  }

  async init() {
    try {
      await fs.mkdir(this.dir, { recursive: true });
    } catch (error) {
      this.enabled = false;
      this.logger?.warn?.(`[delete-guard] 审计目录不可写：${error.message}`);
    }
  }

  /** 追加一个事件；失败不抛出（审计不能反过来中断门禁），但要打到 logger。 */
  write(event) {
    if (!this.enabled) return this.chain;
    const record = { time: new Date().toISOString(), ...event };
    const line = JSON.stringify(record) + '\n';
    this.chain = this.chain
      .then(() => fs.appendFile(path.join(this.dir, `${today()}.jsonl`), line, 'utf8'))
      .catch((error) => {
        this.logger?.warn?.(`[delete-guard] 审计写入失败：${error.message}`);
      });
    return this.chain;
  }

  async flush() {
    await this.chain;
  }

  /** 读取最近 n 行（跨天按文件名倒序）。 */
  async recent(limit = 20) {
    await this.chain;
    let files;
    try {
      files = (await fs.readdir(this.dir)).filter((f) => f.endsWith('.jsonl')).sort().reverse();
    } catch {
      return [];
    }
    const out = [];
    for (const file of files) {
      let text;
      try {
        text = await fs.readFile(path.join(this.dir, file), 'utf8');
      } catch {
        continue;
      }
      const lines = text.split('\n').filter(Boolean);
      for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
        try {
          out.push(JSON.parse(lines[i]));
        } catch {
          /* 跳过坏行 */
        }
      }
      if (out.length >= limit) break;
    }
    return out.reverse();
  }
}
