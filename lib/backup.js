// 备份引擎（纯 Node，CLI 与 Host 共用）。
//
// 目录布局：
//   <root>/_store/<aa>/<bb>/<sha256>      内容寻址对象库（去重）
//   <root>/<YYYY-MM-DD>/<session>/<seq>/ 批次桶 + manifest.jsonl（+ tree/ 硬链接镜像）
//   <root>/_audit/<YYYY-MM-DD>.jsonl     全局审计
//   <root>/_state/                       序号/用量状态
//   <root>/_ipc/                         运行时钩子的允许清单
//
// 约束：备份根内的路径永不备份；目标包含备份根时由 gate 层直接拒绝。
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { isInside, treeKey, parseBatchId } from './paths.js';

export class BackupError extends Error {
  constructor(message, detail = undefined) {
    super(message);
    this.name = 'BackupError';
    this.detail = detail;
  }
}

export class BackupLimitError extends BackupError {
  constructor(message, detail = undefined) {
    super(message);
    this.name = 'BackupLimitError';
    this.detail = detail;
  }
}

function dayString(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function safeSegment(value, fallback) {
  const text = String(value ?? '').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 80);
  return text.length > 0 ? text : fallback;
}

function hashPath(root, sha) {
  return path.join(root, '_store', sha.slice(0, 2), sha.slice(2, 4), sha);
}

/** 按目标根汇总文件数与字节数（用于给用户的拦截报告）。 */
function perRootOf(roots, planResult) {
  return (roots ?? []).map((root) => {
    const resolved = path.resolve(root);
    let files = 0;
    let bytes = 0;
    for (const file of planResult.files) {
      if (isInside(resolved, file.path)) {
        files += 1;
        bytes += file.size ?? 0;
      }
    }
    return { root: resolved, files, bytes };
  });
}

async function statSize(file) {
  try {
    return (await fsp.stat(file)).size;
  } catch {
    return 0;
  }
}

async function readdirSafe(dir) {
  try {
    return await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/** 读取批次清单首行的区域；老批次没有该字段时按 sensitive 处理。 */
async function readBatchZone(manifestPath) {
  try {
    const handle = await fsp.open(manifestPath, 'r');
    try {
      const buffer = Buffer.alloc(8192);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      const firstLine = buffer.subarray(0, bytesRead).toString('utf8').split('\n')[0];
      const header = JSON.parse(firstLine);
      return header?.zone === 'dsh' ? 'dsh' : header?.zone === 'workspace' ? 'workspace' : 'sensitive';
    } finally {
      await handle.close();
    }
  } catch {
    return 'sensitive';
  }
}

export class BackupEngine {
  constructor(backupConfig) {
    this.config = backupConfig;
    this.root = path.resolve(backupConfig.root);
    this.storeDir = path.join(this.root, '_store');
    this.stateDir = path.join(this.root, '_state');
    this.ipcDir = path.join(this.root, '_ipc');
    this.lock = Promise.resolve();
    this.shaLocks = new Map();
    this.usage = { bytes: 0, files: 0 };
    this.initialized = false;
    this.healthy = false;
    this.healthError = null;
  }

  async init() {
    await fsp.mkdir(this.storeDir, { recursive: true });
    await fsp.mkdir(this.stateDir, { recursive: true });
    await fsp.mkdir(this.ipcDir, { recursive: true });
    // 可写探测：写一个小文件（不删除——CLI 可能运行在 Delete Guard 自己的
    // 运行时钩子下，删除会被钩子拒绝）。失败即 fail-closed。
    const probe = path.join(this.stateDir, `.probe-${process.pid}`);
    try {
      await fsp.writeFile(probe, 'ok', 'utf8');
      this.healthy = true;
      this.healthError = null;
    } catch (error) {
      this.healthy = false;
      this.healthError = error.message;
      throw new BackupError(`备份目录不可写：${this.root}（${error.message}）`);
    }
    await this.loadUsage();
    this.initialized = true;
  }

  async loadUsage() {
    const stateFile = path.join(this.stateDir, 'usage.json');
    try {
      const raw = JSON.parse(await fsp.readFile(stateFile, 'utf8'));
      if (typeof raw.bytes === 'number' && typeof raw.files === 'number') {
        this.usage = { bytes: raw.bytes, files: raw.files };
        return;
      }
    } catch {
      /* 重新计算 */
    }
    await this.recomputeUsage();
    await this.saveUsage();
  }

  async recomputeUsage() {
    let bytes = 0;
    let files = 0;
    const walk = async (dir) => {
      for (const entry of await readdirSafe(dir)) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full);
        else if (entry.isFile()) {
          try {
            const st = await fsp.stat(full);
            bytes += st.size;
            files++;
          } catch {
            /* 忽略 */
          }
        }
      }
    };
    await walk(this.storeDir);
    this.usage = { bytes, files };
  }

  async saveUsage() {
    try {
      await fsp.writeFile(path.join(this.stateDir, 'usage.json'), JSON.stringify(this.usage), 'utf8');
    } catch {
      /* 状态文件写失败不阻断备份 */
    }
  }

  async withLock(fn) {
    const previous = this.lock;
    let release;
    this.lock = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  /** 同一个 sha 的落盘串行化，避免并发去重时重复计数/重复 rename。 */
  async withShaLock(sha, fn) {
    const previous = this.shaLocks.get(sha) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    this.shaLocks.set(sha, current);
    await previous;
    try {
      return await fn();
    } finally {
      release();
      if (this.shaLocks.get(sha) === current) this.shaLocks.delete(sha);
    }
  }

  async nextBatchId(sessionId) {
    const date = dayString();
    const session = safeSegment(sessionId, 'ad-hoc');
    const stateFile = path.join(this.stateDir, 'seq.json');
    let state = {};
    try {
      state = JSON.parse(await fsp.readFile(stateFile, 'utf8'));
    } catch {
      state = {};
    }
    const key = `${date}/${session}`;
    const seq = (Number.isInteger(state[key]) ? state[key] : 0) + 1;
    state[key] = seq;
    await fsp.writeFile(stateFile, JSON.stringify(state), 'utf8');
    return { date, session, seq };
  }

  /** 枚举目标：不跟随 reparse point，超限立即抛错。 */
  async plan(paths, options = {}) {
    const maxFiles = this.config.maxBatchFiles;
    const maxBytes = this.config.maxBatchBytes;
    const maxFile = this.config.maxFileBytes;
    const overFile = this.config.overFileLimit === 'record-only' ? 'record-only' : 'block';
    const exclusions = (this.config.exclusions ?? []).map((p) => path.resolve(p));
    const acc = { files: [], dirs: [], links: [], missing: [], overLimit: [], bytes: 0 };

    const ignore = (abs) => {
      if (isInside(this.root, abs)) return true; // 备份根自身永不进入备份
      for (const ex of exclusions) if (isInside(ex, abs)) return true;
      return false;
    };

    const walk = async (abs) => {
      let st;
      try {
        st = await fsp.lstat(abs);
      } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
          acc.missing.push(abs);
          return;
        }
        throw new BackupError(`无法读取 ${abs}：${error.message}`);
      }
      if (st.isSymbolicLink()) {
        let target = null;
        try {
          target = await fsp.readlink(abs);
        } catch {
          target = null;
        }
        acc.links.push({ path: abs, target });
        return;
      }
      if (st.isDirectory()) {
        acc.dirs.push(abs);
        const entries = await readdirSafe(abs);
        for (const entry of entries) {
          const child = path.join(abs, entry.name);
          if (ignore(child)) continue;
          await walk(child);
        }
        return;
      }
      if (!st.isFile()) {
        acc.missing.push(abs);
        return;
      }
      if (st.size > maxFile) {
        if (overFile === 'block') {
          throw new BackupLimitError(
            `单文件 ${abs} 为 ${formatBytes(st.size)}，超过单文件上限 ${formatBytes(maxFile)}`,
            { path: abs, size: st.size, limit: maxFile },
          );
        }
        acc.overLimit.push({ path: abs, size: st.size });
        return;
      }
      acc.bytes += st.size;
      acc.files.push({ path: abs, size: st.size, mtimeMs: st.mtimeMs, mode: st.mode });
      if (acc.files.length > maxFiles) {
        throw new BackupLimitError(
          `本批文件数超过上限 ${maxFiles}，已停止枚举（删除未执行）`,
          { limit: maxFiles, path: abs },
        );
      }
      if (acc.bytes > maxBytes) {
        throw new BackupLimitError(
          `本批总量超过上限 ${formatBytes(maxBytes)}，已停止枚举（删除未执行）`,
          { limit: maxBytes, path: abs },
        );
      }
    };

    // 去掉被其它目录覆盖的子路径，避免重复备份。
    const unique = [...new Set(paths.map((p) => path.resolve(p)))];
    const roots = unique.filter((p) => !unique.some((q) => q !== p && isInside(q, p)));
    for (const root of roots) await walk(root);

    const remaining = options.quotaCheck === false ? Infinity : this.config.quotaBytes - this.usage.bytes;
    if (options.quotaCheck !== false && acc.bytes > remaining) {
      throw new BackupLimitError(
        `备份总量将超过配额：本批 ${formatBytes(acc.bytes)}，剩余 ${formatBytes(Math.max(0, remaining))}（总量上限 ${formatBytes(this.config.quotaBytes)}）`,
        { bytes: acc.bytes, remaining, quota: this.config.quotaBytes },
      );
    }
    return acc;
  }

  /** 执行备份；返回 { batchId, dir, count, bytes } 或空批次。 */
  async backup(paths, meta = {}) {
    return this.withLock(async () => {
      if (!this.healthy) throw new BackupError(`备份目录不可用：${this.healthError ?? this.root}`);
      const planResult = await this.plan(paths);
      const totalItems = planResult.files.length + planResult.dirs.length + planResult.links.length;
      if (totalItems === 0) {
        return {
          batchId: null, dir: null, count: 0, bytes: 0, files: 0, dirs: 0, links: 0, missing: planResult.missing,
          zone: meta.zone ?? 'sensitive',
          perRoot: (paths ?? []).map((root) => ({ root: path.resolve(root), files: 0, bytes: 0 })),
        };
      }
      const { date, session, seq } = await this.nextBatchId(meta.sessionId);
      const batchId = `${date}/${session}/${String(seq).padStart(4, '0')}`;
      const dir = path.join(this.root, date, session, String(seq).padStart(4, '0'));
      await fsp.mkdir(dir, { recursive: true });
      const manifestPath = path.join(dir, 'manifest.jsonl');
      const out = fs.createWriteStream(manifestPath, { flags: 'a' });
      const startedAt = Date.now();
      const writeLine = (record) => out.write(JSON.stringify(record) + '\n');
      const header = {
        type: 'batch',
        version: 1,
        batchId,
        time: new Date().toISOString(),
        sessionId: meta.sessionId ?? null,
        toolCallId: meta.toolCallId ?? null,
        toolName: meta.toolName ?? null,
        command: meta.command ?? null,
        plan: meta.plan ?? null,
        cwd: meta.cwd ?? null,
        // 区域：workspace / dsh / sensitive。清理策略按区域分流。
        zone: meta.zone ?? 'sensitive',
        source: meta.source ?? { execPath: process.execPath, pid: process.pid, ppid: process.ppid },
        policy: meta.policy ?? null,
        missing: planResult.missing,
      };
      writeLine(header);

      let bytes = 0;
      let copied = 0;
      let addedBytes = 0;
      let addedFiles = 0;

      const ensureDir = async (abs) => {
        const rel = treeKey(abs);
        try {
          await fsp.mkdir(path.join(dir, 'tree', rel), { recursive: true });
        } catch {
          /* 镜像失败不影响主体备份 */
        }
        writeLine({ type: 'dir', target: abs, rel, result: 'ok' });
      };
      for (const absDir of planResult.dirs) await ensureDir(absDir);

      const copyOne = async (file) => {
        const stored = await this.copyToStore(file.path, file.size);
        if (stored.created) {
          addedBytes += stored.size;
          addedFiles++;
        }
        const obj = hashPath(this.root, stored.sha);
        const rel = treeKey(file.path);
        await this.mirror(obj, path.join(dir, 'tree', rel));
        bytes += file.size;
        copied++;
        writeLine({
          type: 'file',
          target: file.path,
          rel,
          size: file.size,
          mtime: new Date(file.mtimeMs).toISOString(),
          mtimeMs: file.mtimeMs,
          sha256: stored.sha,
          result: 'ok',
          backupPath: obj,
          restore: { originalPath: file.path, mode: 'copy' },
        });
      };

      try {
        await runPool(planResult.files, Math.max(1, this.config.concurrency ?? 4), copyOne);
        for (const link of planResult.links) {
          writeLine({
            type: 'symlink',
            target: link.path,
            linkTarget: link.target,
            result: 'recorded',
            note: '软链接/junction 只记录，不跟随、不复制内容',
          });
        }
        for (const item of planResult.overLimit) {
          writeLine({ type: 'file', target: item.path, size: item.size, result: 'over-limit', note: '超过单文件上限，未备份内容' });
        }
      } finally {
        await new Promise((resolve) => out.end(resolve));
      }

      const summary = {
        type: 'summary',
        batchId,
        count: copied,
        bytes,
        dirs: planResult.dirs.length,
        links: planResult.links.length,
        overLimit: planResult.overLimit.length,
        missing: planResult.missing.length,
        durationMs: Date.now() - startedAt,
      };
      await fsp.appendFile(manifestPath, JSON.stringify(summary) + '\n', 'utf8');

      this.usage.bytes += addedBytes;
      this.usage.files += addedFiles;
      await this.saveUsage();

      return {
        batchId, dir, count: copied, bytes, files: copied, dirs: planResult.dirs.length,
        links: planResult.links.length, missing: planResult.missing, overLimit: planResult.overLimit,
        durationMs: summary.durationMs, manifestPath,
        zone: meta.zone ?? 'sensitive',
        perRoot: perRootOf(paths, planResult),
      };
    });
  }

  async copyToStore(source, expectedSize) {
    const tmp = path.join(this.storeDir, `_tmp-${crypto.randomUUID()}`);
    const hash = crypto.createHash('sha256');
    const tap = new Transform({
      transform(chunk, _enc, callback) {
        hash.update(chunk);
        callback(null, chunk);
      },
    });
    try {
      await pipeline(fs.createReadStream(source), tap, fs.createWriteStream(tmp));
      const sha = hash.digest('hex');
      const obj = hashPath(this.root, sha);
      return await this.withShaLock(sha, async () => {
        let replaced = false;
        try {
          const st = await fsp.stat(obj);
          if (this.config.verify && st.size !== expectedSize) {
            // 已存在的对象大小不符（损坏）→ 丢弃后用新副本替换
            await retryIo(() => fsp.rm(obj, { force: true }));
            replaced = true;
          } else {
            await retryIo(() => fsp.rm(tmp, { force: true }));
            return { sha, size: expectedSize, created: false };
          }
        } catch {
          /* 对象不存在 */
        }
        if (this.config.verify) {
          const st = await fsp.stat(tmp);
          if (st.size !== expectedSize) throw new BackupError(`复制校验失败：${source}（期望 ${expectedSize} 字节，实际 ${st.size}）`);
        }
        await fsp.mkdir(path.dirname(obj), { recursive: true });
        await retryIo(() => fsp.rename(tmp, obj));
        return { sha, size: expectedSize, created: true, replaced };
      });
    } catch (error) {
      await fsp.rm(tmp, { force: true }).catch(() => {});
      throw error instanceof BackupError ? error : new BackupError(`备份失败：${source}（${error.message}）`);
    }
  }

  async mirror(objectPath, treePath) {
    if (!this.config.mirrorTree) return;
    // 跨卷硬链接不可用；跨卷时不建镜像，manifest 仍可还原。
    if (path.parse(objectPath).root.toLowerCase() !== path.parse(treePath).root.toLowerCase()) return;
    try {
      await fsp.mkdir(path.dirname(treePath), { recursive: true });
      await fsp.link(objectPath, treePath);
    } catch (error) {
      if (error.code === 'EEXIST') return;
      try {
        await fsp.copyFile(objectPath, treePath);
      } catch {
        /* 镜像只是便利，失败不阻断 */
      }
    }
  }

  /** 找到最新批次目录。 */
  async latestBatch() {
    let best = null;
    for (const dateEntry of await readdirSafe(this.root)) {
      if (!dateEntry.isDirectory() || !/^\d{4}-\d{2}-\d{2}$/.test(dateEntry.name)) continue;
      const dateDir = path.join(this.root, dateEntry.name);
      for (const sessionEntry of await readdirSafe(dateDir)) {
        if (!sessionEntry.isDirectory()) continue;
        const sessionDir = path.join(dateDir, sessionEntry.name);
        for (const seqEntry of await readdirSafe(sessionDir)) {
          if (!seqEntry.isDirectory() || !/^\d+$/.test(seqEntry.name)) continue;
          const dir = path.join(sessionDir, seqEntry.name);
          const manifest = path.join(dir, 'manifest.jsonl');
          if (!(await exists(manifest))) continue;
          let st;
          try {
            st = await fsp.stat(manifest);
          } catch {
            continue;
          }
          if (!best || st.mtimeMs > best.mtimeMs) {
            best = { batchId: `${dateEntry.name}/${sessionEntry.name}/${seqEntry.name}`, dir, mtimeMs: st.mtimeMs };
          }
        }
      }
    }
    return best;
  }

  async batchDir(batchId) {
    if (batchId === 'latest') {
      const latest = await this.latestBatch();
      if (!latest) throw new BackupError('没有可还原的批次');
      return latest;
    }
    const parsed = parseBatchId(batchId);
    if (!parsed) throw new BackupError(`批次 id 非法：${batchId}`);
    const dir = path.join(this.root, parsed.date, parsed.session, parsed.seq);
    if (!(await exists(path.join(dir, 'manifest.jsonl')))) throw new BackupError(`批次不存在：${batchId}`);
    return { batchId, dir };
  }

  /** 按 manifest 还原。 */
  async restore(batchId, { to = null, force = false, dryRun = false } = {}) {
    return this.withLock(async () => {
      const target = await this.batchDir(batchId);
      const entries = [];
      const manifest = await fsp.readFile(path.join(target.dir, 'manifest.jsonl'), 'utf8');
      for (const line of manifest.split('\n')) {
        if (!line.trim()) continue;
        try {
          entries.push(JSON.parse(line));
        } catch {
          /* 坏行 */
        }
      }
      const report = { batchId: target.batchId, restored: 0, dirs: 0, links: 0, skipped: 0, failed: 0, bytes: 0, dryRun, errors: [] };
      const resolveDest = (entry) => {
        if (to) {
          const rel = entry.rel ?? path.basename(entry.target ?? '');
          return path.join(to, rel);
        }
        return entry.target;
      };
      for (const entry of entries) {
        try {
          if (entry.type === 'dir') {
            if (!dryRun) await fsp.mkdir(resolveDest(entry), { recursive: true });
            report.dirs++;
            continue;
          }
          if (entry.type === 'symlink') {
            if (!dryRun && entry.linkTarget) {
              await fsp.mkdir(path.dirname(resolveDest(entry)), { recursive: true });
              await fsp.symlink(entry.linkTarget, resolveDest(entry)).catch(() => {});
            }
            report.links++;
            continue;
          }
          if (entry.type !== 'file' || entry.result !== 'ok') {
            report.skipped++;
            continue;
          }
          const dest = resolveDest(entry);
          if (dryRun) {
            report.restored++;
            report.bytes += entry.size ?? 0;
            continue;
          }
          if (!force && (await exists(dest))) {
            throw new BackupError(`目标已存在，拒绝覆盖：${dest}（使用 --force 覆盖）`);
          }
          const src = (await exists(entry.backupPath)) ? entry.backupPath : entry.treePath;
          if (!src || !(await exists(src))) throw new BackupError(`备份对象缺失：${entry.backupPath ?? entry.treePath}`);
          await fsp.mkdir(path.dirname(dest), { recursive: true });
          await fsp.copyFile(src, dest);
          if (entry.mtimeMs) {
            const mtime = new Date(entry.mtimeMs);
            await fsp.utimes(dest, mtime, mtime).catch(() => {});
          }
          if (this.config.verify && entry.sha256) {
            const sha = await sha256File(dest);
            if (sha !== entry.sha256) throw new BackupError(`还原校验失败（哈希不一致）：${dest}`);
          }
          report.restored++;
          report.bytes += entry.size ?? 0;
        } catch (error) {
          report.failed++;
          report.errors.push({ target: entry.target, error: error.message });
        }
      }
      return report;
    });
  }

  async status() {
    const batches = [];
    let totalBytes = 0;
    let totalFiles = 0;
    for (const dateEntry of await readdirSafe(this.root)) {
      if (!dateEntry.isDirectory() || !/^\d{4}-\d{2}-\d{2}$/.test(dateEntry.name)) continue;
      const dateDir = path.join(this.root, dateEntry.name);
      for (const sessionEntry of await readdirSafe(dateDir)) {
        if (!sessionEntry.isDirectory()) continue;
        const sessionDir = path.join(dateDir, sessionEntry.name);
        for (const seqEntry of await readdirSafe(sessionDir)) {
          if (!seqEntry.isDirectory() || !/^\d+$/.test(seqEntry.name)) continue;
          const dir = path.join(sessionDir, seqEntry.name);
          const manifest = path.join(dir, 'manifest.jsonl');
          if (!(await exists(manifest))) continue;
          batches.push({ batchId: `${dateEntry.name}/${sessionEntry.name}/${seqEntry.name}`, dir });
        }
      }
    }
    batches.sort((a, b) => (a.batchId < b.batchId ? -1 : 1));
    for (const batch of batches) {
      try {
        const summary = await readSummary(path.join(batch.dir, 'manifest.jsonl'));
        if (summary) {
          totalBytes += summary.bytes ?? 0;
          totalFiles += summary.count ?? 0;
        }
      } catch {
        /* 忽略 */
      }
    }
    return {
      root: this.root,
      healthy: this.healthy,
      healthError: this.healthError,
      usage: { ...this.usage },
      batches: batches.length,
      latestBatch: batches.length > 0 ? batches[batches.length - 1].batchId : null,
      totalBytes,
      totalFiles,
      limits: {
        maxFileBytes: this.config.maxFileBytes,
        maxBatchBytes: this.config.maxBatchBytes,
        maxBatchFiles: this.config.maxBatchFiles,
        quotaBytes: this.config.quotaBytes,
        retentionDays: this.config.retentionDays,
      },
    };
  }

  /** 删除超过保留期的批次；然后回收无引用的对象。 */
  async cleanup() {
    return this.withLock(async () => {
      // 清理上次崩溃留下的临时对象。
      for (const entry of await readdirSafe(this.storeDir)) {
        if (entry.isFile() && entry.name.startsWith('_tmp-')) {
          await fsp.rm(path.join(this.storeDir, entry.name), { force: true }).catch(() => {});
        }
      }
      const days = Number(this.config.retentionDays) || 0;
      const dshCount = Number(this.config.dshRetentionCount) || 0;
      const dshDays = Number(this.config.dshRetentionDays) || 0;
      const now = Date.now();
      const DAY = 24 * 3600 * 1000;

      // 先收集全部批次（区域 + 时间），再分区判定。
      const batches = [];
      const sessionDirs = new Set();
      const dateDirs = new Set();
      for (const dateEntry of await readdirSafe(this.root)) {
        if (!dateEntry.isDirectory() || !/^\d{4}-\d{2}-\d{2}$/.test(dateEntry.name)) continue;
        const dateDir = path.join(this.root, dateEntry.name);
        for (const sessionEntry of await readdirSafe(dateDir)) {
          if (!sessionEntry.isDirectory()) continue;
          const sessionDir = path.join(dateDir, sessionEntry.name);
          for (const seqEntry of await readdirSafe(sessionDir)) {
            if (!seqEntry.isDirectory() || !/^\d+$/.test(seqEntry.name)) continue;
            const dir = path.join(sessionDir, seqEntry.name);
            const manifest = path.join(dir, 'manifest.jsonl');
            let st;
            try {
              st = await fsp.stat(manifest);
            } catch {
              continue;
            }
            batches.push({ dir, sessionDir, dateDir, mtimeMs: st.mtimeMs, zone: await readBatchZone(manifest) });
            sessionDirs.add(sessionDir);
            dateDirs.add(dateDir);
          }
        }
      }

      // .dsh 区域：只保留最新 N 个（且不超过 N 天）。
      const dshBatches = batches.filter((b) => b.zone === 'dsh').sort((a, b) => b.mtimeMs - a.mtimeMs);
      const keepDsh = new Set();
      if (dshCount > 0) for (const batch of dshBatches.slice(0, dshCount)) keepDsh.add(batch.dir);

      let removedBatches = 0;
      for (const batch of batches) {
        let drop;
        if (batch.zone === 'dsh') {
          const expired = dshDays > 0 && batch.mtimeMs < now - dshDays * DAY;
          const beyondCount = dshCount > 0 && !keepDsh.has(batch.dir);
          drop = expired || beyondCount;
        } else {
          drop = days > 0 && batch.mtimeMs < now - days * DAY;
        }
        if (!drop) continue;
        await fsp.rm(batch.dir, { recursive: true, force: true });
        removedBatches++;
      }

      // 回收空会话/日期目录。
      for (const sessionDir of sessionDirs) {
        try {
          const rest = await fsp.readdir(sessionDir);
          if (rest.length === 0) await fsp.rm(sessionDir, { recursive: true, force: true });
        } catch {
          /* 忽略 */
        }
      }
      for (const dateDir of dateDirs) {
        try {
          const rest = await fsp.readdir(dateDir);
          if (rest.length === 0) await fsp.rm(dateDir, { recursive: true, force: true });
        } catch {
          /* 忽略 */
        }
      }
      const removedObjects = await this.gcLocked();
      await this.recomputeUsage();
      await this.saveUsage();
      return { removedBatches, removedObjects };
    });
  }

  async gcLocked() {
    const referenced = new Set();
    for (const dateEntry of await readdirSafe(this.root)) {
      if (!dateEntry.isDirectory() || !/^\d{4}-\d{2}-\d{2}$/.test(dateEntry.name)) continue;
      const dateDir = path.join(this.root, dateEntry.name);
      for (const sessionEntry of await readdirSafe(dateDir)) {
        if (!sessionEntry.isDirectory()) continue;
        const sessionDir = path.join(dateDir, sessionEntry.name);
        for (const seqEntry of await readdirSafe(sessionDir)) {
          if (!seqEntry.isDirectory() || !/^\d+$/.test(seqEntry.name)) continue;
          const manifest = path.join(sessionDir, seqEntry.name, 'manifest.jsonl');
          let text;
          try {
            text = await fsp.readFile(manifest, 'utf8');
          } catch {
            continue;
          }
          for (const line of text.split('\n')) {
            if (!line.includes('"sha256"')) continue;
            try {
              const record = JSON.parse(line);
              if (record.sha256) referenced.add(record.sha256);
            } catch {
              /* 忽略 */
            }
          }
        }
      }
    }
    let removed = 0;
    for (const aa of await readdirSafe(this.storeDir)) {
      if (!aa.isDirectory()) continue;
      const aaDir = path.join(this.storeDir, aa.name);
      for (const bb of await readdirSafe(aaDir)) {
        if (!bb.isDirectory()) continue;
        const bbDir = path.join(aaDir, bb.name);
        for (const obj of await readdirSafe(bbDir)) {
          if (!obj.isFile()) continue;
          if (!referenced.has(obj.name)) {
            try {
              await fsp.rm(path.join(bbDir, obj.name), { force: true });
              removed++;
            } catch {
              /* 忽略 */
            }
          }
        }
      }
    }
    return removed;
  }

  /** 清理旧的 _ipc 允许文件。 */
  async cleanIpc(maxAgeMs = 3600 * 1000) {
    for (const entry of await readdirSafe(this.ipcDir)) {
      if (!entry.isFile()) continue;
      const full = path.join(this.ipcDir, entry.name);
      try {
        const st = await fsp.stat(full);
        if (Date.now() - st.mtimeMs > maxAgeMs) await fsp.rm(full, { force: true });
      } catch {
        /* 忽略 */
      }
    }
  }
}

async function exists(file) {
  try {
    await fsp.access(file);
    return true;
  } catch {
    return false;
  }
}

/** Windows 上杀软/索引器短暂占用会让 rename/rm 报 EPERM/EBUSY，重试几次。 */
async function retryIo(fn, attempts = 6) {
  let lastError;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (!['EPERM', 'EBUSY', 'EACCES'].includes(error.code) || i === attempts - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, 30 * (i + 1)));
    }
  }
  throw lastError;
}

async function sha256File(file) {
  const hash = crypto.createHash('sha256');
  await pipeline(fs.createReadStream(file), new Transform({
    transform(chunk, _enc, callback) {
      hash.update(chunk);
      callback();
    },
  }));
  return hash.digest('hex');
}

async function readSummary(manifest) {
  try {
    const text = await fsp.readFile(manifest, 'utf8');
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        if (record.type === 'summary') return record;
      } catch {
        /* 忽略 */
      }
    }
  } catch {
    /* 忽略 */
  }
  return null;
}

async function runPool(items, limit, fn) {
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, Math.max(1, items.length)) }, async () => {
    while (true) {
      const current = index++;
      if (current >= items.length) return;
      await fn(items[current], current);
    }
  });
  await Promise.all(workers);
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return String(bytes);
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 100 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export { dayString, hashPath, statSize };
