// DSH 设置页的数据通道。
//
// 只注册一个精确路由，只接受同源 + application/json 的请求：
//   GET  /plugins/dsh-sensitive-data-guard/settings   → 当前设置
//   POST /plugins/dsh-sensitive-data-guard/settings   → 保存并立即生效
//
// 安全说明：webserver 本身没有鉴权（见 @deepseek-ai/dsh-host-webserver README），
// 所以这里自己做两道闸——同源检查 + 强制 JSON。跨站页面发 JSON POST 会先触发
// CORS 预检，我们没有应答预检，等于拦掉；本机同用户进程本来就能直接改配置文件，
// 因此不额外引入凭据机制。

export const SETTINGS_ROUTE = '/plugins/dsh-sensitive-data-guard/settings';

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(text),
  });
  res.end(text);
}

function readBody(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new Error('请求体不是合法 JSON'));
      }
    });
    req.on('error', reject);
  });
}

/** 同源检查：没有 Origin 头（同页面 fetch 常见）或 Origin 主机与 Host 一致才放行。 */
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    const host = String(req.headers.host ?? '');
    return parsed.host === host;
  } catch {
    return false;
  }
}

export async function handleSettingsRequest(core, req, res) {
  try {
    if (!sameOrigin(req)) {
      send(res, 403, { ok: false, error: '仅允许同源请求' });
      return;
    }
    if (req.method === 'GET') {
      send(res, 200, { ok: true, settings: core.settingsSnapshot() });
      return;
    }
    if (req.method === 'POST' || req.method === 'PUT') {
      const type = String(req.headers['content-type'] ?? '').toLowerCase();
      if (!type.includes('application/json')) {
        send(res, 415, { ok: false, error: '需要 Content-Type: application/json' });
        return;
      }
      const body = await readBody(req);
      const result = core.applySettings(body);
      send(res, 200, { ...result, settings: core.settingsSnapshot() });
      return;
    }
    send(res, 405, { ok: false, error: '只支持 GET / POST' });
  } catch (error) {
    send(res, 400, { ok: false, error: error?.message ?? String(error) });
  }
}
