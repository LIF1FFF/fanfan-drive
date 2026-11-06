/**
 * EdgeOne Pages Function —— 个人网盘服务端
 *
 * 路由：/functions/api/[[default]].js → 接管所有 /api/* 请求
 * 运行时：EdgeOne 边缘函数（Web APIs），只用 fetch / Response / TextEncoder /
 *        URLSearchParams 等基础接口；HMAC-SHA1 用内置纯 JS 实现，
 *        避免依赖不同运行时对 Web Crypto 算法的支持差异。
 *
 * 密钥来自 Pages 环境变量（context.env），永远不会下发到浏览器：
 *   QINIU_AK / QINIU_SK / QINIU_BUCKET / QINIU_DOMAIN / PAN_PASSWORD
 *   QINIU_REGION(默认 z0) / QINIU_PRIVATE(默认 1) / MAX_UPLOAD_MB(默认 200)
 */

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const QUOTA_BYTES = 10 * 1024 * 1024 * 1024;
const PLACEHOLDER = '.folder';
const PROXY_LIMIT = 8 * 1024 * 1024; // 边缘函数代传上限，大文件走浏览器直传
const COOKIE = 'pan_sess';

// ---------------------------------------------------------------- 编码 / 摘要

function b64u(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | ((b === undefined ? 0 : b) >> 4)];
    out += b === undefined ? '=' : B64[((b & 15) << 2) | ((c === undefined ? 0 : c) >> 6)];
    out += c === undefined ? '=' : B64[c & 63];
  }
  return out.replace(/\+/g, '-').replace(/\//g, '_');
}

function b64uDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const out = [];
  let buffer = 0, bits = 0;
  for (const ch of s) {
    if (ch === '=') break;
    const v = B64.indexOf(ch);
    if (v < 0) continue;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 255); }
  }
  return new Uint8Array(out);
}

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

function sha1(bytes) {
  const bitLen = bytes.length * 8;
  const total = Math.ceil((bytes.length + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(total - 4, bitLen >>> 0);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, h0); ov.setUint32(4, h1); ov.setUint32(8, h2);
  ov.setUint32(12, h3); ov.setUint32(16, h4);
  return out;
}

function hmacSha1(keyBytes, msgBytes) {
  const block = 64;
  const k = keyBytes.length > block ? sha1(keyBytes) : keyBytes;
  const ipad = new Uint8Array(block), opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    const v = k[i] || 0;
    ipad[i] = v ^ 0x36;
    opad[i] = v ^ 0x5c;
  }
  const inner = new Uint8Array(block + msgBytes.length);
  inner.set(ipad); inner.set(msgBytes, block);
  const ih = sha1(inner);
  const outer = new Uint8Array(block + 20);
  outer.set(opad); outer.set(ih, block);
  return sha1(outer);
}

const sign = (key, data) => b64u(hmacSha1(encoder.encode(key), encoder.encode(data)));

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------- 配置 / 通用

function getConfig(env) {
  let inherited = {};
  try { if (typeof process !== 'undefined' && process.env) inherited = process.env; } catch { /* 边缘运行时无 process */ }
  const e = { ...inherited, ...(env || {}) };
  const cfg = {
    ak: e.QINIU_AK || '',
    sk: e.QINIU_SK || '',
    bucket: e.QINIU_BUCKET || '',
    domain: (e.QINIU_DOMAIN || '').replace(/\/+$/, ''),
    region: e.QINIU_REGION || 'z0',
    privateSpace: e.QINIU_PRIVATE !== '0',
    password: e.PAN_PASSWORD || '',
    maxMB: Number(e.MAX_UPLOAD_MB || 200),
  };
  cfg.uploadHost = e.QINIU_UPLOAD_HOST || `https://up-${cfg.region}.qiniup.com`;
  cfg.rsHost = e.QINIU_RS_HOST || `https://rs-${cfg.region}.qiniuapi.com`;
  cfg.rsfHost = e.QINIU_RSF_HOST || `https://rsf-${cfg.region}.qiniuapi.com`;
  cfg.missing = [
    !cfg.ak && 'QINIU_AK', !cfg.sk && 'QINIU_SK', !cfg.bucket && 'QINIU_BUCKET',
    !cfg.domain && 'QINIU_DOMAIN', !cfg.password && 'PAN_PASSWORD',
  ].filter(Boolean);
  cfg.configured = cfg.missing.length === 0;
  return cfg;
}

const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});

function safeKey(key) {
  if (typeof key !== 'string' || !key || key.length > 500) throw new Error('文件名不合法');
  if (key.startsWith('/') || key.includes('\\') || key.includes('..') || key.includes('\0')) throw new Error('文件名不合法');
  if (key.split('/').some((s) => s.startsWith('.'))) throw new Error('文件名不合法');
  return key;
}

function encodeKey(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

const entry = (cfg, key) => b64u(encoder.encode(`${cfg.bucket}:${key}`));
const nowSec = () => Math.floor(Date.now() / 1000);

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

const sessionKey = (cfg) => cfg.sk + '|' + cfg.password + '|v1';

function issueSession(cfg) {
  const payload = b64u(encoder.encode(JSON.stringify({ exp: Date.now() + 7 * 86400000 })));
  return `${payload}.${sign(sessionKey(cfg), payload)}`;
}

function checkSession(cfg, token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2 || !safeEqual(sign(sessionKey(cfg), parts[0]), parts[1])) return false;
  try {
    const data = JSON.parse(decoder.decode(b64uDecode(parts[0])));
    return data.exp > Date.now();
  } catch { return false; }
}

// ---------------------------------------------------------------- 七牛签名

function uploadToken(cfg, key) {
  const policy = {
    scope: `${cfg.bucket}:${key}`,
    deadline: nowSec() + 3600,
    fsizeLimit: cfg.maxMB * 1024 * 1024,
  };
  const encoded = b64u(encoder.encode(JSON.stringify(policy)));
  return `${cfg.ak}:${sign(cfg.sk, encoded)}:${encoded}`;
}

const qboxAuth = (cfg, reqPath, body = '') => `QBox ${cfg.ak}:${sign(cfg.sk, `${reqPath}\n${body}`)}`;

function downloadUrl(cfg, key) {
  const base = `${cfg.domain}/${encodeKey(key)}`;
  if (!cfg.privateSpace) return base;
  const expireUrl = `${base}${base.includes('?') ? '&' : '?'}e=${nowSec() + 3600}`;
  return `${expireUrl}&token=${cfg.ak}:${sign(cfg.sk, expireUrl)}`;
}

async function qiniuFetch(host, reqPath, { method = 'GET', headers = {}, body = null } = {}) {
  const res = await fetch(host + reqPath, { method, headers, body });
  return { status: res.status, text: await res.text() };
}

function qiniuError(r, fallback) {
  let msg = fallback;
  try { const j = JSON.parse(r.text); if (j.error) msg = j.error; } catch { /* 忽略 */ }
  return new Error(`七牛云返回 ${r.status}：${msg}`);
}

// ---------------------------------------------------------------- 七牛接口

function parseList(text) {
  const items = [], folders = [];
  let marker = '', parsed = 0;
  const trimmed = text.trim();
  const dirName = (d) => d.replace(/\/$/, '').split('/').pop();
  if (trimmed.startsWith('{') && !trimmed.includes('\n')) {
    try {
      const j = JSON.parse(trimmed);
      if (Array.isArray(j.items)) {
        j.items.forEach((it) => items.push({ key: it.key, fsize: it.fsize, mimeType: it.mimeType, time: Math.floor((it.putTime || 0) / 1e7) }));
        (j.commonPrefixes || []).forEach((d) => folders.push({ key: d, name: dirName(d) }));
        return { items, folders, marker: j.marker || '' };
      }
    } catch { /* 按行解析 */ }
  }
  trimmed.split('\n').forEach((line) => {
    if (!line.trim()) return;
    try {
      const j = JSON.parse(line);
      parsed++;
      if (Object.prototype.hasOwnProperty.call(j, 'marker')) marker = j.marker || '';
      if (j.item) items.push({ key: j.item.key, fsize: j.item.fsize, mimeType: j.item.mimeType, time: Math.floor((j.item.putTime || 0) / 1e7) });
      if (j.dir) folders.push({ key: j.dir, name: dirName(j.dir) });
    } catch { /* 忽略 */ }
  });
  if (!parsed && trimmed) throw new Error('无法解析列举结果：' + trimmed.slice(0, 160));
  return { items, folders, marker };
}

async function listPage(cfg, prefix, marker, delimiter) {
  const params = new URLSearchParams({ bucket: cfg.bucket, prefix, limit: '1000', delimiter });
  if (marker) params.set('marker', marker);
  let lastErr;
  for (const path of [`/list?${params}`, `/v2/list?${params}`]) {
    try {
      const r = await qiniuFetch(cfg.rsfHost, path, { headers: { Authorization: qboxAuth(cfg, path) } });
      if (r.status !== 200) { lastErr = qiniuError(r, '列举文件失败'); continue; }
      return parseList(r.text);
    } catch (err) { lastErr = err; }
  }
  throw lastErr || new Error('列举文件失败');
}

async function listAll(cfg, prefix, delimiter = '/') {
  const items = [], folders = [];
  let marker = '';
  for (let page = 0; page < 50; page++) {
    const r = await listPage(cfg, prefix, marker, delimiter);
    items.push(...r.items); folders.push(...r.folders);
    marker = r.marker;
    if (!marker) break;
  }
  return { items, folders };
}

async function batchOp(cfg, ops) {
  const body = ops.map((op) => `op=${op}`).join('&');
  const r = await qiniuFetch(cfg.rsHost, '/batch', {
    method: 'POST',
    headers: { Authorization: qboxAuth(cfg, '/batch', body), 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (r.status !== 200 && r.status !== 298) throw qiniuError(r, '批量操作失败');
}

async function move(cfg, src, dest) {
  const path = `/move/${entry(cfg, src)}/${entry(cfg, dest)}/force/0`;
  const r = await qiniuFetch(cfg.rsHost, path, {
    method: 'POST',
    headers: { Authorization: qboxAuth(cfg, path), 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  if (r.status !== 200) throw qiniuError(r, '重命名失败');
}

/** 服务端代传：浏览器直传被拦截时的兜底，也用于创建空目录占位 */
async function multipartUpload(cfg, key, bytes, filename) {
  const boundary = '----pan' + Math.random().toString(36).slice(2) + Date.now().toString(36);
  const token = uploadToken(cfg, key);
  const parts = [];
  const push = (s) => parts.push(encoder.encode(s));
  const field = (name, value) => push(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`);
  field('token', token);
  field('key', key);
  push(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${String(filename).replace(/["\r\n]/g, '_')}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
  parts.push(bytes);
  push(`\r\n--${boundary}--\r\n`);
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const body = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { body.set(p, offset); offset += p.length; }
  const r = await qiniuFetch(cfg.uploadHost, '/', {
    method: 'POST',
    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
    body,
  });
  if (r.status !== 200) throw qiniuError(r, '上传失败');
}

// ---------------------------------------------------------------- 请求处理

export async function onRequest({ request, env }) {
  const cfg = getConfig(env);
  const url = new URL(request.url);
  const p = url.pathname.replace(/\/+$/, '') || '/';
  const q = (name) => url.searchParams.get(name) || '';
  const method = request.method.toUpperCase();

  try {
    if (method === 'OPTIONS') return new Response(null, { status: 204 });

    if (p === '/api/config' && method === 'GET') {
      if (!cfg.configured) console.error('[网盘配置] 缺少环境变量：' + cfg.missing.join(', '));
      return json({
        mode: 'qiniu',
        configured: cfg.configured,
        authRequired: cfg.configured,
        authenticated: checkSession(cfg, parseCookies(request.headers.get('cookie'))[COOKIE]),
        maxUploadMB: cfg.maxMB,
        quotaBytes: QUOTA_BYTES,
      });
    }

    if (p === '/api/login' && method === 'POST') {
      const { password } = await request.json();
      if (!cfg.configured) return json({ error: '服务暂未就绪，请联系管理员' }, 503);
      if (!safeEqual(String(password || ''), cfg.password)) return json({ error: '密码不对，再试一次' }, 401);
      return json({ ok: true }, 200, {
        'Set-Cookie': `${COOKIE}=${issueSession(cfg)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
      });
    }

    if (p === '/api/logout' && method === 'POST') {
      return json({ ok: true }, 200, { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
    }

    if (!cfg.configured) {
      return json({ error: '服务暂未就绪，请联系管理员' }, 503);
    }
    if (!checkSession(cfg, parseCookies(request.headers.get('cookie'))[COOKIE])) {
      return json({ error: '请先登录', needLogin: true }, 401);
    }

    if (p === '/api/list' && method === 'GET') {
      const prefix = q('prefix');
      const { items, folders } = await listAll(cfg, prefix, '/');
      return json({
        items: items
          .filter((it) => !it.key.endsWith(PLACEHOLDER))
          .map((it) => ({ key: it.key, name: it.key.slice(prefix.length), size: it.fsize, mime: it.mimeType, time: it.time }))
          .sort((a, b) => (b.time || 0) - (a.time || 0)),
        folders: folders
          .map((f) => ({ key: f.key, name: f.key.slice(prefix.length).replace(/\/$/, '') }))
          .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN')),
      });
    }

    if (p === '/api/usage' && method === 'GET') {
      const { items } = await listAll(cfg, '', '');
      return json({ bytes: items.reduce((sum, it) => sum + (it.fsize || 0), 0), quotaBytes: QUOTA_BYTES });
    }

    if (p === '/api/token' && method === 'POST') {
      const { key } = await request.json();
      safeKey(key);
      return json({ mode: 'qiniu', uploadUrl: cfg.uploadHost, token: uploadToken(cfg, key), key });
    }

    if (p === '/api/url' && method === 'GET') {
      const key = safeKey(q('key'));
      const url = downloadUrl(cfg, key);
      return json({ url, thumbnail: url });
    }

    if (p === '/api/upload' && method === 'POST') {
      const key = safeKey(q('key'));
      const bytes = new Uint8Array(await request.arrayBuffer());
      if (bytes.length > PROXY_LIMIT) {
        return json({ error: `代传仅支持 ${Math.floor(PROXY_LIMIT / 1048576)}MB 以内文件，请检查浏览器直传是否被网络拦截` }, 413);
      }
      await multipartUpload(cfg, key, bytes, q('name') || key.split('/').pop());
      return json({ ok: true, key });
    }

    if (p === '/api/delete' && method === 'POST') {
      const { keys, folder } = await request.json();
      if (!Array.isArray(keys) || !keys.length) throw new Error('没有要删除的文件');
      keys.forEach(safeKey);
      let all = [...keys];
      if (folder) {
        const { items } = await listAll(cfg, keys[0], '');
        all = items.map((it) => it.key);
      }
      for (let i = 0; i < all.length; i += 100) {
        await batchOp(cfg, all.slice(i, i + 100).map((k) => `/delete/${entry(cfg, k)}`));
      }
      return json({ ok: true });
    }

    if (p === '/api/mkdir' && method === 'POST') {
      const name = ((await request.json()).name || '').trim();
      if (!name || /[\\/]/.test(name) || name.startsWith('.')) throw new Error('文件夹名称不合法');
      await multipartUpload(cfg, q('prefix') + name + '/' + PLACEHOLDER, new Uint8Array(0), PLACEHOLDER);
      return json({ ok: true });
    }

    if (p === '/api/rename' && method === 'POST') {
      const { key, newKey } = await request.json();
      safeKey(key); safeKey(newKey);
      await move(cfg, key, newKey);
      return json({ ok: true });
    }

    return json({ error: '接口不存在' }, 404);
  } catch (err) {
    return json({ error: err.message || '服务器开小差了' }, 500);
  }
}
