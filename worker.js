// INFINEX 冊子：API（Cloudflare Worker）
// 画面（public/）は静的ファイルとして配信され、/api/ だけがこの Worker で処理されます。
const SESSION_COOKIE = 'ib_session';
const SESSION_DAYS = 30;
const MAX_PROJECT_BYTES = 1_900_000;      // D1 の1行の上限（2MB）より少し小さく
const MAX_ASSET_BYTES = 15 * 1024 * 1024; // 画像1点の上限
const HASH_RE = /^[0-9a-f]{64}$/;
const ID_RE = /^[0-9a-z]{8,40}$/;
const enc = new TextEncoder();

const now = () => new Date().toISOString();
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };
const newId = () => [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(36).padStart(2, '0')).join('').slice(0, 20);
const decName = (v) => { try { return decodeURIComponent(v || '').slice(0, 60); } catch { return ''; } };

// ---------- session ----------
async function hmac(secret, text) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function cookieOf(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}
async function readSession(req, env) {
  const raw = cookieOf(req, SESSION_COOKIE);
  if (!raw) return null;
  const [exp, name, sig] = raw.split('.');
  if (!exp || sig == null || Number(exp) < Date.now()) return null;
  const want = await hmac(env.SESSION_SECRET, `${exp}.${name}`);
  if (!safeEqual(want, sig)) return null;
  return { name: decName(name) };
}
async function sessionCookie(env, name, secure) {
  const exp = Date.now() + SESSION_DAYS * 864e5;
  const n = encodeURIComponent(name || '').replace(/\./g, '%2E');
  const sig = await hmac(env.SESSION_SECRET, `${exp}.${n}`);
  return `${SESSION_COOKIE}=${exp}.${n}.${sig}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure ? '; Secure' : ''}`;
}

// ---------- routing ----------
const routes = [];
const route = (method, pattern, handler, opts = {}) => {
  const keys = []; const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, handler, opts });
};

route('GET', '/api/health', async () => json({ ok: true }), { public: true });

route('POST', '/api/login', async ({ req, env, url }) => {
  const ip = req.headers.get('cf-connecting-ip') || 'local';
  const t = Date.now();
  const lock = await env.DB.prepare('SELECT fails, until FROM login_attempts WHERE ip = ?').bind(ip).first();
  if (lock && lock.fails >= 8 && lock.until > t) fail(429, 'ログインの失敗が続いたため、しばらく待ってからお試しください');
  const b = await req.json().catch(() => ({}));
  const ok = typeof b.password === 'string' && safeEqual(await hmac(env.SESSION_SECRET, b.password), await hmac(env.SESSION_SECRET, env.ADMIN_PASSWORD));
  if (!ok) {
    const fails = lock && lock.until > t ? lock.fails + 1 : 1;
    await env.DB.prepare('INSERT INTO login_attempts (ip, fails, until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, until = excluded.until').bind(ip, fails, t + 15 * 60e3).run();
    fail(401, 'パスワードが違います');
  }
  if (lock) await env.DB.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run();
  const name = String(b.name || '').trim().slice(0, 30);
  return json({ ok: true, name }, 200, { 'set-cookie': await sessionCookie(env, name, url.protocol === 'https:') });
}, { public: true });

route('POST', '/api/logout', async () => json({ ok: true }, 200, { 'set-cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` }), { public: true });

route('GET', '/api/me', async ({ user }) => json({ ok: true, name: user.name }));

// 冊子の一覧
route('GET', '/api/projects', async ({ env }) => {
  const r = await env.DB.prepare('SELECT id, name, rev, size, created_at, updated_at, updated_by FROM projects ORDER BY updated_at DESC').all();
  return json({ projects: r.results });
});

// 新しい冊子（中身は後から PUT で保存）
route('POST', '/api/projects', async ({ req, env, user }) => {
  const b = await req.json().catch(() => ({}));
  const id = newId(); const t = now();
  const data = typeof b.data === 'string' && b.data.length < MAX_PROJECT_BYTES ? b.data : '{}';
  await env.DB.prepare('INSERT INTO projects (id, name, data, rev, size, created_at, updated_at, updated_by) VALUES (?, ?, ?, 1, ?, ?, ?, ?)')
    .bind(id, String(b.name || '').slice(0, 200), data, data.length, t, t, user.name).run();
  return json({ id, rev: 1, updated_at: t });
});

// 冊子を開く：本文はそのまま返し、更新情報はヘッダーで返す（Worker で JSON を組み立て直さない）
route('GET', '/api/projects/:id', async ({ env, p }) => {
  const r = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(p.id).first();
  if (!r) fail(404, 'この冊子は見つかりません（削除された可能性があります）');
  return new Response(r.data, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-rev': String(r.rev), 'x-updated-at': r.updated_at, 'x-updated-by': encodeURIComponent(r.updated_by || ''), 'x-name': encodeURIComponent(r.name || '') } });
});

// 更新状況だけを確認（スマホとパソコンの切り替え時に使う）
route('GET', '/api/projects/:id/meta', async ({ env, p }) => {
  const r = await env.DB.prepare('SELECT id, name, rev, updated_at, updated_by FROM projects WHERE id = ?').bind(p.id).first();
  if (!r) fail(404, 'この冊子は見つかりません');
  return json(r);
});

// 保存：X-Base-Rev が今の版と同じときだけ保存する（別の端末の変更を上書きしない）
route('PUT', '/api/projects/:id', async ({ req, env, p, user }) => {
  const data = await req.text();
  if (data.length > MAX_PROJECT_BYTES) fail(413, '冊子のデータが大きすぎます');
  if (data[0] !== '{') fail(400, '保存するデータの形式が正しくありません');
  const base = Number(req.headers.get('x-base-rev'));
  const force = req.headers.get('x-force') === '1';
  const name = req.headers.has('x-name') ? decName(req.headers.get('x-name')).slice(0, 200) : null;
  const t = now();
  const sql = force
    ? env.DB.prepare('UPDATE projects SET data = ?, name = COALESCE(?, name), size = ?, rev = rev + 1, updated_at = ?, updated_by = ? WHERE id = ? RETURNING rev').bind(data, name, data.length, t, user.name, p.id)
    : env.DB.prepare('UPDATE projects SET data = ?, name = COALESCE(?, name), size = ?, rev = rev + 1, updated_at = ?, updated_by = ? WHERE id = ? AND rev = ? RETURNING rev').bind(data, name, data.length, t, user.name, p.id, base);
  const r = await sql.first();
  if (r) return json({ rev: r.rev, updated_at: t });
  const cur = await env.DB.prepare('SELECT rev, updated_at, updated_by FROM projects WHERE id = ?').bind(p.id).first();
  if (!cur) fail(404, 'この冊子は見つかりません（削除された可能性があります）');
  return json({ conflict: true, ...cur }, 409);
});

route('DELETE', '/api/projects/:id', async ({ env, p }) => {
  const hashes = (await env.DB.prepare('SELECT hash FROM asset_refs WHERE project_id = ?').bind(p.id).all()).results.map((r) => r.hash);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM projects WHERE id = ?').bind(p.id),
    env.DB.prepare('DELETE FROM asset_refs WHERE project_id = ?').bind(p.id),
  ]);
  await removeOrphans(env, hashes);
  return json({ ok: true });
});

route('POST', '/api/projects/:id/duplicate', async ({ env, p, user }) => {
  const src = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(p.id).first();
  if (!src) fail(404, 'この冊子は見つかりません');
  const id = newId(); const t = now(); const name = `${src.name}（複製）`;
  let data = src.data;
  try { const o = JSON.parse(data); if (o && o.meta) { o.meta.title = `${o.meta.title || ''}（複製）`; data = JSON.stringify(o); } } catch { /* そのまま複製 */ }
  await env.DB.batch([
    env.DB.prepare('INSERT INTO projects (id, name, data, rev, size, created_at, updated_at, updated_by) VALUES (?, ?, ?, 1, ?, ?, ?, ?)').bind(id, name, data, data.length, t, t, user.name),
    env.DB.prepare('INSERT OR IGNORE INTO asset_refs (project_id, hash, created_at) SELECT ?, hash, ? FROM asset_refs WHERE project_id = ?').bind(id, t, p.id),
  ]);
  return json({ id, rev: 1 });
});

// 画像の登録状況：まだサーバーに無いものを返し、あるものはこの冊子に紐づける
route('POST', '/api/projects/:id/assets/sync', async ({ req, env, p }) => {
  const b = await req.json().catch(() => ({}));
  const hashes = [...new Set((b.hashes || []).filter((h) => HASH_RE.test(h)))].slice(0, 500);
  if (!hashes.length) return json({ missing: [] });
  const have = new Set();
  for (let i = 0; i < hashes.length; i += 90) {
    const part = hashes.slice(i, i + 90);
    const r = await env.DB.prepare(`SELECT hash FROM assets WHERE hash IN (${part.map(() => '?').join(',')})`).bind(...part).all();
    r.results.forEach((x) => have.add(x.hash));
  }
  const t = now();
  const exist = hashes.filter((h) => have.has(h));
  for (let i = 0; i < exist.length; i += 50) {
    await env.DB.batch(exist.slice(i, i + 50).map((h) => env.DB.prepare('INSERT OR IGNORE INTO asset_refs (project_id, hash, created_at) VALUES (?, ?, ?)').bind(p.id, h, t)));
  }
  return json({ missing: hashes.filter((h) => !have.has(h)) });
});

// 画像のアップロード（本体は KV、名前は内容の SHA-256）
route('PUT', '/api/projects/:id/assets/:hash', async ({ req, env, p }) => {
  if (!HASH_RE.test(p.hash)) fail(400, '画像の識別子が正しくありません');
  const mime = (req.headers.get('content-type') || '').split(';')[0].trim();
  if (!/^image\/(png|jpeg|webp|gif)$/.test(mime)) fail(415, '画像（PNG・JPEG・WebP・GIF）だけを保存できます');
  const buf = await req.arrayBuffer();
  if (!buf.byteLength || buf.byteLength > MAX_ASSET_BYTES) fail(413, '画像が大きすぎます');
  const exists = await env.DB.prepare('SELECT hash FROM assets WHERE hash = ?').bind(p.hash).first();
  if (!exists) await env.FILES.put(`a/${p.hash}`, buf, { metadata: { mime, size: buf.byteLength } });
  const t = now();
  await env.DB.batch([
    env.DB.prepare('INSERT OR IGNORE INTO assets (hash, mime, size, created_at) VALUES (?, ?, ?, ?)').bind(p.hash, mime, buf.byteLength, t),
    env.DB.prepare('INSERT OR IGNORE INTO asset_refs (project_id, hash, created_at) VALUES (?, ?, ?)').bind(p.id, p.hash, t),
  ]);
  return json({ ok: true, url: `/api/assets/${p.hash}` });
});

// 画像の配信（内容が変わらないので長期キャッシュ）
route('GET', '/api/assets/:hash', async ({ env, p }) => {
  if (!HASH_RE.test(p.hash)) fail(404, '見つかりません');
  const o = await env.FILES.getWithMetadata(`a/${p.hash}`, { type: 'stream' });
  if (!o || !o.value) fail(404, '画像が見つかりません');
  return new Response(o.value, { headers: { 'content-type': (o.metadata && o.metadata.mime) || 'application/octet-stream', 'cache-control': 'private, max-age=31536000, immutable' } });
});

// 使っていない画像の整理：1日以上前に登録され、冊子で使われていない画像の紐づけを外す
route('POST', '/api/projects/:id/assets/gc', async ({ req, env, p }) => {
  const b = await req.json().catch(() => ({}));
  const used = new Set((b.used || []).filter((h) => HASH_RE.test(h)));
  const cutoff = new Date(Date.now() - 864e5).toISOString();
  const refs = (await env.DB.prepare('SELECT hash FROM asset_refs WHERE project_id = ? AND created_at < ?').bind(p.id, cutoff).all()).results.map((r) => r.hash);
  const drop = refs.filter((h) => !used.has(h));
  for (let i = 0; i < drop.length; i += 50) {
    await env.DB.batch(drop.slice(i, i + 50).map((h) => env.DB.prepare('DELETE FROM asset_refs WHERE project_id = ? AND hash = ?').bind(p.id, h)));
  }
  await removeOrphans(env, drop);
  return json({ removed: drop.length });
});

async function removeOrphans(env, hashes) {
  for (const h of hashes) {
    const still = await env.DB.prepare('SELECT 1 AS x FROM asset_refs WHERE hash = ? LIMIT 1').bind(h).first();
    if (still) continue;
    await env.FILES.delete(`a/${h}`);
    await env.DB.prepare('DELETE FROM assets WHERE hash = ?').bind(h).run();
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try {
      if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || String(env.SESSION_SECRET).length < 32) fail(503, 'サーバーの初期設定が完了していません（ADMIN_PASSWORD と SESSION_SECRET を登録してください）');
      if (!env.DB || !env.FILES) fail(503, 'サーバーの初期設定が完了していません（D1 と KV の設定を確認してください）');
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = url.pathname.match(r.re); if (!m) continue;
        const p = {}; r.keys.forEach((k, i) => { p[k] = decodeURIComponent(m[i + 1]); });
        if (p.id && !ID_RE.test(p.id)) fail(404, '見つかりません');
        let user = null;
        if (!r.opts.public) {
          user = await readSession(req, env);
          if (!user) fail(401, 'ログインしてください');
          // 別のサイトからの書き換えを防ぐ（画面からの呼び出しには必ず付く）
          if (req.method !== 'GET' && req.headers.get('x-requested-with') !== 'infinex-booklet') fail(403, '許可されていない操作です');
        } else if (req.method !== 'GET' && req.headers.get('x-requested-with') !== 'infinex-booklet') fail(403, '許可されていない操作です');
        return await r.handler({ req, env, url, p, user });
      }
      fail(404, '見つかりません');
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: 'サーバーでエラーが発生しました' }, 500);
    }
  },
};
