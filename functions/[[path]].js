

// functions/[[path]].js  — PART 1 of 2
// ════════════════════════════════════════════════════════════════
//  CM FLIX — Self-hosted Movie / Series streaming app  (D1 EDITION)
//  • Storage: Cloudflare D1 (SQLite)  — binding name: DB
//  • Signed / expiring URL streaming (real R2/mp4 link NEVER in HTML)
//  • Key-only login (admin-created keys, device-limited)
//  • Categories: R Mosaic / Series / 21+ mmsub (Series: Season → Episode)
//  • Slider supports separate landscape banner image (slide_image)
//  • Modern Plyr player + polished UI / logo
//  • My Key chip shows premium days-left (P-NDay) when logged in
//  • TMDB API integration (auto-fetch poster/backdrop/overview)
// ════════════════════════════════════════════════════════════════

// ── Session / key constants ──
const SESSION_HOURS    = 24 * 30;
const COOKIE_NAME      = "__Host-cmflix_sess";
const CSRF_COOKIE      = "__Host-cmflix_csrf";
const MAX_DEVICES_PER_KEY = 2;
const KEY_PREFIX       = "CM";

// ── Contact (Admin) ──
const CONTACT_TELEGRAM = "iqowoq";          // @ မပါဘဲ username ပဲ
const CONTACT_VIBER    = "09688171999";     // Viber phone number

// ── Signed stream URL ──
const STREAM_TTL_SEC   = 6 * 3600;

// Rate limit
const KEY_LOGIN_MAX_ATTEMPTS = 12;
const KEY_LOGIN_WINDOW_SEC   = 600;

// ── Pagination ──
const HOME_PREVIEW_COUNT   = 7;
const ITEMS_PER_PAGE       = 15;
const ADMIN_ITEMS_PER_PAGE = 20;

// ── TMDB ──
const TMDB_IMG_BASE   = "https://image.tmdb.org/t/p";
const TMDB_POSTER_SIZE   = "w500";   // ထောင်လိုက် poster
const TMDB_BACKDROP_SIZE = "w1280";  // အလျားလိုက် slide banner

// ── Categories (fixed) ──
const CATEGORIES = {
  movie:  { id: "movie",  name: "R Mosaic",  icon: "" },
  series: { id: "series", name: "Series",  icon: "" },
  adult:  { id: "adult",  name: "21+ mmsub",     icon: "" },
  random: { id: "random", name: "Random Best", icon: "" },
};
function isValidCategory(c) { return c === "movie" || c === "series" || c === "adult" || c === "random"; }

// ── Per-request cache ──
const _reqCache = new WeakMap();

/* ══════════════════════════════════════════════════
   D1 HELPERS  — DB binding
   ══════════════════════════════════════════════════ */
function db(env) {
  if (!env.DB) throw new Error("D1 binding 'DB' not configured");
  return env.DB;
}

// expired session / rate-limit row တွေကို lazy cleanup (cron မလို)
// ── request တိုင်း run ရင် D1 write quota မြန်မြန်ကုန်လို့ —
//    ၂% (၅၀ ကြိမ်မှ ၁ ကြိမ်) လောက်သာ ကျပန်း run စေတယ်။
async function lazyCleanup(env) {
  if (Math.random() > 0.02) return;   // ⬅️ ၉၈% ကျော် ကျော်လွှားသွားမယ် (write ချွေတာ)
  const now = Date.now();
  try {
    await db(env).batch([
      db(env).prepare("DELETE FROM sessions WHERE expires_at>0 AND expires_at<?").bind(now),
      db(env).prepare("DELETE FROM rate_limits WHERE reset_at>0 AND reset_at<?").bind(Math.floor(now / 1000)),
    ]);
  } catch (_) {}
}

/* ══════════════════════════════════════════════════
   CRYPTO HELPERS
   ══════════════════════════════════════════════════ */
async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  const bytes = new Uint8Array(hash);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const bytes = new Uint8Array(sig);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function randomToken(len = 24) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
  return s;
}

function generateKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  let out = KEY_PREFIX + "-";
  for (let i = 0; i < 12; i++) {
    out += alphabet[arr[i] % alphabet.length];
    if (i === 3 || i === 7) out += "-";
  }
  return out;
}

function normalizeKey(k) {
  return String(k || "").trim().toUpperCase().replace(/\s+/g, "");
}

async function createSessionToken(keyId, deviceShort, secret, sid) {
  const payload = `${keyId}.${deviceShort}.${Date.now()}.${sid || randomToken(8)}`;
  const sig = await hmacSign(secret, payload);
  const token = btoa(payload).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "") + "." + sig;
  return token;
}

async function verifySessionToken(token, secret) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const payloadB64 = parts[0];
    const sig = parts[1];
    const payload = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    const expectedSig = await hmacSign(secret, payload);
    if (!safeEqual(sig, expectedSig)) return null;
    const segs = payload.split(".");
    if (segs.length < 3) return null;
    const keyId = segs[0];
    const deviceShort = segs[1];
    const ts = parseInt(segs[2] || "0", 10);
    const sid = segs[3] || "";
    if (!keyId || !deviceShort) return null;
    if (Date.now() - ts > SESSION_HOURS * 3600 * 1000) return null;
    return { keyId, deviceShort, issued_at: ts, sid };
  } catch (_) { return null; }
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...v] = p.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

function setCookieHeader(name, value, opts = {}) {
  const maxAge = opts.maxAge != null ? opts.maxAge : SESSION_HOURS * 3600;
  return [
    `${name}=${encodeURIComponent(value)}`,
    `Path=/`, `HttpOnly`, `Secure`, `SameSite=Lax`,
    `Max-Age=${maxAge}`,
  ].join("; ");
}

function getClientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "0.0.0.0"
  );
}

function ipNetworkPrefix(ip) {
  if (!ip) return "0.0.0";
  if (ip.includes(":")) return ip.toLowerCase().split(":").slice(0, 4).join(":");
  const parts = ip.split(".");
  return parts.length === 4 ? parts.slice(0, 3).join(".") : ip;
}

function safeNextPath(next) {
  let n = String(next || "/").slice(0, 300);
  if (!n.startsWith("/")) return "/";
  if (n.startsWith("//")) return "/";
  if (n.startsWith("/\\")) return "/";   // backslash open-redirect ကာကွယ်
  if (/[\r\n\t\\]/.test(n)) return "/";  // backslash + control char ကာကွယ်
  return n;
}

// ── Device fingerprint ──
async function deviceIdFrom(request, clientUuid) {
  const ua  = request.headers.get("User-Agent") || "";
  const al  = request.headers.get("Accept-Language") || "";
  const sec = request.headers.get("Sec-CH-UA") || "";
  const pl  = request.headers.get("Sec-CH-UA-Platform") || "";
  const mob = request.headers.get("Sec-CH-UA-Mobile") || "";
  const cu  = clientUuid ? ("|cu:" + clientUuid) : "";
  return (await sha256Hex("dev:" + ua + "|" + al + "|" + sec + "|" + pl + "|" + mob + cu)).slice(0, 32);
}

function shortDeviceLabel(request) {
  const ua = request.headers.get("User-Agent") || "";
  const pl = request.headers.get("Sec-CH-UA-Platform") || "";
  let os = "Unknown";
  if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ios/i.test(ua)) os = "iOS";
  else if (/windows/i.test(ua)) os = "Windows";
  else if (/mac os/i.test(ua)) os = "Mac";
  else if (/linux/i.test(ua)) os = "Linux";
  let browser = "Browser";
  if (/edg/i.test(ua)) browser = "Edge";
  else if (/chrome/i.test(ua)) browser = "Chrome";
  else if (/firefox/i.test(ua)) browser = "Firefox";
  else if (/safari/i.test(ua)) browser = "Safari";
  return `${os} · ${browser}${pl ? " (" + pl.replace(/"/g, "") + ")" : ""}`;
}

/* ══════════════════════════════════════════════════
   SIGNED STREAM URL
   ══════════════════════════════════════════════════ */
function streamSecret(env) {
  const s = env.STREAM_SECRET || env.SESSION_SECRET;
  if (!s) throw new Error("STREAM_SECRET / SESSION_SECRET not configured");
  return s;
}

function streamSignBase(itemId, s, e, d, exp, u) {
  return `${itemId}|${s}|${e}|${d}|${exp}|${u}`;
}

async function makeStreamUrl(env, itemId, { s = -1, e = -1, download = false, u = "" } = {}) {
  const exp = Date.now() + STREAM_TTL_SEC * 1000;
  const d = download ? 1 : 0;
  const sig = await hmacSign(streamSecret(env), streamSignBase(itemId, s, e, d, exp, u));
  const qs = new URLSearchParams();
  qs.set("s", String(s));
  qs.set("e", String(e));
  qs.set("d", String(d));
  qs.set("exp", String(exp));
  if (u) qs.set("u", u);
  qs.set("sig", sig);
  return `/stream/${encodeURIComponent(itemId)}?${qs.toString()}`;
}

async function verifyStreamSig(env, itemId, params) {
  const s = parseInt(params.get("s") ?? "-1", 10);
  const e = parseInt(params.get("e") ?? "-1", 10);
  const d = parseInt(params.get("d") ?? "0", 10) === 1 ? 1 : 0;
  const exp = parseInt(params.get("exp") ?? "0", 10);
  const u = params.get("u") || "";
  const sig = params.get("sig") || "";
  if (!exp || Date.now() > exp) return { ok: false, reason: "expired" };
  const expected = await hmacSign(streamSecret(env), streamSignBase(itemId, s, e, d, exp, u));
  if (!safeEqual(sig, expected)) return { ok: false, reason: "badsig" };
  return { ok: true, s, e, d, u };
}

/* ══════════════════════════════════════════════════
   TMDB HELPERS  (optional — needs env.TMDB_API_KEY)
   • v3 API key (32-char) သို့မဟုတ် v4 Bearer token နှစ်မျိုးလုံး support
   • Title နဲ့ ရှာ → poster_path / backdrop_path / overview ပြန်ပေး
   ══════════════════════════════════════════════════ */
function tmdbConfigured(env) {
  return !!(env.TMDB_API_KEY && String(env.TMDB_API_KEY).trim());
}

function tmdbImgUrl(path, size) {
  if (!path) return "";
  return `${TMDB_IMG_BASE}/${size}${path}`;
}

async function tmdbSearch(env, title, type) {
  if (!tmdbConfigured(env) || !title) return null;
  const key = String(env.TMDB_API_KEY).trim();
  const isBearer = key.length > 40 || key.startsWith("ey"); // v4 token (JWT-ish)
  const kind = type === "series" ? "tv" : "movie";
  const qs = new URLSearchParams();
  qs.set("query", title);
  qs.set("include_adult", type === "adult" ? "true" : "false");
  qs.set("language", "en-US");
  qs.set("page", "1");
  if (!isBearer) qs.set("api_key", key);
  const apiUrl = `https://api.themoviedb.org/3/search/${kind}?${qs.toString()}`;
  const headers = { "accept": "application/json" };
  if (isBearer) headers["Authorization"] = `Bearer ${key}`;
  try {
    const resp = await fetch(apiUrl, { headers });
    if (!resp.ok) return null;
    const data = await resp.json();
    const first = (data.results || [])[0];
    if (!first) return null;
    return {
      poster: tmdbImgUrl(first.poster_path, TMDB_POSTER_SIZE),
      backdrop: tmdbImgUrl(first.backdrop_path, TMDB_BACKDROP_SIZE),
      overview: String(first.overview || "").slice(0, 1500),
      tmdb_title: first.title || first.name || "",
      year: (first.release_date || first.first_air_date || "").slice(0, 4),
    };
  } catch (_) { return null; }
}
/* ══════════════════════════════════════════════════
   ACTRESS (javtiful) — name → slug → photo, with D1 cache
   ══════════════════════════════════════════════════ */
function actressNameToSlug(name) {
  return String(name || "")
    .trim().toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}

function extractActressImage(html) {
  if (!html) return "";
  let m = html.match(/<meta[^>]+property=["']og:image["'][^>]*content=["']([^"']+)["']/i);
  if (m && m[1]) return m[1];
  m = html.match(/<meta[^>]+content=["']([^"']+)["'][^>]*property=["']og:image["']/i);
  if (m && m[1]) return m[1];
  m = html.match(/<meta[^>]+name=["']twitter:image["'][^>]*content=["']([^"']+)["']/i);
  if (m && m[1]) return m[1];
  return "";
}

async function getActressCache(env, slug) {
  if (!slug) return null;
  try {
    const row = await db(env).prepare("SELECT * FROM actress_cache WHERE slug=?").bind(slug).first();
    if (!row) return null;
    return { slug: row.slug, name: row.name || "", image: row.image || "", url: row.url || "" };
  } catch (_) { return null; }
}

async function putActressCache(env, slug, data) {
  try {
    await db(env).prepare(
      `INSERT INTO actress_cache (slug, name, image, url, created_at)
       VALUES (?,?,?,?,?)
       ON CONFLICT(slug) DO UPDATE SET
         name=excluded.name, image=excluded.image, url=excluded.url, created_at=excluded.created_at`
    ).bind(slug, data.name || "", data.image || "", data.url || "", Date.now()).run();
  } catch (_) {}
}

// name → { ok, slug, name, image, url, cached } ; cache ရှိ→server မသွား
async function lookupActress(env, name) {
  const slug = actressNameToSlug(name);
  if (!slug) return { ok: false, error: "နာမည် မှားနေပါတယ်။" };

  const cached = await getActressCache(env, slug);
  if (cached && cached.image) return { ok: true, ...cached, cached: true };

  const pageUrl = `https://javtiful.com/actress/${slug}`;
  let html = "";
  try {
    const resp = await fetch(pageUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
      },
      redirect: "follow",
    });
    if (!resp.ok) return { ok: false, error: `မင်းသမီး ရှာမတွေ့ပါ (HTTP ${resp.status})` };
    html = await resp.text();
  } catch (_) {
    return { ok: false, error: "Server ကို ဆက်သွယ်လို့ မရပါ။" };
  }

  const image = extractActressImage(html);
  if (!image) return { ok: false, error: "ဒီနာမည်အတွက် ပုံ ရှာမတွေ့ပါ။" };

  const result = { slug, name: String(name).trim().slice(0, 80), image, url: pageUrl };
  await putActressCache(env, slug, result);
  return { ok: true, ...result, cached: false };
}

// မင်းသမီးနာမည်တိုင်းကို slug အဖြစ်ပြောင်းပြီး unique list ထုတ် (item တစ်ခုမှာ နာမည်များ comma ခွဲ)
function parseActressNames(raw) {
  return String(raw || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
    .slice(0, 10);
}


/* ══════════════════════════════════════════════════
   KEY STORAGE  (D1: table `keys`)
   row: { key_id, role, created_at, expires_at, duration_label, note, disabled(0/1), devices(JSON) }
   ══════════════════════════════════════════════════ */
function rowToKey(row) {
  if (!row) return null;
  let devices = [];
  try { devices = JSON.parse(row.devices || "[]"); } catch (_) { devices = []; }
  return {
    key: row.key_id,
    role: row.role || "trial",
    created_at: row.created_at || 0,
    expires_at: row.expires_at || 0,
    duration_label: row.duration_label || "",
    note: row.note || "",
    disabled: !!row.disabled,
    devices,
  };
}

async function getKey(env, keyId) {
  if (!keyId) return null;
  const row = await db(env).prepare("SELECT * FROM keys WHERE key_id=?").bind(keyId).first();
  return rowToKey(row);
}

async function putKey(env, keyId, data) {
  await db(env).prepare(
    `INSERT INTO keys (key_id, role, created_at, expires_at, duration_label, note, disabled, devices)
     VALUES (?,?,?,?,?,?,?,?)
     ON CONFLICT(key_id) DO UPDATE SET
       role=excluded.role, created_at=excluded.created_at, expires_at=excluded.expires_at,
       duration_label=excluded.duration_label, note=excluded.note,
       disabled=excluded.disabled, devices=excluded.devices`
  ).bind(
    keyId,
    data.role || "trial",
    data.created_at || 0,
    data.expires_at || 0,
    (data.duration_label || "").slice(0, 40),
    (data.note || "").slice(0, 60),
    data.disabled ? 1 : 0,
    JSON.stringify(data.devices || [])
  ).run();
}

async function deleteKey(env, keyId) {
  const k = await getKey(env, keyId);
  const stmts = [];
  if (k && Array.isArray(k.devices)) {
    for (const d of k.devices) if (d.id) stmts.push(db(env).prepare("DELETE FROM kdev WHERE device_id=?").bind(d.id));
  }
  stmts.push(db(env).prepare("DELETE FROM sessions WHERE key_id=?").bind(keyId));
  stmts.push(db(env).prepare("DELETE FROM keys WHERE key_id=?").bind(keyId));
  if (stmts.length) await db(env).batch(stmts);
}

function isKeyExpired(k) {
  if (!k) return true;
  if (k.disabled) return true;
  if (!k.expires_at) return true;
  return Date.now() > k.expires_at;
}

/* ══════════════════════════════════════════════════
   CONTENT STORAGE  (D1: table `items`)
   ══════════════════════════════════════════════════ */
function generateItemId() {
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
  return "i" + s.slice(0, 12);
}

function rowToItem(row) {
  if (!row) return null;
  const item = {
    id: row.id,
    type: row.type || "movie",
    title: row.title || "",
    poster: row.poster || "",
    slide_image: row.slide_image || "",
    note: row.note || "",
    actress: row.actress || "",
    created_at: row.created_at || 0,
    video_url: row.video_url || "",
    download_url: row.download_url || "",
    published: (row.published == null ? 1 : (row.published ? 1 : 0)),
  };
  if (item.type === "series") {
    try { item.seasons = JSON.parse(row.seasons || "[]"); } catch (_) { item.seasons = []; }
  }
  return item;
}


async function getItem(env, id) {
  if (!id) return null;
  const row = await db(env).prepare("SELECT * FROM items WHERE id=?").bind(id).first();
  return rowToItem(row);
}

async function putItem(env, id, data) {
  await db(env).prepare(
    `INSERT INTO items (id, type, title, poster, slide_image, note, actress, created_at, video_url, download_url, seasons, published)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(id) DO UPDATE SET
       type=excluded.type, title=excluded.title, poster=excluded.poster,
       slide_image=excluded.slide_image, note=excluded.note, actress=excluded.actress,
       created_at=excluded.created_at,
       video_url=excluded.video_url, download_url=excluded.download_url, seasons=excluded.seasons,
       published=excluded.published`
  ).bind(
    id,
    data.type || "movie",
    (data.title || "").slice(0, 160),
    (data.poster || "").slice(0, 600),
    (data.slide_image || "").slice(0, 600),
    (data.note || "").slice(0, 5000),
    (data.actress || "").slice(0, 300),
    data.created_at || 0,
    data.video_url || "",
    data.download_url || "",
    data.type === "series" ? JSON.stringify(data.seasons || []) : "",
    (data.published == null ? 1 : (data.published ? 1 : 0))
  ).run();
}

async function deleteItem(env, id) {
  await db(env).prepare("DELETE FROM items WHERE id=?").bind(id).run();
}

// All item summaries (metadata only)
// includeUnpublished=false (default) → public pages (home/category/search) — published ဖြစ်တာသာ ပြ
// includeUnpublished=true → admin pages — draft အပါအဝင် အားလုံး ပြ
async function listItems(env, includeUnpublished = false) {
  const sql = includeUnpublished
    ? "SELECT id, title, poster, slide_image, type, actress, created_at, published FROM items ORDER BY created_at DESC"
    : "SELECT id, title, poster, slide_image, type, actress, created_at, published FROM items WHERE published=1 ORDER BY created_at DESC";
  const res = await db(env).prepare(sql).all();
  return (res.results || []).map(r => ({
    id: r.id,
    title: r.title || "",
    poster: r.poster || "",
    slide_image: r.slide_image || "",
    type: r.type || "movie",
    actress: r.actress || "",
    created_at: r.created_at || 0,
    published: (r.published == null ? 1 : (r.published ? 1 : 0)),
  }));
}
  
// ── type တစ်ခုအတွက် DB level မှာ filter + LIMIT/OFFSET (page တိုင်း item အကုန်မဆွဲ) ──
// count + slice ကို batch တစ်ခါတည်း ဆွဲ → D1 round-trip သက်သာ
async function listItemsByTypePaged(env, type, page, perPage) {
  const offset = (page - 1) * perPage;
  const [cntRes, listRes] = await db(env).batch([
    db(env).prepare("SELECT COUNT(*) AS c FROM items WHERE published=1 AND type=?").bind(type),
    db(env).prepare(
      "SELECT id, title, poster, slide_image, type, actress, created_at FROM items WHERE published=1 AND type=? ORDER BY created_at DESC LIMIT ? OFFSET ?"
    ).bind(type, perPage, Math.max(0, offset)),
  ]);
  const total = (cntRes.results && cntRes.results[0] && cntRes.results[0].c) ? cntRes.results[0].c : 0;
  const items = (listRes.results || []).map(r => ({
    id: r.id, title: r.title || "", poster: r.poster || "",
    slide_image: r.slide_image || "", type: r.type || "movie",
    actress: r.actress || "", created_at: r.created_at || 0,
  }));
  return { items, total };
}

// ── Home အတွက်: type တစ်ခုစီ N ခုစီ ကို batch တစ်ခါတည်း ဆွဲ (item အကုန်မဆွဲ) ──
async function listHomePreview(env, previewCount, randomCount) {
  const q = (type, lim) => db(env).prepare(
    "SELECT id, title, poster, slide_image, type, created_at FROM items WHERE published=1 AND type=? ORDER BY created_at DESC LIMIT ?"
  ).bind(type, lim);
  const [mv, sr, ad, rd, sl] = await db(env).batch([
    q("movie", previewCount),
    q("series", previewCount),
    q("adult", previewCount),
    q("random", randomCount),
    // slider အတွက် — slide_image (သို့) poster ရှိတဲ့ နောက်ဆုံး ၆ ခု
    db(env).prepare(
      "SELECT id, title, poster, slide_image, type FROM items WHERE published=1 AND (slide_image!='' OR poster!='') ORDER BY created_at DESC LIMIT 6"
    ),
  ]);
  const map = (res) => (res.results || []).map(r => ({
    id: r.id, title: r.title || "", poster: r.poster || "",
    slide_image: r.slide_image || "", type: r.type || "movie", created_at: r.created_at || 0,
  }));
  return { movie: map(mv), series: map(sr), adult: map(ad), random: map(rd), slides: map(sl) };
}

// Draft (မတင်ရသေး) items အရေအတွက် တွက်
async function countDraftItems(env) {
  try {
    const row = await db(env).prepare("SELECT COUNT(*) AS c FROM items WHERE published=0").first();
    return (row && row.c) ? row.c : 0;
  } catch (_) { return 0; }
}

// Draft items အားလုံးကို တစ်ခါတည်း publish (published=1) လုပ်
async function publishAllDrafts(env) {
  const res = await db(env).prepare("UPDATE items SET published=1 WHERE published=0").run();
  return (res.meta && res.meta.changes) ? res.meta.changes : 0;
}
// actress slug တစ်ခုနဲ့ ဆိုင်တဲ့ items အားလုံး
async function listItemsByActressSlug(env, slug) {
  if (!slug) return [];
  const all = await listItems(env);
  return all.filter(i => {
    const names = parseActressNames(i.actress);
    return names.some(n => actressNameToSlug(n) === slug);
  });
}



/* ══════════════════════════════════════════════════
   BOOKMARKS  (D1: table `bookmarks`)
   ══════════════════════════════════════════════════ */
async function isBookmarked(env, keyId, itemId) {
  if (!keyId || !itemId) return false;
  const row = await db(env).prepare(
    "SELECT item_id FROM bookmarks WHERE key_id=? AND item_id=?"
  ).bind(keyId, itemId).first();
  return row !== null;
}

async function addBookmark(env, keyId, itemId) {
  if (!keyId || !itemId) return;
  await db(env).prepare(
    `INSERT INTO bookmarks (key_id, item_id, created_at) VALUES (?,?,?)
     ON CONFLICT(key_id, item_id) DO NOTHING`
  ).bind(keyId, itemId, Date.now()).run();
}

async function removeBookmark(env, keyId, itemId) {
  if (!keyId || !itemId) return;
  await db(env).prepare(
    "DELETE FROM bookmarks WHERE key_id=? AND item_id=?"
  ).bind(keyId, itemId).run();
}

// user ၏ bookmark အားလုံးကို တစ်ခါတည်း ဖျက်
async function clearAllBookmarks(env, keyId) {
  if (!keyId) return;
  await db(env).prepare(
    "DELETE FROM bookmarks WHERE key_id=?"
  ).bind(keyId).run();
}

// user ၏ bookmark လုပ်ထားသော items အားလုံး (item metadata အပြည့်)
async function listBookmarks(env, keyId) {
  if (!keyId) return [];
  const res = await db(env).prepare(
    `SELECT i.id, i.title, i.poster, i.slide_image, i.type, i.created_at, b.created_at AS bm_at
     FROM bookmarks b JOIN items i ON i.id = b.item_id
     WHERE b.key_id=? ORDER BY b.created_at DESC`
  ).bind(keyId).all();
  return (res.results || []).map(r => ({
    id: r.id,
    title: r.title || "",
    poster: r.poster || "",
    slide_image: r.slide_image || "",
    type: r.type || "movie",
    created_at: r.created_at || 0,
  }));
}


/* ══════════════════════════════════════════════════
   SESSIONS  (D1: table `sessions`)
   ══════════════════════════════════════════════════ */
async function recordSession(env, keyId, sid, meta) {
  const now = Date.now();
  await db(env).prepare(
    `INSERT INTO sessions (key_id, sid, created_at, meta, expires_at)
     VALUES (?,?,?,?,?)
     ON CONFLICT(key_id, sid) DO UPDATE SET meta=excluded.meta, expires_at=excluded.expires_at`
  ).bind(
    keyId, sid, now,
    JSON.stringify({ ...meta, created_at: now }),
    now + SESSION_HOURS * 3600 * 1000
  ).run();
}
async function isSessionRevoked(env, keyId, sid) {
  if (!sid) return false;
  const row = await db(env).prepare(
    "SELECT sid FROM sessions WHERE key_id=? AND sid=? AND (expires_at=0 OR expires_at>?)"
  ).bind(keyId, sid, Date.now()).first();
  return row === null;
}
async function revokeSession(env, keyId, sid) {
  await db(env).prepare("DELETE FROM sessions WHERE key_id=? AND sid=?").bind(keyId, sid).run();
}

/* ══════════════════════════════════════════════════
   CURRENT USER (key-based)
   ══════════════════════════════════════════════════ */
async function getCurrentUser(request, env) {
  if (_reqCache.has(request)) return _reqCache.get(request);
  const result = await _getCurrentUserInner(request, env);
  _reqCache.set(request, result);
  return result;
}

async function _getCurrentUserInner(request, env) {
  if (!env.SESSION_SECRET) return null;
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;
  const session = await verifySessionToken(token, env.SESSION_SECRET);
  if (!session) return null;

  if (session.keyId === "__ADMIN__") {
    return { keyId: "__ADMIN__", role: "admin", expires_at: 0, isAdmin: true, sid: session.sid };
  }

  const curDevice = (await deviceIdFrom(request, getCookie(request, "cmflix_duid"))).slice(0, 12);
  if (!safeEqual(session.deviceShort, curDevice)) return null;
  if (await isSessionRevoked(env, session.keyId, session.sid)) return null;

  const k = await getKey(env, session.keyId);
  if (!k) return null;
  return { ...k, keyId: session.keyId, isAdmin: false, sid: session.sid };
}

function isExpired(user) {
  if (!user) return true;
  if (user.isAdmin) return false;
  if (user.disabled) return true;
  if (!user.expires_at) return true;
  return Date.now() > user.expires_at;
}

async function userStreamTag(user) {
  if (!user) return "";
  return (await sha256Hex("u:" + user.keyId + ":" + (user.sid || ""))).slice(0, 12);
}

function htmlEscape(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/* ══════════════════════════════════════════════════
   MY KEY LABEL — Premium ရက်ကျန် တွက်ပြီး P-NDay format
   ══════════════════════════════════════════════════ */
function premiumLabel(user) {
  // login မဝင် → "My Key"
  if (!user) return { text: "My Key", premium: false };
  if (user.isAdmin) return { text: "Admin", premium: true };
  const remainMs = (user.expires_at || 0) - Date.now();
  if (remainMs <= 0) return { text: "Expired", premium: false };
  // 1 ရက်အောက်ဆို အနည်းဆုံး 1 ရက်ပြ (ဥပမာ နာရီပိုင်းကျန်ရင်လည်း P-1Day)
  const days = Math.max(1, Math.ceil(remainMs / 86400000));
  return { text: `P-${days}Day`, premium: true };
}

/* Rate limit (D1: table `rate_limits`) */
async function rateLimitHit(env, key, max, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  const row = await db(env).prepare("SELECT count, reset_at FROM rate_limits WHERE rl_key=?").bind(key).first();
  let count = 0, reset = now + windowSec;
  if (row && row.reset_at > now) { count = row.count; reset = row.reset_at; }
  count += 1;
  await db(env).prepare(
    `INSERT INTO rate_limits (rl_key, count, reset_at) VALUES (?,?,?)
     ON CONFLICT(rl_key) DO UPDATE SET count=excluded.count, reset_at=excluded.reset_at`
  ).bind(key, count, reset).run();
  return { blocked: count > max, count, reset };
}
/* ══════════════════════════════════════════════════
   PREMIUM SVG ICONS HELPER
   ══════════════════════════════════════════════════ */
function getSvgIcon(type, size = 16) {
  const style = `width:${size}px;height:${size}px;display:inline-block;vertical-align:middle;stroke-width:2.2;fill:none;stroke:currentColor;`;
  
  if (type === "home") {
    return `<svg style="${style}" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`;
  }
  if (type === "movie") {
    return `<svg style="${style}" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v18M17 3v18M3 7.5h4M3 12h18M3 16.5h4M17 7.5h4M17 16.5h4"/></svg>`;
  }
  if (type === "series") {
    return `<svg style="${style}" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="15" x="2" y="7" rx="2" ry="2"/><path d="m17 2-5 5-5-5"/></svg>`;
  }
  if (type === "adult") {
    return `<svg style="${style}" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16h.01"/><path d="M12 8v5"/></svg>`;
  }
  if (type === "random") {
    return `<svg style="${style}" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`;
  }
  return "";
}
/* ══════════════════════════════════════════════════
   CSRF
   ══════════════════════════════════════════════════ */
async function getOrCreateCsrf(request, env) {
  let token = getCookie(request, CSRF_COOKIE);
  if (token && /^[a-f0-9]{32,}$/.test(token)) return { token, isNew: false };
  token = randomToken(16);
  return { token, isNew: true };
}
function csrfCookieHeader(token) {
  return [
    `${CSRF_COOKIE}=${encodeURIComponent(token)}`,
    `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`,
    `Max-Age=${SESSION_HOURS * 3600}`,
  ].join("; ");
}
async function verifyCsrf(request, form) {
  const cookie = getCookie(request, CSRF_COOKIE);
  const submitted = form && form.csrf_token;
  if (!cookie || !submitted) return false;
  return safeEqual(String(cookie), String(submitted));
}

/* ══════════════════════════════════════════════════
   DEVICE BINDING (2-phone limit)  — D1: table `kdev`
   ══════════════════════════════════════════════════ */
async function bindDeviceToKey(env, keyObj, keyId, deviceId, request, clientIp) {
  keyObj.devices = Array.isArray(keyObj.devices) ? keyObj.devices : [];
  const existing = keyObj.devices.find(d => d.id === deviceId);
  if (existing) {
    existing.last_seen = Date.now();
    existing.ip = ipNetworkPrefix(clientIp);
    await putKey(env, keyId, keyObj);
    return { ok: true };
  }
  if (keyObj.devices.length >= MAX_DEVICES_PER_KEY) {
    return { ok: false, reason: `ဒီ Key ကို ဖုန်း ${MAX_DEVICES_PER_KEY} လုံး သုံးပြီးသားဖြစ်ပါတယ်။ Admin ထံ ဆက်သွယ်ပါ။` };
  }
  keyObj.devices.push({
    id: deviceId,
    label: shortDeviceLabel(request),
    first_seen: Date.now(),
    last_seen: Date.now(),
    ip: ipNetworkPrefix(clientIp),
  });
  await putKey(env, keyId, keyObj);
  await db(env).prepare(
    `INSERT INTO kdev (device_id, key_id) VALUES (?,?)
     ON CONFLICT(device_id) DO UPDATE SET key_id=excluded.key_id`
  ).bind(deviceId, keyId).run();
  return { ok: true };
}

/* ══════════════════════════════════════════════════
   FORM PARSER
   ══════════════════════════════════════════════════ */
async function parseForm(request) {
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("application/x-www-form-urlencoded")) {
    const txt = await request.text();
    return Object.fromEntries(new URLSearchParams(txt));
  }
  if (ct.includes("multipart/form-data")) {
    const fd = await request.formData();
    const o = {};
    for (const [k, v] of fd.entries()) o[k] = v;
    return o;
  }
  if (ct.includes("application/json")) {
    try { return await request.json(); } catch (_) { return {}; }
  }
  return {};
}

function isHttpUrl(u) {
  return /^https?:\/\//i.test(String(u || "").trim());
}
/* ══════════════════════════════════════════════════
   DOMAIN REWRITE  — link domain အဟောင်း→အသစ် အလိုအလျောက်ပြောင်း
   • database ထဲက မူရင်း link မထိ — သုံးတဲ့အချိန်မှ ပြောင်းပေးတယ်
   • နောက်နောင် domain ပြောင်းရင် ဒီ map ထဲ စာတစ်ကြောင်းပဲ ထပ်ထည့်ရုံ
   ══════════════════════════════════════════════════ */
const DOMAIN_REWRITES = [
  { from: "stream.cmapp.tv", to: "stream.cmreel.com" },
  // နောက်ထပ် domain ပြောင်းရင် ဒီအောက်မှာ ထပ်ထည့်ပါ၊ ဥပမာ —
  // { from: "stream.cmreel.com", to: "stream.cmnew.com" },
];

function rewriteDomain(rawUrl) {
  let u = String(rawUrl || "");
  if (!u) return u;
  for (const r of DOMAIN_REWRITES) {
    if (!r.from || !r.to) continue;
    // http/https နှစ်မျိုးလုံး၊ host တိတိကျကျ ကိုက်မှ ပြောင်း (substring မှား မပြောင်းအောင်)
    u = u.replace(
      new RegExp("^(https?:\\/\\/)" + r.from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=[\\/:?#]|$)", "i"),
      "$1" + r.to
    );
  }
  return u;
}


/* ── PART 1 ends here. PART 2 uses everything above ── */
// functions/[[path]].js  — PART 2 of 2  (append directly below PART 1)
// ════════════════════════════════════════════════════════════════
//  CM FLIX — UI, routes, signed-stream player (Plyr), admin panel
// ════════════════════════════════════════════════════════════════

/* ══════════════════════════════════════════════════
   GLOBAL STYLES  (refined UI)
   ══════════════════════════════════════════════════ */
const CMFLIX_CSS = `
  *{box-sizing:border-box}
  :root{
    --bg0:#05070f; --bg1:#0b0f1c; --bg2:#11172a;
    --card:#10162a; --line:#1f2942;
    --txt:#eef2ff; --mut:#8794b3;
    --acc:#e50914; --acc2:#ff2e54; --gold:#f5c518;
    --ok:#22c55e;
    --r:14px;
  }
  html,body{margin:0;padding:0}
  body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Padauk","Myanmar Text",sans-serif;
    background:radial-gradient(1200px 600px at 85% -10%,rgba(229,9,20,.16),transparent),
               radial-gradient(900px 520px at -8% 4%,rgba(50,90,220,.12),transparent),
               linear-gradient(180deg,var(--bg0),var(--bg1) 55%,var(--bg2));
    color:var(--txt);min-height:100vh;-webkit-tap-highlight-color:transparent}
  a{color:inherit}
  .wrap{max-width:1200px;margin:0 auto;padding:0 16px}

  .topbar{position:sticky;top:0;z-index:200;display:flex;align-items:center;gap:14px;
    padding:12px 18px;background:rgba(5,7,15,.78);backdrop-filter:saturate(160%) blur(16px);border-bottom:1px solid var(--line)}

  /* ── Refined brand / logo (SVG monogram) ── */
  .brand{display:flex;align-items:center;gap:11px;text-decoration:none;white-space:nowrap}
  .brand .mark{width:38px;height:38px;flex:0 0 38px;border-radius:11px;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(140deg,#ff3a3f,#e50914 55%,#a3060d);
    box-shadow:0 6px 18px rgba(229,9,20,.45),inset 0 1px 0 rgba(255,255,255,.25);position:relative;overflow:hidden}
  .brand .mark svg{width:22px;height:22px;display:block;filter:drop-shadow(0 1px 2px rgba(0,0,0,.4))}
  .brand .mark::after{content:"";position:absolute;inset:0;background:linear-gradient(120deg,transparent 40%,rgba(255,255,255,.22) 50%,transparent 60%)}
  .brand .wordmark{display:flex;flex-direction:column;line-height:1}
  .brand .wordmark .t1{font-weight:900;font-size:19px;letter-spacing:1.5px;background:linear-gradient(90deg,#fff,#ffc9cc);-webkit-background-clip:text;background-clip:text;color:transparent}
  .brand .wordmark .t2{font-size:9px;letter-spacing:3px;color:var(--mut);font-weight:700;margin-top:3px}

  .topbar .search{flex:1;max-width:540px;margin:0 auto;position:relative}
  .topbar .search input{width:100%;padding:11px 14px 11px 40px;border-radius:26px;border:1px solid var(--line);
    background:#080d1a;color:#fff;font-size:14px;outline:none;font-family:inherit;transition:.2s}
  .topbar .search input:focus{border-color:var(--acc2);box-shadow:0 0 0 3px rgba(255,46,84,.16)}
  .topbar .search .si{position:absolute;left:14px;top:50%;transform:translateY(-50%);opacity:.55}
  .topbar .acts{display:flex;align-items:center;gap:8px;white-space:nowrap}
  .topbar .acts a{font-size:13px;text-decoration:none;color:var(--mut);font-weight:600;padding:7px 12px;border-radius:9px;transition:.15s}
  .topbar .acts a.me{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;box-shadow:0 4px 12px rgba(229,9,20,.35)}
  .topbar .acts a.me.premium{background:linear-gradient(135deg,#0f9d58,#22c55e);box-shadow:0 4px 12px rgba(34,197,94,.4)}
  .topbar .acts a:hover{color:#fff}
  @media(max-width:640px){.brand .wordmark .t1{font-size:17px}.topbar .acts a:not(.me){display:none}}

  .navchips{display:flex;gap:9px;overflow-x:auto;padding:14px 16px 4px;scrollbar-width:none}
  .navchips::-webkit-scrollbar{display:none}
  .navchips a{flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;padding:9px 17px;border-radius:24px;
    text-decoration:none;font-weight:700;font-size:13.5px;color:#fff;background:#131b2e;border:1px solid var(--line);transition:.15s}
  .navchips a.on{background:linear-gradient(135deg,var(--acc),var(--acc2));border-color:transparent;box-shadow:0 4px 14px rgba(229,9,20,.4)}
  .navchips a:hover{filter:brightness(1.14)}

  /* ဖုန်းမျက်နှာပြင်အသေးများတွင် အားလုံးတစ်တန်းတည်း ကွက်တိပေါ်စေရန် ညှိနှိုင်းခြင်း */
  @media(max-width:640px){
    .navchips{padding:12px 10px 4px;gap:5px;justify-content:space-between}
    .navchips a{padding:7px 11px;font-size:12px;gap:4px}
    .navchips a svg{width:13px !important;height:13px !important}
  }

  /* Hero slider */
  .hero{position:relative;margin:16px 0 6px;border-radius:0;overflow:hidden;box-shadow:0 22px 60px rgba(0,0,0,.6)}
  .hero-track{display:flex;transition:transform .6s cubic-bezier(.45,.05,.2,1)}
  .slide{position:relative;min-width:100%;height:360px;display:flex;align-items:flex-end;overflow:hidden;background:#080c18}
  .slide-bg{position:absolute;inset:0;background-size:cover;background-position:center;background-repeat:no-repeat;transform:scale(1.04)}
  .slide::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,rgba(5,7,15,.95) 0%,rgba(5,7,15,.6) 42%,rgba(5,7,15,.1) 100%)}
  .slide-body{position:relative;z-index:2;padding:30px 34px;max-width:640px}
  .slide-tag{display:inline-block;background:var(--acc);color:#fff;font-size:11px;font-weight:800;padding:5px 12px;border-radius:7px;letter-spacing:.6px;margin-bottom:12px}
  .slide-title{font-size:32px;font-weight:900;margin:0 0 10px;line-height:1.12;text-shadow:0 2px 16px rgba(0,0,0,.65)}
  .slide-desc{color:#cfd6e8;font-size:14px;line-height:1.6;margin:0 0 18px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
  .slide-btn{display:inline-flex;align-items:center;gap:9px;background:#fff;color:#111;font-weight:800;padding:12px 24px;border-radius:10px;text-decoration:none;font-size:14px;transition:.15s}
  .slide-btn:hover{background:var(--acc);color:#fff;transform:translateY(-2px)}
  .hero-dots{position:absolute;bottom:16px;right:22px;z-index:3;display:flex;gap:7px}
  .hero-dots b{width:9px;height:9px;border-radius:50%;background:rgba(255,255,255,.4);cursor:pointer;transition:.25s}
  .hero-dots b.on{background:var(--acc);width:26px;border-radius:5px}
  .hero-nav{position:absolute;top:50%;transform:translateY(-50%);z-index:3;width:42px;height:42px;border-radius:50%;
    border:0;background:rgba(0,0,0,.42);color:#fff;font-size:20px;cursor:pointer;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(6px);transition:.15s}
  .hero-nav:hover{background:var(--acc)}
  .hero-nav.prev{left:16px}.hero-nav.next{right:16px}
  @media(max-width:640px){.slide{height:210px}.slide-title{font-size:21px}.slide-desc{display:none}.slide-body{padding:18px}.hero-nav{display:none}}

  .section{margin:28px 0}
  .section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:15px}
  .section-head h2{display:flex;align-items:center;gap:10px;font-size:20px;margin:0;font-weight:800}
  .section-head a.seeall{font-size:13px;font-weight:700;color:var(--acc2);text-decoration:none;display:inline-flex;align-items:center;gap:4px;transition:.15s}
  .section-head a.seeall:hover{color:#fff}

  .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:13px}
  @media(min-width:560px){.grid{grid-template-columns:repeat(4,1fr);gap:15px}}
  @media(min-width:820px){.grid{grid-template-columns:repeat(5,1fr)}}
  @media(min-width:1024px){.grid{grid-template-columns:repeat(6,1fr)}}

  .card-item{display:block;text-decoration:none;border-radius:13px;overflow:hidden;background:var(--card);
    border:1px solid var(--line);transition:transform .18s,border-color .18s,box-shadow .18s;position:relative}
  .card-item:hover{transform:translateY(-5px);border-color:var(--acc2);box-shadow:0 14px 32px rgba(0,0,0,.55)}
  /* ── Poster ratio: Netflix/IMDb style 2:3 ── fixed, no stretch ── */
  .poster{width:100%;aspect-ratio:2/3;background-size:cover;background-position:center center;background-repeat:no-repeat;background-color:#0a1120;
    display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}
  .poster .noimg{font-size:34px;opacity:.3}
  .poster .play-ov{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;opacity:0;transition:.2s;background:linear-gradient(0deg,rgba(0,0,0,.55),rgba(0,0,0,.15))}
  .card-item:hover .play-ov{opacity:1}
  .poster .play-ov span{width:48px;height:48px;border-radius:50%;background:var(--acc);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 6px 18px rgba(229,9,20,.6)}
  .c-title{padding:9px 10px 11px;font-size:12.5px;font-weight:600;line-height:1.35;
    display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:#e7ecf8}

  .pager{display:flex;gap:6px;align-items:center;justify-content:center;flex-wrap:wrap;margin:30px 0 8px}
  .pager a,.pager span{min-width:40px;text-align:center;padding:9px 13px;border-radius:9px;text-decoration:none;font-size:13.5px;font-weight:700;border:1px solid var(--line);color:#cfe;background:#0d1424;transition:.15s}
  .pager a:hover{filter:brightness(1.3);transform:translateY(-1px)}
  .pager .cur{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;border-color:transparent}
  .pager .dis{opacity:.35;pointer-events:none}
  .pager .gap{border:0;background:transparent;color:var(--mut)}

  .empty{grid-column:1/-1;text-align:center;color:var(--mut);padding:54px 16px;font-size:14px}
  .footer{text-align:center;color:var(--mut);font-size:12px;padding:36px 16px 28px;border-top:1px solid var(--line);margin-top:32px}
  .footer b{color:var(--acc)}
  .contact-row{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
  .contact-lbl{font-size:13px;color:var(--mut);font-weight:600}
  .contact-btn{display:inline-flex;align-items:center;gap:7px;text-decoration:none;font-weight:700;font-size:13px;padding:9px 16px;border-radius:10px;color:#fff;transition:.15s}
  .contact-btn:hover{transform:translateY(-2px);filter:brightness(1.1)}
  .contact-btn.tg{background:linear-gradient(135deg,#229ED9,#37b6ee);box-shadow:0 4px 12px rgba(34,158,217,.35)}
  .contact-btn.vb{background:linear-gradient(135deg,#7360f2,#8f7bff);box-shadow:0 4px 12px rgba(115,96,242,.35)}
  @media(max-width:560px){.contact-lbl{width:100%;margin-bottom:4px}}

  /* ── Random Best: 2-up cover layout (Viki style) ── */
  .cover-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
  @media(min-width:820px){.cover-grid{grid-template-columns:repeat(3,1fr);gap:18px}}
  .cover-item{display:block;text-decoration:none;border-radius:14px;overflow:hidden;background:var(--card);
    border:1px solid var(--line);transition:transform .18s,border-color .18s,box-shadow .18s;position:relative}
  .cover-item:hover{transform:translateY(-5px);border-color:var(--acc2);box-shadow:0 14px 32px rgba(0,0,0,.55)}
  .cover-img{width:100%;aspect-ratio:16/9;background-size:cover;background-position:center center;background-repeat:no-repeat;
    background-color:#0a1120;display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}
  .cover-img .noimg{font-size:40px;opacity:.3}
  .cover-img .play-ov{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;opacity:0;transition:.2s;background:linear-gradient(0deg,rgba(0,0,0,.55),rgba(0,0,0,.15))}
  .cover-item:hover .cover-img .play-ov{opacity:1}
  .cover-img .play-ov span{width:54px;height:54px;border-radius:50%;background:var(--acc);display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 6px 18px rgba(229,9,20,.6)}
  .cover-tag{position:absolute;top:10px;left:10px;z-index:2;display:inline-flex;align-items:center;gap:5px;
    background:rgba(0,0,0,.62);backdrop-filter:blur(6px);color:#fff;font-size:11px;font-weight:800;padding:5px 10px;border-radius:7px;letter-spacing:.4px}
  .cover-title{padding:11px 13px 13px;font-size:14px;font-weight:700;line-height:1.4;
    display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:#e7ecf8}
  @media(max-width:560px){.cover-title{font-size:12.5px;padding:9px 10px 11px}.cover-tag{font-size:10px;padding:4px 8px}}
`;

// Custom image logo
const LOGO_URL = "https://cloudfare-img.darkvpn.giize.com/files/1782459415088_34ee1132-a7ff-4d0c-8f2c-b77082804fa9.png";  // ⬅️ ဒီနေရာမှာ သင့်ကြိုက်တဲ့ logo image link ထည့်ပါ

function logoMark() {
  if (LOGO_URL && /^https?:\/\//i.test(LOGO_URL)) {
    return `<span class="mark"><img src="${LOGO_URL}" alt="CM FLIX" style="width:100%;height:100%;object-fit:cover;border-radius:inherit"></span>`;
  }
  // fallback — image link မထည့်ရင် မူရင်း SVG ကိုပဲ သုံးမယ်
  return `<span class="mark"><svg viewBox="0 0 24 24" fill="none"><path d="M8 5.5v13a1 1 0 0 0 1.54.84l9.5-6.5a1 1 0 0 0 0-1.68l-9.5-6.5A1 1 0 0 0 8 5.5Z" fill="#fff"/></svg></span>`;
}
function brandLogo() {
  return `<a class="brand" href="/">${logoMark()}<span class="wordmark"><span class="t1">CM FLIX</span><span class="t2">STREAM&nbsp;HUB</span></span></a>`;
}
/* ══════════════════════════════════════════════════
   SECURE HTML RESPONSE HELPER
   ══════════════════════════════════════════════════ */
function htmlResponse(body, extraHeaders = {}, status = 200) {
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    ...extraHeaders,
  };
  return new Response(body, { status, headers });
}

// ── Public page (login မလိုတာ) — edge cache (caches.default) helper ──
// login ဝင်/မဝင်အလိုက် HTML ကွဲတာမို့၊ guest (login မဝင်) request တွေကိုသာ cache လုပ်မယ်။
// user login ဝင်ထားရင် (cookie ပါရင်) cache မလုပ်ဘဲ fresh ပြန်ပေးတယ် → key chip/My List မှန်အောင်။
function isGuestRequest(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.indexOf(COOKIE_NAME + "=") === -1;  // session cookie မပါ → guest
}

async function cachedHtml(context, request, ttlSec, builder) {
  // login ဝင်ထားရင် cache မသုံး (personalize ဖြစ်နေလို့)
  if (!isGuestRequest(request)) {
    return new Response(await builder(), { headers: { "content-type": "text/html; charset=utf-8" } });
  }
  const cache = caches.default;
  const cacheKey = new Request(new URL(request.url).toString(), { method: "GET" });
  const hit = await cache.match(cacheKey);
  if (hit) {
    const h = new Headers(hit.headers);
    h.set("X-CMFlix-Page-Cache", "HIT");
    return new Response(hit.body, { status: hit.status, headers: h });
  }
  const html = await builder();
  const resp = new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "Cache-Control": `public, max-age=0, s-maxage=${ttlSec}`,
      "X-CMFlix-Page-Cache": "MISS",
    },
  });
  context.waitUntil(cache.put(cacheKey, resp.clone()));
  return resp;
}


// Plyr CDN (modern player)
const PLYR_CSS_CDN = "https://cdn.plyr.io/3.7.8/plyr.css";
const PLYR_JS_CDN  = "https://cdn.plyr.io/3.7.8/plyr.polyfilled.js";

function pageShell(title, body, opts = {}) {
  return `<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#05070f">
<title>${htmlEscape(title)}</title>
${opts.plyr ? `<link rel="stylesheet" href="${PLYR_CSS_CDN}">` : ""}
<style>${CMFLIX_CSS}${opts.extraCss || ""}</style>
</head>
<body>
${body}
${opts.plyr ? `<script src="${PLYR_JS_CDN}"></script>` : ""}
${opts.script ? `<script>${opts.script}</script>` : ""}
</body></html>`;
}

const AUTH_CSS = `
  .auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .auth-card{background:rgba(13,20,36,.94);backdrop-filter:blur(12px);border:1px solid var(--line);border-radius:20px;padding:34px;width:100%;max-width:440px;box-shadow:0 22px 60px rgba(0,0,0,.65)}
  .auth-card .auth-logo{display:flex;justify-content:center;margin-bottom:18px}
  .auth-card .auth-logo .mark{width:54px;height:54px;flex:0 0 54px;border-radius:15px}
  .auth-card .auth-logo .mark svg{width:30px;height:30px}
  .auth-card h1{margin:0 0 6px;font-size:22px;text-align:center}
  .auth-card p.sub{margin:0 0 18px;color:var(--mut);font-size:13.5px;line-height:1.6;text-align:center}
  label{display:block;font-size:13px;margin:12px 0 6px;color:#cdd;font-weight:600}
  input[type=text],input[type=number],input[type=url],input[type=search],select,textarea{width:100%;padding:12px 14px;border-radius:11px;border:1px solid var(--line);background:#080d1a;color:#fff;font-size:15px;outline:none;font-family:inherit;transition:.15s}
  input:focus,select:focus,textarea:focus{border-color:var(--acc2);box-shadow:0 0 0 3px rgba(255,46,84,.16)}
  textarea{resize:vertical;min-height:64px}
  .key-input{font-size:18px !important;letter-spacing:2px;text-align:center;font-weight:700;text-transform:uppercase}
  .btn{width:100%;margin-top:18px;padding:13px;border:0;border-radius:11px;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;font-weight:800;font-size:15px;cursor:pointer;font-family:inherit;transition:filter .12s,transform .12s}
  .btn:hover{filter:brightness(1.08);transform:translateY(-1px)}
  .btn:disabled{opacity:.6;cursor:not-allowed}
  .btn-sec{background:#1a2540;border:1px solid var(--line)}
  .err{background:#3a1020;border:1px solid #6a2030;color:#ffd;padding:10px 12px;border-radius:9px;margin-bottom:12px;font-size:13px;line-height:1.5}
  .ok{background:#10331a;border:1px solid #225a30;color:#cfc;padding:10px 12px;border-radius:9px;margin-bottom:12px;font-size:13px;line-height:1.5}
  .info{background:#102a3a;border:1px solid #1f4a6a;color:#cef;padding:10px 12px;border-radius:9px;margin-bottom:12px;font-size:13px;line-height:1.5}
  .badge{display:inline-block;padding:3px 9px;border-radius:6px;font-size:11.5px;font-weight:800;margin-left:6px;vertical-align:middle}
  .badge-paid{background:#22c55e;color:#04210f}
  .badge-trial{background:#f59e0b;color:#2a1700}
  .note{font-size:11.5px;color:var(--mut);margin-top:14px;text-align:center;line-height:1.6}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
`;

function topBar(activeCat = "", query = "", user = null) {
  const lbl = premiumLabel(user);
  return `
<div class="topbar">
  ${brandLogo()}
  <form class="search" method="GET" action="/search">
    <span class="si">🔍</span>
    <input type="search" name="q" value="${htmlEscape(query)}" placeholder="ဇာတ်ကား / Series ရှာရန်…" autocomplete="off">
  </form>
  <div class="acts">
    <a href="/category/movie">R Mosaic</a>
    <a href="/category/series">Series</a>
    <a class="me${lbl.premium ? " premium" : ""}" href="/account">${htmlEscape(lbl.text)}</a>
  </div>
</div>
<div class="wrap">
  <nav class="navchips">
    <a class="${activeCat === "" ? "on" : ""}" href="/">${getSvgIcon("home")} Home</a>
    ${user && !user.isAdmin ? `<a href="/mylist"><svg style="width:16px;height:16px;display:inline-block;vertical-align:middle;stroke-width:2.2;fill:none;stroke:currentColor" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="m19 21-7-4-7 4V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg> My List</a>` : ""}
    <a class="${activeCat === "movie" ? "on" : ""}" href="/category/movie">${getSvgIcon("movie")} R Mosaic</a>
    <a class="${activeCat === "series" ? "on" : ""}" href="/category/series">${getSvgIcon("series")} Series</a>
    <a class="${activeCat === "adult" ? "on" : ""}" href="/category/adult">${getSvgIcon("adult")} 21+ mmsub</a>
    <a class="${activeCat === "random" ? "on" : ""}" href="/category/random">${getSvgIcon("random")} Random Best</a>
  </nav>
</div>`;
}

function contactButtons() {
  const tg = `https://t.me/${encodeURIComponent(CONTACT_TELEGRAM)}`;
  const vb = `viber://chat?number=${encodeURIComponent("%2B95" + CONTACT_VIBER.replace(/^0/, ""))}`;
  return `
  <div class="contact-row">
    <span class="contact-lbl">Key ဝယ်ရန် / အကူအညီ —</span>
    <a class="contact-btn tg" href="${tg}" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="currentColor" style="width:16px;height:16px"><path d="M9.04 15.6 8.7 20.3c.5 0 .72-.21.98-.47l2.36-2.25 4.9 3.58c.9.5 1.54.24 1.78-.83l3.23-15.13.001-.001c.28-1.34-.48-1.86-1.36-1.53L2.2 9.86c-1.3.5-1.28 1.23-.22 1.56l4.95 1.54L18.4 6.1c.54-.36 1.03-.16.63.2"/></svg>
      Telegram
    </a>
    <a class="contact-btn vb" href="${vb}" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="currentColor" style="width:16px;height:16px"><path d="M12 2C6.5 2 2 6.04 2 11.02c0 2.2.9 4.2 2.4 5.74l-.9 3.5 3.7-1.2c1.5.7 3.1 1.06 4.8 1.06 5.5 0 10-4.04 10-9.02S17.5 2 12 2z"/></svg>
      Viber
    </a>
  </div>`;
}

function footer() {
  return `<div class="footer">
    ${contactButtons()}
    <div style="margin-top:14px">© ${new Date().getFullYear()} <b>CM FLIX</b> · All rights reserved.</div>
  </div>`;
}

function cardHtml(it) {
  return `
  <a class="card-item" href="/watch/${htmlEscape(it.id)}">
    <div class="poster" style="background-image:url('${htmlEscape(it.poster || "")}')">
      ${it.poster ? "" : '<span class="noimg">🎬</span>'}
      <div class="play-ov"><span>▶</span></div>
    </div>
    <div class="c-title">${htmlEscape(it.title || "Untitled")}</div>
  </a>`;
}

// ── Cover card (2-up Viki style) — uses slide_image (landscape) first ──
// ပြင်ဆင်ပြီးကုဒ်
function coverCardHtml(it) {
  const img = it.slide_image || it.poster || "";
  return `
  <a class="cover-item" href="/watch/${htmlEscape(it.id)}">
    <div class="cover-img" style="background-image:url('${htmlEscape(img)}')">
      ${img ? "" : '<span class="noimg">🎬</span>'}
      <div class="play-ov"><span>▶</span></div>
    </div>
    <div class="cover-title">${htmlEscape(it.title || "Untitled")}</div>
  </a>`;
}

function buildPager(page, totalPages, hrefFor) {
  if (totalPages <= 1) return "";
  const items = [];
  items.push(`<a class="${page <= 1 ? "dis" : ""}" href="${page <= 1 ? "#" : htmlEscape(hrefFor(page - 1))}">‹ Prev</a>`);
  let start = Math.max(1, page - 2);
  let end = Math.min(totalPages, page + 2);
  if (start > 1) {
    items.push(`<a href="${htmlEscape(hrefFor(1))}">1</a>`);
    if (start > 2) items.push(`<span class="gap">…</span>`);
  }
  for (let p = start; p <= end; p++) {
    items.push(p === page ? `<span class="cur">${p}</span>` : `<a href="${htmlEscape(hrefFor(p))}">${p}</a>`);
  }
  if (end < totalPages) {
    if (end < totalPages - 1) items.push(`<span class="gap">…</span>`);
    items.push(`<a href="${htmlEscape(hrefFor(totalPages))}">${totalPages}</a>`);
  }
  items.push(`<a class="${page >= totalPages ? "dis" : ""}" href="${page >= totalPages ? "#" : htmlEscape(hrefFor(page + 1))}">Next ›</a>`);
  return `<div class="pager">${items.join("")}</div>`;
}

/* ══════════════════════════════════════════════════
   HOME PAGE
   ══════════════════════════════════════════════════ */
function homePage(slides, sections, user, showWelcome = false) {
  const slideEls = slides.map((s) => `
    <div class="slide">
      <div class="slide-bg" style="background-image:url('${htmlEscape(s.image || "")}')"></div>
      <div class="slide-body">
        <span class="slide-tag">${htmlEscape(s.tag || "FEATURED")}</span>
        <h1 class="slide-title">${htmlEscape(s.title || "")}</h1>
        <p class="slide-desc">${htmlEscape(s.desc || "")}</p>
        ${s.link ? `<a class="slide-btn" href="${htmlEscape(s.link)}">▶ ကြည့်မယ်</a>` : ""}
      </div>
    </div>`).join("");
  const dots = slides.map((_, i) => `<b class="${i === 0 ? "on" : ""}" data-i="${i}"></b>`).join("");

  const heroHtml = slides.length ? `
  <div class="hero">
    <div class="hero-track" id="heroTrack">${slideEls}</div>
    ${slides.length > 1 ? `
    <button class="hero-nav prev" id="heroPrev">‹</button>
    <button class="hero-nav next" id="heroNext">›</button>
    <div class="hero-dots" id="heroDots">${dots}</div>` : ""}
  </div>` : "";

  const sectionsHtml = sections.map(sec => {
    const cat = CATEGORIES[sec.type];
    const isCover = sec.type === "random";
    const cards = isCover
      ? sec.items.map(coverCardHtml).join("")
      : sec.items.map(cardHtml).join("");
    return `
    <div class="section">
      <div class="section-head">
        <h2 style="display:flex;align-items:center;gap:8px">${getSvgIcon(sec.type, 20)} ${htmlEscape(cat.name)}</h2>
        <a class="seeall" href="/category/${cat.id}">See all →</a>
      </div>
      <div class="${isCover ? "cover-grid" : "grid"}">${cards || `<div class="empty">${cat.name} မရှိသေးပါ</div>`}</div>
    </div>`;
  }).join("");

  // premium ရက်ကျန် တွက်
  const lbl = premiumLabel(user);
  const welcomeBox = showWelcome ? `
  <div class="wrap">
    <div class="welcome-card" id="welcomeCard">
      <div class="welcome-ic">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
      </div>
      <div class="welcome-tx">
        <div class="welcome-h">ဝယ်ယူအားပေးမှုအတွက် ကျေးဇူးတင်ပါသည်</div>
        <div class="welcome-p">CM FLIX မှ ကြိုဆိုပါတယ်။ သင့် Key သက်တမ်း <b>${htmlEscape(lbl.text)}</b> ကျန်ရှိပါသည်။ ယခု ဇာတ်ကားများ အပြည့်အဝ ကြည့်ရှုနိုင်ပါပြီ။</div>
      </div>
      <button class="welcome-x" onclick="var w=document.getElementById('welcomeCard');if(w)w.remove();" aria-label="ပိတ်ရန်">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>
      </button>
    </div>
  </div>` : "";

  const body = `
${topBar("", "", user)}
${welcomeBox}
${heroHtml}
<div class="wrap">
  ${sectionsHtml}
</div>
${footer()}`;

  const script = `
(function(){
  // ── welcome box ပေါ်ပြီးရင် URL ထဲက ?welcome=1 ကို ဖယ်ထုတ် (refresh လုပ်လည်း ထပ်မပေါ်အောင်) ──
  try{
    if(location.search.indexOf('welcome=1')!==-1 && window.history && window.history.replaceState){
      var u=new URL(location.href);
      u.searchParams.delete('welcome');
      var clean=u.pathname + (u.searchParams.toString() ? ('?'+u.searchParams.toString()) : '') + u.hash;
      window.history.replaceState(null, '', clean);
    }
  }catch(_){}

  var track=document.getElementById('heroTrack');
  if(!track) return;
  var slides=track.children.length;
  if(slides<2) return;
  var i=0, dots=document.querySelectorAll('#heroDots b');
  function go(n){ i=(n+slides)%slides; track.style.transform='translateX(-'+(i*100)+'%)';
    dots.forEach(function(d,k){ d.classList.toggle('on',k===i); }); }
  var p=document.getElementById('heroPrev'), nx=document.getElementById('heroNext');
  if(p) p.onclick=function(){ go(i-1); reset(); };
  if(nx) nx.onclick=function(){ go(i+1); reset(); };
  dots.forEach(function(d){ d.onclick=function(){ go(parseInt(d.dataset.i,10)); reset(); }; });
  var timer=setInterval(function(){ go(i+1); }, 5000);
  function reset(){ clearInterval(timer); timer=setInterval(function(){ go(i+1); }, 5000); }
})();`;

  const welcomeCss = `
    .welcome-card{display:flex;align-items:center;gap:15px;margin:16px 0 4px;padding:16px 18px;border-radius:16px;
      background:linear-gradient(135deg,rgba(15,157,88,.16),rgba(34,197,94,.08));border:1px solid #1f7a48;
      box-shadow:0 10px 30px rgba(15,157,88,.18);animation:welcomeIn .5s cubic-bezier(.2,.8,.2,1)}
    @keyframes welcomeIn{from{opacity:0;transform:translateY(-12px) scale(.98)}to{opacity:1;transform:none}}
    .welcome-ic{width:48px;height:48px;flex:0 0 48px;border-radius:50%;display:flex;align-items:center;justify-content:center;
      background:linear-gradient(135deg,#0f9d58,#22c55e);box-shadow:0 6px 18px rgba(34,197,94,.45)}
    .welcome-ic svg{width:25px;height:25px;color:#fff}
    .welcome-tx{flex:1;min-width:0}
    .welcome-h{font-size:16px;font-weight:900;color:#eafff2;margin-bottom:4px;letter-spacing:.2px}
    .welcome-p{font-size:13.5px;color:#bfe9cf;line-height:1.6}
    .welcome-p b{color:#7df0a8;font-weight:800}
    .welcome-x{flex:0 0 auto;width:34px;height:34px;border-radius:10px;border:0;background:rgba(255,255,255,.08);
      color:#cfe;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:.15s}
    .welcome-x svg{width:17px;height:17px}
    .welcome-x:hover{background:rgba(255,255,255,.18);color:#fff}
    @media(max-width:560px){
      .welcome-card{gap:12px;padding:14px}
      .welcome-ic{width:42px;height:42px;flex:0 0 42px}
      .welcome-ic svg{width:22px;height:22px}
      .welcome-h{font-size:14.5px}
      .welcome-p{font-size:12.5px}
    }
  `;
  return pageShell("CM FLIX — Movies & Series", body, { script, extraCss: welcomeCss });
}

function gridPage(title, activeCat, items, page, totalPages, total, hrefFor, query = "", user = null) {
  const isCover = activeCat === "random";
  const cards = isCover
    ? items.map(coverCardHtml).join("")
    : items.map(cardHtml).join("");
  const pager = buildPager(page, totalPages, hrefFor);
  const body = `
${topBar(activeCat, query, user)}
<div class="wrap">
  <div class="section">
    <div class="section-head">
      <h2 style="display:flex;align-items:center;gap:8px">${getSvgIcon(activeCat, 22)} ${htmlEscape(title)}</h2>
      <span style="color:var(--mut);font-size:13px">${total} Total</span>
    </div>
    <div class="${isCover ? "cover-grid" : "grid"}">${cards || `<div class="empty">${query ? "ရှာဖွေမှု မတွေ့ပါ" : "ဘာမှ မရှိသေးပါ"}</div>`}</div>
    ${pager}
  </div>
</div>
${footer()}`;
  return pageShell(title + " — CM FLIX", body);
}

/* ══════════════════════════════════════════════════
   MY LIST PAGE  (bookmarks)
   ══════════════════════════════════════════════════ */
function myListPage(items, user, csrfToken = "") {
  // save list လုပ်ထားသမျှ ဇာတ်ကားအားလုံးကို Random Best ပုံစံ (16:9 cover) တစ်မျိုးတည်း ပြ
  const cards = items.map(it => coverCardHtml(it)).join("");
  const hasItems = items.length > 0;
  const body = `
${topBar("", "", user)}
<div class="wrap">
  <div class="section">
    <div class="section-head">
      <h2 style="display:flex;align-items:center;gap:8px">
        <svg style="width:22px;height:22px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m19 21-7-4-7 4V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
        My List
      </h2>
      <div style="display:flex;align-items:center;gap:12px">
        <span style="color:var(--mut);font-size:13px">${items.length} Saved</span>
        ${hasItems ? `<button id="clearAllBtn" class="ml-clear-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          Clear All
        </button>` : ""}
      </div>
    </div>
    <div class="mylist-grid">${cards || `<div class="empty">သိမ်းထားတဲ့ ဇာတ်ကား မရှိသေးပါ။ ကြိုက်တဲ့ကားရဲ့ စာမျက်နှာမှာ "+ My List ထဲ ထည့်မယ်" ကို နှိပ်ပါ။</div>`}</div>
  </div>
</div>

<!-- Custom Confirm Box -->
<div class="cm-modal-overlay" id="clearModal">
  <div class="cm-modal">
    <div class="cm-modal-ic">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
    </div>
    <div class="cm-modal-h">My List အားလုံး ဖျက်မှာလား?</div>
    <div class="cm-modal-p">သိမ်းထားသမျှ ဇာတ်ကား <b>${items.length}</b> ကား အားလုံးကို စာရင်းမှ ဖယ်ရှားပါမည်။ ဒီလုပ်ဆောင်ချက်ကို ပြန်ပြင်လို့ မရပါ။</div>
    <div class="cm-modal-actions">
      <button class="cm-modal-btn no" id="clearNo">မဖျက်တော့ပါ</button>
      <button class="cm-modal-btn yes" id="clearYes">အားလုံး ဖျက်မယ်</button>
    </div>
  </div>
</div>
${footer()}`;
  // Random Best နဲ့တူညီတဲ့ 2-up / 3-up cover grid (16:9 အချိုးညီ)
  const mlCss = `
    .mylist-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
    @media(min-width:820px){.mylist-grid{grid-template-columns:repeat(3,1fr);gap:18px}}
    .ml-clear-btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:10px;border:1px solid #5a2030;
      background:#2a1420;color:#f88;font-weight:700;font-size:13px;cursor:pointer;font-family:inherit;transition:.15s}
    .ml-clear-btn:hover{background:#3a1828;color:#ffb;border-color:#7a2838;transform:translateY(-1px)}
    .cm-modal-overlay{position:fixed;inset:0;z-index:9999;display:none;align-items:center;justify-content:center;padding:20px;
      background:rgba(3,5,12,.78);backdrop-filter:blur(6px)}
    .cm-modal-overlay.show{display:flex;animation:cmFade .2s ease}
    @keyframes cmFade{from{opacity:0}to{opacity:1}}
    .cm-modal{width:100%;max-width:400px;background:linear-gradient(180deg,#141a2e,#0d1322);border:1px solid var(--line);
      border-radius:20px;padding:28px 24px;text-align:center;box-shadow:0 24px 70px rgba(0,0,0,.7);
      animation:cmPop .26s cubic-bezier(.2,.9,.3,1.2)}
    @keyframes cmPop{from{opacity:0;transform:scale(.9) translateY(10px)}to{opacity:1;transform:none}}
    .cm-modal-ic{width:58px;height:58px;margin:0 auto 16px;border-radius:50%;display:flex;align-items:center;justify-content:center;
      background:linear-gradient(135deg,#c43,#e50914);box-shadow:0 8px 22px rgba(229,9,20,.45)}
    .cm-modal-ic svg{width:28px;height:28px;color:#fff}
    .cm-modal-h{font-size:18px;font-weight:900;color:#fff;margin-bottom:8px}
    .cm-modal-p{font-size:13.5px;color:var(--mut);line-height:1.65;margin-bottom:22px}
    .cm-modal-p b{color:var(--acc2)}
    .cm-modal-actions{display:flex;gap:10px}
    .cm-modal-btn{flex:1;padding:12px;border-radius:11px;border:0;font-weight:800;font-size:14px;cursor:pointer;font-family:inherit;transition:.15s}
    .cm-modal-btn.no{background:#1a2540;color:#cfe;border:1px solid var(--line)}
    .cm-modal-btn.no:hover{background:#22304f}
    .cm-modal-btn.yes{background:linear-gradient(135deg,#c43,#e50914);color:#fff;box-shadow:0 4px 14px rgba(229,9,20,.4)}
    .cm-modal-btn.yes:hover{filter:brightness(1.1)}
    .cm-modal-btn:disabled{opacity:.6;cursor:not-allowed}
  `;
  const script = `
(function(){
  var btn=document.getElementById('clearAllBtn');
  var modal=document.getElementById('clearModal');
  var noBtn=document.getElementById('clearNo');
  var yesBtn=document.getElementById('clearYes');
  if(!btn||!modal) return;
  function open(){ modal.classList.add('show'); }
  function close(){ modal.classList.remove('show'); }
  btn.addEventListener('click',open);
  if(noBtn) noBtn.addEventListener('click',close);
  modal.addEventListener('click',function(e){ if(e.target===modal) close(); });
  document.addEventListener('keydown',function(e){ if(e.key==='Escape') close(); });
  if(yesBtn){
    yesBtn.addEventListener('click',function(){
      yesBtn.disabled=true; noBtn.disabled=true;
      yesBtn.textContent='ဖျက်နေသည်…';
      fetch('/bookmark/clear',{
        method:'POST',
        headers:{'content-type':'application/x-www-form-urlencoded'},
        body:'csrf_token='+encodeURIComponent(${JSON.stringify(csrfToken)})
      }).then(function(r){return r.json();}).then(function(d){
        if(d&&d.ok){ location.reload(); }
        else{ yesBtn.disabled=false; noBtn.disabled=false; yesBtn.textContent='အားလုံး ဖျက်မယ်'; alert((d&&d.error)||'ဖျက်လို့ မရပါ'); }
      }).catch(function(){ yesBtn.disabled=false; noBtn.disabled=false; yesBtn.textContent='အားလုံး ဖျက်မယ်'; });
    });
  }
})();`;
  return pageShell("My List — CM FLIX", body, { extraCss: mlCss, script });
}
/* ══════════════════════════════════════════════════
   ACTRESS PAGE — actress နဲ့ဆိုင်တဲ့ ဇာတ်ကားများ
   ══════════════════════════════════════════════════ */
function actressPage(actress, items, user) {
  const cards = items.map(it => coverCardHtml(it)).join("");
  const body = `
${topBar("", "", user)}
<div class="wrap">
  <div class="actress-hero">
    <div class="actress-hero-img" style="background-image:url('${htmlEscape(actress.image || "")}')">${actress.image ? "" : "👤"}</div>
    <div class="actress-hero-info">
      <div class="actress-hero-lbl">👩 မင်းသမီး</div>
      <h1 class="actress-hero-name">${htmlEscape(actress.name || actress.slug)}</h1>
      <div class="actress-hero-count">${items.length} ဇာတ်ကား</div>
    </div>
  </div>
  <div class="section">
    <div class="cover-grid">${cards || `<div class="empty">ဒီမင်းသမီးနဲ့ ဆိုင်တဲ့ ဇာတ်ကား မရှိသေးပါ</div>`}</div>
  </div>
</div>
${footer()}`;
  const css = `
    .actress-hero{display:flex;align-items:center;gap:20px;margin:22px 0 8px;padding:20px;border-radius:18px;
      background:linear-gradient(135deg,rgba(255,46,84,.14),rgba(14,24,48,.6));border:1px solid var(--line)}
    .actress-hero-img{width:100px;height:100px;flex:0 0 100px;border-radius:50%;background-size:cover;background-position:center;
      background-color:#0e1830;border:4px solid var(--acc2);display:flex;align-items:center;justify-content:center;font-size:42px;
      box-shadow:0 6px 22px rgba(255,46,84,.45)}
    .actress-hero-lbl{font-size:12px;color:var(--mut);font-weight:700}
    .actress-hero-name{font-size:26px;font-weight:900;margin:4px 0 6px}
    .actress-hero-count{font-size:13px;color:#cfe1ff;font-weight:600}
    @media(max-width:560px){.actress-hero{gap:14px;padding:14px}.actress-hero-img{width:78px;height:78px;flex:0 0 78px;font-size:32px}.actress-hero-name{font-size:20px}}
  `;
  return pageShell((actress.name || "Actress") + " — CM FLIX", body, { extraCss: css });
}


/* ══════════════════════════════════════════════════
   WATCH PAGE  — Plyr player, signed stream URLs only
   ══════════════════════════════════════════════════ */
function watchPage(item, user, gated, streams, bookmarked = false, actresses = []) {
  const cat = CATEGORIES[item.type] || CATEGORIES.movie;
  const loggedIn = !!user;

  let playerArea = "";
  let seriesNav = "";
  const posterImg = htmlEscape(item.slide_image || item.poster || "");

  if (item.type === "series") {
    const seasons = Array.isArray(item.seasons) ? item.seasons : [];
    const seasonTabs = seasons.map((s, si) => `
      <button class="season-tab ${si === 0 ? "on" : ""}" data-s="${si}">Season ${s.season || (si + 1)}</button>`).join("");
    const epLists = seasons.map((s, si) => {
      const eps = (s.episodes || []).map((e, ei) => {
        const st = (streams.seasons?.[si]?.[ei]) || { video: "", dl: "" };
        return `
        <button class="ep-btn" data-s="${si}" data-e="${ei}"
          data-video="${htmlEscape(st.video || "")}"
          data-dl="${htmlEscape(st.dl || "")}"
          data-title="${htmlEscape(e.title || ("Episode " + (e.ep || ei + 1)))}">
          <span class="ep-no">${e.ep || ei + 1}</span>
          <span class="ep-tt">${htmlEscape(e.title || ("Episode " + (e.ep || ei + 1)))}</span>
          <span class="ep-play">▶</span>
        </button>`;
      }).join("");
      return `<div class="ep-list ${si === 0 ? "on" : ""}" data-s="${si}">${eps || '<div class="empty">Episode မရှိသေးပါ</div>'}</div>`;
    }).join("");

    seriesNav = `
      <div class="seasons">
        <div class="season-tabs">${seasonTabs || '<span style="color:var(--mut)">Season မရှိသေးပါ</span>'}</div>
        ${epLists}
      </div>`;
    playerArea = `
      <div class="player-box">
        <video id="cmPlayer" playsinline crossorigin preload="none" poster="${posterImg}"></video>
        <div class="cm-loading" id="cmLoading"><div class="cm-ring"></div></div>
        <div class="poster-cover" id="posterCover" style="background-image:url('${posterImg}')">
          <div class="poster-cover-play"><span>▶</span></div>
        </div>
      </div>
      <div class="now-playing" id="nowPlaying"></div>`;
  } else {
    const st = streams.single || { video: "", dl: "" };
    playerArea = `
      <div class="player-box">
        <video id="cmPlayer" playsinline crossorigin preload="none" poster="${posterImg}"
          data-video="${htmlEscape(st.video || "")}" data-dl="${htmlEscape(st.dl || "")}"></video>
        <div class="cm-loading" id="cmLoading"><div class="cm-ring"></div></div>
        <div class="poster-cover" id="posterCover" style="background-image:url('${posterImg}')">
          <div class="poster-cover-play"><span>▶</span></div>
        </div>
      </div>`;
  }

  const gateBanner = gated ? `
    <div class="gate" id="gateBanner">
      ${!loggedIn
        ? `🔒 ကြည့်ရှု / Download ရန် Key ဖြင့် ဝင်ရန် လိုအပ်ပါသည်။ <a href="/login?next=${encodeURIComponent("/watch/" + item.id)}">ဝင်မယ်</a>`
        : `⏳ Key သက်တမ်း ကုန်သွားပါပြီ။ <a href="/account">တိုးရန်</a>`}
    </div>` : "";

  const extraCss = `
    :root{--plyr-color-main:var(--acc2);--plyr-video-control-color:#fff;--plyr-video-background:#000;--plyr-menu-background:#0d1424;--plyr-menu-color:#eef2ff;--plyr-control-radius:8px}
    .watch{display:grid;grid-template-columns:1fr;gap:22px;margin:18px 0}
    @media(min-width:900px){ .watch.has-info{grid-template-columns:1fr 330px} }
    .player-box{position:relative;background:#000;border-radius:0;overflow:hidden;aspect-ratio:16/9;box-shadow:0 14px 40px rgba(0,0,0,.65)}
    .player-box .plyr{height:100%;border-radius:0}
    .player-box video{width:100%;height:100%;background:#000;object-fit:contain;display:block}
    .poster-cover{position:absolute;inset:0;z-index:10;cursor:pointer;background-size:cover;background-position:center center;background-repeat:no-repeat;background-color:#080c18;display:flex;align-items:center;justify-content:center;transition:opacity .25s}
    .poster-cover.hide{display:none}
    .poster-cover-play{display:none}
    /* ── Loading spinner overlay (Play နှိပ်ပြီး buffer လုပ်နေချိန် ပြ) ── */
    .cm-loading{position:absolute;inset:0;z-index:15;display:none;align-items:center;justify-content:center;
      background:rgba(0,0,0,.42);backdrop-filter:blur(1px);pointer-events:none}
    .cm-loading.show{display:flex}
    .cm-loading .cm-ring{width:58px;height:58px;border-radius:50%;
      border:4px solid rgba(255,255,255,.18);border-top-color:var(--acc2);
      animation:cmSpin .8s linear infinite;box-shadow:0 4px 20px rgba(0,0,0,.4)}
    @keyframes cmSpin{to{transform:rotate(360deg)}}
    .meta-title{font-size:25px;font-weight:900;margin:0 0 8px}
    .meta-cat{display:inline-block;font-size:11px;font-weight:800;padding:4px 11px;border-radius:7px;background:#131b2e;margin-bottom:12px;letter-spacing:.4px}
    .meta-note{color:#cfd6e8;font-size:14px;line-height:1.75;margin:0 0 18px;white-space:pre-wrap}
.actions{display:flex;flex-direction:column;gap:9px;margin:16px 0 6px;width:100%}
    .actions a,.actions button{width:100%;text-align:center;padding:11px 18px;border-radius:9px;border:0;cursor:pointer;font-weight:700;font-size:15px;text-decoration:none;font-family:inherit;display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:.18s;letter-spacing:.3px;box-sizing:border-box}
    
    /* အပြာရောင် Gradient Play Button */
    .btn-play{background:linear-gradient(135deg,#2f57ff,#1ca0ff);color:#ffffff !important;box-shadow:0 4px 12px rgba(47,87,255,.2)}
    .btn-play:hover{filter:brightness(1.08);transform:translateY(-1px)}
    
    /* မီးခိုးရောင်ပုတ်ပုတ် Download Button */
    .btn-dl{background:#1f1f1f;color:#ffffff !important;border:1px solid rgba(255,255,255,0.03);box-shadow:0 4px 8px rgba(0,0,0,.3); -webkit-touch-callout: none; user-select: none;}
    .btn-dl:hover{background:#2b2b2b;transform:translateY(-1px)}

    /* Bookmark / My List Button */
    .btn-bm{background:#15203a;color:#cfe1ff !important;border:1px solid var(--line);box-shadow:0 4px 8px rgba(0,0,0,.2);transition:.18s}
    .btn-bm:hover{background:#1b2a4a;transform:translateY(-1px);border-color:var(--acc2)}
    .btn-bm.on{background:linear-gradient(135deg,#0f9d58,#22c55e);color:#fff !important;border-color:transparent;box-shadow:0 4px 12px rgba(34,197,94,.35)}
    .btn-bm .bm-ic{font-weight:900}
    
    @media(max-width:480px){.actions a,.actions button{padding:10px 10px;font-size:14px;gap:6px}}    .gate{background:#2a1420;border:1px solid #6a2030;color:#ffd;padding:12px 14px;border-radius:11px;margin:14px 0;font-size:14px;line-height:1.6}
    .gate a{color:var(--acc2);font-weight:800}
    .now-playing{margin-top:12px;color:var(--acc2);font-weight:700;font-size:14px;min-height:18px}
    .seasons{margin-top:22px}
    .season-tabs{display:flex;gap:8px;overflow-x:auto;padding-bottom:10px;scrollbar-width:none}
    .season-tabs::-webkit-scrollbar{display:none}
    .season-tab{flex:0 0 auto;padding:8px 17px;border-radius:10px;border:1px solid var(--line);background:#131b2e;color:#fff;font-weight:700;font-size:13.5px;cursor:pointer;font-family:inherit;transition:.15s}
    .season-tab.on{background:linear-gradient(135deg,var(--acc),var(--acc2));border-color:transparent}
    .ep-list{
  display:none;
  flex-direction:column;
  gap:8px;
  margin-top:6px;
  max-height: 420px;
  overflow-y: auto;
  padding-right: 6px;
  padding-bottom: 20px;
}
.ep-list.on{display:flex}
.ep-list::-webkit-scrollbar {
  width: 5px;
}
.ep-list::-webkit-scrollbar-track {
  background: rgba(255,255,255,0.02);
  border-radius: 4px;
}
.ep-list::-webkit-scrollbar-thumb {
  background: var(--line);
  border-radius: 4px;
}
.ep-list::-webkit-scrollbar-thumb:hover {
  background: var(--acc2);
}
    .ep-btn{display:flex;align-items:center;gap:12px;width:100%;text-align:left;padding:11px 14px;border-radius:11px;border:1px solid var(--line);background:#0d1424;color:#fff;cursor:pointer;font-family:inherit;transition:.14s}
    .ep-btn:hover{border-color:var(--acc2);background:#131b2e}
    .ep-btn.playing{border-color:var(--acc);background:#1e1420}
    .ep-no{flex:0 0 32px;height:32px;border-radius:9px;background:#1a2540;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px}
    .ep-btn.playing .ep-no{background:var(--acc)}
    .ep-tt{flex:1;font-size:14px;font-weight:600}
    .ep-play{opacity:.6;font-size:13px}
    .info-side .meta-title{font-size:20px}
      .info-side .meta-title{font-size:20px}
    .actress-row{margin:18px 0 6px}
    .actress-row-lbl{font-size:12px;color:var(--mut);font-weight:700;margin-bottom:10px}
    .actress-chips{display:flex;gap:12px;flex-wrap:wrap}
    .actress-chip{display:inline-flex;flex-direction:column;align-items:center;gap:7px;text-decoration:none;width:84px;transition:.18s}
    .actress-chip:hover{transform:translateY(-3px)}
    .actress-chip-img{width:72px;height:72px;border-radius:50%;background-size:cover;background-position:center;background-color:#0e1830;
      border:3px solid var(--acc2);display:flex;align-items:center;justify-content:center;font-size:28px;
      box-shadow:0 4px 14px rgba(255,46,84,.35);transition:.18s}
    .actress-chip:hover .actress-chip-img{border-color:#fff;box-shadow:0 6px 18px rgba(255,46,84,.55)}
    .actress-chip-name{font-size:11.5px;color:#e7ecf8;font-weight:600;text-align:center;line-height:1.3;
      display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
    .cm-toast{position:fixed;left:50%;bottom:30px;transform:translateX(-50%) translateY(20px);z-index:9999;
      display:flex;align-items:center;gap:10px;padding:13px 20px;border-radius:13px;
      background:linear-gradient(135deg,#2a1420,#1a1320);border:1px solid #6a2838;
      box-shadow:0 12px 36px rgba(0,0,0,.6);color:#ffd;font-weight:700;font-size:14px;
      opacity:0;pointer-events:none;transition:opacity .25s,transform .25s;max-width:90vw}
    .cm-toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
    .cm-toast-ic{flex:0 0 auto;width:24px;height:24px;display:flex;align-items:center;justify-content:center;color:var(--acc2)}
    .cm-toast-ic svg{width:22px;height:22px}
    .cm-toast-tx{line-height:1.4}
  `;

  const hasInfo = !!(item.note || item.type === "series");
  const body = `
${topBar(item.type, "", user)}
<div class="wrap">
  ${gateBanner}
  <div class="watch ${hasInfo ? "has-info" : ""}">
    <div class="player-col">
      ${playerArea}
      <div class="actions">
        <button class="btn-play" id="btnPlay">▶ Play</button>
        <button class="btn-dl" id="btnDl">⬇ Download</button>
        ${loggedIn ? `<button class="btn-bm${bookmarked ? " on" : ""}" id="btnBm" data-id="${htmlEscape(item.id)}" data-on="${bookmarked ? "1" : "0"}">
          <span class="bm-ic">${bookmarked ? "✓" : "+"}</span>
          <span class="bm-tx">${bookmarked ? "Saved" : "My List ထဲ ထည့်မယ်"}</span>
        </button>` : ""}
      </div>
      ${item.type !== "series" ? `
        <h1 class="meta-title">${htmlEscape(item.title)}</h1>
        <span class="meta-cat" style="display:inline-flex;align-items:center;gap:6px">${getSvgIcon(item.type, 13)} ${htmlEscape(cat.name)}</span>
        ${item.note ? `<p class="meta-note">${htmlEscape(item.note)}</p>` : ""}
      ` : ""}
      ${actresses.length ? `
        <div class="actress-row">
          <div class="actress-row-lbl">👩 မင်းသမီး</div>
          <div class="actress-chips">
            ${actresses.map(a => `
              <a class="actress-chip" href="/actress/${htmlEscape(a.slug)}" title="${htmlEscape(a.name)} ၏ ဇာတ်ကားများ">
                <span class="actress-chip-img" style="background-image:url('${htmlEscape(a.image || "")}')">${a.image ? "" : "👤"}</span>
                <span class="actress-chip-name">${htmlEscape(a.name)}</span>
              </a>`).join("")}
          </div>
        </div>` : ""}
      ${seriesNav}
    </div>
    ${hasInfo && item.type === "series" ? `
      <div class="info-side">
        <h1 class="meta-title">${htmlEscape(item.title)}</h1>
        <span class="meta-cat" style="display:inline-flex;align-items:center;gap:6px">${getSvgIcon(item.type, 13)} ${htmlEscape(cat.name)}</span>
        ${item.note ? `<p class="meta-note">${htmlEscape(item.note)}</p>` : ""}
      </div>` : ""}
  </div>
</div>

<!-- Custom Toast / Notice Box -->
<div class="cm-toast" id="cmToast">
  <span class="cm-toast-ic">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
  </span>
  <span class="cm-toast-tx" id="cmToastTx">အပိုင်း ရွေးပါ</span>
</div>
${footer()}`;
  const script = `
(function(){
  var GATED = ${gated ? "true" : "false"};
  var v=document.getElementById('cmPlayer');
  var btnPlay=document.getElementById('btnPlay');
  var btnDl=document.getElementById('btnDl');
  var emptyEl=document.getElementById('playerEmpty');
  var nowEl=document.getElementById('nowPlaying');
  var loadEl=document.getElementById('cmLoading');
  var cur={video:'',dl:'',title:''};

  function showLoading(){ if(loadEl) loadEl.classList.add('show'); }
  function hideLoading(){ if(loadEl) loadEl.classList.remove('show'); }

  // ── Custom toast box (browser alert အစား) ──
  var toastEl=document.getElementById('cmToast');
  var toastTxEl=document.getElementById('cmToastTx');
  var toastTimer=null;
  function showToast(msg){
    if(!toastEl){ return; }
    if(toastTxEl) toastTxEl.textContent=msg;
    toastEl.classList.add('show');
    if(toastTimer) clearTimeout(toastTimer);
    toastTimer=setTimeout(function(){ toastEl.classList.remove('show'); }, 2800);
  }

  var coverEl=document.getElementById('posterCover');
  var player=null;
  var playerReady=false;

  function initPlayer(){
    if(player || playerReady) return;
    playerReady=true;
    // play နှိပ်မှသာ controls ပါတဲ့ Plyr ကို ဆောက်မယ်
    v.setAttribute('controls','controls');
    try{
      player=new Plyr(v,{
        controls:['play-large','play','progress','current-time','duration','mute','volume','settings','pip','airplay','fullscreen'],
        settings:['quality','speed','loop'],
        speed:{selected:1,options:[0.5,0.75,1,1.25,1.5,2]},
        ratio:'16:9',
        keyboard:{focused:true,global:true},
        tooltips:{controls:true,seek:true}
      });
    }catch(_){}
    if (player) {
      player.on('enterfullscreen', function() {
        if (screen.orientation && screen.orientation.lock) {
          screen.orientation.lock('landscape').catch(function() {});
        }
      });
      player.on('exitfullscreen', function() {
        if (screen.orientation && screen.orientation.unlock) {
          screen.orientation.unlock();
        }
      });
      // ── Loading spinner — buffer/seek လုပ်နေချိန် ပြ၊ ဖွင့်လို့ရရင် ဖျောက် ──
      player.on('waiting', showLoading);
      player.on('seeking', showLoading);
      player.on('stalled', showLoading);
      player.on('loadstart', showLoading);
      player.on('canplay', hideLoading);
      player.on('playing', hideLoading);
      player.on('seeked', hideLoading);
      player.on('error', hideLoading);
      if(GATED){
        player.on('play',function(){ player.pause(); gateMsg(); });
      }
    } else if (v) {
      // Plyr မရှိရင် native video element event တွေ သုံး
      v.addEventListener('waiting', showLoading);
      v.addEventListener('seeking', showLoading);
      v.addEventListener('stalled', showLoading);
      v.addEventListener('loadstart', showLoading);
      v.addEventListener('canplay', hideLoading);
      v.addEventListener('playing', hideLoading);
      v.addEventListener('seeked', hideLoading);
      v.addEventListener('error', hideLoading);
    }
  }

  function revealPlayer(){
    if(coverEl) coverEl.classList.add('hide');
    initPlayer();
    showLoading();  // Play နှိပ်တာနဲ့ ချက်ချင်း spinner ပြ (buffer လုပ်နေတယ်ဆိုတာ သိစေဖို့)
  }

  function gateMsg(){
    var loginUrl='/login?next='+encodeURIComponent(location.pathname+location.search);
    location.href = ${loggedIn ? "'/account'" : "loginUrl"};
  }

  function applySource(video){
    if(!video) return;
    if(player){ player.source={type:'video',sources:[{src:video,type:'video/mp4'}]}; }
    else if(v){ v.src=video; }
  }

  function setSource(video, dl, title){
    cur.video=video||''; cur.dl=dl||video||''; cur.title=title||'';
    revealPlayer();
    applySource(cur.video);
    if(nowEl && title){ nowEl.textContent='▶ Now playing: '+title; }
  }

  ${item.type !== "series" ? `
  (function(){
    var dv=v.getAttribute('data-video')||''; var dd=v.getAttribute('data-dl')||dv;
    cur.video=dv; cur.dl=dd;
    // source ကို play နှိပ်မှသာ load မယ် (preload မလုပ်ဘူး)
  })();` : ``}

  function tryPlay(){
    if(player){ var p=player.play(); if(p&&p.catch) p.catch(function(){}); }
    else if(v){ var q=v.play(); if(q&&q.catch) q.catch(function(){}); }
  }

  // thumbnail cover ကို နှိပ်ရင် play (Viki ပုံစံ)
  if(coverEl){
    coverEl.addEventListener('click',function(){
      if(GATED){ gateMsg(); return; }
      if(!cur.video){ showToast('${item.type === "series" ? "အပိုင်း ရွေးပါ — link မရှိသေးပါ" : "ဤအပိုင်း link မရှိသေးပါ"}'); return; }
      revealPlayer();
      applySource(cur.video);
      setTimeout(tryPlay,120);
    });
  }

  if(btnPlay){
    btnPlay.addEventListener('click',function(){
      if(GATED){ gateMsg(); return; }
      if(!cur.video){ showToast('${item.type === "series" ? "အပိုင်း ရွေးပြီးမှ Play နှိပ်ပါ — link မရှိသေးပါ" : "ဤအပိုင်း link မရှိသေးပါ"}'); return; }
      revealPlayer();
      applySource(cur.video);
      setTimeout(tryPlay,120);
      document.querySelector('.player-box').scrollIntoView({behavior:'smooth',block:'center'});
    });
  }
  if(btnDl){
    btnDl.addEventListener('contextmenu', function(e){ e.preventDefault(); });
    
    btnDl.addEventListener('click', function(e){
      e.preventDefault();
      if(GATED){ gateMsg(); return; }
      if(!cur.dl){ showToast('${item.type === "series" ? "အပိုင်း ရွေးပြီးမှ Download နှိပ်ပါ — link မရှိသေးပါ" : "Download link မရှိသေးပါ"}'); return; }
      window.location.href = cur.dl;
    });
  }
  if(GATED && v){
    v.addEventListener('play',function(){ v.pause(); gateMsg(); });
  }

  ${item.type === "series" ? `
  document.querySelectorAll('.season-tab').forEach(function(tab){
    tab.addEventListener('click',function(){
      var s=tab.dataset.s;
      document.querySelectorAll('.season-tab').forEach(function(t){t.classList.toggle('on',t===tab);});
      document.querySelectorAll('.ep-list').forEach(function(l){l.classList.toggle('on',l.dataset.s===s);});
    });
  });
  document.querySelectorAll('.ep-btn').forEach(function(b){
    b.addEventListener('click',function(){
      if(GATED){ gateMsg(); return; }
      document.querySelectorAll('.ep-btn').forEach(function(x){x.classList.remove('playing');});
      b.classList.add('playing');
      setSource(b.dataset.video, b.dataset.dl, b.dataset.title);
      setTimeout(tryPlay,120);
      document.querySelector('.player-box').scrollIntoView({behavior:'smooth',block:'center'});
    });
  });
  ` : ``}

  // ── Bookmark toggle ──
  var btnBm=document.getElementById('btnBm');
  if(btnBm){
    btnBm.addEventListener('click',function(){
      var on=btnBm.dataset.on==='1';
      var id=btnBm.dataset.id;
      btnBm.disabled=true;
      fetch('/bookmark/toggle',{
        method:'POST',
        headers:{'content-type':'application/x-www-form-urlencoded'},
        body:'id='+encodeURIComponent(id)+'&action='+(on?'remove':'add')
      }).then(function(r){return r.json();}).then(function(d){
        if(d && d.ok){
          var nowOn=d.bookmarked;
          btnBm.dataset.on=nowOn?'1':'0';
          btnBm.classList.toggle('on',nowOn);
          btnBm.querySelector('.bm-ic').textContent=nowOn?'✓':'+';
          btnBm.querySelector('.bm-tx').textContent=nowOn?'Saved':'My List ထဲ ထည့်မယ်';
        }
      }).catch(function(){}).finally(function(){ btnBm.disabled=false; });
    });
  }
})();`;

  return pageShell((item.title || "Watch") + " — CM FLIX", body, { extraCss, script, plyr: true });
}

/* ══════════════════════════════════════════════════
   LOGIN / EXPIRED / ACCOUNT PAGES
   ══════════════════════════════════════════════════ */
function keyLoginPage(csrfToken, error = "", info = "", nextUrl = "/") {
  const body = `
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo">${logoMark()}</div>
  <h1>CM FLIX — Key Login</h1>
  <p class="sub">Admin ထံမှ ရရှိသော Key ထည့်ပြီး ဝင်ပါ။ Username / Password မလိုပါ။</p>
  ${error ? `<div class="err">${htmlEscape(error)}</div>` : ""}
  ${info ? `<div class="ok">${htmlEscape(info)}</div>` : ""}
  <form method="POST" action="/login" autocomplete="off" id="keyForm">
    <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
    <input type="hidden" name="next" value="${htmlEscape(nextUrl)}">
    <input type="hidden" name="device_uuid" id="duid" value="">
    <label>Your Key</label>
    <input type="text" name="key" class="key-input" placeholder="CM-XXXX-XXXX-XXXX" autocomplete="off" required autofocus>
    <button type="submit" class="btn">ဝင်မယ်</button>
  </form>
  <div class="note">Key တစ်ခုလျှင် ဖုန်း ${MAX_DEVICES_PER_KEY} လုံးအထိ သုံးနိုင်သည်</div>
  <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--line)">${contactButtons()}</div>
</div></div>`;
  const script = `
(function(){
  function rnd(){ try{return crypto.randomUUID();}catch(_){ return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16);}); } }
  var id=''; try{ id=localStorage.getItem('cmflix_duid')||''; }catch(_){}
  if(!id){ var m=document.cookie.match(/(?:^|;\\s*)cmflix_duid=([^;]+)/); if(m) id=decodeURIComponent(m[1]); }
  if(!id) id=rnd();
  try{ localStorage.setItem('cmflix_duid',id); }catch(_){}
  document.cookie='cmflix_duid='+encodeURIComponent(id)+'; Max-Age='+(60*60*24*365*2)+'; Path=/; SameSite=Lax';
  var el=document.getElementById('duid'); if(el) el.value=id;
  var f=document.getElementById('keyForm');
  if(f) f.addEventListener('submit',function(){ var b=f.querySelector('button'); if(b){b.disabled=true;b.innerHTML='<span class="spinner"></span>စောင့်ပါ...';} });
})();`;
  return pageShell("Login — CM FLIX", body, { extraCss: AUTH_CSS, script });
}

function expiredPage(reason = "") {
  const msg = reason || "သင့်ရဲ့ Key သက်တမ်း ကုန်သွားပါပြီ။ သက်တမ်းတိုးရန် Admin ကို ဆက်သွယ်ပါ။";
  const body = `
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo">${logoMark()}</div>
  <h1>Key Expired</h1>
  <p class="sub">${htmlEscape(msg)}</p>
  <a class="btn" href="/login" style="display:block;text-align:center;text-decoration:none;margin-top:10px">Key အသစ်ထည့်ရန်</a>
  <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--line)">${contactButtons()}</div>
</div></div>`;
  return pageShell("Expired — CM FLIX", body, { extraCss: AUTH_CSS });
}

function accountPage(user, info = "", error = "", showWelcome = false) {
  const exp = user.expires_at
    ? new Date(user.expires_at).toLocaleString("en-GB", { hour12: false, timeZone: "Asia/Yangon" })
    : "—";
  const remainMs = (user.expires_at || 0) - Date.now();
  const dDays  = remainMs > 0 ? Math.floor(remainMs / 86400000) : 0;
  const dHours = remainMs > 0 ? Math.floor((remainMs % 86400000) / 3600000) : 0;
  const dMins  = remainMs > 0 ? Math.floor((remainMs % 3600000) / 60000) : 0;
  const daysLeft = remainMs > 0 ? Math.max(1, Math.ceil(remainMs / 86400000)) : 0;
  const expired = remainMs <= 0;

  const roleBadge = user.role === "paid"
    ? '<span class="acc-badge paid">PAID</span>'
    : '<span class="acc-badge trial">TRIAL</span>';

  const devices = Array.isArray(user.devices) ? user.devices : [];
  const devRows = devices.map(d => {
    const seen = d.last_seen
      ? new Date(d.last_seen).toLocaleString("en-GB", { hour12: false, timeZone: "Asia/Yangon" })
      : "—";
    return `<tr>
      <td>
        <div class="dev-name">${htmlEscape(d.label || "Device")}</div>
      </td>
      <td class="dev-seen">${htmlEscape(seen)}</td>
    </tr>`;
  }).join("");

  // ── premium progress ring percentage (visual only) ──
  const ringPct = expired ? 0 : Math.min(100, Math.max(6, Math.round((daysLeft > 30 ? 30 : daysLeft) / 30 * 100)));

  const keySvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>`;
  const clockSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`;
  const phoneSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M11 18h2"/></svg>`;
  const homeSvg  = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`;
  const outSvg   = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`;

  const body = `
<div class="acc-wrap">
  <div class="acc-card">

    <!-- header -->
    <div class="acc-head">
      <div class="acc-id">
        <span class="acc-keyicon">${keySvg}</span>
        <div class="acc-id-text">
          <h1>My Key</h1>
          <div class="acc-keycode">
            <code>${htmlEscape(user.keyId)}</code>
            ${roleBadge}
          </div>
        </div>
      </div>
      <a class="acc-back" href="/">${homeSvg}<span>Home</span></a>
    </div>

    ${info ? `<div class="acc-alert ok">${htmlEscape(info)}</div>` : ""}
    ${error ? `<div class="acc-alert err">${htmlEscape(error)}</div>` : ""}

    ${showWelcome ? `
    <div class="acc-welcome" id="accWelcome">
      <div class="acc-welcome-ic">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M20 6 9 17l-5-5"/>
        </svg>
      </div>
      <div class="acc-welcome-tx">
        <div class="acc-welcome-h">ဝယ်ယူအားပေးမှုအတွက် ကျေးဇူးတင်ပါသည် 🎉</div>
        <div class="acc-welcome-p">သင့် Key သက်တမ်း <b>P-${daysLeft}Day</b> ကျန်ရှိပါသည်။ CM FLIX မှ ကြိုဆိုပါတယ်!</div>
      </div>
      <button class="acc-welcome-x" onclick="this.closest('.acc-welcome').remove()">✕</button>
    </div>` : ""}

    <!-- premium status -->
    <div class="acc-premium ${expired ? "is-expired" : ""}">
      <div class="acc-ring" style="--pct:${ringPct}">
        <div class="acc-ring-in">
          <span class="acc-ring-num">${expired ? "0" : daysLeft}</span>
          <span class="acc-ring-lbl">${expired ? "ကုန်" : "Day"}</span>
        </div>
      </div>
      <div class="acc-premium-info">
        <div class="acc-premium-top">
          <span class="acc-premium-tag">${clockSvg} Premium ရက်ကျန်</span>
          <span class="acc-pchip ${expired ? "off" : "on"}">P-${daysLeft}Day</span>
        </div>
        <div class="acc-countdown">
          ${expired
            ? `<span class="acc-cd-expired">သက်တမ်း ကုန်ဆုံးပြီ</span>`
            : `<b>${dDays}</b> ရက် <b>${dHours}</b> နာရီ <b>${dMins}</b> မိနစ်`}
        </div>
        <div class="acc-expdate">ကုန်ဆုံးမည့်ရက် · ${htmlEscape(exp)} (MMT)</div>
      </div>
    </div>

    <!-- devices -->
    <div class="acc-section">
      <div class="acc-section-head">
        <span class="acc-section-title">${phoneSvg} ချိတ်ဆက်ထားသော Device</span>
        <span class="acc-dev-count">${devices.length}/${MAX_DEVICES_PER_KEY}</span>
      </div>
      <div class="acc-dev-table">
        <table>
          <thead><tr><th>Device</th><th>Last seen</th></tr></thead>
          <tbody>${devRows || '<tr><td colspan="2" class="acc-dev-empty">Device မရှိသေးပါ</td></tr>'}</tbody>
        </table>
      </div>
    </div>

    <!-- footer actions -->
    <div class="acc-actions">
      <a class="acc-btn home" href="/">${homeSvg}<span>Home</span></a>
      <a class="acc-btn out" href="/logout">${outSvg}<span>ဤ Device မှ ထွက်ရန်</span></a>
    </div>

  </div>
</div>`;

  const accCss = `
    .acc-welcome{display:flex;align-items:center;gap:14px;padding:16px 18px;border-radius:16px;margin-bottom:20px;
      background:linear-gradient(135deg,rgba(15,157,88,.18),rgba(34,197,94,.1));border:1px solid #1f7a48;
      animation:accWelcomeIn .45s cubic-bezier(.2,.8,.2,1)}
    @keyframes accWelcomeIn{from{opacity:0;transform:translateY(-10px) scale(.98)}to{opacity:1;transform:none}}
    .acc-welcome-ic{width:46px;height:46px;flex:0 0 46px;border-radius:50%;display:flex;align-items:center;justify-content:center;
      background:linear-gradient(135deg,#0f9d58,#22c55e);box-shadow:0 6px 16px rgba(34,197,94,.4)}
    .acc-welcome-ic svg{width:24px;height:24px;color:#fff}
    .acc-welcome-tx{flex:1;min-width:0}
    .acc-welcome-h{font-size:15.5px;font-weight:900;color:#eafff2;margin-bottom:3px}
    .acc-welcome-p{font-size:13px;color:#bfe9cf;line-height:1.55}
    .acc-welcome-p b{color:#7df0a8}
    .acc-welcome-x{flex:0 0 auto;width:30px;height:30px;border-radius:8px;border:0;background:rgba(255,255,255,.08);
      color:#cfe;cursor:pointer;font-size:14px;font-weight:700;transition:.15s}
    .acc-welcome-x:hover{background:rgba(255,255,255,.16)}
    .acc-wrap{min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:26px 16px 40px}
    .acc-card{width:100%;max-width:560px;background:linear-gradient(180deg,rgba(17,23,42,.96),rgba(11,15,28,.96));
      border:1px solid var(--line);border-radius:22px;padding:26px;box-shadow:0 24px 70px rgba(0,0,0,.6)}
    .acc-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px}
    .acc-id{display:flex;align-items:center;gap:14px;min-width:0}
    .acc-keyicon{width:54px;height:54px;flex:0 0 54px;border-radius:16px;display:flex;align-items:center;justify-content:center;color:#fff;
      background:linear-gradient(140deg,#ff3a3f,#e50914 55%,#a3060d);
      box-shadow:0 8px 22px rgba(229,9,20,.5),inset 0 1px 0 rgba(255,255,255,.3)}
    .acc-keyicon svg{width:27px;height:27px}
    .acc-id-text{min-width:0}
    .acc-id-text h1{margin:0;font-size:23px;font-weight:900;letter-spacing:.3px}
    .acc-keycode{display:flex;align-items:center;gap:8px;margin-top:5px;flex-wrap:wrap}
    .acc-keycode code{color:var(--acc2);font-size:13px;letter-spacing:1px;font-weight:700}
    .acc-badge{font-size:10.5px;font-weight:900;padding:3px 9px;border-radius:6px;letter-spacing:.6px}
    .acc-badge.paid{background:linear-gradient(135deg,#0f9d58,#22c55e);color:#04210f}
    .acc-badge.trial{background:linear-gradient(135deg,#f59e0b,#fbbf24);color:#2a1700}
    .acc-back{display:inline-flex;align-items:center;gap:6px;text-decoration:none;color:var(--mut);font-weight:700;font-size:13px;
      padding:8px 13px;border:1px solid var(--line);border-radius:10px;transition:.15s;white-space:nowrap}
    .acc-back svg{width:15px;height:15px}
    .acc-back:hover{color:#fff;border-color:var(--acc2)}

    .acc-alert{padding:11px 14px;border-radius:11px;margin-bottom:14px;font-size:13.5px;line-height:1.5}
    .acc-alert.ok{background:#10331a;border:1px solid #225a30;color:#cfc}
    .acc-alert.err{background:#3a1020;border:1px solid #6a2030;color:#ffd}

    .acc-premium{display:flex;align-items:center;gap:20px;padding:20px;border-radius:18px;
      background:linear-gradient(135deg,rgba(15,42,26,.7),rgba(14,24,48,.7));border:1px solid #1f5a38;margin-bottom:22px}
    .acc-premium.is-expired{background:linear-gradient(135deg,rgba(58,16,32,.7),rgba(24,16,30,.7));border-color:#6a2030}
    .acc-ring{width:92px;height:92px;flex:0 0 92px;border-radius:50%;display:flex;align-items:center;justify-content:center;
      background:conic-gradient(var(--ok) calc(var(--pct,0)*1%),rgba(255,255,255,.08) 0);position:relative}
    .acc-premium.is-expired .acc-ring{background:conic-gradient(#f66 calc(var(--pct,0)*1%),rgba(255,255,255,.08) 0)}
    .acc-ring-in{width:72px;height:72px;border-radius:50%;background:#0b0f1c;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:1}
    .acc-ring-num{font-size:28px;font-weight:900;color:#fff}
    .acc-ring-lbl{font-size:11px;color:var(--mut);font-weight:700;margin-top:3px}
    .acc-premium-info{flex:1;min-width:0}
    .acc-premium-top{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:8px}
    .acc-premium-tag{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--mut);font-weight:700}
    .acc-premium-tag svg{width:14px;height:14px}
    .acc-pchip{font-size:12px;font-weight:900;padding:3px 10px;border-radius:7px;letter-spacing:.4px}
    .acc-pchip.on{background:linear-gradient(135deg,#0f9d58,#22c55e);color:#fff}
    .acc-pchip.off{background:#3a2530;color:#f88}
    .acc-countdown{font-size:18px;font-weight:700;color:#eef2ff}
    .acc-countdown b{color:var(--acc2);font-size:21px;font-weight:900}
    .acc-cd-expired{color:#f88;font-size:17px;font-weight:800}
    .acc-expdate{font-size:11.5px;color:var(--mut);margin-top:6px}

    .acc-section{margin-bottom:22px}
    .acc-section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:11px}
    .acc-section-title{display:inline-flex;align-items:center;gap:8px;font-size:15px;font-weight:800}
    .acc-section-title svg{width:17px;height:17px;color:var(--acc2)}
    .acc-dev-count{font-size:12px;font-weight:800;color:#cef;background:#15203a;padding:4px 11px;border-radius:20px;border:1px solid var(--line)}
    .acc-dev-table{border:1px solid var(--line);border-radius:13px;overflow:hidden}
    .acc-dev-table table{width:100%;border-collapse:collapse;font-size:13px}
    .acc-dev-table thead tr{background:linear-gradient(90deg,#15192e,#1a1430)}
    .acc-dev-table th{text-align:left;padding:10px 14px;font-size:10.5px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px;font-weight:800}
    .acc-dev-table td{padding:12px 14px;border-top:1px solid var(--line)}
    .dev-name{font-weight:600;color:#e7ecf8}
    .dev-seen{white-space:nowrap;font-size:12px;color:var(--mut)}
    .acc-dev-empty{text-align:center;color:var(--mut);padding:20px !important}

    .acc-actions{display:flex;gap:10px}
    .acc-btn{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:13px;border-radius:12px;
      text-decoration:none;font-weight:800;font-size:14px;transition:.16s}
    .acc-btn svg{width:17px;height:17px}
    .acc-btn.home{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;box-shadow:0 6px 16px rgba(229,9,20,.35)}
    .acc-btn.home:hover{filter:brightness(1.08);transform:translateY(-1px)}
    .acc-btn.out{background:#1a1320;color:#f88;border:1px solid #5a2030}
    .acc-btn.out:hover{background:#241622;transform:translateY(-1px)}

    @media(max-width:480px){
      .acc-card{padding:20px}
      .acc-premium{flex-direction:column;text-align:center;gap:16px}
      .acc-premium-top{justify-content:center}
      .acc-countdown{font-size:16px}
      .acc-actions{flex-direction:column}
    }
  `;

  return pageShell("My Key — CM FLIX", body, { extraCss: AUTH_CSS + accCss });
}


/* ══════════════════════════════════════════════════
   ADMIN PAGE
   ══════════════════════════════════════════════════ */
function adminPage(keys, stats, csrfToken, newKey = "", info = "", items = [], itPage = 1, itTotalPages = 1, itQuery = "", itTotal = 0, itType = "", tmdbOn = false, draftCount = 0) {
  const keyRows = keys.map(k => {
    const exp = k.expires_at ? new Date(k.expires_at).toLocaleString("en-GB", { hour12: false, timeZone: "Asia/Yangon" }) : "—";
    const active = (k.expires_at && Date.now() < k.expires_at && !k.disabled);
    const status = k.disabled
      ? '<span style="color:#888;font-weight:700">● DISABLED</span>'
      : active ? '<span style="color:#6f6;font-weight:700">● ACTIVE</span>'
               : '<span style="color:#f66;font-weight:700">● EXPIRED</span>';
    const roleBadge = k.role === "paid" ? '<span class="badge badge-paid">PAID</span>' : '<span class="badge badge-trial">TRIAL</span>';
    return `<tr>
      <td><input type="checkbox" class="row-check" value="${htmlEscape(k.keyId)}"></td>
      <td><code style="font-size:12px;color:#cef">${htmlEscape(k.keyId)}</code></td>
      <td>${status}</td><td>${roleBadge}</td>
      <td style="white-space:nowrap;font-size:11.5px">${htmlEscape(exp)}</td>
      <td style="text-align:center">${(k.device_count || 0)}/${MAX_DEVICES_PER_KEY}</td>
      <td style="font-size:11px;color:var(--mut)">${htmlEscape(k.note || "—")}</td>
      <td>
        <form method="POST" action="/admin/extend" style="display:inline-flex;gap:4px;align-items:center">
          <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
          <input type="hidden" name="key" value="${htmlEscape(k.keyId)}">
          <input type="number" name="days" value="30" min="1" max="3650" style="width:56px;padding:5px">
          <button type="submit" class="btn-ext">+Days</button>
        </form>
        <form method="POST" action="/admin/resetdevices" style="display:inline" onsubmit="return confirm('Reset devices for ${htmlEscape(k.keyId)}?')">
          <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
          <input type="hidden" name="key" value="${htmlEscape(k.keyId)}">
          <button type="submit" class="btn-reset">Reset</button>
        </form>
        <form method="POST" action="/admin/delete" style="display:inline" onsubmit="return confirm('Delete ${htmlEscape(k.keyId)}?')">
          <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
          <input type="hidden" name="key" value="${htmlEscape(k.keyId)}">
          <button type="submit" class="btn-del">Del</button>
        </form>
      </td>
    </tr>`;
  }).join("");

  const newKeyBox = newKey ? `
    <div class="ok" style="font-size:15px">✅ Key အသစ်: <code style="font-size:17px;color:#04210f;background:#cfc;padding:3px 8px;border-radius:6px;font-weight:800;user-select:all">${htmlEscape(newKey)}</code></div>` : "";

  const itemRows = items.map(m => {
    const cat = CATEGORIES[m.type] || CATEGORIES.movie;
    const isDraft = m.published === 0;
    const statusBadge = isDraft
      ? '<span class="badge" style="background:#5a3a10;color:#ffcf80">⏳ DRAFT</span>'
      : '<span class="badge" style="background:#103a1a;color:#7df0a8">● LIVE</span>';
    return `<tr ${isDraft ? 'style="background:#1a1408"' : ''}>
      <td style="width:54px"><div class="thumb" style="background-image:url('${htmlEscape(m.poster || "")}')">${m.poster ? "" : "🎬"}</div></td>
      <td><a href="/watch/${htmlEscape(m.id)}" target="_blank" style="color:#cef;text-decoration:none;font-weight:600">${htmlEscape(m.title || "Untitled")}</a>
        <div style="font-size:10.5px;color:var(--mut)"><code>${htmlEscape(m.id)}</code>${m.slide_image ? ' · 🖼️ slide' : ''}</div></td>
      <td><span class="badge" style="background:#1a2540;color:#cde">${cat.icon} ${htmlEscape(cat.name)}</span><br>${statusBadge}</td>
      <td style="white-space:nowrap;font-size:11.5px">${m.created_at ? new Date(m.created_at).toLocaleDateString("en-GB", { timeZone: "Asia/Yangon" }) : "—"}</td>
      <td>
        <a class="btn-ext" href="/admin/edit/${htmlEscape(m.id)}" style="text-decoration:none">Edit</a>
        <form method="POST" action="/admin/item/delete" style="display:inline" onsubmit="return confirm('Delete: ${htmlEscape(m.title || m.id)}?')">
          <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
          <input type="hidden" name="id" value="${htmlEscape(m.id)}">
          <button type="submit" class="btn-del">Del</button>
        </form>
      </td>
    </tr>`;
  }).join("");

  const itHref = (p) => {
    let q = `?itpage=${p}`;
    if (itQuery) q += `&itq=${encodeURIComponent(itQuery)}`;
    if (itType) q += `&ittype=${encodeURIComponent(itType)}`;
    return "/admin" + q + "#content";
  };
  const itemPager = buildPager(itPage, itTotalPages, itHref);

  const tmdbBox = tmdbOn ? `
    <div style="background:#0e2030;border:1px solid #1f4a6a;border-radius:11px;padding:12px;margin-bottom:14px">
      <div style="font-weight:800;color:#7fd3ff;margin-bottom:8px">🎞️ TMDB Auto-Fill (Title ထည့်ပြီး နှိပ်ပါ)</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input type="text" id="tmdbQ" placeholder="Movie / Series Title…" style="flex:1;min-width:160px">
        <button type="button" class="btn-ext" id="tmdbBtn" style="padding:9px 16px">Auto-fill</button>
      </div>
      <div id="tmdbMsg" style="font-size:11.5px;color:var(--mut);margin-top:6px"></div>
    </div>` : `
    <div style="font-size:11px;color:var(--mut);margin-bottom:10px">💡 TMDB auto-fill သုံးချင်ရင် <code>TMDB_API_KEY</code> environment variable ထည့်ပါ။</div>`;

  const body = `
<div class="auth-wrap" style="align-items:flex-start;padding-top:24px"><div class="auth-card" style="max-width:1120px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
    <div style="display:flex;align-items:center;gap:12px">
      ${logoMark()}
      <div>
        <h1 style="margin:0;font-size:22px;text-align:left">CM FLIX · Admin</h1>
        <p class="sub" style="margin:4px 0 0;text-align:left">
          Keys: <strong>${stats.total}</strong> ·
          <span style="color:#6f6">Active ${stats.active}</span> ·
          <span style="color:#f66">Expired ${stats.expired}</span> ·
          Paid ${stats.paid} · Trial ${stats.trial} ·
          🎞️ Content ${itTotal}
        </p>
      </div>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <a href="/" target="_blank" style="color:var(--acc2);text-decoration:none;font-weight:700;font-size:13px;padding:6px 12px;border:1px solid var(--line);border-radius:6px">View Site</a>
      <a href="/admin/export" style="color:var(--acc2);text-decoration:none;font-weight:700;font-size:13px;padding:6px 12px;border:1px solid var(--line);border-radius:6px">CSV</a>
      <a href="/logout" style="color:#f88;text-decoration:none;font-weight:700;font-size:13px">Logout</a>
    </div>
  </div>
  ${info ? `<div class="ok">${htmlEscape(info)}</div>` : ""}
  ${newKeyBox}

  <!-- ════ ADD CONTENT ════ -->
  <div id="content" style="background:#15101f;border:1px solid #3a1f3f;border-radius:13px;padding:16px;margin-bottom:18px">
    <div style="font-weight:800;color:var(--acc2);margin-bottom:10px">➕ Content အသစ် တင်ရန် (Signed-link stream — link မပေါက်ကြား)</div>
    ${tmdbBox}
    <form method="POST" action="/admin/item/create" id="addForm">
      <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
      <div style="display:grid;grid-template-columns:1fr;gap:10px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div><label>Category</label>
            <select name="type" id="addType" onchange="cmToggleType(this.value,'add')">
              <option value="movie">🎬 R Mosaic</option>
              <option value="series">📺 Series</option>
              <option value="adult">🔞 21+ mmsub</option>
              <option value="random">⭐ Random Best</option>
            </select>
          </div>
          <div><label>Title</label><input type="text" name="title" id="addTitle" placeholder="ဥပမာ - Action 2025" required></div>
        </div>
                <div style="background:#0e2030;border:1px solid #1f4a6a;border-radius:11px;padding:12px">
          <label style="margin-top:0">👩 မင်းသမီးနာမည် (များစွာဆို comma "," ခြားပါ)</label>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <input type="text" name="actress" id="addActress" placeholder="ဥပမာ - Kitano Mina, Itsukaichi Mei" style="flex:1;min-width:180px">
            <button type="button" class="btn-ext" id="actressPrev" style="padding:9px 16px">ပုံကြည့်</button>
          </div>
          <div id="actressPrevBox" style="display:none;gap:10px;flex-wrap:wrap;margin-top:10px"></div>
          <div id="actressPrevMsg" style="font-size:11.5px;color:var(--mut);margin-top:6px"></div>
        </div>

        <div><label>Poster URL (ထောင်လိုက် ပုံ — card အတွက်)</label><input type="url" name="poster" id="addPoster" placeholder="https://.../poster.jpg"></div>
        <div><label>Slide Banner URL (အလျားလိုက် ပုံ — slider အတွက်၊ optional)</label><input type="url" name="slide_image" id="addSlide" placeholder="https://.../banner-wide.jpg">
          <div style="font-size:11px;color:var(--mut);margin-top:4px">ကွက်လပ်ထားရင် slider မှာ poster ကို သုံးမယ်။ (16:9 / landscape ပုံ ထည့်ရင် အကောင်းဆုံး)</div>
        </div>
        <div class="single-fields"><label>Video URL (direct / R2)</label><input type="url" name="video_url" placeholder="https://.../video.mp4"></div>
        <div class="single-fields"><label>Download URL (optional — ကွက်လပ်ထားရင် video URL ကို သုံးမယ်)</label><input type="url" name="download_url" placeholder="https://.../download.mp4"></div>
        <div class="series-fields" style="display:none">
  <label>Series Episodes (JSON သို့မဟုတ် SQLite Task log များ တိုက်ရိုက်ထည့်နိုင်သည်)</label>
  <textarea name="seasons_json" placeholder="JSON Format ဖြင့်ဖြစ်စေ သို့မဟုတ် ဖုန်းထဲက ကူးယူလာသည့် SQLite Task logs/စာသားများကိုဖြစ်စေ ဤနေရာတွင် တိုက်ရိုက် Paste ချပေးနိုင်ပါသည်။"></textarea>
  <div style="font-size:11px;color:var(--mut);margin-top:4px">Format: JSON စနစ် (သို့မဟုတ်) SQLite task log များကို တိုက်ရိုက်ထည့်သွင်းပါက စနစ်မှ အလိုအလျောက် အပိုင်းများကို ခွဲထုတ်ပေးပါမည်။</div>
</div>
        <div><label>Note / ဖော်ပြချက် (optional)</label><textarea name="note" id="addNote" placeholder="ဇာတ်လမ်းအကျဉ်း…" style="min-height:80px"></textarea></div>
      </div>
      <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap">
        <button type="submit" name="save_mode" value="draft" class="btn" style="flex:1;min-width:160px;background:linear-gradient(135deg,#5a3a10,#8a5a14)">📥 Draft အဖြစ်သိမ်းမယ် (မပြသေး)</button>
        <button type="submit" name="save_mode" value="publish" class="btn" style="flex:1;min-width:160px">🚀 တန်းတင်မယ် (Publish)</button>
      </div>
      <div style="font-size:11.5px;color:var(--mut);margin-top:8px;line-height:1.6">💡 <b>Draft</b> ဆို သိမ်းထားရုံပါ — Home/Category တွေမှာ မပေါ်သေးပါ။ ကြိုက်တဲ့ကားအရေအတွက် Draft နဲ့ စုထားပြီး အောက်က <b>"Publish All Drafts"</b> ခလုတ်နဲ့ တစ်ခါတည်း အကုန်တင်နိုင်ပါတယ်။</div>
    </form>
  </div>

  <!-- ════ PUBLISH ALL DRAFTS BAR ════ -->
  <div style="background:${draftCount > 0 ? '#1a1408' : '#0e1830'};border:1px solid ${draftCount > 0 ? '#5a3a10' : 'var(--line)'};border-radius:13px;padding:16px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap">
    <div>
      <div style="font-weight:800;color:${draftCount > 0 ? '#ffcf80' : '#cef'};font-size:15px">⏳ Draft အရေအတွက်: ${draftCount} ကား</div>
      <div style="font-size:12px;color:var(--mut);margin-top:4px">${draftCount > 0 ? 'အောက်က ခလုတ်နှိပ်ရင် Draft အားလုံးကို တစ်ခါတည်း Publish (တင်) လုပ်ပါမယ်။' : 'မတင်ရသေးတဲ့ Draft မရှိသေးပါ။'}</div>
    </div>
    ${draftCount > 0 ? `
    <form method="POST" action="/admin/item/publishall" onsubmit="return confirm('Draft ${draftCount} ကား အားလုံးကို တစ်ခါတည်း Publish တင်မှာ သေချာပါသလား?')" style="margin:0">
      <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
      <button type="submit" class="btn" style="width:auto;margin:0;padding:13px 24px;background:linear-gradient(135deg,#0f9d58,#22c55e);box-shadow:0 6px 16px rgba(34,197,94,.4)">🚀 Publish All Drafts (${draftCount})</button>
    </form>` : ''}
  </div>

  <!-- ════ CONTENT LIST ════ -->
  <form method="GET" action="/admin" style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">
    <input type="search" name="itq" value="${htmlEscape(itQuery)}" placeholder="🔍 title / id ရှာရန်…" style="flex:1;min-width:180px">
    <select name="ittype" style="width:auto">
      <option value="">All</option>
      <option value="movie" ${itType === "movie" ? "selected" : ""}>🎬 R Mosaic</option>
      <option value="series" ${itType === "series" ? "selected" : ""}>📺 Series</option>
      <option value="adult" ${itType === "adult" ? "selected" : ""}>🔞 21+ mmsub</option>
      <option value="random" ${itType === "random" ? "selected" : ""}>⭐ Random Best</option>
    </select>
    <input type="hidden" name="itpage" value="1">
    <button type="submit" class="btn" style="width:auto;margin:0;padding:11px 18px">Search</button>
  </form>
  ${items.length ? `
  <div style="overflow:auto;border:1px solid var(--line);border-radius:11px;margin-bottom:6px">
    <table style="width:100%;border-collapse:collapse;font-size:13px;min-width:640px">
      <thead><tr style="background:#15101f;text-align:left"><th></th><th>Title / ID</th><th>Type</th><th>Added</th><th>Action</th></tr></thead>
      <tbody>${itemRows}</tbody>
    </table>
  </div>${itemPager}` : `<div style="text-align:center;color:var(--mut);padding:24px;border:1px solid var(--line);border-radius:11px;margin-bottom:16px">${itQuery || itType ? "မတွေ့ပါ" : "Content မရှိသေးပါ"}</div>`}

  <!-- ════ CREATE KEY ════ -->
  <div style="background:#0e1830;border:1px solid var(--line);border-radius:13px;padding:16px;margin:20px 0 16px">
    <div style="font-weight:800;color:#cef;margin-bottom:10px">🔑 Key အသစ် ဖန်တီးရန်</div>
    <form method="POST" action="/admin/create" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
      <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
      <div><label>သက်တမ်း (ရက်)</label><input type="number" name="days" value="1" min="1" max="3650" style="width:90px"></div>
      <div><label>အမျိုးအစား</label><select name="role" style="width:auto"><option value="trial">Trial</option><option value="paid">Paid</option></select></div>
      <div><label>အရေအတွက်</label><input type="number" name="count" value="1" min="1" max="50" style="width:80px"></div>
      <div style="flex:1;min-width:150px"><label>မှတ်ချက်</label><input type="text" name="note" placeholder="ဥပမာ - Ko Aung"></div>
      <button type="submit" class="btn" style="width:auto;margin:0;padding:11px 18px">Create</button>
    </form>
  </div>

  <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
    <input id="q" type="text" placeholder="🔍 Key / note ရှာရန်…" oninput="filterRows()" style="flex:1;min-width:180px">
    <select id="statusFilter" onchange="filterRows()" style="width:auto"><option value="">All status</option><option value="active">Active</option><option value="expired">Expired</option></select>
  </div>
  <div id="bulkBar" style="display:none;background:#131f33;border:1px solid var(--line);border-radius:9px;padding:10px;margin-bottom:10px;align-items:center;gap:8px;flex-wrap:wrap">
    <span id="bulkCount" style="color:#cef;font-weight:600">0 selected</span>
    <form method="POST" action="/admin/bulk" style="display:flex;gap:6px;align-items:center;margin:0">
      <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
      <input type="hidden" name="keys" id="bulkKeys">
      <input type="number" name="days" value="30" min="1" max="3650" style="width:64px;padding:6px">
      <button type="submit" name="action" value="extend" class="btn-ext">Extend all</button>
      <button type="submit" name="action" value="delete" class="btn-del" onclick="return confirm('Delete all selected?')">Delete all</button>
    </form>
  </div>
  <div style="overflow:auto;border:1px solid var(--line);border-radius:11px">
    <table style="width:100%;border-collapse:collapse;font-size:13px;min-width:860px">
      <thead><tr style="background:#131f33;text-align:left">
        <th style="width:28px"><input type="checkbox" id="checkAll" onclick="toggleAll(this)"></th>
        <th>Key</th><th>Status</th><th>Type</th><th>Expires</th><th>Devices</th><th>Note</th><th>Action</th>
      </tr></thead>
      <tbody id="utbody">${keyRows || '<tr><td colspan="8" style="padding:24px;text-align:center;color:var(--mut)">Key မရှိသေးပါ</td></tr>'}</tbody>
    </table>
  </div>
</div></div>
<style>
  th,td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
  th{font-size:11.5px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
  tr:hover td{background:#0e1830}
  .btn-ext,.btn-del,.btn-reset{width:auto;margin:0;padding:6px 10px;font-size:12px;border-radius:7px;border:0;font-weight:700;cursor:pointer;font-family:inherit;display:inline-block}
  .btn-ext{background:var(--acc2);color:#fff}
  .btn-reset{background:#f59e0b;color:#2a1700;margin-left:6px}
  .btn-del{background:#c43;color:#fff;margin-left:6px}
  .thumb{width:36px;height:52px;border-radius:6px;background-size:cover;background-position:center;background-color:#0e1830;display:flex;align-items:center;justify-content:center;font-size:16px}
</style>
<script>
  function filterRows(){
    var q=(document.getElementById('q').value||'').toLowerCase().trim();
    var sf=document.getElementById('statusFilter').value;
    document.querySelectorAll('#utbody tr').forEach(function(tr){
      var t=tr.textContent.toLowerCase();
      var mq=!q||t.indexOf(q)!==-1;
      var ms=!sf||(sf==='active'&&t.indexOf('active')!==-1)||(sf==='expired'&&t.indexOf('expired')!==-1);
      tr.style.display=(mq&&ms)?'':'none';
    });
  }
  function toggleAll(cb){ document.querySelectorAll('.row-check').forEach(function(c){ if(c.closest('tr').style.display!=='none') c.checked=cb.checked; }); updateBulk(); }
  function updateBulk(){
    var ch=Array.from(document.querySelectorAll('.row-check:checked')).map(function(c){return c.value;});
    document.getElementById('bulkBar').style.display=ch.length?'flex':'none';
    document.getElementById('bulkCount').textContent=ch.length+' selected';
    document.getElementById('bulkKeys').value=ch.join(',');
  }
  document.addEventListener('change',function(e){ if(e.target.classList.contains('row-check')) updateBulk(); });
  function cmToggleType(val, scope){
    var root=document.getElementById(scope==='add'?'addForm':'editForm');
    if(!root) return;
    var isSeries=(val==='series');
    root.querySelectorAll('.series-fields').forEach(function(el){ el.style.display=isSeries?'block':'none'; });
    root.querySelectorAll('.single-fields').forEach(function(el){ el.style.display=isSeries?'none':'block'; });
  }
    // Actress preview (javtiful) — comma-separated နာမည်တွေ ပုံကြိုကြည့်
  (function(){
    var btn=document.getElementById('actressPrev'); if(!btn) return;
    var inp=document.getElementById('addActress');
    var box=document.getElementById('actressPrevBox');
    var msg=document.getElementById('actressPrevMsg');
    btn.addEventListener('click',function(){
      var raw=(inp.value||'').trim();
      if(!raw){ msg.textContent='နာမည် ထည့်ပါ။'; return; }
      var names=raw.split(',').map(function(s){return s.trim();}).filter(Boolean).slice(0,10);
      box.style.display='flex'; box.innerHTML=''; msg.textContent='ရှာနေသည်…';
      var done=0;
      names.forEach(function(name){
        var cell=document.createElement('div');
        cell.style.cssText='display:flex;flex-direction:column;align-items:center;gap:5px;width:78px';
        cell.innerHTML='<div style="width:64px;height:64px;border-radius:50%;background:#0e1830;border:2px solid #1f4a6a;display:flex;align-items:center;justify-content:center;font-size:11px;color:#789">…</div><div style="font-size:10.5px;color:#cde;text-align:center">'+name+'</div>';
        box.appendChild(cell);
        fetch('/admin/actress?name='+encodeURIComponent(name))
          .then(function(r){return r.json();})
          .then(function(d){
            done++;
            var c=cell.querySelector('div');
            if(d.ok && d.image){
              c.style.backgroundImage="url('"+d.image+"')";
              c.style.backgroundSize='cover'; c.style.backgroundPosition='center';
              c.style.borderColor='#22c55e'; c.textContent='';
            }else{
              c.style.borderColor='#c43'; c.textContent='✕';
            }
            if(done===names.length) msg.textContent='✅ ပြီးပါပြီ (✕ = ရှာမတွေ့)';
          })
          .catch(function(){ done++; });
      });
    });
  })();

  // TMDB auto-fill
  (function(){
    var btn=document.getElementById('tmdbBtn'); if(!btn) return;
    btn.addEventListener('click',function(){
      var q=(document.getElementById('tmdbQ').value||document.getElementById('addTitle').value||'').trim();
      var type=document.getElementById('addType').value;
      var msg=document.getElementById('tmdbMsg');
      if(!q){ msg.textContent='Title ထည့်ပါ။'; return; }
      msg.textContent='ရှာနေသည်…';
      fetch('/admin/tmdb?q='+encodeURIComponent(q)+'&type='+encodeURIComponent(type))
        .then(function(r){return r.json();})
        .then(function(d){
          if(!d.ok){ msg.textContent=d.error||'ရှာမတွေ့ပါ'; return; }
          if(d.poster) document.getElementById('addPoster').value=d.poster;
          if(d.backdrop) document.getElementById('addSlide').value=d.backdrop;
          if(d.overview && !document.getElementById('addNote').value) document.getElementById('addNote').value=d.overview;
          if(!document.getElementById('addTitle').value && d.tmdb_title) document.getElementById('addTitle').value=d.tmdb_title+(d.year?(' ('+d.year+')'):'');
          msg.textContent='✅ ဖြည့်ပြီးပါပြီ: '+(d.tmdb_title||q)+(d.year?(' · '+d.year):'');
        })
        .catch(function(){ msg.textContent='Error ဖြစ်သွားသည်။'; });
    });
  })();
</script>`;
  return pageShell("Admin — CM FLIX", body, { extraCss: AUTH_CSS });
}

/* ══════════════════════════════════════════════════
   ADMIN EDIT PAGE
   ══════════════════════════════════════════════════ */
function adminEditPage(item, csrfToken, error = "") {
  const isSeries = item.type === "series";
  const seasonsJson = isSeries ? JSON.stringify(item.seasons || [], null, 2) : "";
  const body = `
<div class="auth-wrap" style="align-items:flex-start;padding-top:24px"><div class="auth-card" style="max-width:760px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <h1 style="margin:0;font-size:20px;text-align:left">✏️ Edit — ${htmlEscape(item.title)}</h1>
    <a href="/admin#content" style="color:var(--acc2);text-decoration:none;font-weight:700;font-size:13px">← Back</a>
  </div>
  ${error ? `<div class="err">${htmlEscape(error)}</div>` : ""}
  <form method="POST" action="/admin/item/update" id="editForm">
    <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
    <input type="hidden" name="id" value="${htmlEscape(item.id)}">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div><label>Category</label>
        <select name="type" onchange="cmToggleType(this.value,'edit')">
          <option value="movie" ${item.type === "movie" ? "selected" : ""}>🎬 R Mosaic</option>
          <option value="series" ${item.type === "series" ? "selected" : ""}>📺 Series</option>
          <option value="adult" ${item.type === "adult" ? "selected" : ""}>🔞 21+ mmsub</option>
          <option value="random" ${item.type === "random" ? "selected" : ""}>⭐ Random Best</option>
        </select>
      </div>
      <div><label>Title</label><input type="text" name="title" value="${htmlEscape(item.title || "")}" required></div>
    </div>
        <label>👩 မင်းသမီးနာမည် (များစွာဆို comma "," ခြားပါ)</label>
    <input type="text" name="actress" value="${htmlEscape(item.actress || "")}" placeholder="ဥပမာ - Kitano Mina, Itsukaichi Mei">

    <label>Poster URL (ထောင်လိုက် — card)</label><input type="url" name="poster" value="${htmlEscape(item.poster || "")}">
    <label>Slide Banner URL (အလျားလိုက် — slider, optional)</label><input type="url" name="slide_image" value="${htmlEscape(item.slide_image || "")}">
    <div class="single-fields" style="display:${isSeries ? "none" : "block"}">
      <label>Video URL</label><input type="url" name="video_url" value="${htmlEscape(item.video_url || "")}">
      <label>Download URL (optional)</label><input type="url" name="download_url" value="${htmlEscape(item.download_url || "")}">
    </div>
    <div class="series-fields" style="display:${isSeries ? "block" : "none"}">
      <label>Series Episodes (JSON)</label>
      <textarea name="seasons_json" style="min-height:220px;font-family:ui-monospace,monospace;font-size:12.5px">${htmlEscape(seasonsJson)}</textarea>
    </div>
    <label>Note</label><textarea name="note" style="min-height:100px">${htmlEscape(item.note || "")}</textarea>
    <button type="submit" class="btn">💾 သိမ်းမယ်</button>
  </form>
</div></div>
<script>
  function cmToggleType(val){
    var root=document.getElementById('editForm');
    var isSeries=(val==='series');
    root.querySelectorAll('.series-fields').forEach(function(el){ el.style.display=isSeries?'block':'none'; });
    root.querySelectorAll('.single-fields').forEach(function(el){ el.style.display=isSeries?'none':'block'; });
  }
</script>`;
  return pageShell("Edit — CM FLIX", body, { extraCss: AUTH_CSS });
}

/* ══════════════════════════════════════════════════
   AUTO-PARSE SQL LOGS & SERIES JSON SANITIZER
   ══════════════════════════════════════════════════ */
function parseRawTextToSeasons(rawText) {
  const urlRegex = /(https?:\/\/[^\s"'<>^|`\x00-\x1F\x7F-\x9F]+\.(?:mp4|mkv|m3u8|webm|mov)(?:\?[^\s"<>^|`\x00-\x1F\x7F-\x9F]*)?)/gi;
  const matches = [...new Set(rawText.match(urlRegex) || [])];
  
  if (!matches.length) return null;
  
  const epsMap = [];
  
  for (let url of matches) {
    url = url.split(/[\x00-\x1F\x7F-\x9F]/)[0];
    const decoded = decodeURIComponent(url);
    let seasonNum = 1;
    let epNum = null;
    
    const s1e1 = decoded.match(/[sS](\d+)[eE][pP]?(\d+)/);
    if (s1e1) {
      seasonNum = parseInt(s1e1[1], 10);
      epNum = parseInt(s1e1[2], 10);
    } else {
      const eOnly = decoded.match(/(?:[^a-zA-Z0-9]|^)[eE](\d+)(?:[^a-zA-Z0-9]|$)/);
      if (eOnly) {
        epNum = parseInt(eOnly[1], 10);
      } else {
        const epWord = decoded.match(/(?:[^a-zA-Z0-9]|^)(?:ep|episode)[-_\s]?(\d+)/i);
        if (epWord) {
          epNum = parseInt(epWord[1], 10);
        } else {
          const baseName = decoded.split('/').pop() || "";
          const numOnly = baseName.match(/(?:^|[^0-9])(\d+)(?:\.mp4|\.mkv|\.avi|$)/i);
          if (numOnly) {
            epNum = parseInt(numOnly[1], 10);
          }
        }
      }
    }
    
    if (epNum !== null && epNum > 1000) {
      epNum = null;
    }
    
    epsMap.push({
      season: seasonNum,
      ep: epNum,
      video_url: url
    });
  }
  
  let fallbackEp = 1;
  epsMap.forEach(item => {
    if (item.ep === null) {
      item.ep = fallbackEp++;
    }
  });
  
  const seasonsGrouped = {};
  for (const item of epsMap) {
    if (!seasonsGrouped[item.season]) {
      seasonsGrouped[item.season] = [];
    }
    seasonsGrouped[item.season].push({
      ep: item.ep,
      title: `Episode ${item.ep}`,
      video_url: item.video_url,
      download_url: ""
    });
  }
  
  const finalSeasons = Object.keys(seasonsGrouped)
    .map(s => {
      const sortedEps = seasonsGrouped[s].sort((a, b) => a.ep - b.ep);
      const uniqueEps = [];
      const seen = new Set();
      for (const e of sortedEps) {
        if (!seen.has(e.ep)) {
          seen.add(e.ep);
          uniqueEps.push(e);
        }
      }
      return {
        season: parseInt(s, 10),
        episodes: uniqueEps
      };
    })
    .sort((a, b) => a.season - b.season);
    
  return finalSeasons;
}

function sanitizeSeasons(raw) {
  const trimmed = String(raw || "").trim();
  
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) {
        const out = [];
        for (const s of arr) {
          if (!s || typeof s !== "object") continue;
          const season = parseInt(s.season || out.length + 1, 10) || (out.length + 1);
          const eps = Array.isArray(s.episodes) ? s.episodes : [];
          const cleanEps = [];
          for (const e of eps) {
            if (!e || typeof e !== "object") continue;
            const video_url = String(e.video_url || "").trim().slice(0, 1000);
            if (!isHttpUrl(video_url)) continue;
            cleanEps.push({
              ep: parseInt(e.ep || cleanEps.length + 1, 10) || (cleanEps.length + 1),
              title: String(e.title || "").trim().slice(0, 160),
              video_url,
              download_url: isHttpUrl(e.download_url) ? String(e.download_url).trim().slice(0, 1000) : "",
            });
          }
          out.push({ season, episodes: cleanEps });
        }
        if (out.length) return { ok: true, seasons: out };
      }
    } catch (_) {}
  }
  
  const autoParsed = parseRawTextToSeasons(trimmed);
  if (autoParsed && autoParsed.length > 0) {
    return { ok: true, seasons: autoParsed };
  }
  
  return { ok: false, err: "ထည့်သွင်းလိုက်သော စာသားထဲတွင် အပိုင်း ဗီဒီယို Link များ ရှာမတွေ့ပါ။" };
}

/* ══════════════════════════════════════════════════
   Build signed streams for watchPage
   ══════════════════════════════════════════════════ */
async function buildStreams(env, item, gated, user) {
  if (gated) {
    if (item.type === "series") return { seasons: [] };
    return { single: { video: "", dl: "" } };
  }
  const u = await userStreamTag(user);
  if (item.type === "series") {
    const seasons = Array.isArray(item.seasons) ? item.seasons : [];
    const out = [];
    for (let si = 0; si < seasons.length; si++) {
      const eps = seasons[si].episodes || [];
      const row = [];
      for (let ei = 0; ei < eps.length; ei++) {
        const video = await makeStreamUrl(env, item.id, { s: si, e: ei, download: false, u });
        const dl = await makeStreamUrl(env, item.id, { s: si, e: ei, download: true, u });
        row.push({ video, dl });
      }
      out.push(row);
    }
    return { seasons: out };
  } else {
    const video = await makeStreamUrl(env, item.id, { s: -1, e: -1, download: false, u });
    const dl = await makeStreamUrl(env, item.id, { s: -1, e: -1, download: true, u });
    return { single: { video, dl } };
  }
}

function resolveRealUrl(item, s, e, download) {
  if (item.type === "series") {
    const seasons = Array.isArray(item.seasons) ? item.seasons : [];
    const ep = seasons?.[s]?.episodes?.[e];
    if (!ep) return "";
    if (download) return rewriteDomain(ep.download_url || ep.video_url || "");
    return rewriteDomain(ep.video_url || "");
  }
  if (download) return rewriteDomain(item.download_url || item.video_url || "");
  return rewriteDomain(item.video_url || "");
}

/* ══════════════════════════════════════════════════
   ROUTER
   ══════════════════════════════════════════════════ */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const clientIp = getClientIp(request);

   // ───────────── HOME ─────────────
  if (path === "/" && method === "GET") {
    const user = await getCurrentUser(request, env);
    // login ဝင်ထားရင် welcome box ပါတာမို့ cache မလုပ်၊ guest ဆို cache (၃၀ စက္ကန့်)
    const showWelcome = url.searchParams.get("welcome") === "1" && user && !user.isAdmin && !isExpired(user);
    if (user || showWelcome) {
      const hp = await listHomePreview(env, HOME_PREVIEW_COUNT, 6);
      const sections = [
        { type: "movie",  items: hp.movie },
        { type: "series", items: hp.series },
        { type: "adult",  items: hp.adult },
        { type: "random", items: hp.random },
      ];
      const slides = hp.slides.map(i => ({
        image: i.slide_image || i.poster, title: i.title,
        desc: (CATEGORIES[i.type] || CATEGORIES.movie).name,
        tag: (CATEGORIES[i.type] || CATEGORIES.movie).name.toUpperCase(),
        link: "/watch/" + i.id,
      }));
      return new Response(homePage(slides, sections, user, showWelcome), { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    // guest → edge cache
    return cachedHtml(context, request, 30, async () => {
      const hp = await listHomePreview(env, HOME_PREVIEW_COUNT, 6);
      const sections = [
        { type: "movie",  items: hp.movie },
        { type: "series", items: hp.series },
        { type: "adult",  items: hp.adult },
        { type: "random", items: hp.random },
      ];
      const slides = hp.slides.map(i => ({
        image: i.slide_image || i.poster, title: i.title,
        desc: (CATEGORIES[i.type] || CATEGORIES.movie).name,
        tag: (CATEGORIES[i.type] || CATEGORIES.movie).name.toUpperCase(),
        link: "/watch/" + i.id,
      }));
      return homePage(slides, sections, null, false);
    });
  }


   // ───────────── CATEGORY GRID ─────────────
  if (path.startsWith("/category/") && method === "GET") {
    const cat = path.slice("/category/".length).split("/")[0];
    if (!isValidCategory(cat)) return Response.redirect(new URL("/", url).toString(), 302);
    const user = await getCurrentUser(request, env);
    let page = parseInt(url.searchParams.get("page") || "1", 10);
    if (!Number.isFinite(page) || page < 1) page = 1;
    const build = async (forUser) => {
      const { items: slice, total } = await listItemsByTypePaged(env, cat, page, ITEMS_PER_PAGE);
      const totalPages = Math.max(1, Math.ceil(total / ITEMS_PER_PAGE));
      if (page > totalPages) page = totalPages;
      const c = CATEGORIES[cat];
      return gridPage(`${c.icon} ${c.name}`, cat, slice, page, totalPages, total, (p) => `/category/${cat}?page=${p}`, "", forUser);
    };
    // login ဝင်ထားရင် fresh (key chip ပြရန်)၊ guest ဆို edge cache (၃၀ စက္ကန့်)
    if (user) {
      return new Response(await build(user), { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    return cachedHtml(context, request, 30, () => build(null));
  }


  // ───────────── SEARCH ─────────────
  if (path === "/search" && method === "GET") {
    const user = await getCurrentUser(request, env);
    const q = String(url.searchParams.get("q") || "").trim().slice(0, 80);
    const ql = q.toLowerCase();
    const all = ql ? (await listItems(env)).filter(i => (i.title || "").toLowerCase().includes(ql)) : [];
    const total = all.length;
    const totalPages = Math.max(1, Math.ceil(total / ITEMS_PER_PAGE));
    let page = parseInt(url.searchParams.get("page") || "1", 10);
    if (!Number.isFinite(page) || page < 1) page = 1;
    if (page > totalPages) page = totalPages;
    const slice = all.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);
    return new Response(
      gridPage(`🔍 "${q}"`, "", slice, page, totalPages, total, (p) => `/search?q=${encodeURIComponent(q)}&page=${p}`, q, user),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // ───────────── WATCH ─────────────
  if (path.startsWith("/watch/") && method === "GET") {
    const id = path.slice("/watch/".length).split("/")[0];
    const item = await getItem(env, id);
    if (!item) {
      return new Response(pageShell("Not found", `${topBar("")}<div class="wrap"><div class="empty">ဇာတ်ကား ရှာမတွေ့ပါ · <a href="/" style="color:var(--acc2)">Home</a></div></div>`), {
        headers: { "content-type": "text/html; charset=utf-8" }, status: 404,
      });
    }
    const user = await getCurrentUser(request, env);
    const gated = !user || isExpired(user);
    const streams = await buildStreams(env, item, gated, user);
    const bookmarked = (user && !user.isAdmin) ? await isBookmarked(env, user.keyId, item.id) : false;
    // မင်းသမီးနာမည်တွေအတွက် ပုံ/slug ယူ (cache ကနေ)
    const actresses = [];
    for (const nm of parseActressNames(item.actress)) {
      const slug = actressNameToSlug(nm);
      if (!slug) continue;
      const c = await getActressCache(env, slug);
      actresses.push({ slug, name: nm, image: c ? c.image : "" });
    }
    return new Response(watchPage(item, user, gated, streams, bookmarked, actresses),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // ───────────── STREAM (signed) — Worker PROXY + EDGE CACHE ─────────────
  if (path.startsWith("/stream/") && method === "GET") {
    const id = decodeURIComponent(path.slice("/stream/".length).split("/")[0]);
    const item = await getItem(env, id);
    if (!item) return new Response("Not found", { status: 404 });

    const v = await verifyStreamSig(env, id, url.searchParams);
    if (!v.ok) {
      return new Response(v.reason === "expired" ? "Link expired" : "Invalid link", { status: 403 });
    }

    const user = await getCurrentUser(request, env);
    if (!user || isExpired(user)) {
      return new Response("Login required", { status: 403 });
    }

    const u = await userStreamTag(user);
    if (v.u && !safeEqual(v.u, u)) {
      return new Response("Link not valid for this session", { status: 403 });
    }

    const real = resolveRealUrl(item, v.s, v.e, v.d === 1);
    if (!isHttpUrl(real)) return new Response("No source", { status: 404 });

    const rangeHeader = request.headers.get("Range");

    // ── EDGE CACHE: download မဟုတ်တဲ့ stream chunk တွေကိုသာ cache လုပ်မယ် ──
    // cache key က real-url + range ပေါ်မူတည်တယ် (signed/session token မပါ → cache hit များတယ်)
    const cache = caches.default;
    let cacheKey = null;
    // download မဟုတ်တဲ့ stream တွေထဲက — ဗီဒီယိုအစ (bytes=0-) နဲ့ full request ကိုသာ cache
    // (ကြားက seek byte တွေကို cache မလုပ်ဘူး → cache entry မပေါက်ကွဲ + seek bug မရှိ)
    const isInitialChunk = !rangeHeader || /^bytes=0-/i.test(rangeHeader);
    const cacheable = v.d !== 1 && isInitialChunk;
    if (cacheable) {
      const ckUrl = new URL(request.url);
      ckUrl.search = ""; // signed params တွေ ဖယ်
      ckUrl.searchParams.set("rk", real);                  // real source key
      ckUrl.searchParams.set("rg", rangeHeader || "full"); // bytes=0- (သို့) full
      cacheKey = new Request(ckUrl.toString(), { method: "GET" });
      const cached = await cache.match(cacheKey);
      if (cached) {
        const h = new Headers(cached.headers);
        h.set("X-CMFlix-Cache", "HIT");
        return new Response(cached.body, { status: cached.status, headers: h });
      }
    }

    const fwdHeaders = new Headers();
    if (rangeHeader) fwdHeaders.set("Range", rangeHeader);
    const ifRange = request.headers.get("If-Range");
    if (ifRange) fwdHeaders.set("If-Range", ifRange);

    let originResp;
    try {
      originResp = await fetch(real, { method: "GET", headers: fwdHeaders, redirect: "follow" });
    } catch (_) {
      return new Response("Upstream error", { status: 502 });
    }

    if (!originResp.ok && originResp.status !== 206) {
      return new Response("Upstream unavailable", { status: 502 });
    }

    const outHeaders = new Headers();
    const copyHeader = (name) => {
      const val = originResp.headers.get(name);
      if (val) outHeaders.set(name, val);
    };
    copyHeader("Content-Type");
    copyHeader("Content-Length");
    copyHeader("Content-Range");
    copyHeader("Accept-Ranges");
    copyHeader("Last-Modified");
    copyHeader("ETag");

    if (!outHeaders.has("Content-Type")) outHeaders.set("Content-Type", "video/mp4");
    if (!outHeaders.has("Accept-Ranges")) outHeaders.set("Accept-Ranges", "bytes");
    outHeaders.set("X-Content-Type-Options", "nosniff");

    if (v.d === 1) {
        let downloadName = item.title || "video";
        if (item.type === "series" && v.s !== -1 && v.e !== -1) {
          const seasonNo = item.seasons?.[v.s]?.season || (v.s + 1);
          const epNo = item.seasons?.[v.s]?.episodes?.[v.e]?.ep || (v.e + 1);
          const sStr = String(seasonNo).padStart(2, "0");
          const eStr = String(epNo).padStart(2, "0");
          downloadName = `${downloadName} S${sStr}E${eStr}`;
        }
        const safeName = downloadName
          .replace(/[^\w\-. ]+/g, "_").slice(0, 80).trim() || "video";
        const ext = real.split("?")[0].split(".").pop();
        const fname = /^[a-z0-9]{2,5}$/i.test(ext) ? `${safeName}.${ext}` : `${safeName}.mp4`;
        outHeaders.set("Content-Disposition", `attachment; filename="${fname}"`);
        outHeaders.set("Cache-Control", "private, no-store"); // download ကို cache မလုပ်
        return new Response(originResp.body, { status: originResp.status, headers: outHeaders });
    }

    // ── stream (download မဟုတ်) → edge cache မှာ သိမ်းမယ် ──
    outHeaders.set("Content-Disposition", "inline");
    outHeaders.set("Cache-Control", "public, max-age=86400"); // edge မှာ ၁ ရက် cache
    outHeaders.set("X-CMFlix-Cache", "MISS");

    if (cacheable && cacheKey && (originResp.status === 200 || originResp.status === 206)) {
      // response body ကို နှစ်ခွဲ — တစ်ခု client ကို၊ တစ်ခု cache ကို
      const respForCache = new Response(originResp.body, { status: originResp.status, headers: outHeaders });
      const respForClient = respForCache.clone();
      // cache write ကို နောက်ကွယ်မှာ လုပ်စေမယ် (client ကို မစောင့်စေဘူး)
      context.waitUntil(cache.put(cacheKey, respForCache));
      return respForClient;
    }

    return new Response(originResp.body, { status: originResp.status, headers: outHeaders });
  }


  // ───────────── BOOKMARK TOGGLE ─────────────
  if (path === "/bookmark/toggle" && method === "POST") {
    const user = await getCurrentUser(request, env);
    if (!user || user.isAdmin || isExpired(user)) {
      return new Response(JSON.stringify({ ok: false, error: "login required" }), {
        status: 403, headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    const form = await parseForm(request);
    const itemId = String(form.id || "").trim();
    const action = String(form.action || "").trim();
    if (!itemId) {
      return new Response(JSON.stringify({ ok: false, error: "no id" }), {
        status: 400, headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    const item = await getItem(env, itemId);
    if (!item) {
      return new Response(JSON.stringify({ ok: false, error: "not found" }), {
        status: 404, headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    if (action === "remove") {
      await removeBookmark(env, user.keyId, itemId);
    } else {
      await addBookmark(env, user.keyId, itemId);
    }
    const nowOn = await isBookmarked(env, user.keyId, itemId);
    return new Response(JSON.stringify({ ok: true, bookmarked: nowOn }), {
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }

  // ───────────── BOOKMARK CLEAR ALL ─────────────
  if (path === "/bookmark/clear" && method === "POST") {
    const user = await getCurrentUser(request, env);
    if (!user || user.isAdmin || isExpired(user)) {
      return new Response(JSON.stringify({ ok: false, error: "login required" }), {
        status: 403, headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    const form = await parseForm(request);
    if (!(await verifyCsrf(request, form))) {
      return new Response(JSON.stringify({ ok: false, error: "csrf failed" }), {
        status: 403, headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    await clearAllBookmarks(env, user.keyId);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }

  // ───────────── MY LIST (bookmarks) ─────────────
  if (path === "/mylist" && method === "GET") {
    const user = await getCurrentUser(request, env);
    if (!user) return Response.redirect(new URL("/login?next=/mylist", url).toString(), 302);
    if (user.isAdmin) return Response.redirect(new URL("/admin", url).toString(), 302);
    const items = await listBookmarks(env, user.keyId);
    const { token: csrfToken, isNew: csrfNew } = await getOrCreateCsrf(request, env);
    const headers = { "content-type": "text/html; charset=utf-8" };
    if (csrfNew) headers["Set-Cookie"] = csrfCookieHeader(csrfToken);
    return new Response(myListPage(items, user, csrfToken), { headers });
  }
    // ───────────── ACTRESS PAGE (public) ─────────────
  if (path.startsWith("/actress/") && method === "GET") {
    const slug = decodeURIComponent(path.slice("/actress/".length).split("/")[0]);
    const user = await getCurrentUser(request, env);
    const items = await listItemsByActressSlug(env, slug);
    // cache ထဲက ပုံ/နာမည် ယူ၊ မရှိရင် items ထဲက နာမည်ကို သုံး
    let info = await getActressCache(env, slug);
    if (!info) {
      let dispName = slug;
      for (const it of items) {
        const found = parseActressNames(it.actress).find(n => actressNameToSlug(n) === slug);
        if (found) { dispName = found; break; }
      }
      info = { slug, name: dispName, image: "", url: "" };
    }
    return new Response(actressPage(info, items, user),
      { headers: { "content-type": "text/html; charset=utf-8" } });
  }


  // ───────────── AUTH STATUS ─────────────
  if (path === "/auth/status" && method === "GET") {
    const cur = await getCurrentUser(request, env);
    const loggedIn = !!cur;
    return new Response(JSON.stringify({ loggedIn, expired: loggedIn ? isExpired(cur) : false, isAdmin: !!(cur && cur.isAdmin) }), {
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }

  // ───────────── LOGIN ─────────────
  if (path === "/login") {
    const { token: csrfToken, isNew: csrfNew } = await getOrCreateCsrf(request, env);
    const nextUrl = safeNextPath(url.searchParams.get("next") || "/");
    if (method === "GET") {
      const cur = await getCurrentUser(request, env);
      if (cur && !isExpired(cur)) return Response.redirect(new URL(cur.isAdmin ? "/admin" : "/", url).toString(), 302);
      const headers = { "content-type": "text/html; charset=utf-8" };
      if (csrfNew) headers["Set-Cookie"] = csrfCookieHeader(csrfToken);
      return new Response(keyLoginPage(csrfToken, "", "", nextUrl), { headers });
    }
    if (method === "POST") {
      await lazyCleanup(env);
      const rl = await rateLimitHit(env, `keylogin:${clientIp}`, KEY_LOGIN_MAX_ATTEMPTS, KEY_LOGIN_WINDOW_SEC);
      if (rl.blocked) {
        return new Response(keyLoginPage(csrfToken, "ကြိုးစားခြင်း များနေပါပြီ။ ၁၀ မိနစ်နောက်မှ ထပ်ကြိုးစားပါ"), {
          headers: { "content-type": "text/html; charset=utf-8" }, status: 429,
        });
      }
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) {
        const headers = { "content-type": "text/html; charset=utf-8" };
        if (csrfNew) headers["Set-Cookie"] = csrfCookieHeader(csrfToken);
        return new Response(keyLoginPage(csrfToken, "Session expired. Refresh ပြီး ထပ်ကြိုးစားပါ။"), { headers, status: 403 });
      }
      const safeNext = safeNextPath(form.next || "/");
      const clientUuid = String(form.device_uuid || "").trim().slice(0, 80) || getCookie(request, "cmflix_duid");
      const rawKey = normalizeKey(form.key);
      if (!rawKey) {
        return new Response(keyLoginPage(csrfToken, "Key ထည့်ပါ။", "", safeNext), { headers: { "content-type": "text/html; charset=utf-8" }, status: 400 });
      }
      if (env.ADMIN_KEY && safeEqual(rawKey, normalizeKey(env.ADMIN_KEY))) {
        // admin login အတွက် သီးသန့် rate limit (IP per 30 min ၅ ခါသာ)
        const adminRl = await rateLimitHit(env, `adminlogin:${clientIp}`, 5, 1800);
        if (adminRl.blocked) {
          return new Response(keyLoginPage(csrfToken, "Admin login ကြိုးစားခြင်း များနေပါပြီ။ ၃၀ မိနစ်နောက်မှ ထပ်ကြိုးစားပါ။", "", safeNext), {
            headers: { "content-type": "text/html; charset=utf-8" }, status: 429,
          });
        }
        const deviceShort = (await deviceIdFrom(request, clientUuid)).slice(0, 12);
        const sid = randomToken(8);
        const token = await createSessionToken("__ADMIN__", deviceShort, env.SESSION_SECRET, sid);
        return new Response(null, { status: 302, headers: { "Location": "/admin", "Set-Cookie": setCookieHeader(COOKIE_NAME, token) } });
      }
      const keyObj = await getKey(env, rawKey);
      if (!keyObj) return new Response(keyLoginPage(csrfToken, "Key မှားနေပါတယ် (သို့) ရှာမတွေ့ပါ။", "", safeNext), { headers: { "content-type": "text/html; charset=utf-8" }, status: 401 });
      if (keyObj.disabled) return new Response(expiredPage("ဒီ Key ကို ပိတ်ထားပါသည်။"), { headers: { "content-type": "text/html; charset=utf-8" }, status: 403 });
      if (isKeyExpired(keyObj)) return new Response(expiredPage(), { headers: { "content-type": "text/html; charset=utf-8" }, status: 403 });
      const deviceId = await deviceIdFrom(request, clientUuid);
      const bind = await bindDeviceToKey(env, keyObj, rawKey, deviceId, request, clientIp);
      if (!bind.ok) return new Response(expiredPage(bind.reason), { headers: { "content-type": "text/html; charset=utf-8" }, status: 403 });
      const deviceShort = deviceId.slice(0, 12);
      const sid = randomToken(8);
      const token = await createSessionToken(rawKey, deviceShort, env.SESSION_SECRET, sid);
      await recordSession(env, rawKey, sid, {
        ua: request.headers.get("User-Agent") || "",
        country: request.headers.get("CF-IPCountry") || "",
        ip_prefix: ipNetworkPrefix(clientIp),
        label: shortDeviceLabel(request),
      });
      // login အောင်မြင်ရင် — ဝင်လာတဲ့ စာမျက်နှာ (next) ဆီ ပြန်ပို့ပြီး welcome box ပြဖို့ flag ထည့်
      let dest = safeNext.startsWith("/") ? safeNext : "/";
      const sep = dest.includes("?") ? "&" : "?";
      dest = dest + sep + "welcome=1";
      return new Response(null, { status: 302, headers: { "Location": dest, "Set-Cookie": setCookieHeader(COOKIE_NAME, token) } });
    }
  }

  // ───────────── LOGOUT ─────────────
  if (path === "/logout") {
    const cur = await getCurrentUser(request, env);
    if (cur && !cur.isAdmin && cur.sid) await revokeSession(env, cur.keyId, cur.sid);
    return new Response(null, { status: 302, headers: { "Location": "/login", "Set-Cookie": setCookieHeader(COOKIE_NAME, "", { maxAge: 0 }) } });
  }

  // ───────────── ACCOUNT ─────────────
  if (path === "/account" && method === "GET") {
    const cur = await getCurrentUser(request, env);
    if (!cur) return Response.redirect(new URL("/login", url).toString(), 302);
    if (cur.isAdmin) return Response.redirect(new URL("/admin", url).toString(), 302);
    const showWelcome = url.searchParams.get("welcome") === "1";
    return new Response(accountPage(cur, "", "", showWelcome),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // ───────────── ADMIN ─────────────
  if (path === "/admin" || path.startsWith("/admin/")) {
    const cur = await getCurrentUser(request, env);
    if (!cur || !cur.isAdmin) return Response.redirect(new URL("/login", url).toString(), 302);
    const { token: csrfToken, isNew: csrfNew } = await getOrCreateCsrf(request, env);
    const setCsrf = csrfNew ? { "Set-Cookie": csrfCookieHeader(csrfToken) } : {};

    // TMDB lookup (JSON, admin only)
    if (path === "/admin/tmdb" && method === "GET") {
      if (!tmdbConfigured(env)) {
        return new Response(JSON.stringify({ ok: false, error: "TMDB_API_KEY မထည့်ရသေးပါ။" }), { headers: { "content-type": "application/json" } });
      }
      const q = String(url.searchParams.get("q") || "").trim().slice(0, 100);
      const type = isValidCategory(url.searchParams.get("type")) ? url.searchParams.get("type") : "movie";
      if (!q) return new Response(JSON.stringify({ ok: false, error: "Title ထည့်ပါ။" }), { headers: { "content-type": "application/json" } });
      const r = await tmdbSearch(env, q, type);
      if (!r) return new Response(JSON.stringify({ ok: false, error: "TMDB မှာ ရှာမတွေ့ပါ။" }), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ ok: true, ...r }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
    }

    // ADMIN DASHBOARD
    if (path === "/admin" && method === "GET") {
      const res = await db(env).prepare(
        "SELECT key_id, role, created_at, expires_at, note, disabled, devices FROM keys ORDER BY created_at DESC LIMIT 1000"
      ).all();
      const keys = (res.results || []).map(r => {
        let devCount = 0;
        try { devCount = (JSON.parse(r.devices || "[]") || []).length; } catch (_) {}
        return {
          keyId: r.key_id,
          role: r.role || "trial",
          created_at: r.created_at || 0,
          expires_at: r.expires_at || 0,
          note: r.note || "",
          disabled: !!r.disabled,
          device_count: devCount,
        };
      });
      const now = Date.now();
      const stats = {
        total: keys.length,
        active: keys.filter(k => k.expires_at && k.expires_at > now && !k.disabled).length,
        expired: keys.filter(k => !k.expires_at || k.expires_at <= now || k.disabled).length,
        paid: keys.filter(k => k.role === "paid").length,
        trial: keys.filter(k => k.role === "trial" || !k.role).length,
      };
      let allItems = await listItems(env, true);  // admin → draft အပါအဝင် အားလုံး ပြ
      const draftCount = await countDraftItems(env);
      const itType = String(url.searchParams.get("ittype") || "").trim();
      if (isValidCategory(itType)) allItems = allItems.filter(i => i.type === itType);
      const itQuery = String(url.searchParams.get("itq") || "").trim().slice(0, 80);
      const itQl = itQuery.toLowerCase();
      const filtered = itQl ? allItems.filter(i => (i.title || "").toLowerCase().includes(itQl) || (i.id || "").toLowerCase().includes(itQl)) : allItems;
      const itTotal = filtered.length;
      const itTotalPages = Math.max(1, Math.ceil(itTotal / ADMIN_ITEMS_PER_PAGE));
      let itPage = parseInt(url.searchParams.get("itpage") || "1", 10);
      if (!Number.isFinite(itPage) || itPage < 1) itPage = 1;
      if (itPage > itTotalPages) itPage = itTotalPages;
      const items = filtered.slice((itPage - 1) * ADMIN_ITEMS_PER_PAGE, itPage * ADMIN_ITEMS_PER_PAGE);
      const newKey = url.searchParams.get("newkey") || "";
      const info = url.searchParams.get("info") || "";
      return new Response(
        adminPage(keys, stats, csrfToken, newKey, info, items, itPage, itTotalPages, itQuery, itTotal, isValidCategory(itType) ? itType : "", tmdbConfigured(env), draftCount),
        { headers: { "content-type": "text/html; charset=utf-8", ...setCsrf } }
      );
    }
        // ACTRESS lookup (JSON, admin only)
    if (path === "/admin/actress" && method === "GET") {
      const name = String(url.searchParams.get("name") || "").trim().slice(0, 80);
      if (!name) return new Response(JSON.stringify({ ok: false, error: "နာမည် ထည့်ပါ။" }), { headers: { "content-type": "application/json" } });
      const r = await lookupActress(env, name);
      return new Response(JSON.stringify(r), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
    }


    // EDIT PAGE
    if (path.startsWith("/admin/edit/") && method === "GET") {
      const id = path.slice("/admin/edit/".length).split("/")[0];
      const item = await getItem(env, id);
      if (!item) return Response.redirect(new URL("/admin", url).toString(), 302);
      return new Response(adminEditPage(item, csrfToken), { headers: { "content-type": "text/html; charset=utf-8", ...setCsrf } });
    }

    const redirectInfo = (msg) => {
      const dest = new URL("/admin", url);
      dest.searchParams.set("info", msg);
      dest.hash = "content";
      return Response.redirect(dest.toString(), 302);
    };

    // CREATE ITEM
    if (path === "/admin/item/create" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const type = isValidCategory(form.type) ? form.type : "movie";
      const title = String(form.title || "").trim().slice(0, 160);
      const poster = String(form.poster || "").trim().slice(0, 600);
      const slide_image = String(form.slide_image || "").trim().slice(0, 600);
      const note = String(form.note || "").trim().slice(0, 5000);
      const actress = String(form.actress || "").trim().slice(0, 300);
      if (!title) return redirectInfo("Title ဖြည့်ပါ။");
      if (poster && !isHttpUrl(poster)) return redirectInfo("Poster link မှားနေပါတယ်။");
      if (slide_image && !isHttpUrl(slide_image)) return redirectInfo("Slide banner link မှားနေပါတယ်။");
      const id = generateItemId();
      // save_mode=draft → published=0 (မပြ) ; ဒါမှမဟုတ် publish → published=1 (တန်းတင်)
      const isDraft = String(form.save_mode || "publish") === "draft";
      const data = { id, type, title, poster, slide_image, note, actress, created_at: Date.now(), published: isDraft ? 0 : 1 };
      // မင်းသမီးနာမည်တွေအတွက် ပုံကို cache ထဲ ကြိုသိမ်း (watch page မှာ ပုံပေါ်ဖို့)
      for (const nm of parseActressNames(actress)) {
        const slug = actressNameToSlug(nm);
        if (slug && !(await getActressCache(env, slug))) {
          try { await lookupActress(env, nm); } catch (_) {}
        }
      }
      if (type === "series") {
        const r = sanitizeSeasons(form.seasons_json || "");
        if (!r.ok) return redirectInfo(r.err);
        data.seasons = r.seasons;
      } else {
        const video_url = String(form.video_url || "").trim().slice(0, 1000);
        const download_url = String(form.download_url || "").trim().slice(0, 1000);
        if (!isHttpUrl(video_url)) return redirectInfo("Video URL (http/https) ဖြည့်ပါ။");
        if (download_url && !isHttpUrl(download_url)) return redirectInfo("Download link မှားနေပါတယ်။");
        data.video_url = video_url;
        data.download_url = download_url || video_url;
      }
      await putItem(env, id, data);
      return redirectInfo(isDraft
        ? `"${title}" ကို Draft အဖြစ် သိမ်းပြီးပါပြီ (မပြသေးပါ)။`
        : `"${title}" တင်ပြီးပါပြီ။`);
    }

    // UPDATE ITEM
    if (path === "/admin/item/update" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const id = String(form.id || "").trim();
      const existing = id ? await getItem(env, id) : null;
      if (!existing) return redirectInfo("ပြင်မယ့် content ရှာမတွေ့ပါ။");
      const type = isValidCategory(form.type) ? form.type : existing.type;
      const title = String(form.title || "").trim().slice(0, 160);
      const poster = String(form.poster || "").trim().slice(0, 600);
      const slide_image = String(form.slide_image || "").trim().slice(0, 600);
      const note = String(form.note || "").trim().slice(0, 5000);
      const actress = String(form.actress || "").trim().slice(0, 300);
      if (!title) return new Response(adminEditPage(existing, csrfToken, "Title ဖြည့်ပါ။"),
        { headers: { "content-type": "text/html; charset=utf-8" } });

      if (poster && !isHttpUrl(poster)) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, "Poster link မှားနေပါတယ်။"),
        { headers: { "content-type": "text/html; charset=utf-8" } });

      if (slide_image && !isHttpUrl(slide_image)) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, "Slide banner link မှားနေပါတယ်။"),
        { headers: { "content-type": "text/html; charset=utf-8" } });


      // edit လုပ်တဲ့အခါ — မူရင်း published status ကို ဆက်ထိန်းထား (draft က draft အတိုင်း)
      const data = { id, type, title, poster, slide_image, note, actress, created_at: existing.created_at || Date.now(), published: (existing.published == null ? 1 : existing.published) };
      for (const nm of parseActressNames(actress)) {
        const slug = actressNameToSlug(nm);
        if (slug && !(await getActressCache(env, slug))) {
          try { await lookupActress(env, nm); } catch (_) {}
        }
      }
      if (type === "series") {
        const r = sanitizeSeasons(form.seasons_json || "");
        if (!r.ok) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, r.err),
          { headers: { "content-type": "text/html; charset=utf-8" } });

        data.seasons = r.seasons;
      } else {
        const video_url = String(form.video_url || "").trim().slice(0, 1000);
        const download_url = String(form.download_url || "").trim().slice(0, 1000);
        if (!isHttpUrl(video_url)) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, "Video URL ဖြည့်ပါ။"),
          { headers: { "content-type": "text/html; charset=utf-8" } });

        data.video_url = video_url;
        data.download_url = download_url || video_url;
      }
      await putItem(env, id, data);
      return redirectInfo(`"${title}" ပြင်ဆင်ပြီးပါပြီ။`);
    }

    // DELETE ITEM
    if (path === "/admin/item/delete" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const id = String(form.id || "").trim();
      if (id) await deleteItem(env, id);
      return redirectInfo("Content ဖျက်ပြီးပါပြီ။");
    }

    // PUBLISH ALL DRAFTS — Draft အားလုံးကို တစ်ခါတည်း တင်
    if (path === "/admin/item/publishall" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const n = await publishAllDrafts(env);
      return redirectInfo(n > 0 ? `Draft ${n} ကား အားလုံးကို Publish တင်ပြီးပါပြီ။ 🚀` : "Publish တင်စရာ Draft မရှိပါ။");
    }

    // CREATE KEY(S)
    if (path === "/admin/create" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const days = Math.max(1, Math.min(3650, parseInt(form.days || "1", 10)));
      const role = form.role === "paid" ? "paid" : "trial";
      const count = Math.max(1, Math.min(50, parseInt(form.count || "1", 10)));
      const note = String(form.note || "").slice(0, 60);
      const now = Date.now();
      const created = [];
      for (let i = 0; i < count; i++) {
        let keyId = generateKey();
        let guard = 0;
        while (await getKey(env, keyId) && guard < 5) { keyId = generateKey(); guard++; }
        await putKey(env, keyId, {
          key: keyId, role, created_at: now,
          expires_at: now + days * 24 * 3600 * 1000,
          duration_label: `${days} Day${days > 1 ? "s" : ""}`,
          devices: [], note, disabled: false,
        });
        created.push(keyId);
      }
      const dest = new URL("/admin", url);
      if (count === 1) dest.searchParams.set("newkey", created[0]);
      else dest.searchParams.set("info", `${count} keys created`);
      return Response.redirect(dest.toString(), 302);
    }

    // EXTEND
    if (path === "/admin/extend" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const keyId = normalizeKey(form.key);
      const days = Math.max(1, Math.min(3650, parseInt(form.days || "30", 10)));
      const k = await getKey(env, keyId);
      if (k) {
        const base = (k.expires_at && k.expires_at > Date.now()) ? k.expires_at : Date.now();
        k.expires_at = base + days * 24 * 3600 * 1000;
        k.role = "paid"; k.disabled = false;
        await putKey(env, keyId, k);
      }
      return Response.redirect(new URL("/admin", url).toString(), 302);
    }

    // RESET DEVICES
    if (path === "/admin/resetdevices" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const keyId = normalizeKey(form.key);
      const k = await getKey(env, keyId);
      if (k) {
        const stmts = [];
        if (Array.isArray(k.devices)) for (const d of k.devices) if (d.id) stmts.push(db(env).prepare("DELETE FROM kdev WHERE device_id=?").bind(d.id));
        stmts.push(db(env).prepare("DELETE FROM sessions WHERE key_id=?").bind(keyId));
        if (stmts.length) await db(env).batch(stmts);
        k.devices = [];
        await putKey(env, keyId, k);
      }
      return Response.redirect(new URL("/admin", url).toString(), 302);
    }

    // DELETE KEY
    if (path === "/admin/delete" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const keyId = normalizeKey(form.key);
      if (keyId) await deleteKey(env, keyId);
      return Response.redirect(new URL("/admin", url).toString(), 302);
    }

    // BULK
    if (path === "/admin/bulk" && method === "POST") {
      const form = await parseForm(request);
      if (!(await verifyCsrf(request, form))) return new Response("CSRF failed", { status: 403 });
      const action = String(form.action || "").trim();
      const ids = String(form.keys || "").split(",").map(s => normalizeKey(s)).filter(Boolean);
      const days = Math.max(1, Math.min(3650, parseInt(form.days || "30", 10)));
      for (const keyId of ids) {
        if (action === "delete") await deleteKey(env, keyId);
        else if (action === "extend") {
          const k = await getKey(env, keyId);
          if (k) {
            const base = (k.expires_at && k.expires_at > Date.now()) ? k.expires_at : Date.now();
            k.expires_at = base + days * 24 * 3600 * 1000;
            k.role = "paid"; k.disabled = false;
            await putKey(env, keyId, k);
          }
        }
      }
      return Response.redirect(new URL("/admin", url).toString(), 302);
    }

    // EXPORT CSV
    if (path === "/admin/export" && method === "GET") {
      const res = await db(env).prepare(
        "SELECT key_id, role, created_at, expires_at, note, disabled, devices FROM keys ORDER BY created_at DESC LIMIT 5000"
      ).all();
      const rows = [["key", "role", "created_at", "expires_at", "device_count", "note", "disabled"]];
      for (const r of (res.results || [])) {
        let devCount = 0;
        try { devCount = (JSON.parse(r.devices || "[]") || []).length; } catch (_) {}
        rows.push([
          r.key_id, r.role || "trial",
          r.created_at ? new Date(r.created_at).toISOString() : "",
          r.expires_at ? new Date(r.expires_at).toISOString() : "",
          devCount, r.note || "", r.disabled ? "yes" : "no",
        ]);
      }
      const csv = rows.map(rw => rw.map(c => {
        const s = String(c == null ? "" : c);
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(",")).join("\n");
      return new Response(csv, {
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": `attachment; filename="cmflix-keys-${new Date().toISOString().slice(0, 10)}.csv"`,
        },
      });
    }
  }

  // ───────────── 404 ─────────────
  return new Response(pageShell("404 — CM FLIX", `${topBar("")}<div class="wrap"><div class="empty">404 · ဒီစာမျက်နှာ ရှာမတွေ့ပါ · <a href="/" style="color:var(--acc2)">Home သို့</a></div></div>`), {
    headers: { "content-type": "text/html; charset=utf-8" }, status: 404,
  });
}
