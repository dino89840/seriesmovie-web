// functions/[[path]].js  — PART 1 of 2
// ════════════════════════════════════════════════════════════════
//  CM FLIX — Self-hosted Movie / Series streaming app
//  • Signed / expiring URL streaming (real R2/mp4 link NEVER in HTML)
//  • Key-only login (admin-created keys, device-limited)
//  • Categories: Movies / Series / 21+  (Series: Season → Episode)
//  • Slider supports separate landscape banner image (slide_image)
//  • Production-grade Admin panel + secure session
// ════════════════════════════════════════════════════════════════

// ── Session / key constants ──
const SESSION_HOURS    = 24 * 30;
const COOKIE_NAME      = "__Host-cmflix_sess";
const CSRF_COOKIE      = "__Host-cmflix_csrf";
const MAX_DEVICES_PER_KEY = 2;
const KEY_PREFIX       = "CM";

// ── Signed stream URL ──
const STREAM_TTL_SEC   = 6 * 3600;   // signed link 6 နာရီ ကြာရင် expire
const STREAM_SECRET_FALLBACK = "SESSION_SECRET"; // env.STREAM_SECRET မရှိရင် SESSION_SECRET သုံးမယ်

// Rate limit
const KEY_LOGIN_MAX_ATTEMPTS = 12;
const KEY_LOGIN_WINDOW_SEC   = 600;

// ── Pagination ──
const HOME_PREVIEW_COUNT   = 7;
const ITEMS_PER_PAGE       = 15;
const ADMIN_ITEMS_PER_PAGE = 20;

// ── Categories (fixed) ──
const CATEGORIES = {
  movie:  { id: "movie",  name: "Movies",  icon: "🎬" },
  series: { id: "series", name: "Series",  icon: "📺" },
  adult:  { id: "adult",  name: "21+",     icon: "🔞" },
};
function isValidCategory(c) { return c === "movie" || c === "series" || c === "adult"; }

// ── Per-request cache ──
const _reqCache = new WeakMap();

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
  if (/[\r\n]/.test(n)) return "/";
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
   SIGNED STREAM URL  (real R2 link never exposed in HTML)
   /stream/<itemId>?s=<season>&e=<ep>&d=<0|1>&exp=<ms>&u=<sidShort>&sig=<hmac>
   ══════════════════════════════════════════════════ */
function streamSecret(env) {
  return env.STREAM_SECRET || env.SESSION_SECRET || STREAM_SECRET_FALLBACK;
}

// canonical string ကို sign / verify နှစ်ဖက်လုံး တူညီအောင်
function streamSignBase(itemId, s, e, d, exp, u) {
  return `${itemId}|${s}|${e}|${d}|${exp}|${u}`;
}

// signed path တစ်ခု ဖန်တီးပေးတယ် (u = session id short, link ကို user နဲ့ bind ဖို့)
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

// signed query ကို verify လုပ်တယ် → ok ဖြစ်ရင် {s,e,d} ပြန်ပေး
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
   KEY STORAGE  (KV namespace: AUTH_USERS)
   ══════════════════════════════════════════════════ */
async function getKey(env, keyId) {
  if (!keyId) return null;
  const raw = await env.AUTH_USERS.get(`key:${keyId}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function putKey(env, keyId, data) {
  const active = (data.expires_at && Date.now() < data.expires_at && !data.disabled);
  const meta = {
    role: data.role || "trial",
    expires_at: data.expires_at || 0,
    created_at: data.created_at || 0,
    duration_label: data.duration_label || "",
    device_count: (data.devices || []).length,
    disabled: !!data.disabled,
    note: (data.note || "").slice(0, 40),
    active,
  };
  await env.AUTH_USERS.put(`key:${keyId}`, JSON.stringify(data), { metadata: meta });
}

async function deleteKey(env, keyId) {
  const k = await getKey(env, keyId);
  if (k && Array.isArray(k.devices)) {
    for (const d of k.devices) if (d.id) await env.AUTH_USERS.delete(`kdev:${d.id}`);
  }
  const list = await env.AUTH_USERS.list({ prefix: `sess:${keyId}:` });
  for (const s of list.keys) await env.AUTH_USERS.delete(s.name);
  await env.AUTH_USERS.delete(`key:${keyId}`);
}

function isKeyExpired(k) {
  if (!k) return true;
  if (k.disabled) return true;
  if (!k.expires_at) return true;
  return Date.now() > k.expires_at;
}

/* ══════════════════════════════════════════════════
   CONTENT STORAGE  (KV namespace: AUTH_USERS)
   item:<ID> → JSON
   {
     id, type, title, poster, slide_image, note, created_at,
     video_url, download_url,                       // movie/adult
     seasons:[{season,episodes:[{ep,title,video_url,download_url}]}]  // series
   }
   ══════════════════════════════════════════════════ */
function generateItemId() {
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
  return "i" + s.slice(0, 12);
}

async function getItem(env, id) {
  if (!id) return null;
  const raw = await env.AUTH_USERS.get(`item:${id}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function putItem(env, id, data) {
  const meta = {
    title: (data.title || "").slice(0, 90),
    poster: (data.poster || "").slice(0, 500),
    slide_image: (data.slide_image || "").slice(0, 500),
    type: data.type || "movie",
    created_at: data.created_at || 0,
  };
  await env.AUTH_USERS.put(`item:${id}`, JSON.stringify(data), { metadata: meta });
}

async function deleteItem(env, id) {
  await env.AUTH_USERS.delete(`item:${id}`);
}

// All item summaries (metadata only, no N+1)
async function listItems(env) {
  const items = [];
  let cursor = undefined;
  do {
    const res = await env.AUTH_USERS.list({ prefix: "item:", limit: 1000, cursor });
    for (const k of res.keys) {
      const m = k.metadata || {};
      items.push({
        id: k.name.slice(5),
        title: m.title || "",
        poster: m.poster || "",
        slide_image: m.slide_image || "",
        type: m.type || "movie",
        created_at: m.created_at || 0,
      });
    }
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  items.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  return items;
}

/* ══════════════════════════════════════════════════
   SESSIONS
   ══════════════════════════════════════════════════ */
async function recordSession(env, keyId, sid, meta) {
  await env.AUTH_USERS.put(
    `sess:${keyId}:${sid}`, "1",
    { expirationTtl: SESSION_HOURS * 3600, metadata: { ...meta, created_at: Date.now() } }
  );
}
async function isSessionRevoked(env, keyId, sid) {
  if (!sid) return false;
  const v = await env.AUTH_USERS.get(`sess:${keyId}:${sid}`);
  return v === null;
}
async function revokeSession(env, keyId, sid) {
  await env.AUTH_USERS.delete(`sess:${keyId}:${sid}`);
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

// session id ကို signed-url binding အတွက် short hash
async function userStreamTag(user) {
  if (!user) return "";
  return (await sha256Hex("u:" + user.keyId + ":" + (user.sid || ""))).slice(0, 12);
}

function htmlEscape(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function rateLimitHit(env, key, max, windowSec) {
  const raw = await env.AUTH_USERS.get(`rl:${key}`);
  const now = Math.floor(Date.now() / 1000);
  let entry = { count: 0, reset: now + windowSec };
  if (raw) {
    try { const p = JSON.parse(raw); if (p && p.reset > now) entry = p; } catch (_) {}
  }
  entry.count += 1;
  const ttl = Math.max(1, entry.reset - now);
  await env.AUTH_USERS.put(`rl:${key}`, JSON.stringify(entry), { expirationTtl: ttl });
  return { blocked: entry.count > max, count: entry.count, reset: entry.reset };
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
   DEVICE BINDING (2-phone limit)
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
  await env.AUTH_USERS.put(`kdev:${deviceId}`, keyId);
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

/* ── PART 1 ends here. PART 2 uses everything above ── */
// functions/[[path]].js  — PART 2 of 2  (append directly below PART 1)
// ════════════════════════════════════════════════════════════════
//  CM FLIX — UI, routes, signed-stream player, admin panel
//  • Player uses /stream/<id>?...sig  (real link never in HTML)
//  • Slider uses slide_image (landscape) → no blurry poster
// ════════════════════════════════════════════════════════════════

/* ══════════════════════════════════════════════════
   GLOBAL STYLES
   ══════════════════════════════════════════════════ */
const CMFLIX_CSS = `
  *{box-sizing:border-box}
  :root{
    --bg0:#070a14; --bg1:#0d1220; --bg2:#131a2e;
    --card:#121829; --line:#222c44;
    --txt:#eef2ff; --mut:#8a96b5;
    --acc:#e50914; --acc2:#ff2d55; --gold:#f5c518;
    --ok:#22c55e;
  }
  html,body{margin:0;padding:0}
  body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Padauk","Myanmar Text",sans-serif;
    background:radial-gradient(1100px 560px at 85% -8%,rgba(229,9,20,.18),transparent),
               radial-gradient(900px 500px at -8% 6%,rgba(40,80,200,.14),transparent),
               linear-gradient(180deg,var(--bg0),var(--bg1) 60%,var(--bg2));
    color:var(--txt);min-height:100vh;-webkit-tap-highlight-color:transparent}
  a{color:inherit}
  .wrap{max-width:1180px;margin:0 auto;padding:0 16px}

  .topbar{position:sticky;top:0;z-index:200;display:flex;align-items:center;gap:14px;
    padding:12px 16px;background:rgba(8,11,20,.82);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
  .brand{display:flex;align-items:center;gap:9px;text-decoration:none;font-weight:900;font-size:22px;letter-spacing:.5px;white-space:nowrap}
  .brand .logo-c{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;
    background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 4px 14px rgba(229,9,20,.5);font-size:18px}
  .brand .logo-t{background:linear-gradient(90deg,#fff,#ffd1d4);-webkit-background-clip:text;background-clip:text;color:transparent}
  .brand .logo-t b{color:var(--acc)}
  .topbar .search{flex:1;max-width:520px;margin:0 auto;position:relative}
  .topbar .search input{width:100%;padding:10px 14px 10px 38px;border-radius:24px;border:1px solid var(--line);
    background:#0a1020;color:#fff;font-size:14px;outline:none;font-family:inherit}
  .topbar .search input:focus{border-color:var(--acc2);box-shadow:0 0 0 3px rgba(255,45,85,.18)}
  .topbar .search .si{position:absolute;left:13px;top:50%;transform:translateY(-50%);opacity:.6}
  .topbar .acts{display:flex;align-items:center;gap:8px;white-space:nowrap}
  .topbar .acts a{font-size:13px;text-decoration:none;color:var(--mut);font-weight:600;padding:7px 11px;border-radius:8px}
  .topbar .acts a.me{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
  .topbar .acts a:hover{color:#fff}
  @media(max-width:640px){.brand{font-size:18px}.topbar .acts a:not(.me){display:none}}

  .navchips{display:flex;gap:8px;overflow-x:auto;padding:12px 16px 4px;scrollbar-width:none}
  .navchips::-webkit-scrollbar{display:none}
  .navchips a{flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:22px;
    text-decoration:none;font-weight:700;font-size:13.5px;color:#fff;background:#161d31;border:1px solid var(--line)}
  .navchips a.on{background:linear-gradient(135deg,var(--acc),var(--acc2));border-color:transparent;box-shadow:0 4px 12px rgba(229,9,20,.4)}
  .navchips a:hover{filter:brightness(1.12)}

  /* Hero slider — landscape banner, cover-fit */
  .hero{position:relative;margin:14px 0 6px;border-radius:18px;overflow:hidden;border:1px solid var(--line);box-shadow:0 18px 50px rgba(0,0,0,.55)}
  .hero-track{display:flex;transition:transform .55s cubic-bezier(.4,0,.2,1)}
  .slide{position:relative;min-width:100%;height:340px;display:flex;align-items:flex-end;overflow:hidden;background:#0a0e1a}
  .slide-bg{position:absolute;inset:0;background-size:cover;background-position:center center;background-repeat:no-repeat}
  .slide::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,rgba(7,10,20,.92) 0%,rgba(7,10,20,.55) 45%,rgba(7,10,20,.12) 100%)}
  .slide-body{position:relative;z-index:2;padding:26px 30px;max-width:620px}
  .slide-tag{display:inline-block;background:var(--acc);color:#fff;font-size:11px;font-weight:800;padding:4px 11px;border-radius:6px;letter-spacing:.5px;margin-bottom:10px}
  .slide-title{font-size:30px;font-weight:900;margin:0 0 8px;line-height:1.15;text-shadow:0 2px 14px rgba(0,0,0,.6)}
  .slide-desc{color:#cfd6e8;font-size:14px;line-height:1.6;margin:0 0 16px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
  .slide-btn{display:inline-flex;align-items:center;gap:8px;background:#fff;color:#111;font-weight:800;padding:11px 22px;border-radius:9px;text-decoration:none;font-size:14px}
  .slide-btn:hover{background:var(--acc);color:#fff}
  .hero-dots{position:absolute;bottom:14px;right:20px;z-index:3;display:flex;gap:7px}
  .hero-dots b{width:9px;height:9px;border-radius:50%;background:rgba(255,255,255,.4);cursor:pointer;transition:.2s}
  .hero-dots b.on{background:var(--acc);width:24px;border-radius:5px}
  .hero-nav{position:absolute;top:50%;transform:translateY(-50%);z-index:3;width:40px;height:40px;border-radius:50%;
    border:0;background:rgba(0,0,0,.45);color:#fff;font-size:20px;cursor:pointer;display:flex;align-items:center;justify-content:center}
  .hero-nav:hover{background:var(--acc)}
  .hero-nav.prev{left:14px}.hero-nav.next{right:14px}
  @media(max-width:640px){.slide{height:200px}.slide-title{font-size:20px}.slide-desc{display:none}.slide-body{padding:16px}.hero-nav{display:none}}

  .section{margin:26px 0}
  .section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
  .section-head h2{display:flex;align-items:center;gap:9px;font-size:20px;margin:0;font-weight:800}
  .section-head a.seeall{font-size:13px;font-weight:700;color:var(--acc2);text-decoration:none;display:inline-flex;align-items:center;gap:4px}
  .section-head a.seeall:hover{color:#fff}

  .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
  @media(min-width:560px){.grid{grid-template-columns:repeat(4,1fr);gap:14px}}
  @media(min-width:820px){.grid{grid-template-columns:repeat(5,1fr)}}
  @media(min-width:1024px){.grid{grid-template-columns:repeat(6,1fr)}}

  .card-item{display:block;text-decoration:none;border-radius:12px;overflow:hidden;background:var(--card);
    border:1px solid var(--line);transition:transform .15s,border-color .15s,box-shadow .15s;position:relative}
  .card-item:hover{transform:translateY(-4px);border-color:var(--acc2);box-shadow:0 12px 28px rgba(0,0,0,.5)}
  .poster{width:100%;aspect-ratio:2/3;background-size:cover;background-position:center;background-color:#0c1322;
    display:flex;align-items:center;justify-content:center;position:relative}
  .poster .noimg{font-size:34px;opacity:.35}
  .poster .type-badge{position:absolute;top:7px;left:7px;font-size:10px;font-weight:800;padding:3px 8px;border-radius:6px;
    background:rgba(0,0,0,.7);backdrop-filter:blur(4px);letter-spacing:.4px}
  .poster .type-badge.movie{color:#7dd3fc}
  .poster .type-badge.series{color:#c4b5fd}
  .poster .type-badge.adult{color:#fca5a5}
  .poster .play-ov{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;opacity:0;transition:.18s;background:rgba(0,0,0,.3)}
  .card-item:hover .play-ov{opacity:1}
  .poster .play-ov span{width:46px;height:46px;border-radius:50%;background:var(--acc);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 4px 16px rgba(229,9,20,.6)}
  .c-title{padding:8px 9px 10px;font-size:12.5px;font-weight:600;line-height:1.35;
    display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:#e7ecf8}

  .pager{display:flex;gap:6px;align-items:center;justify-content:center;flex-wrap:wrap;margin:28px 0 8px}
  .pager a,.pager span{min-width:40px;text-align:center;padding:9px 13px;border-radius:9px;text-decoration:none;font-size:13.5px;font-weight:700;border:1px solid var(--line);color:#cfe;background:#0f1626}
  .pager a:hover{filter:brightness(1.3);transform:translateY(-1px)}
  .pager .cur{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;border-color:transparent}
  .pager .dis{opacity:.35;pointer-events:none}
  .pager .gap{border:0;background:transparent;color:var(--mut)}

  .empty{grid-column:1/-1;text-align:center;color:var(--mut);padding:54px 16px;font-size:14px}
  .footer{text-align:center;color:var(--mut);font-size:12px;padding:34px 16px 26px;border-top:1px solid var(--line);margin-top:30px}
  .footer b{color:var(--acc)}
`;

function brandLogo() {
  return `<a class="brand" href="/"><span class="logo-c">🎬</span><span class="logo-t">CM&nbsp;<b>FLIX</b></span></a>`;
}

function pageShell(title, body, opts = {}) {
  return `<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#070a14">
<title>${htmlEscape(title)}</title>
<style>${CMFLIX_CSS}${opts.extraCss || ""}</style>
</head>
<body>
${body}
${opts.script ? `<script>${opts.script}</script>` : ""}
</body></html>`;
}

const AUTH_CSS = `
  .auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .auth-card{background:rgba(15,22,38,.94);backdrop-filter:blur(10px);border:1px solid var(--line);border-radius:18px;padding:32px;width:100%;max-width:440px;box-shadow:0 18px 50px rgba(0,0,0,.6)}
  .auth-card .logo-c{width:46px;height:46px;font-size:24px;border-radius:12px;margin-bottom:14px}
  .auth-card h1{margin:0 0 6px;font-size:22px}
  .auth-card p.sub{margin:0 0 18px;color:var(--mut);font-size:13.5px;line-height:1.6}
  label{display:block;font-size:13px;margin:12px 0 6px;color:#cdd;font-weight:600}
  input[type=text],input[type=number],input[type=url],input[type=search],select,textarea{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:#0a1220;color:#fff;font-size:15px;outline:none;font-family:inherit;transition:border-color .15s,box-shadow .15s}
  input:focus,select:focus,textarea:focus{border-color:var(--acc2);box-shadow:0 0 0 3px rgba(255,45,85,.18)}
  textarea{resize:vertical;min-height:64px}
  .key-input{font-size:18px !important;letter-spacing:2px;text-align:center;font-weight:700;text-transform:uppercase}
  .btn{width:100%;margin-top:18px;padding:13px;border:0;border-radius:10px;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;font-weight:800;font-size:15px;cursor:pointer;font-family:inherit;transition:filter .12s}
  .btn:hover{filter:brightness(1.08)}
  .btn:disabled{opacity:.6;cursor:not-allowed}
  .err{background:#3a1020;border:1px solid #6a2030;color:#ffd;padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:13px;line-height:1.5}
  .ok{background:#10331a;border:1px solid #225a30;color:#cfc;padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:13px;line-height:1.5}
  .info{background:#102a3a;border:1px solid #1f4a6a;color:#cef;padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:13px;line-height:1.5}
  .badge{display:inline-block;padding:3px 9px;border-radius:6px;font-size:11.5px;font-weight:800;margin-left:6px;vertical-align:middle}
  .badge-paid{background:#22c55e;color:#04210f}
  .badge-trial{background:#f59e0b;color:#2a1700}
  .note{font-size:11.5px;color:var(--mut);margin-top:14px;text-align:center;line-height:1.6}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
`;

function topBar(activeCat = "", query = "") {
  return `
<div class="topbar">
  ${brandLogo()}
  <form class="search" method="GET" action="/search">
    <span class="si">🔍</span>
    <input type="search" name="q" value="${htmlEscape(query)}" placeholder="ဇာတ်ကား / Series ရှာရန်…" autocomplete="off">
  </form>
  <div class="acts">
    <a href="/category/movie">Movies</a>
    <a href="/category/series">Series</a>
    <a class="me" href="/account">My Key</a>
  </div>
</div>
<div class="wrap">
  <nav class="navchips">
    <a class="${activeCat === "" ? "on" : ""}" href="/">🏠 Home</a>
    <a class="${activeCat === "movie" ? "on" : ""}" href="/category/movie">🎬 Movies</a>
    <a class="${activeCat === "series" ? "on" : ""}" href="/category/series">📺 Series</a>
    <a class="${activeCat === "adult" ? "on" : ""}" href="/category/adult">🔞 21+</a>
  </nav>
</div>`;
}

function footer() {
  return `<div class="footer">© ${new Date().getFullYear()} <b>CM FLIX</b> · All rights reserved.</div>`;
}

function cardHtml(it) {
  const cat = CATEGORIES[it.type] || CATEGORIES.movie;
  return `
  <a class="card-item" href="/watch/${htmlEscape(it.id)}">
    <div class="poster" style="background-image:url('${htmlEscape(it.poster || "")}')">
      ${it.poster ? "" : '<span class="noimg">🎬</span>'}
      <div class="play-ov"><span>▶</span></div>
    </div>
    <div class="c-title">${htmlEscape(it.title || "Untitled")}</div>
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
   HOME PAGE  (slider uses slide_image fallback to poster)
   ══════════════════════════════════════════════════ */
function homePage(slides, sections) {
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
    const cards = sec.items.map(cardHtml).join("");
    return `
    <div class="section">
      <div class="section-head">
        <h2>${cat.icon} ${htmlEscape(cat.name)}</h2>
        <a class="seeall" href="/category/${cat.id}">See all →</a>
      </div>
      <div class="grid">${cards || `<div class="empty">${cat.name} မရှိသေးပါ</div>`}</div>
    </div>`;
  }).join("");

  const body = `
${topBar("")}
<div class="wrap">
  ${heroHtml}
  ${sectionsHtml}
</div>
${footer()}`;

  const script = `
(function(){
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

  return pageShell("CM FLIX — Movies & Series", body, { script });
}

function gridPage(title, activeCat, items, page, totalPages, total, hrefFor, query = "") {
  const cards = items.map(cardHtml).join("");
  const pager = buildPager(page, totalPages, hrefFor);
  const body = `
${topBar(activeCat, query)}
<div class="wrap">
  <div class="section">
    <div class="section-head">
      <h2>${htmlEscape(title)}</h2>
      <span style="color:var(--mut);font-size:13px">${total} ခု</span>
    </div>
    <div class="grid">${cards || `<div class="empty">${query ? "ရှာဖွေမှု မတွေ့ပါ" : "ဘာမှ မရှိသေးပါ"}</div>`}</div>
    ${pager}
  </div>
</div>
${footer()}`;
  return pageShell(title + " — CM FLIX", body);
}

/* ══════════════════════════════════════════════════
   WATCH PAGE  — signed stream URLs only (no real link in HTML)
   `streams` is precomputed server-side:
     - movie/adult: { video, dl }
     - series: seasons[].episodes[] each { video, dl }
   When user is gated, streams are empty strings → nothing leaks.
   ══════════════════════════════════════════════════ */
function watchPage(item, user, gated, streams) {
  const cat = CATEGORIES[item.type] || CATEGORIES.movie;
  const loggedIn = !!user;

  let playerArea = "";
  let seriesNav = "";

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
        <video id="cmPlayer" controls controlsList="nodownload" playsinline preload="metadata" poster="${htmlEscape(item.slide_image || item.poster || "")}"></video>
        <div class="player-empty" id="playerEmpty">▶ အပိုင်းတစ်ခုကို ရွေးပါ</div>
      </div>
      <div class="now-playing" id="nowPlaying"></div>`;
  } else {
    const st = streams.single || { video: "", dl: "" };
    playerArea = `
      <div class="player-box">
        <video id="cmPlayer" controls controlsList="nodownload" playsinline preload="metadata" poster="${htmlEscape(item.slide_image || item.poster || "")}"
          data-video="${htmlEscape(st.video || "")}" data-dl="${htmlEscape(st.dl || "")}"></video>
      </div>`;
  }

  const gateBanner = gated ? `
    <div class="gate" id="gateBanner">
      ${!loggedIn
        ? `🔒 ကြည့်ရှု / Download ရန် Key ဖြင့် ဝင်ရန် လိုအပ်ပါသည်။ <a href="/login?next=${encodeURIComponent("/watch/" + item.id)}">ဝင်မယ်</a>`
        : `⏳ Key သက်တမ်း ကုန်သွားပါပြီ။ <a href="/account">တိုးရန်</a>`}
    </div>` : "";

  const extraCss = `
    .watch{display:grid;grid-template-columns:1fr;gap:22px;margin:18px 0}
    @media(min-width:900px){ .watch.has-info{grid-template-columns:1fr 320px} }
    .player-box{position:relative;background:#000;border-radius:14px;overflow:hidden;aspect-ratio:16/9;box-shadow:0 10px 34px rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center}
    .player-box video{width:100%;height:100%;background:#000;object-fit:contain;display:block}
    .player-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--mut);font-size:15px;font-weight:600;background:#0a0e1a}
    .player-empty.hide{display:none}
    .meta-title{font-size:24px;font-weight:900;margin:0 0 8px}
    .meta-cat{display:inline-block;font-size:11px;font-weight:800;padding:4px 10px;border-radius:6px;background:#161d31;margin-bottom:12px;letter-spacing:.4px}
    .meta-note{color:#cfd6e8;font-size:14px;line-height:1.75;margin:0 0 18px;white-space:pre-wrap}
    .actions{display:flex;gap:12px;flex-wrap:wrap;margin:6px 0 4px}
    .actions a,.actions button{flex:1 1 170px;max-width:280px;text-align:center;padding:13px 18px;border-radius:10px;border:0;cursor:pointer;font-weight:800;font-size:15px;text-decoration:none;font-family:inherit;display:inline-flex;align-items:center;justify-content:center;gap:8px}
    .btn-play{background:#fff;color:#111}
    .btn-play:hover{background:var(--acc);color:#fff}
    .btn-dl{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
    .btn-dl:hover{filter:brightness(1.1)}
    .gate{background:#2a1420;border:1px solid #6a2030;color:#ffd;padding:12px 14px;border-radius:10px;margin:14px 0;font-size:14px;line-height:1.6}
    .gate a{color:var(--acc2);font-weight:800}
    .now-playing{margin-top:12px;color:var(--acc2);font-weight:700;font-size:14px;min-height:18px}
    .seasons{margin-top:20px}
    .season-tabs{display:flex;gap:8px;overflow-x:auto;padding-bottom:10px;scrollbar-width:none}
    .season-tabs::-webkit-scrollbar{display:none}
    .season-tab{flex:0 0 auto;padding:8px 16px;border-radius:9px;border:1px solid var(--line);background:#161d31;color:#fff;font-weight:700;font-size:13.5px;cursor:pointer;font-family:inherit}
    .season-tab.on{background:linear-gradient(135deg,var(--acc),var(--acc2));border-color:transparent}
    .ep-list{display:none;flex-direction:column;gap:8px;margin-top:6px}
    .ep-list.on{display:flex}
    .ep-btn{display:flex;align-items:center;gap:12px;width:100%;text-align:left;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:#101626;color:#fff;cursor:pointer;font-family:inherit;transition:.12s}
    .ep-btn:hover{border-color:var(--acc2);background:#161d31}
    .ep-btn.playing{border-color:var(--acc);background:#1e1420}
    .ep-no{flex:0 0 32px;height:32px;border-radius:8px;background:#1c2740;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px}
    .ep-btn.playing .ep-no{background:var(--acc)}
    .ep-tt{flex:1;font-size:14px;font-weight:600}
    .ep-play{opacity:.6;font-size:13px}
    .info-side .meta-title{font-size:20px}
  `;

  const hasInfo = !!(item.note || item.type === "series");
  const body = `
${topBar(item.type)}
<div class="wrap">
  ${gateBanner}
  <div class="watch ${hasInfo ? "has-info" : ""}">
    <div class="player-col">
      ${playerArea}
      <div class="actions">
        <button class="btn-play" id="btnPlay">▶ Play</button>
        <a class="btn-dl" id="btnDl" href="#">⬇ Download</a>
      </div>
      ${item.type !== "series" ? `
        <h1 class="meta-title">${htmlEscape(item.title)}</h1>
        <span class="meta-cat">${cat.icon} ${htmlEscape(cat.name)}</span>
        ${item.note ? `<p class="meta-note">${htmlEscape(item.note)}</p>` : ""}
      ` : ""}
      ${seriesNav}
    </div>
    ${hasInfo && item.type === "series" ? `
      <div class="info-side">
        <h1 class="meta-title">${htmlEscape(item.title)}</h1>
        <span class="meta-cat">${cat.icon} ${htmlEscape(cat.name)}</span>
        ${item.note ? `<p class="meta-note">${htmlEscape(item.note)}</p>` : ""}
      </div>` : ""}
  </div>
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
  var cur={video:'',dl:'',title:''};

  function gateMsg(){
    var loginUrl='/login?next='+encodeURIComponent(location.pathname+location.search);
    location.href = ${loggedIn ? "'/account'" : "loginUrl"};
  }

  function setSource(video, dl, title){
    cur.video=video||''; cur.dl=dl||video||''; cur.title=title||'';
    if(emptyEl) emptyEl.classList.add('hide');
    if(v){ v.src=cur.video; }
    if(btnDl){ btnDl.href=cur.dl || '#'; }
    if(nowEl && title){ nowEl.textContent='▶ Now playing: '+title; }
  }

  ${item.type !== "series" ? `
  (function(){
    var dv=v.getAttribute('data-video')||''; var dd=v.getAttribute('data-dl')||dv;
    cur.video=dv; cur.dl=dd;
    if(btnDl) btnDl.href=dd||'#';
  })();` : ``}

  if(btnPlay){
    btnPlay.addEventListener('click',function(){
      if(GATED){ gateMsg(); return; }
      if(!cur.video){ alert('အပိုင်း / link မရှိသေးပါ'); return; }
      if(!v.src) v.src=cur.video;
      var p=v.play(); if(p&&p.catch) p.catch(function(){});
      v.scrollIntoView({behavior:'smooth',block:'center'});
    });
  }
  if(btnDl){
    btnDl.addEventListener('click',function(e){
      if(GATED){ e.preventDefault(); gateMsg(); return; }
      if(!cur.dl){ e.preventDefault(); alert('Download link မရှိသေးပါ'); }
    });
  }
  if(v){
    v.addEventListener('play',function(){ if(GATED){ v.pause(); gateMsg(); } });
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
      var p=v.play(); if(p&&p.catch) p.catch(function(){});
      v.scrollIntoView({behavior:'smooth',block:'center'});
    });
  });
  ` : ``}
})();`;

  return pageShell((item.title || "Watch") + " — CM FLIX", body, { extraCss, script });
}

/* ══════════════════════════════════════════════════
   LOGIN / EXPIRED / ACCOUNT PAGES
   ══════════════════════════════════════════════════ */
function keyLoginPage(csrfToken, error = "", info = "", nextUrl = "/") {
  const body = `
<div class="auth-wrap"><div class="auth-card">
  <div class="logo-c" style="display:inline-flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--acc),var(--acc2))">🎬</div>
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
  <div class="logo-c" style="display:inline-flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--acc),var(--acc2))">🎬</div>
  <h1>Key Expired</h1>
  <p class="sub">${htmlEscape(msg)}</p>
  <a class="btn" href="/login" style="display:block;text-align:center;text-decoration:none;margin-top:10px">Key အသစ်ထည့်ရန်</a>
</div></div>`;
  return pageShell("Expired — CM FLIX", body, { extraCss: AUTH_CSS });
}

function accountPage(user, info = "", error = "") {
  const exp = user.expires_at ? new Date(user.expires_at).toLocaleString("en-GB", { hour12: false, timeZone: "Asia/Yangon" }) : "—";
  const remainMs = (user.expires_at || 0) - Date.now();
  const remainText = remainMs > 0
    ? `${Math.floor(remainMs / 86400000)} ရက် ${Math.floor((remainMs % 86400000) / 3600000)} နာရီ ${Math.floor((remainMs % 3600000) / 60000)} မိနစ်`
    : "ကုန်ဆုံးပြီ";
  const roleBadge = user.role === "paid"
    ? '<span class="badge badge-paid">PAID</span>'
    : '<span class="badge badge-trial">TRIAL</span>';
  const devices = Array.isArray(user.devices) ? user.devices : [];
  const devRows = devices.map(d => {
    const seen = d.last_seen ? new Date(d.last_seen).toLocaleString("en-GB", { hour12: false, timeZone: "Asia/Yangon" }) : "—";
    return `<tr><td>${htmlEscape(d.label || "Device")}</td><td style="white-space:nowrap;font-size:11.5px">${htmlEscape(seen)}</td></tr>`;
  }).join("");

  const body = `
<div class="auth-wrap"><div class="auth-card" style="max-width:560px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
    <div>
      <h1 style="margin:0">My Key</h1>
      <p class="sub" style="margin:4px 0 0"><code style="color:var(--acc2)">${htmlEscape(user.keyId)}</code> ${roleBadge}</p>
    </div>
    <a href="/" style="color:var(--acc2);text-decoration:none;font-weight:700;font-size:13px">← Home</a>
  </div>
  ${info ? `<div class="ok">${htmlEscape(info)}</div>` : ""}
  ${error ? `<div class="err">${htmlEscape(error)}</div>` : ""}
  <div class="info" style="display:flex;justify-content:space-between;align-items:center">
    <div>
      <div style="font-size:11.5px;color:var(--mut)">သက်တမ်း ကျန်ရှိ</div>
      <div style="font-size:18px;font-weight:700;color:var(--acc2)">${htmlEscape(remainText)}</div>
      <div style="font-size:11px;color:var(--mut);margin-top:2px">ကုန်ဆုံးမည့်ရက်: ${htmlEscape(exp)} (MMT)</div>
    </div>
  </div>
  <h3 style="margin:24px 0 10px;font-size:15px">ချိတ်ဆက်ထားသော Device (${devices.length}/${MAX_DEVICES_PER_KEY})</h3>
  <div style="overflow:auto;border:1px solid var(--line);border-radius:10px">
    <table style="width:100%;border-collapse:collapse;font-size:12.5px">
      <thead><tr style="background:#152033;text-align:left"><th>Device</th><th>Last seen</th></tr></thead>
      <tbody>${devRows || '<tr><td colspan="2" style="padding:18px;text-align:center;color:var(--mut)">Device မရှိသေးပါ</td></tr>'}</tbody>
    </table>
  </div>
  <div style="margin-top:20px;text-align:center">
    <a href="/" style="color:var(--acc2);text-decoration:none;font-weight:700;margin-right:18px">🏠 Home</a>
    <a href="/logout" style="color:#f88;text-decoration:none;font-weight:700">ဤ Device မှ ထွက်ရန်</a>
  </div>
</div></div>
<style>th,td{padding:8px 10px;border-bottom:1px solid var(--line)}th{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}</style>`;
  return pageShell("My Key — CM FLIX", body, { extraCss: AUTH_CSS });
}

/* ══════════════════════════════════════════════════
   ADMIN PAGE  (now includes Slide Image field)
   ══════════════════════════════════════════════════ */
function adminPage(keys, stats, csrfToken, newKey = "", info = "", items = [], itPage = 1, itTotalPages = 1, itQuery = "", itTotal = 0, itType = "") {
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
    return `<tr>
      <td style="width:54px"><div class="thumb" style="background-image:url('${htmlEscape(m.poster || "")}')">${m.poster ? "" : "🎬"}</div></td>
      <td><a href="/watch/${htmlEscape(m.id)}" target="_blank" style="color:#cef;text-decoration:none;font-weight:600">${htmlEscape(m.title || "Untitled")}</a>
        <div style="font-size:10.5px;color:var(--mut)"><code>${htmlEscape(m.id)}</code>${m.slide_image ? ' · 🖼️ slide' : ''}</div></td>
      <td><span class="badge" style="background:#1c2740;color:#cde">${cat.icon} ${htmlEscape(cat.name)}</span></td>
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

  const body = `
<div class="auth-wrap" style="align-items:flex-start;padding-top:24px"><div class="auth-card" style="max-width:1120px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
    <div>
      <h1 style="margin:0;font-size:22px">🎬 CM FLIX · Admin</h1>
      <p class="sub" style="margin:4px 0 0">
        Keys: <strong>${stats.total}</strong> ·
        <span style="color:#6f6">Active ${stats.active}</span> ·
        <span style="color:#f66">Expired ${stats.expired}</span> ·
        Paid ${stats.paid} · Trial ${stats.trial} ·
        🎞️ Content ${itTotal}
      </p>
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
  <div id="content" style="background:#15101f;border:1px solid #3a1f3f;border-radius:12px;padding:16px;margin-bottom:18px">
    <div style="font-weight:800;color:var(--acc2);margin-bottom:10px">➕ Content အသစ် တင်ရန် (Signed-link stream — link မပေါက်ကြား)</div>
    <form method="POST" action="/admin/item/create" id="addForm">
      <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
      <div style="display:grid;grid-template-columns:1fr;gap:10px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div><label>Category</label>
            <select name="type" id="addType" onchange="cmToggleType(this.value,'add')">
              <option value="movie">🎬 Movie</option>
              <option value="series">📺 Series</option>
              <option value="adult">🔞 21+</option>
            </select>
          </div>
          <div><label>Title</label><input type="text" name="title" placeholder="ဥပမာ - Action 2025" required></div>
        </div>
        <div><label>Poster URL (ထောင်လိုက် ပုံ — card အတွက်)</label><input type="url" name="poster" placeholder="https://.../poster.jpg"></div>
        <div><label>Slide Banner URL (အလျားလိုက် ပုံ — slider အတွက်၊ optional)</label><input type="url" name="slide_image" placeholder="https://.../banner-wide.jpg">
          <div style="font-size:11px;color:var(--mut);margin-top:4px">ကွက်လပ်ထားရင် slider မှာ poster ကို သုံးမယ်။ (16:9 / landscape ပုံ ထည့်ရင် အကောင်းဆုံး)</div>
        </div>
        <div class="single-fields"><label>Video URL (direct / R2)</label><input type="url" name="video_url" placeholder="https://.../video.mp4"></div>
        <div class="single-fields"><label>Download URL (optional — ကွက်လပ်ထားရင် video URL ကို သုံးမယ်)</label><input type="url" name="download_url" placeholder="https://.../download.mp4"></div>
        <div class="series-fields" style="display:none">
          <label>Series Episodes (JSON) — Season/Episode</label>
          <textarea name="seasons_json" placeholder='[{"season":1,"episodes":[{"ep":1,"title":"Ep 1","video_url":"https://.../s1e1.mp4","download_url":""},{"ep":2,"title":"Ep 2","video_url":"https://.../s1e2.mp4"}]},{"season":2,"episodes":[{"ep":1,"title":"S2 Ep1","video_url":"https://.../s2e1.mp4"}]}]'></textarea>
          <div style="font-size:11px;color:var(--mut);margin-top:4px">Format: season တစ်ခုစီမှာ episodes array။ episode တစ်ခုစီမှာ ep, title, video_url, download_url(optional)။</div>
        </div>
        <div><label>Note / ဖော်ပြချက် (optional)</label><textarea name="note" placeholder="ဇာတ်လမ်းအကျဉ်း…" style="min-height:80px"></textarea></div>
      </div>
      <button type="submit" class="btn" style="margin-top:14px">တင်မယ်</button>
    </form>
  </div>

  <!-- ════ CONTENT LIST ════ -->
  <form method="GET" action="/admin" style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">
    <input type="search" name="itq" value="${htmlEscape(itQuery)}" placeholder="🔍 title / id ရှာရန်…" style="flex:1;min-width:180px">
    <select name="ittype" style="width:auto">
      <option value="">All</option>
      <option value="movie" ${itType === "movie" ? "selected" : ""}>🎬 Movie</option>
      <option value="series" ${itType === "series" ? "selected" : ""}>📺 Series</option>
      <option value="adult" ${itType === "adult" ? "selected" : ""}>🔞 21+</option>
    </select>
    <input type="hidden" name="itpage" value="1">
    <button type="submit" class="btn" style="width:auto;margin:0;padding:11px 18px">Search</button>
  </form>
  ${items.length ? `
  <div style="overflow:auto;border:1px solid var(--line);border-radius:10px;margin-bottom:6px">
    <table style="width:100%;border-collapse:collapse;font-size:13px;min-width:640px">
      <thead><tr style="background:#15101f;text-align:left"><th></th><th>Title / ID</th><th>Type</th><th>Added</th><th>Action</th></tr></thead>
      <tbody>${itemRows}</tbody>
    </table>
  </div>${itemPager}` : `<div style="text-align:center;color:var(--mut);padding:24px;border:1px solid var(--line);border-radius:10px;margin-bottom:16px">${itQuery || itType ? "မတွေ့ပါ" : "Content မရှိသေးပါ"}</div>`}

  <!-- ════ CREATE KEY ════ -->
  <div style="background:#101a2c;border:1px solid var(--line);border-radius:12px;padding:16px;margin:20px 0 16px">
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
  <div id="bulkBar" style="display:none;background:#152033;border:1px solid var(--line);border-radius:8px;padding:10px;margin-bottom:10px;align-items:center;gap:8px;flex-wrap:wrap">
    <span id="bulkCount" style="color:#cef;font-weight:600">0 selected</span>
    <form method="POST" action="/admin/bulk" style="display:flex;gap:6px;align-items:center;margin:0">
      <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
      <input type="hidden" name="keys" id="bulkKeys">
      <input type="number" name="days" value="30" min="1" max="3650" style="width:64px;padding:6px">
      <button type="submit" name="action" value="extend" class="btn-ext">Extend all</button>
      <button type="submit" name="action" value="delete" class="btn-del" onclick="return confirm('Delete all selected?')">Delete all</button>
    </form>
  </div>
  <div style="overflow:auto;border:1px solid var(--line);border-radius:10px">
    <table style="width:100%;border-collapse:collapse;font-size:13px;min-width:860px">
      <thead><tr style="background:#152033;text-align:left">
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
  tr:hover td{background:#101a2c}
  .btn-ext,.btn-del,.btn-reset{width:auto;margin:0;padding:6px 10px;font-size:12px;border-radius:6px;border:0;font-weight:700;cursor:pointer;font-family:inherit;display:inline-block}
  .btn-ext{background:var(--acc2);color:#fff}
  .btn-reset{background:#f59e0b;color:#2a1700;margin-left:6px}
  .btn-del{background:#c43;color:#fff;margin-left:6px}
  .thumb{width:36px;height:52px;border-radius:5px;background-size:cover;background-position:center;background-color:#101a2c;display:flex;align-items:center;justify-content:center;font-size:16px}
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
</script>`;
  return pageShell("Admin — CM FLIX", body, { extraCss: AUTH_CSS });
}

/* ══════════════════════════════════════════════════
   ADMIN EDIT PAGE  (with Slide Image)
   ══════════════════════════════════════════════════ */
function adminEditPage(item, csrfToken, error = "") {
  const isSeries = item.type === "series";
  const seasonsJson = isSeries ? JSON.stringify(item.seasons || [], null, 2) : "";
  const body = `
<div class="auth-wrap" style="align-items:flex-start;padding-top:24px"><div class="auth-card" style="max-width:760px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <h1 style="margin:0;font-size:20px">✏️ Edit — ${htmlEscape(item.title)}</h1>
    <a href="/admin#content" style="color:var(--acc2);text-decoration:none;font-weight:700;font-size:13px">← Back</a>
  </div>
  ${error ? `<div class="err">${htmlEscape(error)}</div>` : ""}
  <form method="POST" action="/admin/item/update" id="editForm">
    <input type="hidden" name="csrf_token" value="${htmlEscape(csrfToken)}">
    <input type="hidden" name="id" value="${htmlEscape(item.id)}">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div><label>Category</label>
        <select name="type" onchange="cmToggleType(this.value,'edit')">
          <option value="movie" ${item.type === "movie" ? "selected" : ""}>🎬 Movie</option>
          <option value="series" ${item.type === "series" ? "selected" : ""}>📺 Series</option>
          <option value="adult" ${item.type === "adult" ? "selected" : ""}>🔞 21+</option>
        </select>
      </div>
      <div><label>Title</label><input type="text" name="title" value="${htmlEscape(item.title || "")}" required></div>
    </div>
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
   SERIES JSON SANITIZER
   ══════════════════════════════════════════════════ */
function sanitizeSeasons(raw) {
  let arr;
  try { arr = JSON.parse(raw); } catch (_) { return { ok: false, err: "Episodes JSON format မှားနေပါတယ်။" }; }
  if (!Array.isArray(arr)) return { ok: false, err: "JSON က array ဖြစ်ရပါမယ်။" };
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
  if (!out.length) return { ok: false, err: "Episode အနည်းဆုံး တစ်ခု ထည့်ပါ။" };
  return { ok: true, seasons: out };
}

/* ══════════════════════════════════════════════════
   Build signed streams for watchPage (server-side only)
   ══════════════════════════════════════════════════ */
async function buildStreams(env, item, gated, user) {
  if (gated) {
    // gated ဖြစ်ရင် link လုံးဝ မထုတ်ဘူး
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

// signed request → real R2 link ကို resolve
function resolveRealUrl(item, s, e, download) {
  if (item.type === "series") {
    const seasons = Array.isArray(item.seasons) ? item.seasons : [];
    const ep = seasons?.[s]?.episodes?.[e];
    if (!ep) return "";
    if (download) return ep.download_url || ep.video_url || "";
    return ep.video_url || "";
  }
  if (download) return item.download_url || item.video_url || "";
  return item.video_url || "";
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
    const all = await listItems(env);
    const byType = (t) => all.filter(i => i.type === t);
    const sections = [
      { type: "movie",  items: byType("movie").slice(0, HOME_PREVIEW_COUNT) },
      { type: "series", items: byType("series").slice(0, HOME_PREVIEW_COUNT) },
      { type: "adult",  items: byType("adult").slice(0, HOME_PREVIEW_COUNT) },
    ];
    // hero slides = slide_image ရှိတဲ့အရာတွေ ဦးစားပေး၊ မရှိရင် poster fallback
    const withImg = all.filter(i => i.slide_image || i.poster);
    const slidePool = withImg.slice(0, 6);
    const slides = slidePool.map(i => ({
      image: i.slide_image || i.poster,
      title: i.title,
      desc: (CATEGORIES[i.type] || CATEGORIES.movie).name,
      tag: (CATEGORIES[i.type] || CATEGORIES.movie).name.toUpperCase(),
      link: "/watch/" + i.id,
    }));
    return new Response(homePage(slides, sections), { headers: { "content-type": "text/html; charset=utf-8" } });
  }

  // ───────────── CATEGORY GRID ─────────────
  if (path.startsWith("/category/") && method === "GET") {
    const cat = path.slice("/category/".length).split("/")[0];
    if (!isValidCategory(cat)) return Response.redirect(new URL("/", url).toString(), 302);
    const all = (await listItems(env)).filter(i => i.type === cat);
    const total = all.length;
    const totalPages = Math.max(1, Math.ceil(total / ITEMS_PER_PAGE));
    let page = parseInt(url.searchParams.get("page") || "1", 10);
    if (!Number.isFinite(page) || page < 1) page = 1;
    if (page > totalPages) page = totalPages;
    const slice = all.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);
    const c = CATEGORIES[cat];
    return new Response(
      gridPage(`${c.icon} ${c.name}`, cat, slice, page, totalPages, total, (p) => `/category/${cat}?page=${p}`),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // ───────────── SEARCH ─────────────
  if (path === "/search" && method === "GET") {
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
      gridPage(`🔍 "${q}"`, "", slice, page, totalPages, total, (p) => `/search?q=${encodeURIComponent(q)}&page=${p}`, q),
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
    return new Response(watchPage(item, user, gated, streams), { headers: { "content-type": "text/html; charset=utf-8" } });
  }

  // ───────────── STREAM (signed) — Worker PROXY (real link ဘယ်တော့မှ မပေါက်ကြား) ─────────────
  if (path.startsWith("/stream/") && method === "GET") {
    const id = decodeURIComponent(path.slice("/stream/".length).split("/")[0]);
    const item = await getItem(env, id);
    if (!item) return new Response("Not found", { status: 404 });

    // 1) signature စစ် — expire / badsig ဆို ချက်ချင်း ပိတ်
    const v = await verifyStreamSig(env, id, url.searchParams);
    if (!v.ok) {
      return new Response(v.reason === "expired" ? "Link expired" : "Invalid link", { status: 403 });
    }

    // 2) login + valid user ဖြစ်မှသာ ဖွင့်ပေး
    const user = await getCurrentUser(request, env);
    if (!user || isExpired(user)) {
      return new Response("Login required", { status: 403 });
    }

    // 3) link ကို ထုတ်ပေးခဲ့သူနဲ့ session တူမတူ (binding)
    const u = await userStreamTag(user);
    if (v.u && !safeEqual(v.u, u)) {
      return new Response("Link not valid for this session", { status: 403 });
    }

    // 4) real R2 / origin link ကို resolve — client ဆီ ဘယ်တော့မှ မပေးဘူး
    const real = resolveRealUrl(item, v.s, v.e, v.d === 1);
    if (!isHttpUrl(real)) return new Response("No source", { status: 404 });

    // 5) Worker ကိုယ်တိုင် origin ဆီကနေ fetch (proxy / ရေပိုက်နည်း)
    //    Range header ကို pass-through → seek / ဖြတ်ကျော်ကြည့်ခြင်း အလုပ်လုပ်အောင်
    const rangeHeader = request.headers.get("Range");
    const fwdHeaders = new Headers();
    if (rangeHeader) fwdHeaders.set("Range", rangeHeader);
    const ifRange = request.headers.get("If-Range");
    if (ifRange) fwdHeaders.set("If-Range", ifRange);

    let originResp;
    try {
      originResp = await fetch(real, {
        method: "GET",
        headers: fwdHeaders,
        redirect: "follow",
      });
    } catch (_) {
      return new Response("Upstream error", { status: 502 });
    }

    if (!originResp.ok && originResp.status !== 206) {
      return new Response("Upstream unavailable", { status: 502 });
    }

    // 6) response headers ကို သန့်ရှင်းအောင် ပြန်တည်ဆောက် — origin link / internal info မပေါက်အောင်
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

    // Content-Type မရှိရင် mp4 default
    if (!outHeaders.has("Content-Type")) outHeaders.set("Content-Type", "video/mp4");
    // Range support ကို client သိအောင်
    if (!outHeaders.has("Accept-Ranges")) outHeaders.set("Accept-Ranges", "bytes");

    // signed link မို့ cache မလုပ်စေချင်
    outHeaders.set("Cache-Control", "private, no-store");
    // referrer / origin info မပေါက်အောင်
    outHeaders.set("X-Content-Type-Options", "nosniff");

    // 7) download mode ဆို attachment အဖြစ် ဖိုင်နာမည်ပေး
    if (v.d === 1) {
      const safeName = (item.title || "video")
        .replace(/[^\w\-. ]+/g, "_")
        .slice(0, 80)
        .trim() || "video";
      const ext = real.split("?")[0].split(".").pop();
      const fname = /^[a-z0-9]{2,5}$/i.test(ext) ? `${safeName}.${ext}` : `${safeName}.mp4`;
      outHeaders.set("Content-Disposition", `attachment; filename="${fname}"`);
    } else {
      outHeaders.set("Content-Disposition", "inline");
    }

    // 8) body ကို stream အဖြစ် တိုက်ရိုက် pipe — memory မစား၊ video ချက်ချင်း စီးဆင်း
    //    origin status (200 / 206) ကို အတိအကျ ပြန်ပေး → Range အလုပ်လုပ်
    return new Response(originResp.body, {
      status: originResp.status,
      headers: outHeaders,
    });
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
      const dest = safeNext.startsWith("/") ? safeNext : "/";
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
    return new Response(accountPage(cur), { headers: { "content-type": "text/html; charset=utf-8" } });
  }

  // ───────────── ADMIN ─────────────
  if (path === "/admin" || path.startsWith("/admin/")) {
    const cur = await getCurrentUser(request, env);
    if (!cur || !cur.isAdmin) return Response.redirect(new URL("/login", url).toString(), 302);
    const { token: csrfToken, isNew: csrfNew } = await getOrCreateCsrf(request, env);
    const setCsrf = csrfNew ? { "Set-Cookie": csrfCookieHeader(csrfToken) } : {};

    // ADMIN DASHBOARD
    if (path === "/admin" && method === "GET") {
      const list = await env.AUTH_USERS.list({ prefix: "key:", limit: 1000 });
      const keys = [];
      for (const k of list.keys) keys.push({ keyId: k.name.slice(4), ...(k.metadata || {}) });
      keys.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
      const now = Date.now();
      const stats = {
        total: keys.length,
        active: keys.filter(k => k.expires_at && k.expires_at > now && !k.disabled).length,
        expired: keys.filter(k => !k.expires_at || k.expires_at <= now || k.disabled).length,
        paid: keys.filter(k => k.role === "paid").length,
        trial: keys.filter(k => k.role === "trial" || !k.role).length,
      };
      let allItems = await listItems(env);
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
        adminPage(keys, stats, csrfToken, newKey, info, items, itPage, itTotalPages, itQuery, itTotal, isValidCategory(itType) ? itType : ""),
        { headers: { "content-type": "text/html; charset=utf-8", ...setCsrf } }
      );
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
      if (!title) return redirectInfo("Title ဖြည့်ပါ။");
      if (poster && !isHttpUrl(poster)) return redirectInfo("Poster link မှားနေပါတယ်။");
      if (slide_image && !isHttpUrl(slide_image)) return redirectInfo("Slide banner link မှားနေပါတယ်။");
      const id = generateItemId();
      const data = { id, type, title, poster, slide_image, note, created_at: Date.now() };
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
      return redirectInfo(`"${title}" တင်ပြီးပါပြီ။`);
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
      if (!title) return new Response(adminEditPage(existing, csrfToken, "Title ဖြည့်ပါ။"), { headers: { "content-type": "text/html; charset=utf-8" } });
      if (slide_image && !isHttpUrl(slide_image)) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, "Slide banner link မှားနေပါတယ်။"), { headers: { "content-type": "text/html; charset=utf-8" } });
      const data = { id, type, title, poster, slide_image, note, created_at: existing.created_at || Date.now() };
      if (type === "series") {
        const r = sanitizeSeasons(form.seasons_json || "");
        if (!r.ok) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, r.err), { headers: { "content-type": "text/html; charset=utf-8" } });
        data.seasons = r.seasons;
      } else {
        const video_url = String(form.video_url || "").trim().slice(0, 1000);
        const download_url = String(form.download_url || "").trim().slice(0, 1000);
        if (!isHttpUrl(video_url)) return new Response(adminEditPage({ ...existing, type, title, poster, slide_image, note }, csrfToken, "Video URL ဖြည့်ပါ။"), { headers: { "content-type": "text/html; charset=utf-8" } });
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
        if (Array.isArray(k.devices)) for (const d of k.devices) if (d.id) await env.AUTH_USERS.delete(`kdev:${d.id}`);
        k.devices = [];
        await putKey(env, keyId, k);
        const sl = await env.AUTH_USERS.list({ prefix: `sess:${keyId}:` });
        for (const s of sl.keys) await env.AUTH_USERS.delete(s.name);
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
      const list = await env.AUTH_USERS.list({ prefix: "key:", limit: 1000 });
      const rows = [["key", "role", "created_at", "expires_at", "device_count", "note", "disabled"]];
      for (const k of list.keys) {
        const m = k.metadata || {};
        rows.push([
          k.name.slice(4), m.role || "trial",
          m.created_at ? new Date(m.created_at).toISOString() : "",
          m.expires_at ? new Date(m.expires_at).toISOString() : "",
          m.device_count || 0, m.note || "", m.disabled ? "yes" : "no",
        ]);
      }
      const csv = rows.map(r => r.map(c => {
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
