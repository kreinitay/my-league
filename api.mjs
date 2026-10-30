// שרת קטן לאתר הליגה: שומר את כל הנתונים ב-Netlify Blobs.
// קריאה פתוחה לכולם, כתיבה רק עם סיסמת האדמין (משתנה סביבה ADMIN_PASSWORD).
import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";
import webpush from "web-push";

const KEY = "league";
const MAX_BYTES = 4 * 1024 * 1024;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readPassword() {
  try {
    const v = globalThis.Netlify?.env?.get?.("ADMIN_PASSWORD");
    if (v) return v;
  } catch {}
  return process.env.ADMIN_PASSWORD || "";
}

export function checkPassword(given, real) {
  if (!real) return { ok: false, reason: "no-password-set" };
  const a = createHash("sha256").update(String(given ?? "")).digest();
  const b = createHash("sha256").update(String(real)).digest();
  return { ok: timingSafeEqual(a, b) };
}

function validData(d) {
  return (
    d && typeof d === "object" && !Array.isArray(d) &&
    Array.isArray(d.teams) && Array.isArray(d.players) && Array.isArray(d.games) &&
    d.league && typeof d.league === "object"
  );
}

// makeHandler מקבל store כדי שאפשר יהיה לבדוק את הקוד בלי Netlify
export function makeHandler(openStore, getRealPassword = readPassword, openChat = null, openPush = null) {
  return async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");
    const store = openStore();

    if (path.endsWith("/api/data") && req.method === "GET") {
      const doc = await store.get(KEY, { type: "json" });
      const have = url.searchParams.get("have");
      // חוסך תעבורה (וקרדיטים): אם לדפדפן כבר יש את הגרסה הזאת, לא שולחים שוב את כל הקובץ
      if (doc && have !== null && Number(have) === Number(doc.rev)) return json({ same: true, rev: doc.rev });
      return json(doc || { data: null, rev: 0 });
    }

    if (path.endsWith("/api/login") && req.method === "POST") {
      let body = {};
      try { body = await req.json(); } catch {}
      const res = checkPassword(body.password, getRealPassword());
      if (res.reason === "no-password-set") return json({ ok: false, error: "no-password-set" }, 500);
      if (!res.ok) { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }
      return json({ ok: true });
    }

    if (path.endsWith("/api/data") && (req.method === "PUT" || req.method === "POST")) {
      const res = checkPassword(req.headers.get("x-admin-password"), getRealPassword());
      if (res.reason === "no-password-set") return json({ ok: false, error: "no-password-set" }, 500);
      if (!res.ok) { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }

      const text = await req.text();
      if (text.length > MAX_BYTES) return json({ ok: false, error: "too-big" }, 413);
      let body;
      try { body = JSON.parse(text); } catch { return json({ ok: false, error: "bad-json" }, 400); }
      if (!validData(body.data)) return json({ ok: false, error: "bad-data" }, 400);

      const current = (await store.get(KEY, { type: "json" })) || { data: null, rev: 0 };
      if (!body.force && Number(body.baseRev) !== Number(current.rev)) {
        return json({ ok: false, error: "conflict", current }, 409);
      }
      const doc = { data: body.data, rev: Number(current.rev) + 1, savedAt: new Date().toISOString() };
      await store.setJSON(KEY, doc);
      return json({ ok: true, rev: doc.rev, savedAt: doc.savedAt });
    }

    if (path.endsWith("/sw.js")) return new Response(SW_JS, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache" } });
    if (path.includes("/api/push")) return pushRoute(req, url, path, openPush ? openPush() : store, getRealPassword);
    if (path.includes("/api/chat")) return chatRoute(req, url, path, openChat ? openChat() : store, getRealPassword, store);

    return json({ ok: false, error: "not-found" }, 404);
  };
}

export default makeHandler(
  () => getStore({ name: "league-data", consistency: "strong" }),
  readPassword,
  () => getStore({ name: "league-chat", consistency: "strong" }),
  () => getStore({ name: "league-push", consistency: "strong" }),
);

export const config = { path: ["/api/data", "/api/login", "/api/chat", "/api/chat/*", "/api/push", "/api/push/*", "/sw.js"] };

/* ================= צ'אט =================
   חדר גדול אחד + 3 חדרים צדדיים. כדי לקרוא או לכתוב צריך "קוד צ'אט" שהמנהל קובע בהגדרות.
   כל שינוי בחדר (הודעה, תגובה, הצבעה, ניחוש) מקבל מספר seq, והדפדפן מבקש רק מה שהשתנה מאז הפעם הקודמת. */
const ROOMS = ["main", "s1", "s2", "s3"];
const DEF_NAMES = { main: "הצ'אט הגדול", s1: "חדר צד 1", s2: "חדר צד 2", s3: "חדר צד 3" };
const REACTS = ["👍", "🔥", "😂", "🏀", "👏"];
const MAX_MSGS = 300, MAX_TEXT = 400, MAX_NAME = 20;
const clean = (v, n) => String(v ?? "").replace(/[\u0000-\u0008\u000B-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "").replace(/\n{3,}/g, "\n\n").trim().slice(0, n);
const cleanId = (v) => String(v ?? "").replace(/[^a-z0-9]/gi, "").slice(0, 24);

async function chatConfig(store) {
  const c = (await store.get("config", { type: "json" })) || {};
  const names = { ...DEF_NAMES, ...(c.names || {}) };
  return { enabled: !!c.enabled, code: String(c.code || ""), names };
}
function sameSecret(a, b) {
  if (!b) return false;
  const x = createHash("sha256").update(String(a ?? "")).digest();
  const y = createHash("sha256").update(String(b)).digest();
  return timingSafeEqual(x, y);
}
const emptyRoom = () => ({ msgs: [], del: [], seq: 0 });
// עדכון בטוח של חדר: אם שני אנשים כותבים באותו רגע, שום דבר לא הולך לאיבוד
async function updateRoom(store, room, fn) {
  const key = "room-" + room;
  for (let i = 0; i < 8; i++) {
    const cur = await store.getWithMetadata(key, { type: "json" });
    const doc = { ...emptyRoom(), ...(cur?.data || {}) };
    const res = fn(doc);
    if (res && res.error) return res;
    const w = cur ? await store.setJSON(key, doc, { onlyIfMatch: cur.etag }) : await store.setJSON(key, doc, { onlyIfNew: true });
    if (w.modified !== false) return res || { ok: true };
    await sleep(40 + Math.random() * 80);
  }
  return { error: "busy" };
}
async function updateKey(store, key, init, fn) {
  for (let i = 0; i < 8; i++) {
    const cur = await store.getWithMetadata(key, { type: "json" });
    const doc = cur?.data ?? init();
    const res = fn(doc);
    if (res && res.error) return res;
    const w = cur ? await store.setJSON(key, doc, { onlyIfMatch: cur.etag }) : await store.setJSON(key, doc, { onlyIfNew: true });
    if (w.modified !== false) return res || { ok: true };
    await sleep(40 + Math.random() * 80);
  }
  return { error: "busy" };
}
const touch = (doc, m) => { doc.seq = (doc.seq || 0) + 1; if (m) m.u = doc.seq; };
function addMsg(doc, msg) {
  const now = Date.now(), lastTs = doc.msgs.length ? doc.msgs[doc.msgs.length - 1].ts : 0;
  msg.id = now.toString(36) + Math.random().toString(36).slice(2, 6); msg.ts = Math.max(now, lastTs + 1);
  doc.msgs.push(msg); touch(doc, msg);
  if (doc.msgs.length > MAX_MSGS) doc.msgs = doc.msgs.slice(-MAX_MSGS);
  return msg;
}
// האם המשחק כבר התחיל/נגמר (לפי נתוני האתר) – אחרי זה אי אפשר לנחש
async function gameLocked(dataStore, gid, doc) {
  doc ||= await dataStore.get(KEY, { type: "json" });
  const g = doc?.data?.games?.find((x) => x.id === gid);
  if (!g) return true;
  const live = g.pubSnap || g;
  if (live.status && live.status !== "scheduled") return true;
  if (Number.isFinite(live.homeScore) || Number.isFinite(live.awayScore)) return true;
  if (g.date) {
    const start = Date.parse(g.date + "T" + (/^\d\d:\d\d$/.test(g.time || "") ? g.time : "23:59") + ":00+02:00");
    if (Number.isFinite(start) && Date.now() > start) return true;
  }
  return false;
}

async function chatRoute(req, url, path, store, getRealPassword, dataStore) {
  const isAdmin = checkPassword(req.headers.get("x-admin-password"), getRealPassword()).ok;
  const cfg = await chatConfig(store);
  const sub = path.replace(/^.*\/api\/chat/, "");
  const deny = async () => { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); };

  if (sub === "/config") {
    if (!isAdmin) return deny();
    if (req.method === "GET") return json({ ok: true, ...cfg });
    let b = {}; try { b = await req.json(); } catch {}
    const names = {};
    for (const r of ROOMS) names[r] = clean(b.names?.[r], 30) || DEF_NAMES[r];
    const next = { enabled: !!b.enabled, code: clean(b.code, 40), names };
    if (next.enabled && next.code.length < 4) return json({ ok: false, error: "short-code" }, 400);
    await store.setJSON("config", next);
    return json({ ok: true, ...next });
  }

  let given = req.headers.get("x-chat-code") || "";
  try { given = decodeURIComponent(given); } catch {}
  const codeOk = isAdmin || (cfg.enabled && sameSecret(clean(given, 40), cfg.code));
  if (!cfg.enabled && !isAdmin) return json({ ok: false, error: "closed" }, 403);
  if (!codeOk) { await sleep(700); return json({ ok: false, error: "wrong-code" }, 401); }
  if (sub === "/join") return json({ ok: true, enabled: cfg.enabled, rooms: ROOMS.map((id) => ({ id, name: cfg.names[id] })) });

  const room = url.searchParams.get("room") || "main";
  if (!ROOMS.includes(room)) return json({ ok: false, error: "bad-room" }, 400);
  let b = {}; if (req.method !== "GET") { try { b = await req.json(); } catch {} }


  /* ---- סקרים: שאלה + 2-6 תשובות, אפשר לתזמן מתי נפתח ומתי נסגר ---- */
  if (sub === "/polls" || sub === "/polls/vote") {
    const now = Date.now(), who = clean(url.searchParams.get("name") || b.name, MAX_NAME);
    const view = (p) => {
      const counts = p.opts.map((_, i) => Object.values(p.votes || {}).filter((v) => v === i).length);
      return { id: p.id, q: p.q, opts: p.opts, start: p.start, end: p.end || 0, counts, total: Object.keys(p.votes || {}).length,
        mine: who && p.votes && who in p.votes ? p.votes[who] : null, open: now >= p.start && (!p.end || now < p.end) };
    };
    if (req.method === "GET") {
      const d = (await store.get("polls", { type: "json" })) || { list: [] };
      return json({ ok: true, polls: d.list.filter((p) => isAdmin || now >= p.start).map(view).sort((x, y) => y.start - x.start) });
    }
    if (sub === "/polls/vote") {
      const id = cleanId(b.id), opt = Number(b.opt);
      if (!who) return json({ ok: false, error: "empty" }, 400);
      const res = await updateKey(store, "polls", () => ({ list: [] }), (d) => {
        const p = d.list.find((x) => x.id === id); if (!p) return { error: "no-msg" };
        if (!(now >= p.start && (!p.end || now < p.end))) return { error: "closed" };
        if (!(opt >= 0 && opt < p.opts.length)) return { error: "empty" };
        p.votes ||= {}; p.votes[who] = opt; return { ok: true, poll: view(p) };
      });
      return res.error ? json({ ok: false, error: res.error }, res.error === "closed" ? 409 : 400) : json(res);
    }
    if (!isAdmin) return deny();
    const res = await updateKey(store, "polls", () => ({ list: [] }), (d) => {
      const id = cleanId(b.id);
      if (b.del) { d.list = d.list.filter((x) => x.id !== id); return { ok: true }; }
      if (b.closeNow) { const p = d.list.find((x) => x.id === id); if (p) p.end = now; return { ok: true }; }
      const q = clean(b.q, 160), opts = (Array.isArray(b.opts) ? b.opts : []).map((o) => clean(o, 60)).filter(Boolean).slice(0, 6);
      if (!q || opts.length < 2) return { error: "empty" };
      const start = Number(b.start) > 0 ? Number(b.start) : now, end = Number(b.end) > start ? Number(b.end) : 0;
      d.list.unshift({ id: now.toString(36) + Math.random().toString(36).slice(2, 6), q, opts, start, end, votes: {} });
      d.list = d.list.slice(0, 60); return { ok: true };
    });
    return res.error ? json({ ok: false, error: res.error }, 400) : json(res);
  }

  /* ---- ניחושים: לכל משחק שעוד לא התחיל מנחשים תוצאה ---- */
  if (sub === "/preds" && req.method === "GET") {
    const d = (await store.get("preds", { type: "json" })) || {};
    return json({ ok: true, preds: d });
  }
  if (sub === "/predict" && req.method === "POST") {
    const who = clean(b.name, MAX_NAME); if (!who) return json({ ok: false, error: "empty" }, 400);
    const picks = (Array.isArray(b.picks) ? b.picks : []).slice(0, 12).map((x) => ({ gid: cleanId(x.gid), h: Math.round(Number(x.h)), a: Math.round(Number(x.a)) }))
      .filter((x) => x.gid && x.h >= 0 && x.h <= 250 && x.a >= 0 && x.a <= 250);
    if (!picks.length) return json({ ok: false, error: "empty" }, 400);
    const data = await dataStore.get(KEY, { type: "json" });
    const okPicks = []; for (const x of picks) if (!(await gameLocked(dataStore, x.gid, data))) okPicks.push(x);
    if (!okPicks.length) return json({ ok: false, error: "closed" }, 409);
    const res = await updateKey(store, "preds", () => ({}), (d) => { for (const x of okPicks) (d[x.gid] ||= {})[who] = [x.h, x.a]; return { ok: true, saved: okPicks.length, locked: picks.length - okPicks.length }; });
    return res.error ? json({ ok: false, error: res.error }, 503) : json(res);
  }

  /* ---- לוח אימונים שבועי – רק למי שיש קוד ---- */
  if (sub === "/training") {
    if (req.method === "GET") return json({ ok: true, ...((await store.get("training", { type: "json" })) || { slots: [], note: "" }) });
    if (!isAdmin) return deny();
    const slots = (Array.isArray(b.slots) ? b.slots : []).slice(0, 14).map((x) => ({ d: Math.max(0, Math.min(6, Math.round(Number(x.d)) || 0)), from: clean(x.from, 5), to: clean(x.to, 5), place: clean(x.place, 60), note: clean(x.note, 60) }))
      .filter((x) => /^\d\d:\d\d$/.test(x.from)).sort((x, y) => x.d - y.d || x.from.localeCompare(y.from));
    const doc = { slots, note: clean(b.note, 300), updated: Date.now() };
    await store.setJSON("training", doc);
    return json({ ok: true, ...doc });
  }

  if (req.method === "GET" && sub === "") {
    const doc = { ...emptyRoom(), ...((await store.get("room-" + room, { type: "json" })) || {}) };
    const since = Number(url.searchParams.get("since") || 0);
    if (since && since === doc.seq) return json({ ok: true, seq: doc.seq, msgs: [] });          // אין חדש – תשובה קטנטנה
    const msgs = since && since < doc.seq ? doc.msgs.filter((m) => (m.u || 0) > since) : doc.msgs.slice(-80);
    return json({ ok: true, seq: doc.seq, full: !since || since > doc.seq, msgs, del: (doc.del || []).slice(-50), pin: doc.pin || null });
  }

  const name = clean(b.name, MAX_NAME), pid = cleanId(b.pid);
  const send = async (fn) => {
    const res = await updateRoom(store, room, fn);
    if (res.error) return json({ ok: false, error: res.error }, { slow: 429, closed: 409, empty: 400, "no-msg": 404, "bad-room": 400 }[res.error] || 503);
    return json(res);
  };

  if (req.method === "POST" && sub === "") {
    const text = clean(b.text, MAX_TEXT);
    const ref = b.ref && ["game", "player"].includes(b.ref.t) ? { t: b.ref.t, id: cleanId(b.ref.id) } : null;
    if (!name || (!text && !ref)) return json({ ok: false, error: "empty" }, 400);
    return send((doc) => {
      const now = Date.now();
      if (doc.msgs.filter((m) => m.name === name && now - m.ts < 10000).length >= 5) return { error: "slow" };   // לא יותר מ-5 הודעות ב-10 שניות
      const rp = b.reply && doc.msgs.find((m) => m.id === cleanId(b.reply));
      const msg = { name, text, ...(pid ? { pid } : {}), ...(ref ? { ref } : {}), ...(isAdmin ? { admin: true } : {}),
        ...(rp ? { reply: { id: rp.id, name: rp.name, text: String(rp.text || "").slice(0, 80) } } : {}) };
      return { ok: true, msg: addMsg(doc, msg) };
    });
  }

  if (req.method === "POST" && sub === "/react") {
    const e = String(b.e || ""), id = cleanId(b.id);
    if (!name || !REACTS.includes(e)) return json({ ok: false, error: "empty" }, 400);
    return send((doc) => {
      const m = doc.msgs.find((x) => x.id === id); if (!m) return { error: "no-msg" };
      m.re ||= {}; const list = m.re[e] ||= [];
      const i = list.indexOf(name); if (i >= 0) list.splice(i, 1); else list.push(name);
      if (!list.length) delete m.re[e];
      touch(doc, m); return { ok: true, msg: m };
    });
  }

  if (req.method === "POST" && sub === "/pin") {
    if (!isAdmin) return deny();
    const id = cleanId(b.id);
    return send((doc) => {
      if (!id) doc.pin = null;
      else { const m = doc.msgs.find((x) => x.id === id); if (!m) return { error: "no-msg" }; doc.pin = { id: m.id, name: m.name, text: m.text || "", ts: m.ts }; }
      touch(doc); return { ok: true, pin: doc.pin };
    });
  }

  // הודעה אוטומטית (סוף משחק / שחקן המחזור) – פעם אחת לכל מפתח
  if (req.method === "POST" && sub === "/announce") {
    if (!isAdmin) return deny();
    if (!cfg.enabled) return json({ ok: false, error: "closed" }, 409);
    const key = clean(b.key, 60), text = clean(b.text, MAX_TEXT);
    const ref = b.ref && ["game", "player"].includes(b.ref.t) ? { t: b.ref.t, id: cleanId(b.ref.id) } : null;
    if (!key || !text) return json({ ok: false, error: "empty" }, 400);
    return send((doc) => {
      doc.ann ||= {}; if (doc.ann[key]) return { ok: true, dup: true };
      doc.ann[key] = Date.now();
      return { ok: true, msg: addMsg(doc, { kind: "sys", name: "האתר", text, ...(ref ? { ref } : {}) }) };
    });
  }

  if (req.method === "DELETE") {
    if (!isAdmin) return deny();
    const id = url.searchParams.get("id") || "";
    return send((doc) => {
      if (id === "all") { doc.del = [...(doc.del || []), ...doc.msgs.map((m) => m.id)].slice(-300); doc.msgs = []; doc.pin = null; }
      else { doc.msgs = doc.msgs.filter((m) => m.id !== id); doc.del = [...(doc.del || []), id].slice(-300); if (doc.pin?.id === id) doc.pin = null; }
      touch(doc); return { ok: true };
    });
  }
  return json({ ok: false, error: "not-found" }, 404);
}

/* ================= התראות לטלפון (כמו ב-365) =================
   כל אחד בוחר: התראה כשמשחק מתחיל ו/או נגמר, על כל המשחקים או רק על קבוצות שבחר.
   ההתראה נשלחת כשהמנהל שומר: סימן "משוחק עכשיו" (התחלה) או הכניס תוצאה סופית (סוף).
   המפתחות (VAPID) נוצרים לבד בפעם הראשונה ונשמרים בשרת – אין מה להגדיר. */
async function vapid(store) {
  let k = await store.get("vapid", { type: "json" });
  if (!k?.publicKey) {
    const fresh = webpush.generateVAPIDKeys();
    const w = await store.setJSON("vapid", fresh, { onlyIfNew: true });
    k = w.modified === false ? await store.get("vapid", { type: "json" }) : fresh;
  }
  return k;
}
const subKey = (endpoint) => createHash("sha256").update(String(endpoint)).digest("hex").slice(0, 32);
async function pushRoute(req, url, path, store, getRealPassword) {
  const sub = path.replace(/^.*\/api\/push/, "");
  if (sub === "/key" && req.method === "GET") return json({ ok: true, key: (await vapid(store)).publicKey });
  let b = {}; if (req.method !== "GET") { try { b = await req.json(); } catch {} }

  if (sub === "/sub") {
    const s = b.sub, ep = s?.endpoint;
    if (typeof ep !== "string" || !/^https:\/\//.test(ep) || ep.length > 1000) return json({ ok: false, error: "bad-sub" }, 400);
    const k = subKey(ep);
    if (req.method === "DELETE") { await updateKey(store, "subs", () => ({}), (d) => { delete d[k]; return { ok: true }; }); return json({ ok: true }); }
    if (!s.keys?.p256dh || !s.keys?.auth) return json({ ok: false, error: "bad-sub" }, 400);
    const pr = b.prefs || {};
    const prefs = { start: !!pr.start, final: !!pr.final, teams: (Array.isArray(pr.teams) ? pr.teams : []).map(cleanId).filter(Boolean).slice(0, 20) };
    const res = await updateKey(store, "subs", () => ({}), (d) => {
      if (!d[k] && Object.keys(d).length >= 2000) return { error: "full" };
      d[k] = { sub: { endpoint: ep, keys: { p256dh: String(s.keys.p256dh).slice(0, 200), auth: String(s.keys.auth).slice(0, 100) } }, prefs, ts: Date.now() };
      return { ok: true };
    });
    return res.error ? json({ ok: false, error: res.error }, 503) : json({ ok: true, prefs });
  }

  if (sub === "/send" && req.method === "POST") {
    if (!checkPassword(req.headers.get("x-admin-password"), getRealPassword()).ok) { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }
    const type = b.type === "start" ? "start" : "final", key = clean(b.key, 80);
    const title = clean(b.title, 80), body = clean(b.body, 160), link = /^#\/[\w/?=&-]*$/.test(b.url || "") ? b.url : "#/";
    const tids = (Array.isArray(b.tids) ? b.tids : []).map(cleanId);
    if (!key || !title) return json({ ok: false, error: "empty" }, 400);
    const first = await updateKey(store, "sent", () => ({}), (d) => { if (d[key]) return { ok: true, dup: true }; d[key] = Date.now();
      const ks = Object.keys(d); if (ks.length > 500) for (const x of ks.sort((p, q) => d[p] - d[q]).slice(0, ks.length - 500)) delete d[x]; return { ok: true }; });
    if (first.dup) return json({ ok: true, dup: true, sent: 0 });
    const k = await vapid(store);
    webpush.setVapidDetails(new URL(req.url).origin.startsWith("https://") ? new URL(req.url).origin : "mailto:league@example.com", k.publicKey, k.privateKey);
    const subs = (await store.get("subs", { type: "json" })) || {};
    const targets = Object.entries(subs).filter(([, x]) => x.prefs?.[type] && (!x.prefs.teams?.length || x.prefs.teams.some((t) => tids.includes(t))));
    const payload = JSON.stringify({ title, body, url: link, tag: key });
    const dead = [];
    const results = await Promise.allSettled(targets.map(([id, x]) => webpush.sendNotification(x.sub, payload, { TTL: 6 * 3600, urgency: "high" }).catch((e) => { if (e.statusCode === 404 || e.statusCode === 410) dead.push(id); throw e; })));
    if (dead.length) await updateKey(store, "subs", () => ({}), (d) => { for (const id of dead) delete d[id]; return { ok: true }; });
    return json({ ok: true, sent: results.filter((r) => r.status === "fulfilled").length, failed: results.filter((r) => r.status === "rejected").length, removed: dead.length });
  }
  return json({ ok: false, error: "not-found" }, 404);
}

/* קוד ההתראות שרץ ברקע בטלפון (service worker) – מוגש מכאן כדי שלא יהיה עוד קובץ .js בתיקייה */
const SW_JS = "/* התראות לטלפון – מציג את ההתראה ופותח את העמוד הנכון כשלוחצים עליה */\nself.addEventListener(\"install\", () => self.skipWaiting());\nself.addEventListener(\"activate\", (e) => e.waitUntil(self.clients.claim()));\nself.addEventListener(\"push\", (e) => {\n  let d = {}; try { d = e.data ? e.data.json() : {}; } catch { d = { title: e.data && e.data.text() }; }\n  e.waitUntil(self.registration.showNotification(d.title || \"הליגה\", { body: d.body || \"\", icon: \"icon.svg\", badge: \"icon.svg\", tag: d.tag || undefined, data: { url: d.url || \"#/\" }, dir: \"rtl\", lang: \"he\" }));\n});\nself.addEventListener(\"notificationclick\", (e) => {\n  e.notification.close();\n  const target = new URL(\"./\" + (e.notification.data && e.notification.data.url || \"#/\"), self.registration.scope).href;\n  e.waitUntil((async () => {\n    const all = await self.clients.matchAll({ type: \"window\", includeUncontrolled: true });\n    for (const c of all) { if (\"focus\" in c) { await c.focus(); if (\"navigate\" in c) { try { await c.navigate(target); } catch {} } return; } }\n    if (self.clients.openWindow) await self.clients.openWindow(target);\n  })());\n});\n";
