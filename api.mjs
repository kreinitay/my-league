// שרת קטן לאתר הליגה: שומר את כל הנתונים ב-Netlify Blobs.
// קריאה פתוחה לכולם, כתיבה רק עם סיסמת האדמין (משתנה סביבה ADMIN_PASSWORD).
import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
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

/* ---- דרגות: מנהל (הסיסמה ב-Netlify) · סטטיסטיקאי · מנהל צ'אט (קודים שהמנהל קובע בהגדרות) ---- */
async function staffLevel(given, store, getRealPassword) {
  if (!given) return "";
  if (checkPassword(given, getRealPassword()).ok) return "admin";
  const st = (await store.get("staff", { type: "json" })) || {};
  const eq = (code) => code && checkPassword(given, code).ok;
  if (eq(st.stat)) return "stat";
  if (eq(st.mod)) return "mod";
  return "";
}
// סטטיסטיקאי: מותר להוסיף ולערוך משחקים, שחקנים וקבוצות – אסור למחוק, לשנות הגדרות או לגעת בטיוטה של כל האתר
function statAllowed(oldD, newD) {
  if (!oldD) return false;
  const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  if (!same(oldD.league, newD.league) || !same(oldD.draft, newD.draft)) return false;
  for (const k of ["games", "teams", "players"]) { const ids = new Set(newD[k].map((x) => x.id)); if (!oldD[k].every((x) => ids.has(x.id))) return false; }
  return true;
}

// makeHandler מקבל store כדי שאפשר יהיה לבדוק את הקוד בלי Netlify
export function makeHandler(openStore, getRealPassword = readPassword, openChat = null, openPush = null) {
  return async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");
    const store = openStore();
    const lvl = await staffLevel(req.headers.get("x-admin-password"), store, getRealPassword);

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
      if (!getRealPassword()) return json({ ok: false, error: "no-password-set" }, 500);
      const level = await staffLevel(body.password, store, getRealPassword);
      if (!level) { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }
      return json({ ok: true, level });
    }

    if (path.endsWith("/api/data") && (req.method === "PUT" || req.method === "POST")) {
      if (!getRealPassword()) return json({ ok: false, error: "no-password-set" }, 500);
      if (lvl !== "admin" && lvl !== "stat") { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }

      const text = await req.text();
      if (text.length > MAX_BYTES) return json({ ok: false, error: "too-big" }, 413);
      let body;
      try { body = JSON.parse(text); } catch { return json({ ok: false, error: "bad-json" }, 400); }
      if (!validData(body.data)) return json({ ok: false, error: "bad-data" }, 400);

      const current = (await store.get(KEY, { type: "json" })) || { data: null, rev: 0 };
      if (!body.force && Number(body.baseRev) !== Number(current.rev)) {
        return json({ ok: false, error: "conflict", current }, 409);
      }
      if (lvl === "stat" && !statAllowed(current.data, body.data)) return json({ ok: false, error: "not-allowed" }, 403);
      const doc = { data: body.data, rev: Number(current.rev) + 1, savedAt: new Date().toISOString() };
      await store.setJSON(KEY, doc);
      return json({ ok: true, rev: doc.rev, savedAt: doc.savedAt });
    }

    // קודי הצוות – רק המנהל רואה ומשנה
    if (path.endsWith("/api/staff")) {
      if (lvl !== "admin") { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }
      if (req.method === "GET") { const st = (await store.get("staff", { type: "json" })) || {}; return json({ ok: true, stat: st.stat || "", mod: st.mod || "" }); }
      let b = {}; try { b = await req.json(); } catch {}
      const c = (v) => String(v ?? "").trim().slice(0, 40);
      const st = { stat: c(b.stat), mod: c(b.mod) };
      if ((st.stat && st.stat.length < 4) || (st.mod && st.mod.length < 4)) return json({ ok: false, error: "short-code" }, 400);
      if (st.stat && st.stat === st.mod) return json({ ok: false, error: "same-code" }, 400);
      if ([st.stat, st.mod].some((x) => x && checkPassword(x, getRealPassword()).ok)) return json({ ok: false, error: "same-code" }, 400);
      await store.setJSON("staff", st);
      return json({ ok: true, ...st });
    }
    if (path.endsWith("/sw.js")) return new Response(SW_JS, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache" } });
    if (path.includes("/api/push")) return pushRoute(req, url, path, openPush ? openPush() : store, lvl, openChat ? openChat() : store);
    if (path.includes("/api/chat")) return chatRoute(req, url, path, openChat ? openChat() : store, lvl, store, openPush ? openPush() : store);

    return json({ ok: false, error: "not-found" }, 404);
  };
}

export default makeHandler(
  () => getStore({ name: "league-data", consistency: "strong" }),
  readPassword,
  () => getStore({ name: "league-chat", consistency: "strong" }),
  () => getStore({ name: "league-push", consistency: "strong" }),
);

export const config = { path: ["/api/data", "/api/login", "/api/chat", "/api/chat/*", "/api/push", "/api/push/*", "/api/staff", "/sw.js"] };

/* ================= צ'אט =================
   כל מי שנכנס בוחר מי הוא (שחקן/מאמן/הורה...), מקבל "כרטיס כניסה" (token) שנשמר בדפדפן, ומופיע אצל המנהל ברשימת "אנשים".
   5 חדרים: 1 כולם · 2 שחקני הקבוצה · 3 שחקנים + מאמן · 4-5 חדרים שהמנהל בוחר מי בהם.
   בחדרים 2-5 המנהל יכול להוסיף ולהוציא אנשים. כל שינוי בחדר מקבל מספר seq, והדפדפן מבקש רק מה שהשתנה. */
const ROOMS = ["main", "s1", "s2", "s3", "s4"];
const DEF_NAMES = { main: "כולם", s1: "שחקני הקבוצה", s2: "שחקנים ומאמן", s3: "חדר 4", s4: "חדר 5" };
const ROLES = ["ph_player", "ph_coach", "ph_parent", "o_player", "o_coach", "o_parent", "other"];
// מי נכנס לכל חדר אוטומטית (המנהל יכול להוסיף/להוציא אנשים בנוסף)
const RULES = { main: () => true, s1: (u) => u.role === "ph_player", s2: (u) => u.role === "ph_player" || u.role === "ph_coach", s3: () => false, s4: () => false };
const PH = (u) => /^ph_/.test(u?.role || "");
// לוח האימונים ההתחלתי (חוזר כל שבוע עד שהמנהל משנה). d: 0 = ראשון ... 6 = שבת · כל אימון חוץ משישי = שעה וחצי
const DEF_TRAINING = { slots: [
  { d: 0, from: "18:30", to: "20:00", place: "יפה נוף", note: "" },
  { d: 3, from: "18:30", to: "20:00", place: "אלישבע", note: "" },
  { d: 4, from: "17:00", to: "18:30", place: "יפה נוף", note: "בדרך כלל יש משחק ב-17:30 – המנהל יעדכן" },
  { d: 5, from: "12:30", to: "14:30", place: "", note: "" },
], note: "", noteUntil: 0 };
const REACTS = ["👍", "❤️", "🔥", "😂", "😮", "😢", "👏", "🏀", "💪", "🎉", "🙏", "👀"];
const MAX_MSGS = 300, MAX_TEXT = 400, MAX_NAME = 20;
const clean = (v, n) => String(v ?? "").replace(/[\u0000-\u0008\u000B-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "").replace(/\n{3,}/g, "\n\n").trim().slice(0, n);
const cleanId = (v) => String(v ?? "").replace(/[^a-z0-9]/gi, "").slice(0, 24);
const newId = () => Date.now().toString(36) + randomBytes(4).toString("hex");
const hashTok = (t) => createHash("sha256").update(String(t)).digest("hex");

async function chatConfig(store) {
  const c = (await store.get("config", { type: "json" })) || {};
  return { enabled: !!c.enabled, code: String(c.code || ""), names: { ...DEF_NAMES, ...(c.names || {}) }, members: c.members || {}, epoch: c.epoch || 1, roomCodes: c.roomCodes || {} };
}
function sameSecret(a, b) {
  if (!b) return false;
  const x = createHash("sha256").update(String(a ?? "")).digest();
  const y = createHash("sha256").update(String(b)).digest();
  return timingSafeEqual(x, y);
}
function canRoom(cfg, u, room, isAdmin) {
  if (isAdmin) return true;
  if (!u || !ROOMS.includes(room)) return false;
  if (room === "main") return true;                       // החדר הגדול – תמיד לכולם
  const o = cfg.members[room] || {};
  if ((o.remove || []).includes(u.id)) return false;
  if ((o.add || []).includes(u.id)) return true;
  return RULES[room](u);
}
const roomsFor = (cfg, u, isAdmin) => ROOMS.filter((r) => canRoom(cfg, u, r, isAdmin)).map((id) => ({ id, name: cfg.names[id] }));
const pubUser = (u) => u && { id: u.id, name: u.name, role: u.role, pid: u.pid || "" };

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
const emptyRoom = () => ({ msgs: [], del: [], seq: 0 });
const updateRoom = (store, room, fn) => updateKey(store, "room-" + room, emptyRoom, (d) => { for (const [k, v] of Object.entries(emptyRoom())) d[k] ??= v; return fn(d); });
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

async function chatRoute(req, url, path, store, lvl, dataStore, pushStore) {
  const origin = new URL(req.url).origin;
  // התראה לטלפון מתוך הצ'אט – רק למי שביקש את סוג ההתראה הזה ושמותר לו לראות את מה שקרה
  const notify = (pref, ok, payload) => pushTo(pushStore, origin, (x) => { const u = x.uid && users[x.uid]; return x.prefs?.[pref] && u && !u.blocked && ok(u); }, payload).catch(() => 0);
  const isAdmin = lvl === "admin", isMod = isAdmin || lvl === "mod", canAnn = isAdmin || lvl === "stat";
  const cfg = await chatConfig(store);
  const sub = path.replace(/^.*\/api\/chat/, "");
  const deny = async () => { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); };
  let b = {}; if (req.method !== "GET") { try { b = await req.json(); } catch {} }
  const now = Date.now();

  /* ---- הגדרות (מנהל) ---- */
  if (sub === "/config") {
    if (!isAdmin) return deny();
    if (req.method === "GET") return json({ ok: true, ...cfg });
    const names = {}; for (const r of ROOMS) names[r] = clean(b.names?.[r], 30) || DEF_NAMES[r];
    // אין קוד כניסה לצ'אט – נכנסים עם שם ו"מי אתה". קודים לחדרים 4-5 – רשות
    const code = "", roomCodes = {};
    for (const r of ["s1", "s2", "s3", "s4"]) { const c = clean(b.roomCodes?.[r], 40); if (c) roomCodes[r] = c; }
    if (Object.values(roomCodes).some((c) => c.length < 4)) return json({ ok: false, error: "short-code" }, 400);
    const res = await updateKey(store, "config", () => ({}), (c) => {
        c.enabled = !!b.enabled; c.code = code; c.names = names; c.members ||= {}; c.roomCodes = roomCodes;
      return { ok: true, enabled: c.enabled, code: c.code, names: c.names, epoch: c.epoch || 1, roomCodes };
    });
    return json(res);
  }

  // הודעה אוטומטית (סוף משחק / שחקן המחזור) – פעם אחת לכל מפתח, רק בחדר של כולם
  if (req.method === "POST" && sub === "/announce") {
    if (!canAnn) return deny();
    if (!cfg.enabled) return json({ ok: false, error: "closed" }, 409);
    const room = "main";
    const key = clean(b.key, 60), text = clean(b.text, MAX_TEXT);
    const ref = b.ref && ["game", "player"].includes(b.ref.t) ? { t: b.ref.t, id: cleanId(b.ref.id) } : null;
    if (!key || !text) return json({ ok: false, error: "empty" }, 400);
    const res = await updateRoom(store, room, (doc) => {
      doc.ann ||= {}; if (doc.ann[key]) return { ok: true, dup: true };
      doc.ann[key] = now;
      return { ok: true, msg: addMsg(doc, { kind: "sys", name: "האתר", text, ...(ref ? { ref } : {}) }) };
    });
    return res.error ? json({ ok: false, error: res.error }, 503) : json(res);
  }

  /* ---- זיהוי: מי אתה ---- */
  const users = (await store.get("users", { type: "json" })) || {};
  const tok = req.headers.get("x-chat-token") || b.token || "";
  let me = tok ? Object.values(users).find((u) => u.th === hashTok(tok)) : null;
  if (me && me.blocked) me = me.blocked ? Object.assign(me, { _blocked: true }) : null;

  // כניסה לאתר: שם + "מי אתה" (משמש את כל האתר, לא רק את הצ'אט) – עובד גם כשהצ'אט סגור
  if (sub === "/join" && req.method === "POST") {
    if (me?._blocked) return json({ ok: false, error: "blocked" }, 403);
    const wantsProfile = b.name !== undefined || b.role !== undefined;
    const name = clean(b.name, MAX_NAME), role = ROLES.includes(b.role) ? b.role : "", pid = cleanId(b.pid);
    if (!me && (!name || !role)) return json({ ok: false, error: "who" }, 400);
    // מוצאים לפי ה-token (גם אם הקוד השתנה) – כדי שאותו אדם יישאר אותו אדם
    const old = tok ? Object.values(users).find((u) => u.th === hashTok(tok)) : null;
    const token = old ? tok : randomBytes(18).toString("base64url");
    const res = await updateKey(store, "users", () => ({}), (d) => {
      let u = old && d[old.id];
      if (!u) { if (Object.keys(d).length >= 3000) return { error: "full" }; u = { id: newId(), th: hashTok(token), created: now, joins: 0 }; d[u.id] = u; }
      if (u.blocked) return { error: "blocked" };
      if (name) u.name = name; if (role) u.role = role; if (wantsProfile) u.pid = pid;
      u.epoch = cfg.epoch; u.last = now; u.joins = (u.joins || 0) + 1;
      return { ok: true, u: { ...u } };
    });
    if (res.error) return json({ ok: false, error: res.error }, res.error === "blocked" ? 403 : 503);
    return json({ ok: true, token, user: pubUser(res.u), enabled: cfg.enabled || isMod, rooms: cfg.enabled || isMod ? roomsFor(cfg, res.u, isMod) : [], staff: lvl || "" });
  }

  if (!cfg.enabled && !isMod) return json({ ok: false, error: "closed" }, 403);
  if (me?._blocked) return json({ ok: false, error: "blocked" }, 403);
  if (!me && !isMod) { await sleep(300); return json({ ok: false, error: "relogin" }, 401); }
  // "נראה לאחרונה" – מתעדכן לכל היותר פעם ב-5 דקות (חוסך כתיבות)
  if (me && now - (me.last || 0) > 5 * 60000) await updateKey(store, "users", () => ({}), (d) => { if (d[me.id]) d[me.id].last = now; return { ok: true }; });
  const who = me ? pubUser(me) : { id: "admin", name: clean(b.name, MAX_NAME) || "מנהל", role: "ph_coach", pid: "" };

  /* ---- אנשים (מנהל): מי נכנס, מתי, לאיזה חדרים ---- */
  if (sub === "/users") {
    if (!isMod) return deny();
    if (req.method === "GET") {
      const list = Object.values(users).map((u) => ({ ...pubUser(u), created: u.created, last: u.last, joins: u.joins || 0, blocked: !!u.blocked, rooms: ROOMS.filter((r) => canRoom(cfg, u, r, false)) }));
      return json({ ok: true, users: list.sort((x, y) => (y.last || 0) - (x.last || 0)), names: cfg.names });
    }
    const id = cleanId(b.id);
    if (b.room) {                                          // להוסיף/להוציא מחדר 2-5
      if (!ROOMS.includes(b.room) || b.room === "main") return json({ ok: false, error: "bad-room" }, 400);
      const u = users[id]; if (!u) return json({ ok: false, error: "no-user" }, 404);
      const res = await updateKey(store, "config", () => ({}), (c) => {
        c.members ||= {}; const o = c.members[b.room] ||= { add: [], remove: [] };
        o.add = (o.add || []).filter((x) => x !== id); o.remove = (o.remove || []).filter((x) => x !== id);
        const auto = RULES[b.room](u);
        if (b.inRoom && !auto) o.add.push(id); if (!b.inRoom) o.remove.push(id);     // הוצאה ע"י המנהל נשארת (גם קוד חדר לא מחזיר)
        return { ok: true };
      });
      return json(res);
    }
    const res = await updateKey(store, "users", () => ({}), (d) => {
      if (!d[id]) return { error: "no-user" };
      if (b.del) delete d[id]; else if ("blocked" in b) d[id].blocked = !!b.blocked;
      if (b.role && ROLES.includes(b.role)) d[id].role = b.role;
      return { ok: true };
    });
    return res.error ? json({ ok: false, error: res.error }, 404) : json(res);
  }

  // סקרים שנפתחו (גם כאלה שתוזמנו מראש) ועוד לא נשלחה עליהם התראה
  async function notifyPolls() {
    const d = (await store.get("polls", { type: "json" })) || { list: [] };
    const due = d.list.filter((p) => !p.notified && p.start <= now && (!p.end || now < p.end));
    if (!due.length) return;
    const r = await updateKey(store, "polls", () => ({ list: [] }), (x) => { for (const p of x.list) if (due.some((q) => q.id === p.id)) p.notified = now; return { ok: true }; });
    if (r.error) return;
    for (const p of due) await notify("poll", (u) => !p.roles?.length || p.roles.includes(u.role), { title: "📊 סקר חדש", body: p.q, url: "#/polls", tag: "poll-" + p.id });
  }

  /* ---- מרכז הצ'אטים: כל החדרים שלך + ההודעה האחרונה בכל אחד ---- */
  if (sub === "/rooms" && req.method === "GET") {
    await notifyPolls();
    const rs = roomsFor(cfg, me, isMod);
    // חדרים עם קוד שעוד לא נכנסת אליהם – מוצגים נעולים (אלא אם המנהל הוציא אותך מהם)
    const locked = Object.keys(cfg.roomCodes).filter((r) => ROOMS.includes(r) && !rs.some((x) => x.id === r) && !(cfg.members[r]?.remove || []).includes(me?.id)).map((id) => ({ id, name: cfg.names[id], locked: true }));
    const out = await Promise.all(rs.map(async (r) => {
      const d = (await store.get("room-" + r.id, { type: "json" })) || emptyRoom();
      const l = d.msgs[d.msgs.length - 1];
      return { ...r, seq: d.seq || 0, count: d.msgs.length, last: l ? { name: l.name, text: String(l.text || "").slice(0, 80), ts: l.ts } : null };
    }));
    return json({ ok: true, rooms: [...out, ...locked].sort((x, y) => ROOMS.indexOf(x.id) - ROOMS.indexOf(y.id)), user: who });
  }

  /* ---- קוד לחדר (חדרים 4-5): מי שיודע את הקוד נכנס לחדר ---- */
  if (sub === "/roomcode" && req.method === "POST") {
    const r = String(b.room || ""), want = cfg.roomCodes[r];
    if (!me || !want) return json({ ok: false, error: "no-room" }, 403);
    if ((cfg.members[r]?.remove || []).includes(me.id)) return json({ ok: false, error: "no-room" }, 403);
    if (!sameSecret(clean(b.code, 40), want)) { await sleep(800); return json({ ok: false, error: "wrong-room-code" }, 400); }
    await updateKey(store, "config", () => ({}), (c) => { c.members ||= {}; const o = c.members[r] ||= { add: [], remove: [] }; o.add ||= []; if (!o.add.includes(me.id)) o.add.push(me.id); return { ok: true }; });
    return json({ ok: true, room: { id: r, name: cfg.names[r] } });
  }

  /* ---- סקרים: שאלה + 2-6 תשובות, אפשר לתזמן, ואפשר להציג רק לסוגים מסוימים ---- */
  if (sub === "/polls" || sub === "/polls/vote") {
    const sees = (p) => isMod || !p.roles?.length || (me && p.roles.includes(me.role));
    const view = (p) => {
      const counts = p.opts.map((_, i) => Object.values(p.votes || {}).filter((v) => v === i).length);
      return { id: p.id, q: p.q, opts: p.opts, start: p.start, end: p.end || 0, roles: p.roles || [], counts, total: Object.keys(p.votes || {}).length,
        mine: p.votes && who.id in p.votes ? p.votes[who.id] : null, open: now >= p.start && (!p.end || now < p.end) };
    };
    if (req.method === "GET") {
      const d = (await store.get("polls", { type: "json" })) || { list: [] };
      return json({ ok: true, polls: d.list.filter((p) => (isMod || now >= p.start) && sees(p)).map(view).sort((x, y) => y.start - x.start) });
    }
    if (sub === "/polls/vote") {
      const id = cleanId(b.id), opt = Number(b.opt);
      const res = await updateKey(store, "polls", () => ({ list: [] }), (d) => {
        const p = d.list.find((x) => x.id === id); if (!p || !sees(p)) return { error: "no-msg" };
        if (!(now >= p.start && (!p.end || now < p.end))) return { error: "closed" };
        if (!(opt >= 0 && opt < p.opts.length)) return { error: "empty" };
        p.votes ||= {}; p.votes[who.id] = opt; return { ok: true, poll: view(p) };
      });
      return res.error ? json({ ok: false, error: res.error }, res.error === "closed" ? 409 : 400) : json(res);
    }
    if (!isMod) return deny();
    const res = await updateKey(store, "polls", () => ({ list: [] }), (d) => {
      const id = cleanId(b.id);
      if (b.del) { d.list = d.list.filter((x) => x.id !== id); return { ok: true }; }
      if (b.closeNow) { const p = d.list.find((x) => x.id === id); if (p) p.end = now; return { ok: true }; }
      const q = clean(b.q, 160), opts = (Array.isArray(b.opts) ? b.opts : []).map((o) => clean(o, 60)).filter(Boolean).slice(0, 6);
      if (!q || opts.length < 2) return { error: "empty" };
      const start = Number(b.start) > 0 ? Number(b.start) : now, end = Number(b.end) > start ? Number(b.end) : 0;
      const roles = (Array.isArray(b.roles) ? b.roles : []).filter((r) => ROLES.includes(r));
      d.list.unshift({ id: newId(), q, opts, start, end, roles, votes: {} });
      d.list = d.list.slice(0, 60); return { ok: true };
    });
    if (res.error) return json({ ok: false, error: res.error }, 400);
    await notifyPolls();
    return json(res);
  }

  /* ---- ניחושים ---- */
  if (sub === "/preds" && req.method === "GET") {
    const d = (await store.get("preds", { type: "json" })) || {};
    const names = {}; for (const u of Object.values(users)) names[u.id] = u.name;
    return json({ ok: true, preds: d, names });
  }
  if (sub === "/predict" && req.method === "POST") {
    // ניחוש = תוצאה, ובונוס רשות: מי יהיה הקלע המוביל (tp) וכמה נקודות יקלע (tpp)
    const picks = (Array.isArray(b.picks) ? b.picks : []).slice(0, 12).map((x) => ({ gid: cleanId(x.gid), h: Math.round(Number(x.h)), a: Math.round(Number(x.a)), tp: cleanId(x.tp), tpp: x.tpp === "" || x.tpp == null ? null : Math.round(Number(x.tpp)) }))
      .filter((x) => x.gid && x.h >= 0 && x.h <= 250 && x.a >= 0 && x.a <= 250 && (x.tpp === null || (x.tpp >= 0 && x.tpp <= 100)));
    if (!picks.length) return json({ ok: false, error: "empty" }, 400);
    const data = await dataStore.get(KEY, { type: "json" });
    const okPicks = []; for (const x of picks) if (!(await gameLocked(dataStore, x.gid, data))) okPicks.push(x);
    if (!okPicks.length) return json({ ok: false, error: "closed" }, 409);
    const res = await updateKey(store, "preds", () => ({}), (d) => { for (const x of okPicks) (d[x.gid] ||= {})[who.id] = x.tp ? [x.h, x.a, x.tp, x.tpp] : [x.h, x.a]; return { ok: true, saved: okPicks.length, locked: picks.length - okPicks.length }; });
    return res.error ? json({ ok: false, error: res.error }, 503) : json(res);
  }

  /* ---- לוח אימונים – רק לשחקנים, מאמנים והורים של הקבוצה ---- */
  if (sub === "/training") {
    if (!isMod && !PH(me)) return json({ ok: false, error: "not-team" }, 403);
    if (req.method === "GET") return json({ ok: true, ...((await store.get("training", { type: "json" })) || DEF_TRAINING) });
    if (!isMod) return deny();
    const slots = (Array.isArray(b.slots) ? b.slots : []).slice(0, 14).map((x) => ({ d: Math.max(0, Math.min(6, Math.round(Number(x.d)) || 0)), from: clean(x.from, 5), to: clean(x.to, 5), place: clean(x.place, 60), note: clean(x.note, 60) }))
      .filter((x) => /^\d\d:\d\d$/.test(x.from)).sort((x, y) => x.d - y.d || x.from.localeCompare(y.from));
    const note = clean(b.note, 300);
    const doc = { slots, note, noteUntil: note && Number(b.noteUntil) > 0 ? Number(b.noteUntil) : 0, updated: now };
    await store.setJSON("training", doc);
    return json({ ok: true, ...doc });
  }

  /* ---- הודעות בחדר ---- */
  const room = url.searchParams.get("room") || "main";
  if (!ROOMS.includes(room)) return json({ ok: false, error: "bad-room" }, 400);
  if (!canRoom(cfg, me, room, isMod)) return json({ ok: false, error: "no-room" }, 403);
  const send = async (fn) => {
    const res = await updateRoom(store, room, fn);
    if (res.error) return json({ ok: false, error: res.error }, { slow: 429, closed: 409, empty: 400, "no-msg": 404 }[res.error] || 503);
    return json(res);
  };

  if (req.method === "GET" && sub === "") {
    const doc = { ...emptyRoom(), ...((await store.get("room-" + room, { type: "json" })) || {}) };
    const since = Number(url.searchParams.get("since") || 0);
    if (since && since === doc.seq) return json({ ok: true, seq: doc.seq, msgs: [] });          // אין חדש – תשובה קטנטנה
    const msgs = since && since < doc.seq ? doc.msgs.filter((m) => (m.u || 0) > since) : doc.msgs.slice(-80);
    return json({ ok: true, seq: doc.seq, full: !since || since > doc.seq, msgs, del: (doc.del || []).slice(-50), pin: doc.pin || null });
  }

  if (req.method === "POST" && sub === "") {
    const text = clean(b.text, MAX_TEXT);
    const ref = b.ref && ["game", "player"].includes(b.ref.t) ? { t: b.ref.t, id: cleanId(b.ref.id) } : null;
    if (!text && !ref) return json({ ok: false, error: "empty" }, 400);
    const res = await updateRoom(store, room, (doc) => {
      if (doc.msgs.filter((m) => m.uid === who.id && now - m.ts < 10000).length >= 5) return { error: "slow" };   // לא יותר מ-5 הודעות ב-10 שניות
      const rp = b.reply && doc.msgs.find((m) => m.id === cleanId(b.reply));
      const msg = { uid: who.id, name: who.name, role: who.role, ...(who.pid ? { pid: who.pid } : {}), text, ...(ref ? { ref } : {}), ...(isMod ? { admin: true } : {}),
        ...(rp ? { reply: { id: rp.id, name: rp.name, text: String(rp.text || "").slice(0, 80) } } : {}) };
      return { ok: true, msg: addMsg(doc, msg), replyTo: rp && rp.uid && rp.uid !== who.id ? rp.uid : "" };
    });
    if (res.error) return json({ ok: false, error: res.error }, { slow: 429, empty: 400 }[res.error] || 503);
    if (res.replyTo) await notify("reply", (u) => u.id === res.replyTo && canRoom(cfg, u, room, false),
      { title: `↩ ${who.name} ענה לך`, body: text || "📎", url: "#/chat?r=" + room, tag: "reply-" + res.msg.id });
    delete res.replyTo; return json(res);
  }

  if (req.method === "POST" && sub === "/react") {
    const e = String(b.e || ""), id = cleanId(b.id);
    if (!REACTS.includes(e)) return json({ ok: false, error: "empty" }, 400);
    return send((doc) => {
      const m = doc.msgs.find((x) => x.id === id); if (!m) return { error: "no-msg" };
      m.re ||= {}; const list = m.re[e] ||= [];
      const i = list.indexOf(who.id); if (i >= 0) list.splice(i, 1); else list.push(who.id);
      if (!list.length) delete m.re[e];
      touch(doc, m); return { ok: true, msg: m };
    });
  }

  if (req.method === "POST" && sub === "/pin") {
    if (!isMod) return deny();
    const id = cleanId(b.id);
    const res = await updateRoom(store, room, (doc) => {
      if (!id) doc.pin = null;
      else { const m = doc.msgs.find((x) => x.id === id); if (!m) return { error: "no-msg" }; doc.pin = { id: m.id, name: m.name, text: m.text || "", ts: m.ts }; }
      touch(doc); return { ok: true, pin: doc.pin };
    });
    if (res.error) return json({ ok: false, error: res.error }, 404);
    if (res.pin) await notify("pin", (u) => canRoom(cfg, u, room, false), { title: `📌 ${cfg.names[room]}`, body: `${res.pin.name}: ${res.pin.text}`.slice(0, 160), url: "#/chat?r=" + room, tag: "pin-" + room });
    return json(res);
  }

  if (req.method === "DELETE") {
    if (!isMod) return deny();
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
// שולח התראה לכל המנויים שעוברים את הסינון; מנויים שכבר לא קיימים נמחקים
async function pushTo(store, origin, filter, msg) {
  const subs = (await store.get("subs", { type: "json" })) || {};
  const targets = Object.entries(subs).filter(([, x]) => { try { return filter(x); } catch { return false; } });
  if (!targets.length) return { sent: 0, failed: 0, removed: 0 };
  const k = await vapid(store);
  webpush.setVapidDetails(origin.startsWith("https://") ? origin : "mailto:league@example.com", k.publicKey, k.privateKey);
  const payload = JSON.stringify({ title: msg.title, body: msg.body || "", url: msg.url || "#/", tag: msg.tag });
  const dead = [];
  const results = await Promise.allSettled(targets.map(([id, x]) => webpush.sendNotification(x.sub, payload, { TTL: 6 * 3600, urgency: "high" }).catch((e) => { if (e.statusCode === 404 || e.statusCode === 410) dead.push(id); throw e; })));
  if (dead.length) await updateKey(store, "subs", () => ({}), (d) => { for (const id of dead) delete d[id]; return { ok: true }; });
  return { sent: results.filter((r) => r.status === "fulfilled").length, failed: results.filter((r) => r.status === "rejected").length, removed: dead.length };
}
const subKey = (endpoint) => createHash("sha256").update(String(endpoint)).digest("hex").slice(0, 32);
async function pushRoute(req, url, path, store, lvl, chatStore) {
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
    const prefs = { start: !!pr.start, final: !!pr.final, teams: (Array.isArray(pr.teams) ? pr.teams : []).map(cleanId).filter(Boolean).slice(0, 20), poll: !!pr.poll, pin: !!pr.pin, reply: !!pr.reply };
    // התראות מהצ'אט רק למי שנכנס לצ'אט (מזהים אותו לפי כרטיס הכניסה שלו)
    let uid = "";
    if (b.chatToken && (prefs.poll || prefs.pin || prefs.reply)) {
      const users = (await chatStore.get("users", { type: "json" })) || {};
      const u = Object.values(users).find((x) => x.th === hashTok(b.chatToken));
      if (u && !u.blocked) uid = u.id;
    }
    const res = await updateKey(store, "subs", () => ({}), (d) => {
      if (!d[k] && Object.keys(d).length >= 2000) return { error: "full" };
      d[k] = { sub: { endpoint: ep, keys: { p256dh: String(s.keys.p256dh).slice(0, 200), auth: String(s.keys.auth).slice(0, 100) } }, prefs, uid, ts: Date.now() };
      return { ok: true };
    });
    return res.error ? json({ ok: false, error: res.error }, 503) : json({ ok: true, prefs, chat: !!uid });
  }

  if (sub === "/send" && req.method === "POST") {
    if (lvl !== "admin" && lvl !== "stat") { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }
    const type = b.type === "start" ? "start" : "final", key = clean(b.key, 80);
    const title = clean(b.title, 80), body = clean(b.body, 160), link = /^#\/[\w/?=&-]*$/.test(b.url || "") ? b.url : "#/";
    const tids = (Array.isArray(b.tids) ? b.tids : []).map(cleanId);
    if (!key || !title) return json({ ok: false, error: "empty" }, 400);
    const first = await updateKey(store, "sent", () => ({}), (d) => { if (d[key]) return { ok: true, dup: true }; d[key] = Date.now();
      const ks = Object.keys(d); if (ks.length > 500) for (const x of ks.sort((p, q) => d[p] - d[q]).slice(0, ks.length - 500)) delete d[x]; return { ok: true }; });
    if (first.dup) return json({ ok: true, dup: true, sent: 0 });
    const r = await pushTo(store, new URL(req.url).origin, (x) => x.prefs?.[type] && (!x.prefs.teams?.length || x.prefs.teams.some((t) => tids.includes(t))), { title, body, url: link, tag: key });
    return json({ ok: true, ...r });
  }
  return json({ ok: false, error: "not-found" }, 404);
}

/* קוד ההתראות שרץ ברקע בטלפון (service worker) – מוגש מכאן כדי שלא יהיה עוד קובץ .js בתיקייה */
const SW_JS = "/* התראות לטלפון – מציג את ההתראה ופותח את העמוד הנכון כשלוחצים עליה */\nself.addEventListener(\"install\", () => self.skipWaiting());\nself.addEventListener(\"activate\", (e) => e.waitUntil(self.clients.claim()));\nself.addEventListener(\"push\", (e) => {\n  let d = {}; try { d = e.data ? e.data.json() : {}; } catch { d = { title: e.data && e.data.text() }; }\n  e.waitUntil(self.registration.showNotification(d.title || \"הליגה\", { body: d.body || \"\", icon: \"icon.svg\", badge: \"icon.svg\", tag: d.tag || undefined, data: { url: d.url || \"#/\" }, dir: \"rtl\", lang: \"he\" }));\n});\nself.addEventListener(\"notificationclick\", (e) => {\n  e.notification.close();\n  const target = new URL(\"./\" + (e.notification.data && e.notification.data.url || \"#/\"), self.registration.scope).href;\n  e.waitUntil((async () => {\n    const all = await self.clients.matchAll({ type: \"window\", includeUncontrolled: true });\n    for (const c of all) { if (\"focus\" in c) { await c.focus(); if (\"navigate\" in c) { try { await c.navigate(target); } catch {} } return; } }\n    if (self.clients.openWindow) await self.clients.openWindow(target);\n  })());\n});\n";
