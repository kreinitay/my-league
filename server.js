// אתר הליגה – השרת ב-Cloudflare (קובץ אחד, נבנה אוטומטית). לא צריך לערוך.

// shims/blobs.mjs
function getStore() {
  throw new Error("getStore is not used on Cloudflare");
}

// node_modules/@noble/hashes/esm/_assert.js
function isBytes(a) {
  return a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
}
function bytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}
function exists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function output(out, instance) {
  bytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`);
  }
}

// node_modules/@noble/hashes/esm/utils.js
var createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
var rotr = (word, shift) => word << 32 - shift | word >>> shift;
var isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  bytes(data);
  return data;
}
var Hash = class {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
};
var toStr = {}.toString;
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
var Chi = (a, b, c) => a & b ^ ~a & c;
var Maj = (a, b, c) => a & b ^ a & c ^ b & c;
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    exists(this);
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    exists(this);
    output(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
};

// node_modules/@noble/hashes/esm/sha256.js
var SHA256_K = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_IV = /* @__PURE__ */ new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  constructor() {
    super(64, 32, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    SHA256_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
};
var sha256 = /* @__PURE__ */ wrapConstructor(() => new SHA256());

// shims/crypto.mjs
var enc = new TextEncoder();
var Bytes = class extends Uint8Array {
  toString(e) {
    if (e === "hex") return [...this].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (e === "base64url" || e === "base64") {
      let s = "";
      for (const b of this) s += String.fromCharCode(b);
      const b64 = btoa(s);
      return e === "base64" ? b64 : b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    return new TextDecoder().decode(this);
  }
};
function createHash() {
  const parts = [];
  return {
    update(x) {
      parts.push(typeof x === "string" ? enc.encode(x) : x);
      return this;
    },
    digest(e) {
      const h = sha256.create();
      for (const p of parts) h.update(p);
      const out = new Bytes(h.digest());
      return e ? out.toString(e) : out;
    }
  };
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}
function randomBytes(n) {
  const b = new Bytes(n);
  crypto.getRandomValues(b);
  return b;
}

// shims/webpush.mjs
var te = new TextEncoder();
var b64u = (u8) => {
  let s = "";
  for (const b of new Uint8Array(u8)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
var unb64u = (s) => {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
};
var cat = (...a) => {
  const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n);
  let i = 0;
  for (const x of a) {
    o.set(x, i);
    i += x.length;
  }
  return o;
};
var S = crypto.subtle;
async function hkdf(salt, ikm, info, len) {
  const k = await S.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await S.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
var details = null;
async function generateVAPIDKeys() {
  const kp = await S.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const j = await S.exportKey("jwk", kp.privateKey);
  return { publicKey: b64u(cat(new Uint8Array([4]), unb64u(j.x), unb64u(j.y))), privateKey: j.d };
}
function setVapidDetails(subject, publicKey, privateKey) {
  details = { subject, publicKey, privateKey };
}
async function vapidAuth(endpoint) {
  const pub = unb64u(details.publicKey);
  const key = await S.importKey("jwk", { kty: "EC", crv: "P-256", x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), d: details.privateKey, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const head = b64u(te.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(te.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1e3) + 12 * 3600, sub: details.subject })));
  const sig = await S.sign({ name: "ECDSA", hash: "SHA-256" }, key, te.encode(head + "." + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${details.publicKey}`;
}
async function encrypt(sub, payload) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const eph = await S.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await S.exportKey("raw", eph.publicKey));
  const uaKey = await S.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await S.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(te.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, te.encode("Content-Encoding: nonce\0"), 12);
  const k = await S.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await S.encrypt({ name: "AES-GCM", iv: nonce }, k, cat(te.encode(payload), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
async function sendNotification(sub, payload, opts = {}) {
  const body = await encrypt(sub, String(payload));
  const r = await fetch(sub.endpoint, { method: "POST", body, headers: {
    "content-encoding": "aes128gcm",
    "content-type": "application/octet-stream",
    ttl: String(opts.TTL ?? 3600),
    urgency: opts.urgency || "normal",
    authorization: await vapidAuth(sub.endpoint)
  } });
  if (!r.ok) {
    const e = new Error("push " + r.status);
    e.statusCode = r.status;
    throw e;
  }
  return { statusCode: r.status };
}
var webpush_default = { generateVAPIDKeys, setVapidDetails, sendNotification };

// api.mjs
var KEY = "league";
var MAX_BYTES = 4 * 1024 * 1024;
var json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function readPassword() {
  try {
    const v = globalThis.Netlify?.env?.get?.("ADMIN_PASSWORD");
    if (v) return v;
  } catch {
  }
  return process.env.ADMIN_PASSWORD || "";
}
function checkPassword(given, real) {
  if (!real) return { ok: false, reason: "no-password-set" };
  const a = createHash("sha256").update(String(given ?? "")).digest();
  const b = createHash("sha256").update(String(real)).digest();
  return { ok: timingSafeEqual(a, b) };
}
function validData(d) {
  return d && typeof d === "object" && !Array.isArray(d) && Array.isArray(d.teams) && Array.isArray(d.players) && Array.isArray(d.games) && d.league && typeof d.league === "object";
}
async function staffLevel(given, store, getRealPassword) {
  if (!given) return "";
  if (checkPassword(given, getRealPassword()).ok) return "admin";
  const st = await store.get("staff", { type: "json" }) || {};
  const eq = (code) => code && checkPassword(given, code).ok;
  if (eq(st.stat)) return "stat";
  if (eq(st.mod)) return "mod";
  return "";
}
function statAllowed(oldD, newD) {
  if (!oldD) return false;
  const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  if (!same(oldD.league, newD.league) || !same(oldD.draft, newD.draft)) return false;
  for (const k of ["games", "teams", "players"]) {
    const ids = new Set(newD[k].map((x) => x.id));
    if (!oldD[k].every((x) => ids.has(x.id))) return false;
  }
  return true;
}
function makeHandler(openStore, getRealPassword = readPassword, openChat = null, openPush = null) {
  return async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");
    const store = openStore();
    const lvl = await staffLevel(req.headers.get("x-admin-password"), store, getRealPassword);
    if (path.endsWith("/api/data") && req.method === "GET") {
      const doc = await store.get(KEY, { type: "json" });
      const have = url.searchParams.get("have");
      if (doc && have !== null && Number(have) === Number(doc.rev)) return json({ same: true, rev: doc.rev });
      return json(doc || { data: null, rev: 0 });
    }
    if (path.endsWith("/api/login") && req.method === "POST") {
      let body = {};
      try {
        body = await req.json();
      } catch {
      }
      if (!getRealPassword()) return json({ ok: false, error: "no-password-set" }, 500);
      const level = await staffLevel(body.password, store, getRealPassword);
      if (!level) {
        await sleep(600);
        return json({ ok: false, error: "wrong-password" }, 401);
      }
      return json({ ok: true, level });
    }
    if (path.endsWith("/api/data") && (req.method === "PUT" || req.method === "POST")) {
      if (!getRealPassword()) return json({ ok: false, error: "no-password-set" }, 500);
      if (lvl !== "admin" && lvl !== "stat") {
        await sleep(600);
        return json({ ok: false, error: "wrong-password" }, 401);
      }
      const text = await req.text();
      if (text.length > MAX_BYTES) return json({ ok: false, error: "too-big" }, 413);
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        return json({ ok: false, error: "bad-json" }, 400);
      }
      if (!validData(body.data)) return json({ ok: false, error: "bad-data" }, 400);
      const current = await store.get(KEY, { type: "json" }) || { data: null, rev: 0 };
      if (!body.force && Number(body.baseRev) !== Number(current.rev)) {
        return json({ ok: false, error: "conflict", current }, 409);
      }
      if (lvl === "stat" && !statAllowed(current.data, body.data)) return json({ ok: false, error: "not-allowed" }, 403);
      const doc = { data: body.data, rev: Number(current.rev) + 1, savedAt: (/* @__PURE__ */ new Date()).toISOString() };
      await store.setJSON(KEY, doc);
      return json({ ok: true, rev: doc.rev, savedAt: doc.savedAt });
    }
    if (path.endsWith("/api/staff")) {
      if (lvl !== "admin") {
        await sleep(600);
        return json({ ok: false, error: "wrong-password" }, 401);
      }
      if (req.method === "GET") {
        const st2 = await store.get("staff", { type: "json" }) || {};
        return json({ ok: true, stat: st2.stat || "", mod: st2.mod || "" });
      }
      let b = {};
      try {
        b = await req.json();
      } catch {
      }
      const c = (v) => String(v ?? "").trim().slice(0, 40);
      const st = { stat: c(b.stat), mod: c(b.mod) };
      if (st.stat && st.stat.length < 4 || st.mod && st.mod.length < 4) return json({ ok: false, error: "short-code" }, 400);
      if (st.stat && st.stat === st.mod) return json({ ok: false, error: "same-code" }, 400);
      if ([st.stat, st.mod].some((x) => x && checkPassword(x, getRealPassword()).ok)) return json({ ok: false, error: "same-code" }, 400);
      await store.setJSON("staff", st);
      return json({ ok: true, ...st });
    }
    if (path.endsWith("/api/ibba") && req.method === "GET") {
      try {
        return json(await ibbaSync(store));
      } catch (e) {
        return json({ ok: false, error: String(e?.message || e) }, 502);
      }
    }
    if (path.endsWith("/sw.js")) return new Response(SW_JS, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache" } });
    if (path.includes("/api/push")) return pushRoute(req, url, path, openPush ? openPush() : store, lvl, openChat ? openChat() : store);
    if (path.includes("/api/chat")) return chatRoute(req, url, path, openChat ? openChat() : store, lvl, store, openPush ? openPush() : store);
    return json({ ok: false, error: "not-found" }, 404);
  };
}
var api_default = makeHandler(
  () => getStore({ name: "league-data", consistency: "strong" }),
  readPassword,
  () => getStore({ name: "league-chat", consistency: "strong" }),
  () => getStore({ name: "league-push", consistency: "strong" })
);
var ROOMS = ["main", "s1", "s2", "s3", "s4"];
var DEF_NAMES = { main: "\u05DB\u05D5\u05DC\u05DD", s1: "\u05E9\u05D7\u05E7\u05E0\u05D9 \u05D4\u05E7\u05D1\u05D5\u05E6\u05D4", s2: "\u05E9\u05D7\u05E7\u05E0\u05D9\u05DD \u05D5\u05DE\u05D0\u05DE\u05DF", s3: "\u05D7\u05D3\u05E8 4", s4: "\u05D7\u05D3\u05E8 5" };
var ROLES = ["ph_player", "ph_coach", "ph_parent", "o_player", "o_coach", "o_parent", "other"];
var RULES = { main: () => true, s1: (u) => u.role === "ph_player", s2: (u) => u.role === "ph_player" || u.role === "ph_coach", s3: () => false, s4: () => false };
var PH = (u) => /^ph_/.test(u?.role || "");
var DEF_TRAINING = { slots: [
  { d: 0, from: "18:30", to: "20:00", place: "\u05D9\u05E4\u05D4 \u05E0\u05D5\u05E3", note: "" },
  { d: 3, from: "18:30", to: "20:00", place: "\u05D0\u05DC\u05D9\u05E9\u05D1\u05E2", note: "" },
  { d: 4, from: "17:00", to: "18:30", place: "\u05D9\u05E4\u05D4 \u05E0\u05D5\u05E3", note: "\u05D1\u05D3\u05E8\u05DA \u05DB\u05DC\u05DC \u05D9\u05E9 \u05DE\u05E9\u05D7\u05E7 \u05D1-17:30 \u2013 \u05D4\u05DE\u05E0\u05D4\u05DC \u05D9\u05E2\u05D3\u05DB\u05DF" },
  { d: 5, from: "12:30", to: "14:30", place: "", note: "" }
], note: "", noteUntil: 0 };
var REACTS = ["\u{1F44D}", "\u2764\uFE0F", "\u{1F525}", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F44F}", "\u{1F3C0}", "\u{1F4AA}", "\u{1F389}", "\u{1F64F}", "\u{1F440}"];
var MAX_MSGS = 300;
var MAX_TEXT = 400;
var MAX_NAME = 20;
var clean = (v, n) => String(v ?? "").replace(/[\u0000-\u0008\u000B-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "").replace(/\n{3,}/g, "\n\n").trim().slice(0, n);
var cleanId = (v) => String(v ?? "").replace(/[^a-z0-9]/gi, "").slice(0, 24);
var newId = () => Date.now().toString(36) + randomBytes(4).toString("hex");
var hashTok = (t) => createHash("sha256").update(String(t)).digest("hex");
async function chatConfig(store) {
  const c = await store.get("config", { type: "json" }) || {};
  return { enabled: !!c.enabled, code: String(c.code || ""), names: { ...DEF_NAMES, ...c.names || {} }, members: c.members || {}, epoch: c.epoch || 1, roomCodes: c.roomCodes || {} };
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
  if (room === "main") return true;
  const o = cfg.members[room] || {};
  if ((o.remove || []).includes(u.id)) return false;
  if ((o.add || []).includes(u.id)) return true;
  return RULES[room](u);
}
var roomsFor = (cfg, u, isAdmin) => ROOMS.filter((r) => canRoom(cfg, u, r, isAdmin)).map((id) => ({ id, name: cfg.names[id] }));
var pubUser = (u) => u && { id: u.id, name: u.name, role: u.role, pid: u.pid || "" };
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
var emptyRoom = () => ({ msgs: [], del: [], seq: 0 });
var updateRoom = (store, room, fn) => updateKey(store, "room-" + room, emptyRoom, (d) => {
  for (const [k, v] of Object.entries(emptyRoom())) d[k] ??= v;
  return fn(d);
});
var touch = (doc, m) => {
  doc.seq = (doc.seq || 0) + 1;
  if (m) m.u = doc.seq;
};
function addMsg(doc, msg) {
  const now = Date.now(), lastTs = doc.msgs.length ? doc.msgs[doc.msgs.length - 1].ts : 0;
  msg.id = now.toString(36) + Math.random().toString(36).slice(2, 6);
  msg.ts = Math.max(now, lastTs + 1);
  doc.msgs.push(msg);
  touch(doc, msg);
  if (doc.msgs.length > MAX_MSGS) doc.msgs = doc.msgs.slice(-MAX_MSGS);
  return msg;
}
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
  const notify = (pref, ok, payload) => pushTo(pushStore, origin, (x) => {
    const u = x.uid && users[x.uid];
    return x.prefs?.[pref] && u && !u.blocked && ok(u);
  }, payload).catch(() => 0);
  const isAdmin = lvl === "admin", isMod = isAdmin || lvl === "mod", canAnn = isAdmin || lvl === "stat";
  const cfg = await chatConfig(store);
  const sub = path.replace(/^.*\/api\/chat/, "");
  const deny = async () => {
    await sleep(600);
    return json({ ok: false, error: "wrong-password" }, 401);
  };
  let b = {};
  if (req.method !== "GET") {
    try {
      b = await req.json();
    } catch {
    }
  }
  const now = Date.now();
  if (sub === "/config") {
    if (!isAdmin) return deny();
    if (req.method === "GET") return json({ ok: true, ...cfg });
    const names = {};
    for (const r of ROOMS) names[r] = clean(b.names?.[r], 30) || DEF_NAMES[r];
    const code = "", roomCodes = {};
    for (const r of ["s1", "s2", "s3", "s4"]) {
      const c = clean(b.roomCodes?.[r], 40);
      if (c) roomCodes[r] = c;
    }
    if (Object.values(roomCodes).some((c) => c.length < 4)) return json({ ok: false, error: "short-code" }, 400);
    const res = await updateKey(store, "config", () => ({}), (c) => {
      c.enabled = !!b.enabled;
      c.code = code;
      c.names = names;
      c.members ||= {};
      c.roomCodes = roomCodes;
      return { ok: true, enabled: c.enabled, code: c.code, names: c.names, epoch: c.epoch || 1, roomCodes };
    });
    return json(res);
  }
  if (req.method === "POST" && sub === "/announce") {
    if (!canAnn) return deny();
    if (!cfg.enabled) return json({ ok: false, error: "closed" }, 409);
    const room2 = "main";
    const key = clean(b.key, 60), text = clean(b.text, MAX_TEXT);
    const ref = b.ref && ["game", "player"].includes(b.ref.t) ? { t: b.ref.t, id: cleanId(b.ref.id) } : null;
    if (!key || !text) return json({ ok: false, error: "empty" }, 400);
    const res = await updateRoom(store, room2, (doc) => {
      doc.ann ||= {};
      if (doc.ann[key]) return { ok: true, dup: true };
      doc.ann[key] = now;
      return { ok: true, msg: addMsg(doc, { kind: "sys", name: "\u05D4\u05D0\u05EA\u05E8", text, ...ref ? { ref } : {} }) };
    });
    return res.error ? json({ ok: false, error: res.error }, 503) : json(res);
  }
  const users = await store.get("users", { type: "json" }) || {};
  const tok = req.headers.get("x-chat-token") || b.token || "";
  let me = tok ? Object.values(users).find((u) => u.th === hashTok(tok)) : null;
  if (me && me.blocked) me = me.blocked ? Object.assign(me, { _blocked: true }) : null;
  if (sub === "/join" && req.method === "POST") {
    if (me?._blocked) return json({ ok: false, error: "blocked" }, 403);
    const wantsProfile = b.name !== void 0 || b.role !== void 0;
    const name = clean(b.name, MAX_NAME), role = ROLES.includes(b.role) ? b.role : "", pid = cleanId(b.pid);
    if (!me && (!name || !role)) return json({ ok: false, error: "who" }, 400);
    const old = tok ? Object.values(users).find((u) => u.th === hashTok(tok)) : null;
    const token = old ? tok : randomBytes(18).toString("base64url");
    const res = await updateKey(store, "users", () => ({}), (d) => {
      let u = old && d[old.id];
      if (!u) {
        if (Object.keys(d).length >= 3e3) return { error: "full" };
        u = { id: newId(), th: hashTok(token), created: now, joins: 0 };
        d[u.id] = u;
      }
      if (u.blocked) return { error: "blocked" };
      if (name) u.name = name;
      if (role) u.role = role;
      if (wantsProfile) u.pid = pid;
      u.epoch = cfg.epoch;
      u.last = now;
      u.joins = (u.joins || 0) + 1;
      return { ok: true, u: { ...u } };
    });
    if (res.error) return json({ ok: false, error: res.error }, res.error === "blocked" ? 403 : 503);
    return json({ ok: true, token, user: pubUser(res.u), enabled: cfg.enabled || isMod, rooms: cfg.enabled || isMod ? roomsFor(cfg, res.u, isMod) : [], staff: lvl || "" });
  }
  if (!cfg.enabled && !isMod) return json({ ok: false, error: "closed" }, 403);
  if (me?._blocked) return json({ ok: false, error: "blocked" }, 403);
  if (!me && !isMod) {
    await sleep(300);
    return json({ ok: false, error: "relogin" }, 401);
  }
  if (me && now - (me.last || 0) > 5 * 6e4) await updateKey(store, "users", () => ({}), (d) => {
    if (d[me.id]) d[me.id].last = now;
    return { ok: true };
  });
  const who = me ? pubUser(me) : { id: "admin", name: clean(b.name, MAX_NAME) || "\u05DE\u05E0\u05D4\u05DC", role: "ph_coach", pid: "" };
  if (sub === "/users") {
    if (!isMod) return deny();
    if (req.method === "GET") {
      const list = Object.values(users).map((u) => ({ ...pubUser(u), created: u.created, last: u.last, joins: u.joins || 0, blocked: !!u.blocked, rooms: ROOMS.filter((r) => canRoom(cfg, u, r, false)) }));
      return json({ ok: true, users: list.sort((x, y) => (y.last || 0) - (x.last || 0)), names: cfg.names });
    }
    const id = cleanId(b.id);
    if (b.room) {
      if (!ROOMS.includes(b.room) || b.room === "main") return json({ ok: false, error: "bad-room" }, 400);
      const u = users[id];
      if (!u) return json({ ok: false, error: "no-user" }, 404);
      const res2 = await updateKey(store, "config", () => ({}), (c) => {
        c.members ||= {};
        const o = c.members[b.room] ||= { add: [], remove: [] };
        o.add = (o.add || []).filter((x) => x !== id);
        o.remove = (o.remove || []).filter((x) => x !== id);
        const auto = RULES[b.room](u);
        if (b.inRoom && !auto) o.add.push(id);
        if (!b.inRoom) o.remove.push(id);
        return { ok: true };
      });
      return json(res2);
    }
    const res = await updateKey(store, "users", () => ({}), (d) => {
      if (!d[id]) return { error: "no-user" };
      if (b.del) delete d[id];
      else if ("blocked" in b) d[id].blocked = !!b.blocked;
      if (b.role && ROLES.includes(b.role)) d[id].role = b.role;
      return { ok: true };
    });
    return res.error ? json({ ok: false, error: res.error }, 404) : json(res);
  }
  async function notifyPolls() {
    const d = await store.get("polls", { type: "json" }) || { list: [] };
    const due = d.list.filter((p) => !p.notified && p.start <= now && (!p.end || now < p.end));
    if (!due.length) return;
    const r = await updateKey(store, "polls", () => ({ list: [] }), (x) => {
      for (const p of x.list) if (due.some((q) => q.id === p.id)) p.notified = now;
      return { ok: true };
    });
    if (r.error) return;
    for (const p of due) await notify("poll", (u) => !p.roles?.length || p.roles.includes(u.role), { title: "\u{1F4CA} \u05E1\u05E7\u05E8 \u05D7\u05D3\u05E9", body: p.q, url: "#/polls", tag: "poll-" + p.id });
  }
  if (sub === "/rooms" && req.method === "GET") {
    await notifyPolls();
    const rs = roomsFor(cfg, me, isMod);
    const locked = Object.keys(cfg.roomCodes).filter((r) => ROOMS.includes(r) && !rs.some((x) => x.id === r) && !(cfg.members[r]?.remove || []).includes(me?.id)).map((id) => ({ id, name: cfg.names[id], locked: true }));
    const out = await Promise.all(rs.map(async (r) => {
      const d = await store.get("room-" + r.id, { type: "json" }) || emptyRoom();
      const l = d.msgs[d.msgs.length - 1];
      return { ...r, seq: d.seq || 0, count: d.msgs.length, last: l ? { name: l.name, text: String(l.text || "").slice(0, 80), ts: l.ts } : null };
    }));
    return json({ ok: true, rooms: [...out, ...locked].sort((x, y) => ROOMS.indexOf(x.id) - ROOMS.indexOf(y.id)), user: who });
  }
  if (sub === "/roomcode" && req.method === "POST") {
    const r = String(b.room || ""), want = cfg.roomCodes[r];
    if (!me || !want) return json({ ok: false, error: "no-room" }, 403);
    if ((cfg.members[r]?.remove || []).includes(me.id)) return json({ ok: false, error: "no-room" }, 403);
    if (!sameSecret(clean(b.code, 40), want)) {
      await sleep(800);
      return json({ ok: false, error: "wrong-room-code" }, 400);
    }
    await updateKey(store, "config", () => ({}), (c) => {
      c.members ||= {};
      const o = c.members[r] ||= { add: [], remove: [] };
      o.add ||= [];
      if (!o.add.includes(me.id)) o.add.push(me.id);
      return { ok: true };
    });
    return json({ ok: true, room: { id: r, name: cfg.names[r] } });
  }
  if (sub === "/polls" || sub === "/polls/vote") {
    const sees = (p) => isMod || !p.roles?.length || me && p.roles.includes(me.role);
    const view = (p) => {
      const counts = p.opts.map((_, i) => Object.values(p.votes || {}).filter((v) => v === i).length);
      return {
        id: p.id,
        q: p.q,
        opts: p.opts,
        start: p.start,
        end: p.end || 0,
        roles: p.roles || [],
        counts,
        total: Object.keys(p.votes || {}).length,
        mine: p.votes && who.id in p.votes ? p.votes[who.id] : null,
        open: now >= p.start && (!p.end || now < p.end)
      };
    };
    if (req.method === "GET") {
      const d = await store.get("polls", { type: "json" }) || { list: [] };
      return json({ ok: true, polls: d.list.filter((p) => (isMod || now >= p.start) && sees(p)).map(view).sort((x, y) => y.start - x.start) });
    }
    if (sub === "/polls/vote") {
      const id = cleanId(b.id), opt = Number(b.opt);
      const res2 = await updateKey(store, "polls", () => ({ list: [] }), (d) => {
        const p = d.list.find((x) => x.id === id);
        if (!p || !sees(p)) return { error: "no-msg" };
        if (!(now >= p.start && (!p.end || now < p.end))) return { error: "closed" };
        if (!(opt >= 0 && opt < p.opts.length)) return { error: "empty" };
        p.votes ||= {};
        p.votes[who.id] = opt;
        return { ok: true, poll: view(p) };
      });
      return res2.error ? json({ ok: false, error: res2.error }, res2.error === "closed" ? 409 : 400) : json(res2);
    }
    if (!isMod) return deny();
    const res = await updateKey(store, "polls", () => ({ list: [] }), (d) => {
      const id = cleanId(b.id);
      if (b.del) {
        d.list = d.list.filter((x) => x.id !== id);
        return { ok: true };
      }
      if (b.closeNow) {
        const p = d.list.find((x) => x.id === id);
        if (p) p.end = now;
        return { ok: true };
      }
      const q = clean(b.q, 160), opts = (Array.isArray(b.opts) ? b.opts : []).map((o) => clean(o, 60)).filter(Boolean).slice(0, 32);
      if (!q || opts.length < 2) return { error: "empty" };
      const start = Number(b.start) > 0 ? Number(b.start) : now, end = Number(b.end) > start ? Number(b.end) : 0;
      const roles = (Array.isArray(b.roles) ? b.roles : []).filter((r) => ROLES.includes(r));
      d.list.unshift({ id: newId(), q, opts, start, end, roles, votes: {} });
      d.list = d.list.slice(0, 60);
      return { ok: true };
    });
    if (res.error) return json({ ok: false, error: res.error }, 400);
    await notifyPolls();
    return json(res);
  }
  if (sub === "/preds" && req.method === "GET") {
    const d = await store.get("preds", { type: "json" }) || {};
    const names = {};
    for (const u of Object.values(users)) names[u.id] = u.name;
    return json({ ok: true, preds: d, names });
  }
  if (sub === "/predict" && req.method === "POST") {
    const num = (v, lo, hi) => {
      if (v === "" || v == null) return null;
      const n = Math.round(Number(v));
      return Number.isFinite(n) && n >= lo && n <= hi ? n : void 0;
    };
    const picks = (Array.isArray(b.picks) ? b.picks : []).slice(0, 20).map((x) => ({
      gid: cleanId(x.gid),
      h: Math.round(Number(x.h)),
      a: Math.round(Number(x.a)),
      tp: cleanId(x.tp),
      tpp: num(x.tpp, 0, 100),
      hf: num(x.hf, 0, 1),
      q1: num(x.q1, 0, 1),
      t3: num(x.t3, 0, 80),
      bq: num(x.bq, 1, 4)
    })).filter((x) => x.gid && x.h >= 0 && x.h <= 250 && x.a >= 0 && x.a <= 250 && [x.tpp, x.hf, x.q1, x.t3, x.bq].every((v) => v !== void 0));
    if (!picks.length) return json({ ok: false, error: "empty" }, 400);
    const data = await dataStore.get(KEY, { type: "json" });
    const limit = new Date(now + 10 * 864e5).toISOString().slice(0, 10);
    const okPicks = [];
    for (const x of picks) {
      const g = data?.data?.games?.find((y) => y.id === x.gid);
      if (g && (g.date || "") <= limit && !await gameLocked(dataStore, x.gid, data)) okPicks.push(x);
    }
    if (!okPicks.length) return json({ ok: false, error: "closed" }, 409);
    const res = await updateKey(store, "preds", () => ({}), (d) => {
      for (const x of okPicks) (d[x.gid] ||= {})[who.id] = [x.h, x.a, x.tp || null, x.tpp, x.hf, x.q1, x.t3, x.bq];
      return { ok: true, saved: okPicks.length, locked: picks.length - okPicks.length };
    });
    return res.error ? json({ ok: false, error: res.error }, 503) : json(res);
  }
  if (sub === "/training") {
    if (!isMod && !PH(me)) return json({ ok: false, error: "not-team" }, 403);
    if (req.method === "GET") return json({ ok: true, ...await store.get("training", { type: "json" }) || DEF_TRAINING });
    if (!isMod) return deny();
    const slots = (Array.isArray(b.slots) ? b.slots : []).slice(0, 14).map((x) => ({ d: Math.max(0, Math.min(6, Math.round(Number(x.d)) || 0)), from: clean(x.from, 5), to: clean(x.to, 5), place: clean(x.place, 60), note: clean(x.note, 60) })).filter((x) => /^\d\d:\d\d$/.test(x.from)).sort((x, y) => x.d - y.d || x.from.localeCompare(y.from));
    const note = clean(b.note, 300);
    const doc = { slots, note, noteUntil: note && Number(b.noteUntil) > 0 ? Number(b.noteUntil) : 0, updated: now };
    await store.setJSON("training", doc);
    return json({ ok: true, ...doc });
  }
  const room = url.searchParams.get("room") || "main";
  if (!ROOMS.includes(room)) return json({ ok: false, error: "bad-room" }, 400);
  if (!canRoom(cfg, me, room, isMod)) return json({ ok: false, error: "no-room" }, 403);
  const send = async (fn) => {
    const res = await updateRoom(store, room, fn);
    if (res.error) return json({ ok: false, error: res.error }, { slow: 429, closed: 409, empty: 400, "no-msg": 404 }[res.error] || 503);
    return json(res);
  };
  if (req.method === "GET" && sub === "") {
    const doc = { ...emptyRoom(), ...await store.get("room-" + room, { type: "json" }) || {} };
    const since = Number(url.searchParams.get("since") || 0);
    if (since && since === doc.seq) return json({ ok: true, seq: doc.seq, msgs: [] });
    const msgs = since && since < doc.seq ? doc.msgs.filter((m) => (m.u || 0) > since) : doc.msgs.slice(-80);
    return json({ ok: true, seq: doc.seq, full: !since || since > doc.seq, msgs, del: (doc.del || []).slice(-50), pin: doc.pin || null });
  }
  if (req.method === "POST" && sub === "") {
    const text = clean(b.text, MAX_TEXT);
    const ref = b.ref && ["game", "player"].includes(b.ref.t) ? { t: b.ref.t, id: cleanId(b.ref.id) } : null;
    if (!text && !ref) return json({ ok: false, error: "empty" }, 400);
    const res = await updateRoom(store, room, (doc) => {
      if (doc.msgs.filter((m) => m.uid === who.id && now - m.ts < 1e4).length >= 5) return { error: "slow" };
      const rp = b.reply && doc.msgs.find((m) => m.id === cleanId(b.reply));
      const msg = {
        uid: who.id,
        name: who.name,
        role: who.role,
        ...who.pid ? { pid: who.pid } : {},
        text,
        ...ref ? { ref } : {},
        ...isMod ? { admin: true } : {},
        ...rp ? { reply: { id: rp.id, name: rp.name, text: String(rp.text || "").slice(0, 80) } } : {}
      };
      return { ok: true, msg: addMsg(doc, msg), replyTo: rp && rp.uid && rp.uid !== who.id ? rp.uid : "" };
    });
    if (res.error) return json({ ok: false, error: res.error }, { slow: 429, empty: 400 }[res.error] || 503);
    if (res.replyTo) await notify(
      "reply",
      (u) => u.id === res.replyTo && canRoom(cfg, u, room, false),
      { title: `\u21A9 ${who.name} \u05E2\u05E0\u05D4 \u05DC\u05DA`, body: text || "\u{1F4CE}", url: "#/chat?r=" + room, tag: "reply-" + res.msg.id }
    );
    delete res.replyTo;
    return json(res);
  }
  if (req.method === "POST" && sub === "/react") {
    const e = String(b.e || ""), id = cleanId(b.id);
    if (!REACTS.includes(e)) return json({ ok: false, error: "empty" }, 400);
    return send((doc) => {
      const m = doc.msgs.find((x) => x.id === id);
      if (!m) return { error: "no-msg" };
      m.re ||= {};
      const list = m.re[e] ||= [];
      const i = list.indexOf(who.id);
      if (i >= 0) list.splice(i, 1);
      else list.push(who.id);
      if (!list.length) delete m.re[e];
      touch(doc, m);
      return { ok: true, msg: m };
    });
  }
  if (req.method === "POST" && sub === "/pin") {
    if (!isMod) return deny();
    const id = cleanId(b.id);
    const res = await updateRoom(store, room, (doc) => {
      if (!id) doc.pin = null;
      else {
        const m = doc.msgs.find((x) => x.id === id);
        if (!m) return { error: "no-msg" };
        doc.pin = { id: m.id, name: m.name, text: m.text || "", ts: m.ts };
      }
      touch(doc);
      return { ok: true, pin: doc.pin };
    });
    if (res.error) return json({ ok: false, error: res.error }, 404);
    if (res.pin) await notify("pin", (u) => canRoom(cfg, u, room, false), { title: `\u{1F4CC} ${cfg.names[room]}`, body: `${res.pin.name}: ${res.pin.text}`.slice(0, 160), url: "#/chat?r=" + room, tag: "pin-" + room });
    return json(res);
  }
  if (req.method === "DELETE") {
    if (!isMod) return deny();
    const id = url.searchParams.get("id") || "";
    return send((doc) => {
      if (id === "all") {
        doc.del = [...doc.del || [], ...doc.msgs.map((m) => m.id)].slice(-300);
        doc.msgs = [];
        doc.pin = null;
      } else {
        doc.msgs = doc.msgs.filter((m) => m.id !== id);
        doc.del = [...doc.del || [], id].slice(-300);
        if (doc.pin?.id === id) doc.pin = null;
      }
      touch(doc);
      return { ok: true };
    });
  }
  return json({ ok: false, error: "not-found" }, 404);
}
async function vapid(store) {
  let k = await store.get("vapid", { type: "json" });
  if (!k?.publicKey) {
    const fresh = await webpush_default.generateVAPIDKeys();
    const w = await store.setJSON("vapid", fresh, { onlyIfNew: true });
    k = w.modified === false ? await store.get("vapid", { type: "json" }) : fresh;
  }
  return k;
}
async function pushTo(store, origin, filter, msg) {
  const subs = await store.get("subs", { type: "json" }) || {};
  const targets = Object.entries(subs).filter(([, x]) => {
    try {
      return filter(x);
    } catch {
      return false;
    }
  });
  if (!targets.length) return { sent: 0, failed: 0, removed: 0 };
  const k = await vapid(store);
  webpush_default.setVapidDetails(origin.startsWith("https://") ? origin : "mailto:league@example.com", k.publicKey, k.privateKey);
  const payload = JSON.stringify({ title: msg.title, body: msg.body || "", url: msg.url || "#/", tag: msg.tag });
  const dead = [];
  const results = await Promise.allSettled(targets.map(([id, x]) => webpush_default.sendNotification(x.sub, payload, { TTL: 6 * 3600, urgency: "high" }).catch((e) => {
    if (e.statusCode === 404 || e.statusCode === 410) dead.push(id);
    throw e;
  })));
  if (dead.length) await updateKey(store, "subs", () => ({}), (d) => {
    for (const id of dead) delete d[id];
    return { ok: true };
  });
  return { sent: results.filter((r) => r.status === "fulfilled").length, failed: results.filter((r) => r.status === "rejected").length, removed: dead.length };
}
var subKey = (endpoint) => createHash("sha256").update(String(endpoint)).digest("hex").slice(0, 32);
async function pushRoute(req, url, path, store, lvl, chatStore) {
  const sub = path.replace(/^.*\/api\/push/, "");
  if (sub === "/key" && req.method === "GET") return json({ ok: true, key: (await vapid(store)).publicKey });
  let b = {};
  if (req.method !== "GET") {
    try {
      b = await req.json();
    } catch {
    }
  }
  if (sub === "/sub") {
    const s = b.sub, ep = s?.endpoint;
    if (typeof ep !== "string" || !/^https:\/\//.test(ep) || ep.length > 1e3) return json({ ok: false, error: "bad-sub" }, 400);
    const k = subKey(ep);
    if (req.method === "DELETE") {
      await updateKey(store, "subs", () => ({}), (d) => {
        delete d[k];
        return { ok: true };
      });
      return json({ ok: true });
    }
    if (!s.keys?.p256dh || !s.keys?.auth) return json({ ok: false, error: "bad-sub" }, 400);
    const pr = b.prefs || {};
    const prefs = { start: !!pr.start, final: !!pr.final, remind: !!pr.remind, teams: (Array.isArray(pr.teams) ? pr.teams : []).map(cleanId).filter(Boolean).slice(0, 20), poll: !!pr.poll, pin: !!pr.pin, reply: !!pr.reply };
    let uid = "";
    if (b.chatToken && (prefs.poll || prefs.pin || prefs.reply)) {
      const users = await chatStore.get("users", { type: "json" }) || {};
      const u = Object.values(users).find((x) => x.th === hashTok(b.chatToken));
      if (u && !u.blocked) uid = u.id;
    }
    const res = await updateKey(store, "subs", () => ({}), (d) => {
      if (!d[k] && Object.keys(d).length >= 2e3) return { error: "full" };
      d[k] = { sub: { endpoint: ep, keys: { p256dh: String(s.keys.p256dh).slice(0, 200), auth: String(s.keys.auth).slice(0, 100) } }, prefs, uid, ts: Date.now() };
      return { ok: true };
    });
    return res.error ? json({ ok: false, error: res.error }, 503) : json({ ok: true, prefs, chat: !!uid });
  }
  if (sub === "/send" && req.method === "POST") {
    if (lvl !== "admin" && lvl !== "stat") {
      await sleep(600);
      return json({ ok: false, error: "wrong-password" }, 401);
    }
    const type = b.type === "start" ? "start" : "final", key = clean(b.key, 80);
    const title = clean(b.title, 80), body = clean(b.body, 160), link = /^#\/[\w/?=&-]*$/.test(b.url || "") ? b.url : "#/";
    const tids = (Array.isArray(b.tids) ? b.tids : []).map(cleanId);
    if (!key || !title) return json({ ok: false, error: "empty" }, 400);
    const first = await updateKey(store, "sent", () => ({}), (d) => {
      if (d[key]) return { ok: true, dup: true };
      d[key] = Date.now();
      const ks = Object.keys(d);
      if (ks.length > 500) for (const x of ks.sort((p, q) => d[p] - d[q]).slice(0, ks.length - 500)) delete d[x];
      return { ok: true };
    });
    if (first.dup) return json({ ok: true, dup: true, sent: 0 });
    const r = await pushTo(store, new URL(req.url).origin, (x) => x.prefs?.[type] && (!x.prefs.teams?.length || x.prefs.teams.some((t) => tids.includes(t))), { title, body, url: link, tag: key });
    return json({ ok: true, ...r });
  }
  return json({ ok: false, error: "not-found" }, 404);
}
function ilOffsetMin(d) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Jerusalem", hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).formatToParts(d).map((x) => [x.type, x.value]));
  return (Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute) - Math.floor(d.getTime() / 6e4) * 6e4) / 6e4;
}
function gameStartUtc(date, time) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || "") || !/^\d{2}:\d{2}$/.test(time || "")) return null;
  const guess = /* @__PURE__ */ new Date(`${date}T${time}:00Z`);
  return new Date(guess.getTime() - ilOffsetMin(guess) * 6e4);
}
async function runReminders(dataStore, pushStore, origin, now = /* @__PURE__ */ new Date()) {
  const doc = await dataStore.get("league", { type: "json" });
  const d = doc?.data;
  if (!d?.games) return { sent: 0, games: 0 };
  const tn = (id) => (d.teams.find((t) => t.id === id)?.name || "").replace(/\s*מחוזית.*$/, "");
  let sent = 0, games = 0;
  for (const g of d.games) {
    if (g.status === "final" || g.status === "live") continue;
    const t = gameStartUtc(g.date, g.time);
    if (!t) continue;
    const mins = (t - now) / 6e4;
    if (mins < 40 || mins > 76) continue;
    const key = "remind:" + g.id;
    const first = await updateKey(pushStore, "sent", () => ({}), (x) => {
      if (x[key]) return { ok: true, dup: true };
      x[key] = Date.now();
      return { ok: true };
    });
    if (first.dup) continue;
    games++;
    const venue = g.venue || d.teams.find((x) => x.id === g.homeId)?.venue || "";
    const tids = [g.homeId, g.awayId];
    try {
      const r = await pushTo(
        pushStore,
        origin,
        (x) => x.prefs?.remind && (!x.prefs.teams?.length || x.prefs.teams.some((id) => tids.includes(id))),
        { title: `\u23F0 \u05D1\u05E2\u05D5\u05D3 \u05E9\u05E2\u05D4: ${tn(g.homeId)} \u05E0\u05D2\u05D3 ${tn(g.awayId)}`, body: `${g.time}${venue ? " \xB7 " + venue : ""}`, url: "#/game/" + g.id, tag: key }
      );
      sent += r.sent;
    } catch {
    }
  }
  return { sent, games };
}
var SW_JS = '/* \u05D4\u05EA\u05E8\u05D0\u05D5\u05EA \u05DC\u05D8\u05DC\u05E4\u05D5\u05DF \u2013 \u05DE\u05E6\u05D9\u05D2 \u05D0\u05EA \u05D4\u05D4\u05EA\u05E8\u05D0\u05D4 \u05D5\u05E4\u05D5\u05EA\u05D7 \u05D0\u05EA \u05D4\u05E2\u05DE\u05D5\u05D3 \u05D4\u05E0\u05DB\u05D5\u05DF \u05DB\u05E9\u05DC\u05D5\u05D7\u05E6\u05D9\u05DD \u05E2\u05DC\u05D9\u05D4 */\nself.addEventListener("install", () => self.skipWaiting());\nself.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));\nself.addEventListener("push", (e) => {\n  let d = {}; try { d = e.data ? e.data.json() : {}; } catch { d = { title: e.data && e.data.text() }; }\n  e.waitUntil(self.registration.showNotification(d.title || "\u05D4\u05DC\u05D9\u05D2\u05D4", { body: d.body || "", icon: "icon.svg", badge: "icon.svg", tag: d.tag || undefined, data: { url: d.url || "#/" }, dir: "rtl", lang: "he" }));\n});\nself.addEventListener("notificationclick", (e) => {\n  e.notification.close();\n  const target = new URL("./" + (e.notification.data && e.notification.data.url || "#/"), self.registration.scope).href;\n  e.waitUntil((async () => {\n    const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });\n    for (const c of all) { if ("focus" in c) { await c.focus(); if ("navigate" in c) { try { await c.navigate(target); } catch {} } return; } }\n    if (self.clients.openWindow) await self.clients.openWindow(target);\n  })());\n});\n';
var IBBA_DEF = { league: 119989, season: 119888 };
var IBBA_TTL = 25e3;
var ibNorm = (s) => String(s || "").replace(/["'׳״`]/g, "").replace(/מחוזית|ילדים א|שומרון/g, " ").replace(/(^|\s)(מכבי|הפועל|בני|עירוני|אליצור|בית"?ר)(?=\s)/g, " ").replace(/\s+/g, " ").trim();
function ibSim(a, b) {
  a = ibNorm(a);
  b = ibNorm(b);
  if (!a || !b) return 0;
  if (a === b) return 1;
  const bg = (s) => {
    const m = /* @__PURE__ */ new Map();
    for (let i = 0; i < s.length - 1; i++) {
      const k = s.slice(i, i + 2);
      m.set(k, (m.get(k) || 0) + 1);
    }
    return m;
  };
  const A = bg(a), B = bg(b);
  let inter = 0;
  for (const [k, v] of A) inter += Math.min(v, B.get(k) || 0);
  return 2 * inter / (a.length - 1 + b.length - 1);
}
function ibbaMatch(data, ev) {
  const byId = data.games.find((g) => g.ibbaId === ev.id);
  if (byId) return byId;
  const tn = (id) => data.teams.find((t) => t.id === id)?.name || "";
  let best = null, bs = 0;
  for (const g of data.games) {
    const h = ibSim(tn(g.homeId), ev.home?.team), a = ibSim(tn(g.awayId), ev.away?.team);
    if (h < 0.55 || a < 0.55) continue;
    const sc = h + a + (String(g.date || "") === String(ev.date || "").slice(0, 10) ? 0.5 : 0);
    if (sc > bs) {
      bs = sc;
      best = g;
    }
  }
  return bs >= 1.4 ? best : null;
}
var ibNum = (v) => v === "" || v == null || isNaN(Number(v)) ? null : Number(v);
function ibbaApply(data, events) {
  const changed = [];
  for (const ev of events) {
    const hs = ibNum(ev.home?.points), as = ibNum(ev.away?.points), st = String(ev.state || "").toLowerCase();
    const finished = st === "finished" || st === "final" || st === "ended";
    if (hs === null || as === null) continue;
    if (!finished && hs === 0 && as === 0 && !ev.quarter_current) continue;
    const g = ibbaMatch(data, ev);
    if (!g) continue;
    if (!g.ibbaId) g.ibbaId = ev.id;
    if (g.status === "final" && g.homeScore != null && g.awayScore != null) continue;
    const q = parseInt(ev.quarter_current, 10);
    const next = finished ? { status: "final", homeScore: hs, awayScore: as } : { status: "live", homeScore: hs, awayScore: as, liveQ: q >= 1 && q <= 4 ? q : g.liveQ || 0, liveClock: String(ev.quarter_current_time || "").slice(0, 8) };
    if (Object.entries(next).some(([k, v]) => g[k] !== v)) {
      Object.assign(g, next);
      if (finished) {
        delete g.liveQ;
        delete g.liveClock;
      }
      g.ibbaAt = (/* @__PURE__ */ new Date()).toISOString();
      changed.push({ id: g.id, ...next });
    }
  }
  return changed;
}
async function ibbaFetch(cfg, fetchFn = fetch) {
  const f = "id,date,state,quarter_current,quarter_current_time,home,away,teams";
  const u = `https://ibasketball.co.il/wp-json/sportspress/v2/events?leagues=${cfg.league}&seasons=${cfg.season}&per_page=40&_fields=${f}`;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8e3);
  try {
    const r = await fetchFn(u, { signal: ctl.signal, headers: { accept: "application/json", "user-agent": "Mozilla/5.0 (league-stats fan site; score only)" } });
    if (!r.ok) throw new Error("ibba-http-" + r.status);
    const j = await r.json();
    if (!Array.isArray(j)) throw new Error("ibba-bad-json");
    return j;
  } finally {
    clearTimeout(t);
  }
}
async function ibbaSync(store, { now = Date.now(), fetchFn = fetch, force = false } = {}) {
  const cache = await store.get("ibba", { type: "json" }) || {};
  const doc = await store.get(KEY, { type: "json" });
  if (!doc?.data) return { ok: false, error: "no-data" };
  if (!force && cache.at && now - cache.at < IBBA_TTL) return { ok: true, cached: true, rev: doc.rev, live: cache.live || [] };
  const L = doc.data.league || {};
  if (L.ibbaOff) return { ok: true, off: true, rev: doc.rev, live: [] };
  const cfg = { league: Number(L.ibbaLeague) || IBBA_DEF.league, season: Number(L.ibbaSeason) || IBBA_DEF.season };
  const due = doc.data.games.some((g) => {
    if (g.status === "final" && g.homeScore != null) return false;
    const t = gameStartUtc(g.date, g.time || "18:00");
    return t && t - 15 * 6e4 <= now && now - t < 3 * 864e5;
  });
  if (!force && !due) {
    await store.setJSON("ibba", { at: now, live: [], idle: true });
    return { ok: true, idle: true, rev: doc.rev, live: [] };
  }
  await store.setJSON("ibba", { ...cache, at: now });
  const events = await ibbaFetch(cfg, fetchFn);
  const changed = ibbaApply(doc.data, events);
  let rev = doc.rev;
  if (changed.length) {
    const cur = await store.get(KEY, { type: "json" });
    if (Number(cur?.rev) === Number(doc.rev)) {
      rev = Number(doc.rev) + 1;
      await store.setJSON(KEY, { data: doc.data, rev, savedAt: (/* @__PURE__ */ new Date()).toISOString(), by: "ibba" });
    } else rev = cur.rev;
  }
  const live = doc.data.games.filter((g) => g.status === "live").map((g) => ({ id: g.id, h: g.homeScore, a: g.awayScore, q: g.liveQ || 0, c: g.liveClock || "" }));
  await store.setJSON("ibba", { at: now, live, changed: changed.length });
  return { ok: true, rev, changed, live };
}

// worker-src.mjs
var ready = null;
function d1Store(db, ns) {
  const K = (k) => ns + ":" + k;
  const s = {
    async get(key, o) {
      const r = await db.prepare("SELECT v FROM kv WHERE k=?").bind(K(key)).first();
      if (!r) return null;
      return o?.type === "json" ? JSON.parse(r.v) : r.v;
    },
    async getWithMetadata(key, o) {
      const r = await db.prepare("SELECT v, etag FROM kv WHERE k=?").bind(K(key)).first();
      if (!r) return null;
      return { data: o?.type === "json" ? JSON.parse(r.v) : r.v, etag: String(r.etag) };
    },
    async setJSON(key, val, o = {}) {
      const v = JSON.stringify(val);
      let res;
      if (o.onlyIfMatch) res = await db.prepare("UPDATE kv SET v=?, etag=etag+1 WHERE k=? AND etag=?").bind(v, K(key), Number(o.onlyIfMatch)).run();
      else if (o.onlyIfNew) res = await db.prepare("INSERT OR IGNORE INTO kv (k, v, etag) VALUES (?, ?, 1)").bind(K(key), v).run();
      else res = await db.prepare("INSERT INTO kv (k, v, etag) VALUES (?, ?, 1) ON CONFLICT(k) DO UPDATE SET v=excluded.v, etag=kv.etag+1").bind(K(key), v).run();
      const modified = (res.meta?.changes ?? 1) > 0;
      if (modified && ns === "data" && key === "league") await db.prepare("INSERT INTO kv (k, v, etag) VALUES ('data:league:rev', ?, 1) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(val?.rev ?? 0)).run();
      return { modified };
    },
    async delete(key) {
      await db.prepare("DELETE FROM kv WHERE k=?").bind(K(key)).run();
    }
  };
  return s;
}
var jsonRes = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
var API = /^\/(api\/(data|login|chat|push|staff|ibba|tick)(\/.*)?|sw\.js)$/;
async function tick(env, origin, force) {
  const db = env.DB, now = Date.now();
  const last = await db.prepare("SELECT v FROM kv WHERE k='sys:tick'").first();
  if (!force && last && now - Number(last.v) < 14 * 6e4) return { skipped: true };
  await db.prepare("INSERT INTO kv (k, v, etag) VALUES ('sys:tick', ?, 1) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(now)).run();
  const out = {};
  try {
    out.remind = await runReminders(d1Store(db, "data"), d1Store(db, "push"), origin);
  } catch (e) {
    out.remind = String(e);
  }
  try {
    const r = await ibbaSync(d1Store(db, "data"));
    out.ibba = { ok: r.ok, changed: r.changed?.length || 0, idle: r.idle, error: r.error };
  } catch (e) {
    out.ibba = String(e);
  }
  return out;
}
var worker_src_default = {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!API.test(url.pathname.replace(/\/+$/, "") || "/")) return env.ASSETS.fetch(req);
    if (!env.DB) return jsonRes({ ok: false, error: "no-db: \u05D7\u05E1\u05E8 \u05D7\u05D9\u05D1\u05D5\u05E8 D1 \u05D1\u05E9\u05DD DB \u05D1\u05D4\u05D2\u05D3\u05E8\u05D5\u05EA Cloudflare" }, 500);
    ready ||= env.DB.prepare("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, etag INTEGER NOT NULL DEFAULT 1)").run().catch((e) => {
      ready = null;
      throw e;
    });
    await ready;
    globalThis.Netlify = { env: { get: (k) => env[k] } };
    globalThis.process ||= { env: {} };
    const path = url.pathname.replace(/\/+$/, "");
    if (path === "/api/data" && req.method === "GET") {
      const rev = await env.DB.prepare("SELECT v FROM kv WHERE k='data:league:rev'").first();
      const have = url.searchParams.get("have");
      ctx.waitUntil(tick(env, url.origin).catch(() => {
      }));
      if (rev && have !== null && Number(have) === Number(rev.v)) return jsonRes({ same: true, rev: Number(rev.v) });
      const r = await env.DB.prepare("SELECT v FROM kv WHERE k='data:league'").first();
      return new Response(r ? r.v : JSON.stringify({ data: null, rev: 0 }), { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
    }
    if (path === "/api/tick") return jsonRes({ ok: true, ...await tick(env, url.origin, url.searchParams.has("now")) });
    const h = makeHandler(() => d1Store(env.DB, "data"), () => env.ADMIN_PASSWORD || "", () => d1Store(env.DB, "chat"), () => d1Store(env.DB, "push"));
    return h(req);
  }
};
export {
  worker_src_default as default
};
