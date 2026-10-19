const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const scrypt = require('util').promisify(crypto.scrypt);

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB = path.join(DIR, 'db.json');
const PUB = path.join(__dirname, 'public');
// browsers only send Secure cookies over https; COOKIE_SECURE=0 for local testing
const SECURE = process.env.COOKIE_SECURE !== '0';
// priorities: green = unwichtig, yellow = relevant, red = ganz wichtig
const COLORS = ['green', 'yellow', 'red'];
const KINDS = ['list', 'staples'];
const LANGS = ['de', 'en'];
const DAY = 864e5;
const SESSION_DAYS = 30;
const INVITE_DAYS = 7;
const SIGNUPS_PER_IP_DAY = 3;
// who may create an account: anyone (open), only people with an invite link (invite; the very first account always works)
const REGISTRATION = process.env.REGISTRATION === 'invite' ? 'invite' : 'open';
// whose X-Real-IP / X-Forwarded-For counts: the proxy on this machine, or with TRUST_PROXY=private also one in a
// private network (Docker); the rate limits need the visitor's address, not the proxy's
const PROXY = process.env.TRUST_PROXY === 'private'
  ? /^(::ffff:)?(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|^::1$|^f[cd][0-9a-f]{2}:/i : /^(::ffff:)?127\.|^::1$/;
// files in BRANDING_DIR replace the built-in ones of the same name; hero.png there shows up in the header
const BRANDING = process.env.BRANDING_DIR;
const NAME_RE = /^[\p{L}\p{N}._-]{2,32}$/u;
// scrypt cost: 128 * N * r bytes = 32 MiB per hash; stored with every hash, older ones are upgraded on login
const SCRYPT = { N: 2 ** 15, r: 8, p: 1 };
// the same rules the forms tick off while typing
const { pwOk } = require('./public/pwrules');

const DEFAULTS = {
  de: { group: n => `Gruppe von ${n}`, list: 'Einkauf', staples: 'Vorrat' },
  en: { group: n => `${n}’s group`, list: 'Shopping', staples: 'Pantry' },
};

const uid = () => crypto.randomUUID();
const now = () => Date.now();
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const secret = () => crypto.randomBytes(32).toString('base64url');

// secrets come from a file named in the environment (Docker secret) or from systemd (LoadCredential=<name>:...)
function credential(name, envFile) {
  const file = process.env[envFile] || (process.env.CREDENTIALS_DIRECTORY && path.join(process.env.CREDENTIALS_DIRECTORY, name));
  return file && fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : null;
}

/* ---------------- storage: one JSON file, AES-256-GCM encrypted at rest ---------------- */
// without a key (local testing) the file stays plain
const KEY = (() => {
  const hex = credential('dbkey', 'DB_KEY_FILE');
  if (!hex) return null;
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error('db key must be 64 hex characters');
  return Buffer.from(hex, 'hex');
})();

function encode(obj) {
  const json = JSON.stringify(obj);
  if (!KEY) return json;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const data = Buffer.concat([c.update(json, 'utf8'), c.final()]);
  return JSON.stringify({ enc: 'aes-256-gcm', iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') });
}

function decode(text) {
  const o = JSON.parse(text);
  if (!o.enc) return o;
  if (!KEY) throw new Error('db.json is encrypted, but no key is configured');
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(o.iv, 'base64'));
  d.setAuthTag(Buffer.from(o.tag, 'base64'));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(o.data, 'base64')), d.final()]).toString('utf8'));
}

// db: { groups: [{id, name, admins: [user ids], version, lists}], users: [{…, groups: [ids], lists, version}], sessions, invites }
// shared lists live in their group, private lists in their user; sessions and invites only keep a sha256
let db, plain = false;
try {
  const text = fs.readFileSync(DB, 'utf8');
  db = decode(text);
  plain = KEY && !JSON.parse(text).enc;
} catch (e) {
  // a broken or undecryptable db.json must not be replaced by an empty one
  if (e.code !== 'ENOENT') throw e;
  db = { groups: [], users: [], sessions: [], invites: [] };
  fs.mkdirSync(DIR, { recursive: true });
}
if (plain || !fs.existsSync(DB)) save();

// bumps the version of every group or user whose lists changed, so open apps fetch them again
function save(...changed) {
  for (const c of changed) c.version++;
  const tmp = DB + '.tmp';
  fs.writeFileSync(tmp, encode(db), { mode: 0o600 });
  fs.renameSync(tmp, DB);
}

function prune() {
  db.sessions = db.sessions.filter(s => s.expires > now());
  db.invites = db.invites.filter(i => i.expires > now());
}

/* ---------------- groups ---------------- */
const groupsOf = user => db.groups.filter(g => user.groups.includes(g.id));
const groupOf = (user, id) => id && user.groups.includes(id) ? db.groups.find(g => g.id === id) : undefined;
const membersOf = g => db.users.filter(u => u.groups.includes(g.id)).sort((a, b) => a.created - b.created);

// the first group of a new account gets an empty shopping list and pantry, groups made later only the shopping list
function newGroup(user, name) {
  const t = now(), d = DEFAULTS[user.lang] || DEFAULTS.de;
  const g = {
    id: uid(), name: clean(name, 40) || d.group(user.name), admins: [user.id], version: 1, created: t,
    lists: [{ id: uid(), name: d.list, kind: 'list', by: user.id, created: t, items: [] }],
  };
  if (!name) g.lists.push({ id: uid(), name: d.staples, kind: 'staples', by: user.id, created: t + 1, items: [] });
  db.groups.push(g);
  user.groups.push(g.id);
  return g;
}

// gone for every member, with its shared lists
function deleteGroup(g) {
  for (const u of db.users) u.groups = u.groups.filter(id => id !== g.id);
  db.groups = db.groups.filter(x => x !== g);
  db.invites = db.invites.filter(i => i.group !== g.id);
}

const isAdmin = (g, user) => g.admins.includes(user.id);
const lastAdmin = (g, user) => g.admins.length === 1 && g.admins[0] === user.id;

// what the last admin chose for a group they leave: 'delete', the id of the new admin, or nothing (longest member)
const badChoice = (user, g, to) => lastAdmin(g, user) && to && to !== 'delete' && !membersOf(g).some(u => u.id === to && u !== user);

// an empty group is deleted, one without admins gets a new one
function leaveGroup(user, g, to) {
  if (lastAdmin(g, user) && to === 'delete') return deleteGroup(g);
  user.groups = user.groups.filter(id => id !== g.id);
  g.admins = g.admins.filter(id => id !== user.id);
  const rest = membersOf(g);
  if (!rest.length) return deleteGroup(g);
  if (!g.admins.length) g.admins = [rest.some(u => u.id === to) ? to : rest[0].id];
  g.version++;
}

/* ---------------- passwords, sessions, invites ---------------- */
const maxmem = p => 256 * p.N * p.r;

async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const { N, r, p } = SCRYPT;
  const key = await scrypt(pw.normalize('NFC'), salt, 64, { N, r, p, maxmem: maxmem(SCRYPT) });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

// "scrypt$N$r$p$salt$key"; the first version stored "scrypt$salt$key" with Node's defaults
function parseHash(stored) {
  const f = stored.split('$');
  if (f.length === 3) return { N: 16384, r: 8, p: 1, salt: f[1], key: f[2] };
  return { N: +f[1], r: +f[2], p: +f[3], salt: f[4], key: f[5] };
}
async function checkPw(pw, stored) {
  const h = parseHash(stored);
  const want = Buffer.from(h.key, 'base64');
  const got = await scrypt(pw.normalize('NFC'), Buffer.from(h.salt, 'base64'), want.length, { N: h.N, r: h.r, p: h.p, maxmem: maxmem(h) });
  return crypto.timingSafeEqual(got, want);
}
const outdated = stored => { const h = parseHash(stored); return h.N !== SCRYPT.N || h.r !== SCRYPT.r || h.p !== SCRYPT.p; };
// unknown names get checked against this, so they take as long as wrong passwords
const DUMMY = `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${Buffer.alloc(16).toString('base64')}$${Buffer.alloc(64).toString('base64')}`;

// the rules the forms show up front: 8-200 characters, not a common password,
// not one character repeated, the user name not inside
const pwError = (pw, name) => pwOk(pw, name) ? undefined : 'pw_invalid';
const byName = name => db.users.find(u => u.name.toLowerCase() === String(name ?? '').trim().toLowerCase());

function cookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
}
function setCookie(res, value, maxAge) {
  res.setHeader('Set-Cookie', `sid=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}` + (SECURE ? '; Secure' : ''));
}

function startSession(res, user) {
  const t = secret();
  prune();
  db.sessions.push({ hash: sha(t), user: user.id, created: now(), expires: now() + SESSION_DAYS * DAY });
  save();
  setCookie(res, t, SESSION_DAYS * DAY / 1000);
}

function session(req, res) {
  const t = cookie(req, 'sid');
  const s = t && db.sessions.find(x => x.hash === sha(t));
  if (!s || s.expires < now()) return [];
  const user = db.users.find(u => u.id === s.user);
  if (!user) return [];
  // sliding expiry, written at most once a day
  if (s.expires - now() < (SESSION_DAYS - 1) * DAY) {
    s.expires = now() + SESSION_DAYS * DAY;
    save();
    setCookie(res, t, SESSION_DAYS * DAY / 1000);
  }
  return [user, s];
}

const findInvite = code => code && db.invites.find(i => i.hash === sha(code) && i.expires > now());

function createInvite(group, by) {
  const code = secret();
  prune();
  db.invites.push({ id: uid(), hash: sha(code), group, by, created: now(), expires: now() + INVITE_DAYS * DAY });
  save();
  return code;
}

/* ---------------- limits per IP: 10 failures per 15 minutes, 3 sign-ups per day ---------------- */
// the reverse proxy in front sets X-Real-IP or X-Forwarded-For; only trusted from the addresses in PROXY
function clientIp(req) {
  const r = req.socket.remoteAddress || '';
  const real = req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',').pop();
  return real && PROXY.test(r) ? String(real).trim() : r;
}
function counter(max, ms) {
  const m = new Map();
  return {
    over(req) { const f = m.get(clientIp(req)); return f && f.until > now() && f.n >= max; },
    add(req) {
      const key = clientIp(req), f = m.get(key);
      if (m.size > 10000) for (const [k, v] of m) if (v.until < now()) m.delete(k);
      if (!f || f.until < now()) m.set(key, { n: 1, until: now() + ms });
      else f.n++;
    },
  };
}
const fails = counter(10, 15 * 60e3);
const signups = counter(SIGNUPS_PER_IP_DAY, DAY);

/* ---------------- lists ---------------- */
const clean = (s, max = 200) => String(s ?? '').trim().replace(/\s+/g, ' ').slice(0, max);
// a list the user may touch, with where it lives: one of their groups, or the user (private)
function locate(user, id) {
  for (const c of [user, ...groupsOf(user)]) {
    const l = c.lists.find(x => x.id === id);
    if (l) return [l, c];
  }
  return [];
}
function locateItem(user, id) {
  for (const c of [user, ...groupsOf(user)]) for (const l of c.lists) {
    const it = l.items.find(i => i.id === id);
    if (it) return [l, it, c];
  }
  return [];
}

// adds items to a list, skipping names already open there; re-adding a checked-off item un-checks it
function addItems(list, incoming) {
  const open = new Set(list.items.filter(i => !i.done).map(i => i.name.toLowerCase()));
  let added = 0;
  for (const x of incoming.slice(0, 500)) {
    const name = clean(x.name);
    const key = name.toLowerCase();
    if (!name || open.has(key)) continue;
    open.add(key);
    const color = COLORS.includes(x.color) ? x.color : list.kind === 'staples' ? 'green' : 'yellow';
    const old = list.items.find(i => i.done && i.name.toLowerCase() === key);
    if (old) { old.done = false; old.created = now() + added; old.color = color; }
    else if (list.items.length < 2000) list.items.push({ id: uid(), name, done: false, color, created: now() + added });
    else break;
    added++;
  }
  return added;
}

// bought it -> the matching staples entries the user can see are stocked again
function setDone(lists, list, item, done) {
  item.done = done;
  if (done && list.kind !== 'staples') {
    const key = item.name.toLowerCase();
    for (const s of lists) if (s.kind === 'staples')
      for (const i of s.items) if (i.name.toLowerCase() === key) i.color = 'green';
  }
}

/* ---------------- http ---------------- */
// no proxy setup is assumed, so the app sends its own security headers
const SECURITY = {
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; " +
    "img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};
function send(res, code, body, type = 'application/json', headers = {}) {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...SECURITY, ...headers });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const fail = (res, code, error) => send(res, code, { error });

function redirect(res, to) {
  res.writeHead(302, { Location: to, 'Cache-Control': 'no-store' });
  res.end();
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { reject(e); } });
  });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2' };

function me(user) {
  const nameOf = id => db.users.find(u => u.id === id)?.name;
  return {
    user: { id: user.id, name: user.name, lang: user.lang },
    groups: groupsOf(user).map(g => ({
      id: g.id, name: g.name, admins: g.admins,
      members: membersOf(g).map(u => ({ id: u.id, name: u.name })),
      invites: db.invites.filter(i => i.group === g.id && i.expires > now()).map(i => ({ id: i.id, by: nameOf(i.by), expires: i.expires })),
    })),
  };
}

async function api(req, res, parts) {
  const [res1, id, sub, subId] = parts;
  const M = req.method;

  // other sites can't add custom headers without CORS, so this blocks cross-site requests
  if (M !== 'GET' && req.headers['x-shop'] !== '1') return fail(res, 403, 'forbidden');

  /* ---- without login ---- */
  if (res1 === 'login' && M === 'POST') {
    if (fails.over(req)) return fail(res, 429, 'too_many');
    const b = await readBody(req);
    const password = String(b.password ?? '');
    const user = byName(b.name);
    const ok = await checkPw(password, user ? user.pass : DUMMY);
    if (!user || !ok) { fails.add(req); return fail(res, 401, 'bad_login'); }
    if (outdated(user.pass)) user.pass = await hashPw(password);
    startSession(res, user);
    return send(res, 200, me(user));
  }

  if (res1 === 'invite' && id && M === 'GET') {
    if (fails.over(req)) return fail(res, 429, 'too_many');
    const inv = findInvite(id);
    const g = inv && db.groups.find(x => x.id === inv.group);
    if (!g) { fails.add(req); return fail(res, 404, 'invite_invalid'); }
    return send(res, 200, { groupId: g.id, group: g.name, by: db.users.find(u => u.id === inv.by)?.name || null });
  }

  // what the sign-up form needs to know
  if (res1 === 'setup' && M === 'GET') return send(res, 200, { registration: db.users.length ? REGISTRATION : 'first' });

  // a new account is signed in right away: in the group of its invite, or with an own one
  if (res1 === 'register' && M === 'POST') {
    if (fails.over(req)) return fail(res, 429, 'too_many');
    const b = await readBody(req);
    if (b.code && !findInvite(b.code)) { fails.add(req); return fail(res, 404, 'invite_invalid'); }
    if (!b.code && REGISTRATION === 'invite' && db.users.length) return fail(res, 403, 'invite_only');
    if (signups.over(req)) return fail(res, 429, 'signup_limit');
    const name = String(b.name ?? '').trim();
    const password = String(b.password ?? '');
    if (!NAME_RE.test(name)) return fail(res, 400, 'name_format');
    const bad = pwError(password, name);
    if (bad) return fail(res, 400, bad);
    if (byName(name)) return fail(res, 409, 'name_taken');
    const pass = await hashPw(password);
    // checked again after the await: the invite and the name may be gone by now
    const inv = b.code && findInvite(b.code);
    if (b.code && !inv) return fail(res, 404, 'invite_invalid');
    if (byName(name)) return fail(res, 409, 'name_taken');
    signups.add(req);
    const user = { id: uid(), name, pass, lang: LANGS.includes(b.lang) ? b.lang : 'de', created: now(), groups: [], lists: [], version: 1 };
    db.users.push(user);
    const g = inv && db.groups.find(x => x.id === inv.group);
    if (g) { user.groups.push(g.id); g.version++; db.invites = db.invites.filter(i => i !== inv); } else newGroup(user);
    startSession(res, user);
    return send(res, 200, me(user));
  }

  /* ---- with login ---- */
  const [user, sess] = session(req, res);
  if (!user) return fail(res, 401, 'login_required');

  if (res1 === 'me' && M === 'GET') return send(res, 200, me(user));

  if (res1 === 'me' && M === 'PATCH') {
    const b = await readBody(req);
    if (LANGS.includes(b.lang)) { user.lang = b.lang; save(); }
    return send(res, 200, me(user));
  }

  if (res1 === 'me' && M === 'DELETE') {
    if (fails.over(req)) return fail(res, 429, 'too_many');
    const b = await readBody(req);
    if (!await checkPw(String(b.password ?? ''), user.pass)) { fails.add(req); return fail(res, 400, 'old_pw_wrong'); }
    // private lists go with the account; groups it was admin of go to the chosen member or get deleted
    const choice = b.groups && typeof b.groups === 'object' ? b.groups : {};
    if (groupsOf(user).some(g => badChoice(user, g, choice[g.id]))) return fail(res, 400, 'member_not_found');
    for (const g of groupsOf(user)) leaveGroup(user, g, choice[g.id]);
    db.users = db.users.filter(u => u !== user);
    db.sessions = db.sessions.filter(s => s.user !== user.id);
    db.invites = db.invites.filter(i => i.by !== user.id);
    save();
    setCookie(res, '', 0);
    return send(res, 200, {});
  }

  // everything stored about this account, as a JSON download
  if (res1 === 'export' && M === 'GET') {
    const list = l => ({ name: l.name, kind: l.kind, created: new Date(l.created).toISOString(),
      items: l.items.map(i => ({ name: i.name, priority: i.color, done: !!i.done, created: new Date(i.created).toISOString() })) });
    const data = {
      exported: new Date().toISOString(),
      account: { name: user.name, language: user.lang, created: new Date(user.created).toISOString() },
      privateLists: user.lists.map(list),
      groups: groupsOf(user).map(g => ({ name: g.name, admin: isAdmin(g, user), members: membersOf(g).map(u => u.name), lists: g.lists.map(list) })),
      invitesCreated: db.invites.filter(i => i.by === user.id && i.expires > now()).map(i => ({ group: db.groups.find(g => g.id === i.group)?.name, expires: new Date(i.expires).toISOString() })),
    };
    return send(res, 200, JSON.stringify(data, null, 2), 'application/json; charset=utf-8',
      { 'Content-Disposition': 'attachment; filename="shoplist-export.json"' });
  }

  if (res1 === 'logout' && M === 'POST') {
    db.sessions = db.sessions.filter(s => s !== sess);
    save();
    setCookie(res, '', 0);
    return send(res, 200, {});
  }

  if (res1 === 'password' && M === 'POST') {
    if (fails.over(req)) return fail(res, 429, 'too_many');
    const b = await readBody(req);
    if (!await checkPw(String(b.old ?? ''), user.pass)) { fails.add(req); return fail(res, 400, 'old_pw_wrong'); }
    const password = String(b.password ?? '');
    const bad = pwError(password, user.name);
    if (bad) return fail(res, 400, bad);
    user.pass = await hashPw(password);
    // signs out every other device
    db.sessions = db.sessions.filter(s => s.user !== user.id || s === sess);
    save();
    return send(res, 200, {});
  }

  // joining one more group with an existing account
  if (res1 === 'join' && M === 'POST') {
    const b = await readBody(req);
    const inv = findInvite(b.code);
    const g = inv && db.groups.find(x => x.id === inv.group);
    if (!g) { fails.add(req); return fail(res, 404, 'invite_invalid'); }
    if (!user.groups.includes(g.id)) user.groups.push(g.id);
    db.invites = db.invites.filter(i => i !== inv);
    save(g);
    return send(res, 200, { group: g.id, ...me(user) });
  }

  if (res1 === 'groups' && !id && M === 'POST') {
    const b = await readBody(req);
    if (!clean(b.name, 40)) return fail(res, 400, 'name_required');
    if (user.groups.length >= 20) return fail(res, 409, 'too_many_groups');
    const g = newGroup(user, b.name);
    save();
    return send(res, 200, { group: g.id, ...me(user) });
  }

  if (res1 === 'groups' && id) {
    const g = groupOf(user, id);
    if (!g) return fail(res, 404, 'group_not_found');
    if (!sub && M === 'PATCH') {
      const b = await readBody(req);
      const name = clean(b.name, 40);
      if (name) { g.name = name; save(g); }
      return send(res, 200, me(user));
    }
    if (sub === 'invites' && M === 'POST') {
      if (db.invites.filter(i => i.group === g.id && i.expires > now()).length >= 10) return fail(res, 409, 'too_many_invites');
      return send(res, 200, { code: createInvite(g.id, user.id), ...me(user) });
    }
    if (sub === 'invites' && subId && M === 'DELETE') {
      db.invites = db.invites.filter(i => !(i.id === subId && i.group === g.id));
      save();
      return send(res, 200, me(user));
    }
    // admins: make another member admin too, or take it back (never from the last one)
    if (sub === 'admins' && subId && (M === 'POST' || M === 'DELETE')) {
      if (!isAdmin(g, user)) return fail(res, 403, 'admin_only');
      const other = membersOf(g).find(u => u.id === subId);
      if (!other) return fail(res, 404, 'member_not_found');
      if (M === 'POST' && !isAdmin(g, other)) g.admins.push(other.id);
      if (M === 'DELETE') {
        if (g.admins.length === 1 && isAdmin(g, other)) return fail(res, 409, 'last_admin');
        g.admins = g.admins.filter(id => id !== other.id);
      }
      save(g);
      return send(res, 200, me(user));
    }
    if (sub === 'members' && subId && M === 'DELETE') {
      if (!isAdmin(g, user)) return fail(res, 403, 'admin_only');
      const other = db.users.find(u => u.id === subId && u.groups.includes(g.id));
      if (!other || other === user) return fail(res, 404, 'member_not_found');
      leaveGroup(other, g);
      save();
      return send(res, 200, me(user));
    }
    if (sub === 'leave' && M === 'POST') {
      const b = await readBody(req);
      if (badChoice(user, g, b.to)) return fail(res, 400, 'member_not_found');
      leaveGroup(user, g, b.to);
      save();
      return send(res, 200, me(user));
    }
    return fail(res, 404, 'not_found');
  }

  // the lists of one group (?g=, first one by default) plus the user's private lists
  if (res1 === 'state' && M === 'GET') {
    const q = new URL(req.url, 'http://x').searchParams;
    const g = groupOf(user, q.get('g')) || groupsOf(user)[0];
    const version = `${g ? g.id + ':' + g.version : '-'}:${user.version}`;
    if (q.get('since') === version) return send(res, 200, { version, unchanged: true });
    return send(res, 200, { version, group: g?.id || null, lists: [...(g?.lists || []), ...user.lists.map(l => ({ ...l, private: true }))] });
  }

  if (res1 === 'lists') {
    if (!id && M === 'POST') {
      const b = await readBody(req);
      const name = clean(b.name, 40);
      if (!name) return fail(res, 400, 'name_required');
      const into = b.private ? user : groupOf(user, b.group);
      if (!into) return fail(res, 404, 'group_not_found');
      if (into.lists.length >= 50) return fail(res, 409, 'too_many_lists');
      const list = { id: uid(), name, kind: KINDS.includes(b.kind) ? b.kind : 'list', by: user.id, created: now(), items: [] };
      into.lists.push(list);
      save(into);
      return send(res, 200, { id: list.id });
    }
    const [list, from] = locate(user, id);
    if (!list) return fail(res, 404, 'list_not_found');
    if (!sub && M === 'PATCH') {
      const b = await readBody(req);
      if (b.name !== undefined) { const n = clean(b.name, 40); if (n) list.name = n; }
      // private -> a group of the user; shared -> private only for lists you made yourself
      let to = from;
      if (b.private === true && from !== user) {
        if (list.by !== user.id) return fail(res, 403, 'not_yours');
        to = user;
      }
      if (b.private === false && from === user) {
        to = groupOf(user, b.group);
        if (!to) return fail(res, 404, 'group_not_found');
      }
      if (to !== from) {
        if (to.lists.length >= 50) return fail(res, 409, 'too_many_lists');
        from.lists = from.lists.filter(l => l !== list);
        to.lists.push(list);
      }
      save(from, ...(to !== from ? [to] : []));
      return send(res, 200, {});
    }
    if (!sub && M === 'DELETE') {
      from.lists = from.lists.filter(l => l !== list);
      save(from);
      return send(res, 200, {});
    }
    if (sub === 'items' && M === 'POST') {
      // body: {name, color} or {items: [{name, color}]}
      const b = await readBody(req);
      const added = addItems(list, Array.isArray(b.items) ? b.items : [b]);
      if (added) save(from);
      return send(res, 200, { added });
    }
    if (sub === 'transfer' && M === 'POST') {
      // staples list: copy everything yellow/red onto a shopping list, keeping the priority
      const b = await readBody(req);
      const [to, into] = locate(user, b.to);
      if (!to || to === list) return fail(res, 400, 'bad_target');
      const added = addItems(to, list.items.filter(i => i.color !== 'green'));
      if (added) save(into);
      return send(res, 200, { added });
    }
    if (sub === 'done' && M === 'DELETE') {
      list.items = list.items.filter(i => !i.done);
      save(from);
      return send(res, 200, {});
    }
    return fail(res, 405, 'bad_request');
  }

  if (res1 === 'items' && id) {
    const [list, item, from] = locateItem(user, id);
    if (!item) return fail(res, 404, 'item_not_found');
    if (M === 'PATCH') {
      const b = await readBody(req);
      // bought in a group list: restock that group's pantry and your own; private lists only your own
      if (typeof b.done === 'boolean') setDone(from === user ? user.lists : [...from.lists, ...user.lists], list, item, b.done);
      if (COLORS.includes(b.color)) item.color = b.color;
      if (b.name !== undefined) { const n = clean(b.name); if (n) item.name = n; }
      save(from, ...(from !== user && b.done ? [user] : []));
      return send(res, 200, {});
    }
    if (M === 'DELETE') {
      list.items = list.items.filter(i => i !== item);
      save(from);
      return send(res, 200, {});
    }
  }
  return fail(res, 404, 'not_found');
}

// pages without an own hero.png get no header picture at all
const page = data => BRANDING && fs.existsSync(path.join(BRANDING, 'hero.png')) ? data : data.toString().replace(/\s*<img src="hero.png"[^>]*>/, '');

// a public file, or its replacement from BRANDING_DIR
function asset(p) {
  const own = BRANDING && path.join(BRANDING, p);
  if (own && own.startsWith(path.resolve(BRANDING) + path.sep) && fs.existsSync(own) && fs.statSync(own).isFile()) return own;
  const file = path.join(PUB, p);
  return file.startsWith(PUB + path.sep) ? file : null;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/api/')) {
      return await api(req, res, url.pathname.slice(5).split('/').filter(Boolean));
    }
    // the app needs a session, the login page sends signed-in users on; browsers keep the #hash across redirects
    let p = path.normalize(decodeURIComponent(url.pathname));
    if (p === '/' || p === '/index.html') {
      if (!session(req, res)[0]) return redirect(res, '/login');
      p = '/index.html';
      return fs.readFile(asset(p), (err, data) => err ? send(res, 404, 'not found', 'text/plain')
        // marks the real app page, so the offline cache never keeps a login redirect or a bot check instead
        : send(res, 200, page(data), MIME['.html'], { 'X-Shoplist-App': '1' }));
    } else if (p === '/login' || p === '/login.html') {
      if (session(req, res)[0]) return redirect(res, '/');
      p = '/login.html';
    }
    const file = asset(p);
    if (!file) return send(res, 403, 'forbidden', 'text/plain');
    fs.readFile(file, (err, data) => {
      if (err) return send(res, 404, 'not found', 'text/plain');
      if (file.endsWith('.html')) data = page(data);
      send(res, 200, data, MIME[path.extname(file)] || 'application/octet-stream');
    });
  } catch (e) {
    if (!res.headersSent) fail(res, 400, 'bad_request');
  }
});

// forgotten password (there are no mails): with the app stopped, `node server.js reset-password <name>`
// prints a new password and signs that account out everywhere
if (process.argv[2] === 'reset-password') {
  const user = byName(process.argv[3]);
  if (!user) { console.error(`no account named "${process.argv[3] ?? ''}"`); process.exit(1); }
  const password = crypto.randomBytes(12).toString('base64url');
  hashPw(password).then(pass => {
    user.pass = pass;
    db.sessions = db.sessions.filter(x => x.user !== user.id);
    save();
    console.log(`new password for ${user.name}: ${password}`);
  });
} else server.listen(PORT, HOST, () => {
  console.log(`shopping list on ${HOST}:${PORT}` + (KEY ? ', db encrypted' : ', db NOT encrypted (no key)') +
    `, registration ${REGISTRATION}`);
});
