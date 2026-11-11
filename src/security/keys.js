// API keys — stored only as scrypt hashes. Each key has scopes and a derived HMAC signing secret.
//
//   API key        sjwk_<kid>_<secret>   shown once; server keeps scrypt(secret, salt)
//   Signing secret sjss_<base64url>      HMAC-SHA256(master, "signing:"+kid) — recomputed, never stored
//   Session token  sjsess.<payload>.<sig> short-lived (browser UI), signed with the master key
//   SSE ticket     sjtkt.<payload>.<sig>  60 s, single-use, bound to one scan id
import fs from 'node:fs';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { dataPath, writeSecure, readJson, masterKey, audit } from './store.js';

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export const SCOPES = ['read', 'scan', 'active', 'admin'];
const KEY_RE = /^sjwk_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$/;
const b64u = (buf) => Buffer.from(buf).toString('base64url');

const file = () => dataPath('keys.json');
let cache = { mtimeMs: -1, keys: [] };

function load() {
  let st;
  try { st = fs.statSync(file()); } catch { cache = { mtimeMs: 0, keys: [] }; return cache.keys; }
  if (st.mtimeMs !== cache.mtimeMs) cache = { mtimeMs: st.mtimeMs, keys: readJson(file(), { keys: [] }).keys || [] };
  return cache.keys;
}
function save(keys) {
  writeSecure(file(), JSON.stringify({ version: 1, keys }, null, 2));
  cache = { mtimeMs: fs.statSync(file()).mtimeMs, keys };
}

export const listKeys = () => load().map(({ hash, salt, ...k }) => k);
export const activeKeyCount = () => load().filter(k => !k.revoked).length;
export const findKey = (kid) => load().find(k => k.id === kid && !k.revoked) || null;

export function signingSecretFor(kid) {
  return 'sjss_' + b64u(crypto.createHmac('sha256', masterKey()).update('signing:' + kid).digest());
}

export async function createKey(name, scopes = ['read', 'scan']) {
  if (!name || !/^[\w .@-]{1,64}$/.test(name)) throw new Error('Key name must be 1–64 chars: letters, numbers, space . @ - _');
  const bad = scopes.filter(s => !SCOPES.includes(s));
  if (bad.length) throw new Error(`Unknown scope(s): ${bad.join(', ')}. Valid: ${SCOPES.join(', ')}`);
  const keys = load();
  let id;
  do { id = crypto.randomBytes(4).toString('hex'); } while (keys.some(k => k.id === id));
  const secret = b64u(crypto.randomBytes(32));
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(secret, salt, 32, SCRYPT);
  const rec = {
    id, name, scopes: [...new Set(scopes)], prefix: `sjwk_${id}_${secret.slice(0, 4)}…`,
    hash: hash.toString('base64'), salt: salt.toString('base64'), algo: 'scrypt-N16384-r8-p1',
    createdAt: new Date().toISOString(), lastUsedAt: null, revoked: false,
  };
  save([...keys, rec]);
  audit('key.create', { kid: id, name, scopes: rec.scopes });
  return { id, name, scopes: rec.scopes, apiKey: `sjwk_${id}_${secret}`, signingSecret: signingSecretFor(id) };
}

export function revokeKey(kid) {
  const keys = load();
  const k = keys.find(x => x.id === kid);
  if (!k) throw new Error(`No key with id ${kid}`);
  if (k.revoked) return false;
  k.revoked = true; k.revokedAt = new Date().toISOString();
  save(keys);
  audit('key.revoke', { kid });
  return true;
}

// Verified-key cache so scrypt (~50 ms) runs once per key per 5 minutes, not on every request
const verified = new Map(); // sha256(apiKey) -> { kid, exp }
export async function verifyApiKey(apiKey) {
  const m = KEY_RE.exec(apiKey || '');
  if (!m) return null;
  const fp = crypto.createHash('sha256').update(apiKey).digest('hex');
  const hit = verified.get(fp);
  if (hit && hit.exp > Date.now()) { const k = findKey(hit.kid); if (k) return k; }
  const k = findKey(m[1]);
  if (!k) return null;
  const h = await scrypt(m[2], Buffer.from(k.salt, 'base64'), 32, SCRYPT);
  if (!crypto.timingSafeEqual(h, Buffer.from(k.hash, 'base64'))) return null;
  verified.set(fp, { kid: k.id, exp: Date.now() + 5 * 60 * 1000 });
  if (verified.size > 1000) verified.delete(verified.keys().next().value);
  return k;
}

// lastUsedAt is buffered and merged into the file (re-read first so CLI changes are never clobbered)
const pendingUse = new Map();
let flushTimer;
export function touchKey(kid) {
  pendingUse.set(kid, new Date().toISOString());
  if (!flushTimer) flushTimer = setTimeout(flushUsage, 15000).unref?.() ?? null;
}
export function flushUsage() {
  flushTimer = null;
  if (!pendingUse.size) return;
  cache.mtimeMs = -1;
  const keys = load();
  for (const k of keys) if (pendingUse.has(k.id)) k.lastUsedAt = pendingUse.get(k.id);
  pendingUse.clear();
  try { save(keys); } catch {}
}

// ---- Signed tokens (sessions + SSE tickets) ----
function signToken(prefix, payload) {
  const body = b64u(JSON.stringify(payload));
  const sig = b64u(crypto.createHmac('sha256', masterKey()).update(`${prefix}.${body}`).digest());
  return `${prefix}.${body}.${sig}`;
}
function readToken(prefix, token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3 || parts[0] !== prefix) return null;
  const expect = crypto.createHmac('sha256', masterKey()).update(`${prefix}.${parts[1]}`).digest();
  const got = Buffer.from(parts[2], 'base64url');
  if (got.length !== expect.length || !crypto.timingSafeEqual(got, expect)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); } catch { return null; }
  if (!p.exp || p.exp < Date.now()) return null;
  return p;
}

export const SESSION_TTL_MS = Number(process.env.SESSION_TTL_HOURS || 8) * 3600 * 1000;
export function createSession(kid) {
  return { token: signToken('sjsess', { kid, iat: Date.now(), exp: Date.now() + SESSION_TTL_MS, n: b64u(crypto.randomBytes(9)) }), expiresIn: SESSION_TTL_MS / 1000 };
}
export function verifySession(token) {
  const p = readToken('sjsess', token);
  if (!p) return null;
  const k = findKey(p.kid);
  return k ? { key: k, exp: p.exp } : null; // revoking the key kills its sessions instantly
}

const usedTickets = new Map();
export function createTicket(kid, scanId, ttlMs = 60000) {
  return signToken('sjtkt', { kid, sid: scanId, exp: Date.now() + ttlMs, n: b64u(crypto.randomBytes(12)) });
}
export function consumeTicket(token, scanId) {
  const p = readToken('sjtkt', token);
  if (!p || p.sid !== scanId || usedTickets.has(p.n)) return null;
  usedTickets.set(p.n, p.exp);
  for (const [n, exp] of usedTickets) if (exp < Date.now()) usedTickets.delete(n);
  return p.kid === 'local' ? { id: 'local' } : findKey(p.kid);
}
