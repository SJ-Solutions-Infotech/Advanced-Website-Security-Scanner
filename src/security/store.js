// Data directory (keys, secrets, signing keys, audit log) — shared by the CLI and the server.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const DATA_DIR = path.resolve(process.env.WEBSCAN_DATA_DIR || path.join(ROOT, 'data'));

export function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(DATA_DIR, 0o700); } catch {}
  return DATA_DIR;
}

export const dataPath = (name) => path.join(ensureDataDir(), name);

// Atomic write: temp file + rename, owner-only permissions
export function writeSecure(file, content) {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

// 32-byte master secret: derives HMAC signing secrets, signs session tokens and SSE tickets.
let master;
export function masterKey() {
  if (master) return master;
  if (process.env.WEBSCAN_MASTER_KEY) {
    master = Buffer.from(process.env.WEBSCAN_MASTER_KEY, process.env.WEBSCAN_MASTER_KEY.length === 64 ? 'hex' : 'base64');
    if (master.length < 32) throw new Error('WEBSCAN_MASTER_KEY must be at least 32 bytes (64 hex chars)');
    return master;
  }
  const f = dataPath('master.key');
  if (!fs.existsSync(f)) writeSecure(f, crypto.randomBytes(32).toString('hex') + '\n');
  master = Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
  return master;
}

// Append-only JSONL audit log
export function audit(event, data = {}) {
  try {
    fs.appendFileSync(dataPath('audit.log'), JSON.stringify({ t: new Date().toISOString(), event, ...data }) + '\n', { mode: 0o600 });
  } catch {}
}
