// HMAC-SHA256 request signing (replay-protected).
//
// Client sends:
//   X-WebScan-Key:        <key id>          (8 hex chars, from `webscan keys create`)
//   X-WebScan-Timestamp:  <unix seconds>    must be within ±300 s of server time
//   X-WebScan-Nonce:      <random 16–64 chars, unique per request>
//   X-WebScan-Signature:  hex( HMAC-SHA256( signingSecret, stringToSign ) )
//
// stringToSign = METHOD \n PATH?QUERY \n TIMESTAMP \n NONCE \n hex(SHA256(body))
import crypto from 'node:crypto';

export const MAX_SKEW_S = Number(process.env.HMAC_MAX_SKEW || 300);

export function stringToSign(method, pathWithQuery, timestamp, nonce, body = '') {
  const bodyHash = crypto.createHash('sha256').update(body || '').digest('hex');
  return [method.toUpperCase(), pathWithQuery, String(timestamp), nonce, bodyHash].join('\n');
}

export function sign(secret, method, pathWithQuery, body = '', { timestamp = Math.floor(Date.now() / 1000), nonce = crypto.randomBytes(16).toString('hex') } = {}) {
  const signature = crypto.createHmac('sha256', secret).update(stringToSign(method, pathWithQuery, timestamp, nonce, body)).digest('hex');
  return { timestamp, nonce, signature };
}

const nonces = new Map(); // "kid:nonce" -> expiry ms
function rememberNonce(id) {
  const now = Date.now();
  if (nonces.has(id)) return false;
  nonces.set(id, now + (MAX_SKEW_S * 2 + 5) * 1000);
  if (nonces.size > 50000 || Math.random() < 0.01) for (const [n, exp] of nonces) if (exp < now) nonces.delete(n);
  return true;
}

export function hasHmacHeaders(headers) {
  return !!(headers['x-webscan-key'] || headers['x-webscan-signature']);
}

// Returns { ok: true, kid } or { ok: false, reason }
export function verifyRequest({ method, pathWithQuery, headers, body, secretFor }) {
  const kid = String(headers['x-webscan-key'] || '');
  const ts = String(headers['x-webscan-timestamp'] || '');
  const nonce = String(headers['x-webscan-nonce'] || '');
  const sig = String(headers['x-webscan-signature'] || '');
  if (!/^[0-9a-f]{8}$/.test(kid)) return { ok: false, reason: 'bad or missing X-WebScan-Key' };
  if (!/^\d{9,11}$/.test(ts)) return { ok: false, reason: 'bad or missing X-WebScan-Timestamp (unix seconds)' };
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) return { ok: false, reason: 'bad or missing X-WebScan-Nonce (16–64 url-safe chars)' };
  if (!/^[0-9a-f]{64}$/.test(sig)) return { ok: false, reason: 'bad or missing X-WebScan-Signature (64 hex chars)' };
  const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
  if (skew > MAX_SKEW_S) return { ok: false, reason: `timestamp outside ±${MAX_SKEW_S}s window (skew ${skew}s) — check the client clock` };
  const secret = secretFor(kid);
  if (!secret) return { ok: false, reason: 'unknown or revoked key' };
  const expect = crypto.createHmac('sha256', secret).update(stringToSign(method, pathWithQuery, ts, nonce, body)).digest();
  if (!crypto.timingSafeEqual(expect, Buffer.from(sig, 'hex'))) return { ok: false, reason: 'signature mismatch' };
  if (!rememberNonce(`${kid}:${nonce}`)) return { ok: false, reason: 'replayed request (nonce already used)' };
  return { ok: true, kid };
}
