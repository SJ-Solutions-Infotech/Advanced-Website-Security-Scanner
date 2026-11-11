// Report integrity: SHA-256 of the canonical JSON + Ed25519 signature.
// Anyone with the public key can verify a report was produced by this scanner and not edited.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { dataPath, writeSecure } from './store.js';

// Deterministic JSON: object keys sorted recursively, undefined dropped (same as JSON.stringify)
export function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return '[' + v.map(x => (x === undefined || typeof x === 'function' ? 'null' : canonicalize(x))).join(',') + ']';
  return '{' + Object.keys(v).filter(k => v[k] !== undefined && typeof v[k] !== 'function').sort()
    .map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}

let keys;
export function signingKeys() {
  if (keys) return keys;
  const privFile = dataPath('report-signing.key');
  const pubFile = dataPath('report-signing.pub');
  if (!fs.existsSync(privFile)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    writeSecure(privFile, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    fs.writeFileSync(pubFile, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(privFile));
  const publicKey = crypto.createPublicKey(privateKey);
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  if (!fs.existsSync(pubFile)) fs.writeFileSync(pubFile, publicPem, { mode: 0o644 });
  keys = { privateKey, publicKey, publicPem, fingerprint: fingerprint(publicKey) };
  return keys;
}

export function fingerprint(publicKey) {
  const der = (typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : publicKey).export({ type: 'spki', format: 'der' });
  return 'SHA256:' + crypto.createHash('sha256').update(der).digest('base64').replace(/=+$/, '');
}

export function signReport(report) {
  const { integrity, ...body } = JSON.parse(JSON.stringify(report)); // normalise exactly as it will be saved
  const canon = canonicalize(body);
  const k = signingKeys();
  const hash = crypto.createHash('sha256').update(canon).digest('hex');
  const signature = crypto.sign(null, Buffer.from(canon), k.privateKey).toString('base64');
  report.integrity = {
    algorithm: 'SHA-256', canonicalization: 'sorted-keys-json', hash,
    signatureAlgorithm: 'Ed25519', signature, publicKeyFingerprint: k.fingerprint, signedAt: new Date().toISOString(),
  };
  return report;
}

// Returns { valid, signed, hashMatches, signatureValid, fingerprint, keyMatchesServer, reason }
export function verifyReport(report, publicKeyPem) {
  if (!report || typeof report !== 'object') return { valid: false, signed: false, reason: 'Not a JSON report' };
  const integ = report.integrity;
  if (!integ?.hash || !integ?.signature) return { valid: false, signed: false, reason: 'Report has no integrity block (unsigned)' };
  const { integrity, ...body } = report;
  const canon = canonicalize(body);
  const hash = crypto.createHash('sha256').update(canon).digest('hex');
  const hashMatches = hash === integ.hash;
  let signatureValid = false, fp, keyMatchesServer = null, reason;
  try {
    const pub = publicKeyPem ? crypto.createPublicKey(publicKeyPem) : signingKeys().publicKey;
    fp = fingerprint(pub);
    signatureValid = crypto.verify(null, Buffer.from(canon), pub, Buffer.from(integ.signature, 'base64'));
    if (!publicKeyPem) keyMatchesServer = fp === integ.publicKeyFingerprint;
  } catch (e) { reason = 'Signature check failed: ' + e.message; }
  if (!reason) {
    if (!hashMatches) reason = 'Content hash mismatch — the report was modified after signing';
    else if (!signatureValid) reason = fp !== integ.publicKeyFingerprint
      ? `Signed by a different key (${integ.publicKeyFingerprint}) than the one used to verify (${fp})`
      : 'Invalid signature';
  }
  return { valid: hashMatches && signatureValid, signed: true, hashMatches, signatureValid, hash, expectedHash: integ.hash,
    fingerprint: fp, signedBy: integ.publicKeyFingerprint, signedAt: integ.signedAt, keyMatchesServer, reason: reason || 'Report is authentic and unmodified' };
}
