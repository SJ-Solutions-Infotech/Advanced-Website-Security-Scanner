#!/usr/bin/env node
// Standalone verifier for signed SJ WebScan reports — give this file + the public key to a client.
// Needs only Node 18+. No install, no network.
//
//   node verify-report.mjs report.json webscan-report-signing.pub
//
// Exit code 0 = authentic and unmodified, 3 = invalid.
import fs from 'node:fs';
import crypto from 'node:crypto';

const [file, pubFile] = process.argv.slice(2);
if (!file || !pubFile) { console.log('Usage: node verify-report.mjs <report.json> <public-key.pem>'); process.exit(1); }

function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return '[' + v.map(x => (x === undefined ? 'null' : canonicalize(x))).join(',') + ']';
  return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}

const report = JSON.parse(fs.readFileSync(file, 'utf8'));
const { integrity, ...body } = report;
if (!integrity?.signature) { console.log('✖ Report is not signed'); process.exit(3); }
const pub = crypto.createPublicKey(fs.readFileSync(pubFile, 'utf8'));
const fp = 'SHA256:' + crypto.createHash('sha256').update(pub.export({ type: 'spki', format: 'der' })).digest('base64').replace(/=+$/, '');
const canon = canonicalize(body);
const hash = crypto.createHash('sha256').update(canon).digest('hex');
const hashOk = hash === integrity.hash;
const sigOk = crypto.verify(null, Buffer.from(canon), pub, Buffer.from(integrity.signature, 'base64'));

console.log(hashOk && sigOk ? '✔ VALID — report is authentic and has not been modified' : '✖ INVALID');
console.log(`  site:       ${report.target?.finalUrl}`);
console.log(`  scanned:    ${report.scannedAt}   score ${report.score?.overall}/100 (${report.score?.grade})`);
console.log(`  hash:       ${hashOk ? 'matches' : 'MISMATCH — content was changed after signing'}  ${hash}`);
console.log(`  signature:  ${sigOk ? 'valid' : 'INVALID'}  (signed by ${integrity.publicKeyFingerprint}, verified with ${fp})`);
process.exit(hashOk && sigOk ? 0 : 3);
