#!/usr/bin/env node
// Minimal HMAC-signed API client for SJ WebScan (zero dependencies, standalone — copy it anywhere).
//
//   export WEBSCAN_URL=https://scan.example.com
//   export WEBSCAN_KEY_ID=ab12cd34
//   export WEBSCAN_SIGNING_SECRET=sjss_...
//
//   node signed-client.mjs GET  /api/whoami
//   node signed-client.mjs POST /api/scan '{"url":"https://example.com","tools":["whois"]}'
//   node signed-client.mjs scan https://example.com            # start + wait + print score
//
// Import it too:  import { signedFetch } from './signed-client.mjs'
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

export function signRequest(secret, method, pathWithQuery, body = '') {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const toSign = [method.toUpperCase(), pathWithQuery, timestamp, nonce, bodyHash].join('\n');
  const signature = crypto.createHmac('sha256', secret).update(toSign).digest('hex');
  return { 'X-WebScan-Timestamp': String(timestamp), 'X-WebScan-Nonce': nonce, 'X-WebScan-Signature': signature };
}

export async function signedFetch(method, pathWithQuery, bodyObj, {
  baseUrl = process.env.WEBSCAN_URL || 'http://127.0.0.1:8080',
  keyId = process.env.WEBSCAN_KEY_ID,
  secret = process.env.WEBSCAN_SIGNING_SECRET,
} = {}) {
  if (!keyId || !secret) throw new Error('Set WEBSCAN_KEY_ID and WEBSCAN_SIGNING_SECRET');
  const body = bodyObj === undefined ? '' : typeof bodyObj === 'string' ? bodyObj : JSON.stringify(bodyObj);
  const res = await fetch(baseUrl.replace(/\/$/, '') + pathWithQuery, {
    method, body: body || undefined,
    headers: { 'Content-Type': 'application/json', 'X-WebScan-Key': keyId, ...signRequest(secret, method, pathWithQuery, body) },
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, headers: Object.fromEntries(res.headers), data };
}

async function cli() {
  const [method, p, body] = process.argv.slice(2);
  if (!method) { console.log('Usage: signed-client.mjs <METHOD> <path> [jsonBody]  |  signed-client.mjs scan <url>'); process.exit(1); }
  if (method === 'scan') {
    const start = await signedFetch('POST', '/api/scan', { url: p });
    if (start.status !== 202) { console.error(start.status, start.data); process.exit(1); }
    const id = start.data.id;
    process.stderr.write(`scan ${id} started`);
    for (;;) {
      await new Promise(r => setTimeout(r, 3000));
      const s = await signedFetch('GET', `/api/scan/${id}`);
      if (s.data.status === 'running') { process.stderr.write('.'); continue; }
      process.stderr.write('\n');
      if (s.data.status === 'error') { console.error('Scan failed:', s.data.error); process.exit(1); }
      const r = s.data.report;
      console.log(JSON.stringify({ url: r.target.finalUrl, score: r.score, summary: r.summary, file: s.data.file, hash: r.integrity?.hash }, null, 2));
      return;
    }
  }
  const r = await signedFetch(method.toUpperCase(), p, body);
  console.log(r.status, typeof r.data === 'string' ? r.data : JSON.stringify(r.data, null, 2));
  if (r.status >= 400) process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) cli().catch(e => { console.error(e.message); process.exit(1); });
