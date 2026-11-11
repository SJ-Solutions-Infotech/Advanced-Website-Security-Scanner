// SJ WebScan web UI + API — zero-dependency HTTP server with Server-Sent Events for live progress.
//
// Security (v1.1):
//   • API keys stored as scrypt hashes, with scopes: read | scan | active | admin   (webscan keys create …)
//   • Auth: Bearer API key · HMAC-SHA256 signed requests (replay-protected) · browser sessions · 60 s SSE tickets
//   • Per-IP API rate limit, per-key scan quota, concurrent-scan caps, lockout after repeated auth failures
//   • Signed reports (Ed25519) + POST /api/verify · JSONL audit log · CSP with script hash
//
// Environment:
//   HOST=127.0.0.1 PORT=8080
//   TRUST_PROXY=1                 use X-Forwarded-For (only behind your own nginx / load balancer)
//   REQUIRE_HMAC=1                reject raw Bearer API keys on API calls (HMAC or browser session only)
//   ALLOW_NO_AUTH=1               allow running with no keys on a non-loopback HOST (not recommended)
//   RL_API_PER_MIN=120            API requests per IP per minute
//   RL_SCANS_PER_HOUR=10          new scans per key (or per IP when auth is off) per hour
//   RL_LOGIN_PER_15MIN=10         session logins per IP per 15 min
//   LOCKOUT_FAILURES=5            failed auths per IP in 15 min before lockout
//   LOCKOUT_MINUTES=15
//   MAX_SCANS=2                   concurrent scans (server-wide)
//   MAX_SCANS_PER_CLIENT=1        concurrent scans per key
//   WEBSCAN_RPS=10                built-in checks: requests/sec per scanned host
//   WEBSCAN_TOOL_RPS=50           external tools: requests/sec cap
//   SESSION_TTL_HOURS=8
//   ALLOW_PRIVATE=1  ALLOW_ACTIVE=0  WEBSCAN_DATA_DIR=./data
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scan, MODULES, VERSION } from './src/scanner.js';
import { toolInventory, DEFAULT_TOOL_RPS } from './src/tools/runner.js';
import { DEFAULT_RPS } from './src/http.js';
import { RateLimiter, Lockout } from './src/security/ratelimit.js';
import { verifyRequest, hasHmacHeaders } from './src/security/hmac.js';
import { verifyReport, signingKeys } from './src/security/integrity.js';
import { audit, DATA_DIR } from './src/security/store.js';
import {
  SCOPES, activeKeyCount, findKey, verifyApiKey, signingSecretFor, touchKey, flushUsage,
  createSession, verifySession, createTicket, consumeTicket,
} from './src/security/keys.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? Number(process.env[k]) : d);
const HOST = process.env.HOST || '127.0.0.1';
const PORT = env('PORT', 8080);
const LOOPBACK = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const REQUIRE_HMAC = process.env.REQUIRE_HMAC === '1';
const ALLOW_ACTIVE = process.env.ALLOW_ACTIVE !== '0';
const MAX_SCANS = env('MAX_SCANS', 2);
const MAX_SCANS_PER_CLIENT = env('MAX_SCANS_PER_CLIENT', 1);
const REPORT_DIR = path.join(__dirname, 'reports');
fs.mkdirSync(REPORT_DIR, { recursive: true });

const LIMITS = {
  apiPerMin: env('RL_API_PER_MIN', 120),
  scansPerHour: env('RL_SCANS_PER_HOUR', 10),
  loginsPer15Min: env('RL_LOGIN_PER_15MIN', 10),
  lockoutFailures: env('LOCKOUT_FAILURES', 5),
  lockoutMinutes: env('LOCKOUT_MINUTES', 15),
  maxScans: MAX_SCANS, maxScansPerClient: MAX_SCANS_PER_CLIENT,
};
const apiLimiter = new RateLimiter({ windowMs: 60_000, max: LIMITS.apiPerMin, name: 'api' });
const scanLimiter = new RateLimiter({ windowMs: 3_600_000, max: LIMITS.scansPerHour, name: 'scans' });
const loginLimiter = new RateLimiter({ windowMs: 900_000, max: LIMITS.loginsPer15Min, name: 'login' });
const lockout = new Lockout({ maxFailures: LIMITS.lockoutFailures, windowMs: 900_000, lockMs: LIMITS.lockoutMinutes * 60_000 });

const authRequired = () => activeKeyCount() > 0;
const jobs = new Map(); // id -> { id, owner, status, events[], clients:Set, report, error, startedAt, url }

class HttpError extends Error {
  constructor(status, message, headers = {}) { super(message); this.status = status; this.headers = headers; }
}

// ---------- helpers ----------
const BASE_HEADERS = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};
function send(res, code, body, type = 'application/json', extra = {}) {
  if (res.headersSent) return res.end();
  res.writeHead(code, { 'Content-Type': type, ...BASE_HEADERS, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xff) return xff.replace(/^::ffff:/, '');
  }
  return String(req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, `Body too large (max ${Math.round(limit / 1024)} KB)`)); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function parseJson(raw) {
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { throw new HttpError(400, 'Invalid JSON body'); }
}

function rlHeaders(r, prefix = 'X-RateLimit') {
  return { [`${prefix}-Limit`]: String(r.limit), [`${prefix}-Remaining`]: String(r.remaining), [`${prefix}-Reset`]: String(r.reset) };
}

// The UI page is served with a CSP that only allows its own inline script, pinned by SHA-256 hash
function uiPage() {
  const html = fs.readFileSync(path.join(__dirname, 'public/index.html'), 'utf8');
  const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map(m => `'sha256-${crypto.createHash('sha256').update(m[1]).digest('base64')}'`).join(' ');
  const csp = `default-src 'none'; script-src ${hashes}; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`;
  return { html, csp };
}

// ---------- authentication ----------
async function authenticate(req, url, rawBody) {
  if (!authRequired()) return { id: 'local', name: 'local (no keys configured)', scopes: [...SCOPES], method: 'open' };
  let key, method;
  const authz = String(req.headers.authorization || '');
  if (hasHmacHeaders(req.headers)) {
    const v = verifyRequest({
      method: req.method, pathWithQuery: url.pathname + url.search, headers: req.headers, body: rawBody,
      secretFor: (kid) => (findKey(kid) ? signingSecretFor(kid) : null),
    });
    if (!v.ok) throw new HttpError(401, `HMAC authentication failed: ${v.reason}`);
    key = findKey(v.kid); method = 'hmac';
  } else if (authz.startsWith('Session ')) {
    const s = verifySession(authz.slice(8).trim());
    if (!s) throw new HttpError(401, 'Session expired or invalid — sign in again');
    key = s.key; method = 'session';
  } else if (authz.startsWith('Bearer ')) {
    if (REQUIRE_HMAC) throw Object.assign(new HttpError(401, 'Bearer API keys are disabled on this server (REQUIRE_HMAC=1) — sign requests with HMAC'), { noLockout: true });
    key = await verifyApiKey(authz.slice(7).trim());
    if (!key) throw new HttpError(401, 'Invalid or revoked API key');
    method = 'bearer';
  } else {
    throw new HttpError(401, 'Authentication required: Bearer API key, HMAC signature, or session');
  }
  if (!key) throw new HttpError(401, 'Unknown or revoked key');
  touchKey(key.id);
  return { id: key.id, name: key.name, scopes: key.scopes, method };
}

function requireScope(who, scope) {
  if (!who.scopes.includes(scope) && !who.scopes.includes('admin')) {
    throw new HttpError(403, `This key lacks the "${scope}" scope (has: ${who.scopes.join(', ') || 'none'})`);
  }
}
const canSeeJob = (who, job) => job.owner === who.id || who.scopes.includes('admin') || who.id === 'local';

// ---------- scans ----------
function emit(job, type, data) {
  const ev = { type, data, t: Date.now() };
  job.events.push(ev);
  if (job.events.length > 5000) job.events.splice(0, 1000);
  const line = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of job.clients) c.write(line);
}

function startScan(body, who, ip) {
  if (!body.url || typeof body.url !== 'string') throw new HttpError(400, 'url is required');
  if (body.authorized === true) {
    if (!ALLOW_ACTIVE) throw new HttpError(403, 'Active scanning is disabled on this server (ALLOW_ACTIVE=0)');
    requireScope(who, 'active');
  }
  const running = [...jobs.values()].filter(j => j.status === 'running');
  if (running.length >= MAX_SCANS) throw new HttpError(429, `Server busy: ${running.length}/${MAX_SCANS} scans running. Try again shortly.`, { 'Retry-After': '30' });
  const mine = running.filter(j => j.owner === who.id).length;
  if (mine >= MAX_SCANS_PER_CLIENT) throw new HttpError(429, `You already have ${mine} scan(s) running (limit ${MAX_SCANS_PER_CLIENT}). Wait for it to finish.`, { 'Retry-After': '30' });

  const quotaKey = who.id === 'local' ? `ip:${ip}` : `key:${who.id}`;
  const q = scanLimiter.hit(quotaKey);
  if (!q.allowed) {
    audit('ratelimit.scans', { kid: who.id, ip });
    throw new HttpError(429, `Scan quota exceeded (${LIMITS.scansPerHour}/hour). Try again in ${Math.ceil(q.retryAfter / 60)} min.`, { 'Retry-After': String(q.retryAfter), ...rlHeaders(q, 'X-Scan-Quota') });
  }

  const id = crypto.randomUUID();
  const job = { id, owner: who.id, status: 'running', events: [], clients: new Set(), startedAt: new Date().toISOString(), url: body.url };
  jobs.set(id, job);
  const opts = {
    modules: Array.isArray(body.modules) ? body.modules.filter(m => MODULES.includes(m)) : undefined,
    tools: Array.isArray(body.tools) ? body.tools.map(String).slice(0, 50) : [],
    authorized: ALLOW_ACTIVE && body.authorized === true,
    links: body.links !== false,
    maxLinks: Math.min(Math.max(Number(body.maxLinks) || 60, 0), 300),
    allowPrivate: process.env.ALLOW_PRIVATE === '1',
    verbose: body.verbose === true,
    rps: DEFAULT_RPS,          // server-wide value; clients cannot raise it
    toolRps: DEFAULT_TOOL_RPS,
    requestedBy: who.id === 'local' ? undefined : `${who.name} (${who.id})`,
  };
  audit('scan.start', { scan: id, kid: who.id, ip, url: body.url, tools: opts.tools, authorized: opts.authorized, method: who.method });
  scan(body.url, opts, {
    log: (m) => emit(job, 'log', m),
    stage: (s) => emit(job, 'stage', s),
    tool: (r) => emit(job, 'tool', { id: r.id, name: r.name, status: r.status, summary: r.summary || r.reason || r.error || '' }),
  }).then((report) => {
    job.report = report; job.status = 'done';
    const file = `${report.target.host}-${report.scannedAt.replace(/[:.]/g, '-')}.json`;
    fs.writeFileSync(path.join(REPORT_DIR, file), JSON.stringify(report, null, 2));
    job.file = file;
    audit('scan.done', { scan: id, kid: who.id, file, score: report.score.overall, hash: report.integrity?.hash });
    emit(job, 'done', { file });
  }).catch((e) => {
    job.status = 'error'; job.error = e.message;
    audit('scan.error', { scan: id, kid: who.id, error: e.message });
    emit(job, 'failed', e.message);
  }).finally(() => {
    for (const c of job.clients) c.end();
    job.clients.clear();
    setTimeout(() => jobs.delete(id), 60 * 60 * 1000).unref();
  });
  return { job, quota: q };
}

function streamEvents(req, res, job) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff' });
  for (const ev of job.events) res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev.data)}\n\n`);
  if (job.status !== 'running') return res.end();
  job.clients.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(ping); job.clients.delete(res); });
}

const reportFile = (name) => path.join(REPORT_DIR, path.basename(name));

// ---------- router ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;
  const ip = clientIp(req);
  try {
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      const { html, csp } = uiPage();
      return send(res, 200, html, 'text/html; charset=utf-8', { 'Content-Security-Policy': csp });
    }
    if (!p.startsWith('/api/')) throw new HttpError(404, 'Not found');

    // Public, cheap endpoints (still rate limited)
    const rl = apiLimiter.hit(`ip:${ip}`);
    Object.entries(rlHeaders(rl)).forEach(([k, v]) => res.setHeader(k, v));
    if (!rl.allowed) {
      audit('ratelimit.api', { ip, path: p });
      throw new HttpError(429, `Rate limit exceeded: ${LIMITS.apiPerMin} requests/min. Retry in ${rl.retryAfter}s.`, { 'Retry-After': String(rl.retryAfter) });
    }
    if (req.method === 'GET' && p === '/api/meta') {
      return send(res, 200, {
        version: VERSION, modules: MODULES, allowActive: ALLOW_ACTIVE, authRequired: authRequired(), requireHmac: REQUIRE_HMAC,
        limits: LIMITS, rps: DEFAULT_RPS, toolRps: DEFAULT_TOOL_RPS, reportKeyFingerprint: signingKeys().fingerprint,
      });
    }
    if (req.method === 'GET' && p === '/api/public-key') {
      const k = signingKeys();
      if (url.searchParams.has('pem')) return send(res, 200, k.publicPem, 'application/x-pem-file', { 'Content-Disposition': 'attachment; filename="webscan-report-signing.pub"' });
      return send(res, 200, { algorithm: 'Ed25519', fingerprint: k.fingerprint, pem: k.publicPem });
    }

    // Everything below can fail authentication → enforce lockout first
    const locked = lockout.lockedFor(`ip:${ip}`);
    if (locked) throw new HttpError(429, `Too many failed authentication attempts. Locked for ${Math.ceil(locked / 60)} more min.`, { 'Retry-After': String(locked) });

    if (req.method === 'POST' && p === '/api/session') {
      const lr = loginLimiter.hit(`ip:${ip}`);
      if (!lr.allowed) throw new HttpError(429, `Too many sign-in attempts. Retry in ${Math.ceil(lr.retryAfter / 60)} min.`, { 'Retry-After': String(lr.retryAfter) });
      const body = parseJson(await readBody(req, 4096));
      if (!authRequired()) return send(res, 200, { token: null, open: true, name: 'local', scopes: SCOPES });
      const key = await verifyApiKey(String(body.apiKey || '').trim());
      if (!key) return authFailure(res, ip, p, 'invalid API key at sign-in');
      lockout.success(`ip:${ip}`);
      touchKey(key.id);
      audit('session.create', { kid: key.id, ip });
      const s = createSession(key.id);
      return send(res, 200, { ...s, name: key.name, id: key.id, scopes: key.scopes });
    }

    // SSE stream: accepts a one-time ticket (?ticket=) because EventSource cannot send headers
    let m = p.match(/^\/api\/scan\/([0-9a-f-]{36})\/events$/);
    if (m && req.method === 'GET' && url.searchParams.has('ticket')) {
      const job = jobs.get(m[1]);
      if (!job) throw new HttpError(404, 'Unknown scan id');
      const k = consumeTicket(url.searchParams.get('ticket'), job.id);
      if (!k) throw new HttpError(401, 'Ticket invalid, expired or already used — request a new one');
      return streamEvents(req, res, job);
    }

    const bodyLimit = p === '/api/verify' ? 25 * 1024 * 1024 : 64 * 1024;
    const raw = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method) ? await readBody(req, bodyLimit) : '';
    let who;
    try { who = await authenticate(req, url, raw); }
    catch (e) { if (e.status === 401 && !e.noLockout) return authFailure(res, ip, p, e.message); throw e; }
    lockout.success(`ip:${ip}`);

    if (req.method === 'GET' && p === '/api/whoami') {
      return send(res, 200, { id: who.id, name: who.name, scopes: who.scopes, method: who.method, ip,
        scansRemainingThisHour: Math.max(0, Math.floor(LIMITS.scansPerHour - scanLimiter.peek(who.id === 'local' ? `ip:${ip}` : `key:${who.id}`))) });
    }
    if (req.method === 'GET' && p === '/api/tools') { requireScope(who, 'read'); return send(res, 200, toolInventory()); }

    if (req.method === 'POST' && p === '/api/scan') {
      requireScope(who, 'scan');
      const { job, quota } = startScan(parseJson(raw), who, ip);
      return send(res, 202, { id: job.id }, 'application/json', rlHeaders(quota, 'X-Scan-Quota'));
    }

    m = p.match(/^\/api\/scan\/([0-9a-f-]{36})(\/events|\/ticket)?$/);
    if (m) {
      requireScope(who, 'read');
      const job = jobs.get(m[1]);
      if (!job || !canSeeJob(who, job)) throw new HttpError(404, 'Unknown scan id');
      if (m[2] === '/ticket' && req.method === 'POST') return send(res, 200, { ticket: createTicket(who.id, job.id), expiresIn: 60 });
      if (m[2] === '/events' && req.method === 'GET') return streamEvents(req, res, job);
      if (!m[2] && req.method === 'GET') return send(res, 200, { id: job.id, status: job.status, error: job.error, report: job.report, file: job.file });
    }

    if (req.method === 'GET' && p === '/api/reports') {
      requireScope(who, 'read');
      const files = fs.readdirSync(REPORT_DIR).filter(f => f.endsWith('.json')).map(f => {
        const st = fs.statSync(reportFile(f));
        let meta = {};
        try {
          const r = JSON.parse(fs.readFileSync(reportFile(f), 'utf8'));
          meta = { url: r.target?.finalUrl, score: r.score?.overall, grade: r.score?.grade, scannedAt: r.scannedAt, signed: !!r.integrity, requestedBy: r.options?.requestedBy };
        } catch {}
        return { file: f, size: st.size, mtime: st.mtime, ...meta };
      }).sort((a, b) => new Date(b.mtime) - new Date(a.mtime)).slice(0, 200);
      return send(res, 200, files);
    }
    m = p.match(/^\/api\/reports\/([\w.-]+\.json)$/);
    if (m && req.method === 'GET') {
      requireScope(who, 'read');
      const f = reportFile(m[1]);
      if (!fs.existsSync(f)) throw new HttpError(404, 'Report not found');
      res.writeHead(200, { 'Content-Type': 'application/json', ...BASE_HEADERS, 'Content-Disposition': url.searchParams.has('download') ? `attachment; filename="${path.basename(f)}"` : 'inline' });
      return fs.createReadStream(f).pipe(res);
    }
    if (m && req.method === 'DELETE') {
      requireScope(who, 'admin');
      const f = reportFile(m[1]);
      if (fs.existsSync(f)) fs.unlinkSync(f);
      audit('report.delete', { kid: who.id, ip, file: path.basename(f) });
      return send(res, 200, { ok: true });
    }

    if (req.method === 'POST' && p === '/api/verify') {
      requireScope(who, 'read');
      const result = verifyReport(parseJson(raw));
      return send(res, 200, { ...result, serverKeyFingerprint: signingKeys().fingerprint });
    }

    throw new HttpError(404, 'Not found');
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    send(res, status, { error: status === 500 ? 'Internal error' : e.message }, 'application/json', e.headers || {});
  }
});

function authFailure(res, ip, p, reason) {
  const r = lockout.fail(`ip:${ip}`);
  audit(r.locked ? 'auth.lockout' : 'auth.fail', { ip, path: p, reason });
  if (r.locked) {
    const s = LIMITS.lockoutMinutes * 60;
    return send(res, 429, { error: `Too many failed authentication attempts — locked for ${LIMITS.lockoutMinutes} min.` }, 'application/json', { 'Retry-After': String(s) });
  }
  return send(res, 401, { error: reason, attemptsLeft: r.remaining }, 'application/json', { 'WWW-Authenticate': 'Bearer realm="webscan"' });
}

// ---------- startup ----------
if (process.env.WEBSCAN_TOKEN) {
  console.warn('⚠  WEBSCAN_TOKEN is no longer used (v1.1 uses hashed API keys). Create one with:  node bin/webscan.js keys create "<name>" --scopes read,scan');
}
if (!authRequired() && !LOOPBACK && process.env.ALLOW_NO_AUTH !== '1') {
  console.error(`✖ Refusing to listen on ${HOST} without authentication.\n  Create an API key first:  node bin/webscan.js keys create "admin" --scopes read,scan,active,admin\n  (or set ALLOW_NO_AUTH=1 to override — not recommended)`);
  process.exit(1);
}
signingKeys(); // generate report-signing keys on first start

server.listen(PORT, HOST, () => {
  console.log(`SJ WebScan v${VERSION} → http://${HOST}:${PORT}`);
  console.log(`  auth: ${authRequired() ? `${activeKeyCount()} API key(s)${REQUIRE_HMAC ? ', HMAC required for API clients' : ''}` : 'OFF (loopback only — create a key to enable)'}`);
  console.log(`  limits: ${LIMITS.apiPerMin} req/min/IP · ${LIMITS.scansPerHour} scans/h/key · ${MAX_SCANS} concurrent (${MAX_SCANS_PER_CLIENT}/key) · lockout ${LIMITS.lockoutFailures} fails → ${LIMITS.lockoutMinutes} min`);
  console.log(`  target throttle: ${DEFAULT_RPS} req/s built-in · ${DEFAULT_TOOL_RPS} req/s tools · data dir ${DATA_DIR}`);
  if (TRUST_PROXY) console.log('  trusting X-Forwarded-For (TRUST_PROXY=1) — make sure only your proxy can reach this port');
});

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { flushUsage(); process.exit(0); });
