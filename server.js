// SJ WebScan web UI — zero-dependency HTTP server with Server-Sent Events for live progress.
//
//   HOST=127.0.0.1 PORT=8080 node server.js
//   WEBSCAN_TOKEN=secret      require a token (strongly recommended if HOST is not 127.0.0.1)
//   ALLOW_PRIVATE=1           allow scanning internal/private IPs
//   ALLOW_ACTIVE=0            hard-disable active tools from the UI
//   MAX_SCANS=2               concurrent scans
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scan, MODULES, VERSION } from './src/scanner.js';
import { toolInventory } from './src/tools/runner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8080);
const TOKEN = process.env.WEBSCAN_TOKEN || '';
const MAX_SCANS = Number(process.env.MAX_SCANS || 2);
const ALLOW_ACTIVE = process.env.ALLOW_ACTIVE !== '0';
const REPORT_DIR = path.join(__dirname, 'reports');
fs.mkdirSync(REPORT_DIR, { recursive: true });

const jobs = new Map(); // id -> { id, status, events[], clients:Set, report, error, startedAt, url }

function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function authed(req, url) {
  if (!TOKEN) return true;
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : url.searchParams.get('token') || '';
  return t.length === TOKEN.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(TOKEN));
}

function readJson(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > limit) { reject(new Error('Body too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error('Invalid JSON')); } });
  });
}

function emit(job, type, data) {
  const ev = { type, data, t: Date.now() };
  job.events.push(ev);
  if (job.events.length > 5000) job.events.splice(0, 1000);
  const line = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of job.clients) c.write(line);
}

function startScan(body) {
  const running = [...jobs.values()].filter(j => j.status === 'running').length;
  if (running >= MAX_SCANS) throw Object.assign(new Error(`Too many scans running (${running}/${MAX_SCANS}). Try again shortly.`), { code: 429 });
  const id = crypto.randomUUID();
  const job = { id, status: 'running', events: [], clients: new Set(), startedAt: new Date().toISOString(), url: body.url };
  jobs.set(id, job);
  const opts = {
    modules: Array.isArray(body.modules) ? body.modules.filter(m => MODULES.includes(m)) : undefined,
    tools: Array.isArray(body.tools) ? body.tools.map(String) : [],
    authorized: ALLOW_ACTIVE && body.authorized === true,
    links: body.links !== false,
    maxLinks: Math.min(Number(body.maxLinks) || 60, 300),
    allowPrivate: process.env.ALLOW_PRIVATE === '1',
    verbose: body.verbose === true,
  };
  scan(body.url, opts, {
    log: (m) => emit(job, 'log', m),
    stage: (s) => emit(job, 'stage', s),
    tool: (r) => emit(job, 'tool', { id: r.id, name: r.name, status: r.status, summary: r.summary || r.reason || r.error || '' }),
  }).then((report) => {
    job.report = report; job.status = 'done';
    const file = `${report.target.host}-${report.scannedAt.replace(/[:.]/g, '-')}.json`;
    fs.writeFileSync(path.join(REPORT_DIR, file), JSON.stringify(report, null, 2));
    job.file = file;
    emit(job, 'done', { file });
  }).catch((e) => {
    job.status = 'error'; job.error = e.message;
    emit(job, 'error', e.message);
  }).finally(() => {
    for (const c of job.clients) c.end();
    job.clients.clear();
    setTimeout(() => jobs.delete(id), 60 * 60 * 1000);
  });
  return job;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;
  try {
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public/index.html')), 'text/html; charset=utf-8');
    }
    if (!p.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    if (!authed(req, url)) return send(res, 401, { error: 'Unauthorized — set token' });

    if (req.method === 'GET' && p === '/api/meta') return send(res, 200, { version: VERSION, modules: MODULES, allowActive: ALLOW_ACTIVE, tokenRequired: !!TOKEN });
    if (req.method === 'GET' && p === '/api/tools') return send(res, 200, toolInventory());

    if (req.method === 'POST' && p === '/api/scan') {
      const body = await readJson(req);
      if (!body.url) return send(res, 400, { error: 'url is required' });
      const job = startScan(body);
      return send(res, 202, { id: job.id });
    }

    let m = p.match(/^\/api\/scan\/([0-9a-f-]{36})(\/events)?$/);
    if (m && req.method === 'GET') {
      const job = jobs.get(m[1]);
      if (!job) return send(res, 404, { error: 'Unknown scan id' });
      if (!m[2]) return send(res, 200, { id: job.id, status: job.status, error: job.error, report: job.report, file: job.file });
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      for (const ev of job.events) res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev.data)}\n\n`);
      if (job.status !== 'running') return res.end();
      job.clients.add(res);
      const ping = setInterval(() => res.write(': ping\n\n'), 15000);
      req.on('close', () => { clearInterval(ping); job.clients.delete(res); });
      return;
    }

    if (req.method === 'GET' && p === '/api/reports') {
      const files = fs.readdirSync(REPORT_DIR).filter(f => f.endsWith('.json')).map(f => {
        const st = fs.statSync(path.join(REPORT_DIR, f));
        let meta = {};
        try { const r = JSON.parse(fs.readFileSync(path.join(REPORT_DIR, f), 'utf8')); meta = { url: r.target?.finalUrl, score: r.score?.overall, grade: r.score?.grade, scannedAt: r.scannedAt }; } catch {}
        return { file: f, size: st.size, mtime: st.mtime, ...meta };
      }).sort((a, b) => new Date(b.mtime) - new Date(a.mtime)).slice(0, 200);
      return send(res, 200, files);
    }
    m = p.match(/^\/api\/reports\/([\w.-]+\.json)$/);
    if (m && req.method === 'GET') {
      const f = path.join(REPORT_DIR, path.basename(m[1]));
      if (!fs.existsSync(f)) return send(res, 404, { error: 'Report not found' });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': url.searchParams.has('download') ? `attachment; filename="${path.basename(f)}"` : 'inline' });
      return fs.createReadStream(f).pipe(res);
    }
    if (m && req.method === 'DELETE') {
      const f = path.join(REPORT_DIR, path.basename(m[1]));
      if (fs.existsSync(f)) fs.unlinkSync(f);
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    send(res, e.code === 429 ? 429 : 400, { error: e.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`SJ WebScan v${VERSION} UI → http://${HOST}:${PORT}${TOKEN ? '  (token required)' : ''}`);
  if (HOST !== '127.0.0.1' && HOST !== 'localhost' && !TOKEN) console.warn('⚠  Listening on a public interface without WEBSCAN_TOKEN — anyone could use this server to scan. Set WEBSCAN_TOKEN.');
});
