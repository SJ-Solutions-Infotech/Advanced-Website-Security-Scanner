// Executes external tools safely: argv arrays (no shell), timeouts, output caps, ANSI stripping.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { TOOLS, defaultWordlist } from './registry.js';
import { pool } from '../http.js';

const MAX_OUT = 4 * 1024 * 1024;
const EXTRA_PATHS = [path.join(os.homedir(), 'go/bin'), path.join(os.homedir(), '.local/bin'), '/usr/local/go/bin', '/snap/bin', '/opt/testssl.sh', '/usr/share/nikto', '/opt/homebrew/bin'];
const stripAnsi = (s) => s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\r/g, '');

const binCache = new Map();
export function findBin(names) {
  const key = names.join('|');
  if (binCache.has(key)) return binCache.get(key);
  const dirs = [...(process.env.PATH || '').split(path.delimiter), ...EXTRA_PATHS];
  let found = null;
  outer: for (const n of names) {
    for (const d of dirs) {
      const p = path.join(d, n);
      try { fs.accessSync(p, fs.constants.X_OK); if (fs.statSync(p).isFile()) { found = p; break outer; } } catch {}
    }
  }
  binCache.set(key, found);
  return found;
}

export function toolInventory() {
  return TOOLS.map(t => ({
    id: t.id, name: t.name, category: t.category, intrusive: t.intrusive, homepage: t.homepage, install: t.install,
    path: findBin(t.bins), installed: !!findBin(t.bins), needsWordlist: !!t.needsWordlist,
  }));
}

function exec(bin, args, { timeout, stdin, onLine }) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let out = '', err = '', killed = false;
    const child = spawn(bin, args, { shell: false, env: { ...process.env, NO_COLOR: '1', TERM: 'dumb' }, stdio: ['pipe', 'pipe', 'pipe'] });
    const timer = setTimeout(() => { killed = true; child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5000); }, timeout * 1000);
    let lineBuf = '';
    child.stdout.on('data', (d) => {
      const s = d.toString();
      if (out.length < MAX_OUT) out += s;
      if (onLine) { lineBuf += s; const parts = lineBuf.split('\n'); lineBuf = parts.pop(); parts.forEach(l => l.trim() && onLine(stripAnsi(l))); }
    });
    child.stderr.on('data', (d) => { if (err.length < 256 * 1024) err += d.toString(); });
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, out, err: e.message, ms: Date.now() - t0, killed }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, out: stripAnsi(out), err: stripAnsi(err), ms: Date.now() - t0, killed }); });
    if (stdin) child.stdin.end(stdin); else child.stdin.end();
  });
}

export async function runTool(tool, target, ctx, opts, log) {
  const base = { id: tool.id, name: tool.name, category: tool.category, intrusive: tool.intrusive, homepage: tool.homepage };
  const bin = findBin(tool.bins);
  if (!bin) return { ...base, status: 'not_installed', install: tool.install };
  if (tool.intrusive && !opts.authorized) return { ...base, status: 'skipped', reason: 'Active/intrusive tool — requires authorization flag' };
  if (tool.onlyIf && !tool.onlyIf(ctx)) return { ...base, status: 'skipped', reason: 'Not applicable to detected technology' };
  const wordlist = opts.wordlist || defaultWordlist();
  if (tool.needsWordlist && !wordlist) return { ...base, status: 'skipped', reason: 'No wordlist found (set WEBSCAN_WORDLIST or --wordlist)' };

  const args = tool.args(target, { wordlist });
  const stdin = tool.stdin ? tool.stdin(target, ctx) : undefined;
  const timeout = Math.min(tool.timeout || 300, opts.toolTimeout || Infinity);
  log?.(`▶ ${tool.name}: ${path.basename(bin)} ${args.map(a => (/\s/.test(a) ? `"${a}"` : a)).join(' ')}`);
  const r = await exec(bin, args, { timeout, stdin, onLine: opts.verbose ? (l) => log?.(`  ${tool.id} │ ${l.slice(0, 300)}`) : null });
  const raw = (r.out || '') + (r.err && !r.out ? r.err : '');
  const result = { ...base, command: [path.basename(bin), ...args].join(' '), durationMs: r.ms, exitCode: r.code };

  const invalid = tool.validate?.(r.out, r.err);
  if (invalid) return { ...result, status: 'error', error: invalid };
  if (r.killed) result.status = 'timeout';
  else if (r.code !== 0 && !(tool.okExitCodes || []).includes(r.code) && !r.out.trim()) {
    return { ...result, status: 'error', error: (r.err || `exit code ${r.code}`).trim().split('\n').slice(-5).join('\n') };
  } else result.status = 'ok';

  try {
    const p = tool.parse ? tool.parse(r.out || '', target) : { summary: '', items: [] };
    Object.assign(result, { summary: p.summary, items: (p.items || []).slice(0, 1000), findings: p.findings || [] });
    if (p.subdomains) ctx.subdomains = [...new Set([...(ctx.subdomains || []), ...p.subdomains])];
    if (p.emails) ctx.emails = [...new Set([...(ctx.emails || []), ...p.emails])];
  } catch (e) {
    result.parseError = e.message;
  }
  result.raw = raw.length > 200000 ? raw.slice(0, 200000) + '\n…[truncated]' : raw;
  log?.(`✔ ${tool.name} ${result.status} in ${(r.ms / 1000).toFixed(1)}s — ${result.summary || ''}`);
  return result;
}

// Phase order: passive collectors → tools that consume collected subdomains → active tools
export async function runTools(ids, target, ctx, opts, log, onResult) {
  const selected = TOOLS.filter(t => ids.includes(t.id));
  const phaseA = selected.filter(t => !t.intrusive && !t.stdin);
  const phaseB = selected.filter(t => !t.intrusive && t.stdin);
  const phaseC = selected.filter(t => t.intrusive);
  const results = [];
  const run = async (t) => { const r = await runTool(t, target, ctx, opts, log); results.push(r); onResult?.(r); return r; };
  await pool(phaseA, opts.concurrency || 4, run);
  await pool(phaseB, 2, run);
  await pool(phaseC, opts.activeConcurrency || 2, run);
  const order = TOOLS.map(t => t.id);
  return results.sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
}

export const PROFILES = {
  none: [],
  passive: TOOLS.filter(t => !t.intrusive).map(t => t.id),
  full: TOOLS.map(t => t.id),
};
