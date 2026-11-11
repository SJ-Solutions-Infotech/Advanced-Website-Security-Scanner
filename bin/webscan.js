#!/usr/bin/env node
// SJ WebScan CLI
import fs from 'node:fs';
import path from 'node:path';
import { scan, MODULES, VERSION } from '../src/scanner.js';
import { toolInventory, PROFILES, DEFAULT_TOOL_RPS } from '../src/tools/runner.js';
import { DEFAULT_RPS } from '../src/http.js';
import { createKey, listKeys, revokeKey, flushUsage, SCOPES } from '../src/security/keys.js';
import { verifyReport, signingKeys } from '../src/security/integrity.js';
import { DATA_DIR } from '../src/security/store.js';

const HELP = `
SJ WebScan v${VERSION} — website vulnerability & health scanner

Usage:
  webscan <url> [options]                 Scan a website
  webscan tools [--install-help]          List the 27 supported tools and install status
  webscan keys create <name> [--scopes read,scan,active,admin]
                                          Create an API key (shown once; stored as a scrypt hash)
  webscan keys list                       List API keys
  webscan keys revoke <id>                Revoke a key (its sessions stop working immediately)
  webscan verify <report.json> [--pubkey <file>]
                                          Check a report's SHA-256 hash and Ed25519 signature
  webscan public-key [--out <file>]       Print the report-signing public key (give it to clients)

Scan options:
  -o, --out <file>        Write JSON report to file (default: reports/<host>-<time>.json)
  --json                  Print the JSON report to stdout (no pretty output)
  -m, --modules <list>    Built-in modules (default all): ${MODULES.join(',')}
  -t, --tools <list>      External tools: none | passive | full | comma list (e.g. subfinder,nuclei)
  --authorized            Allow ACTIVE tools (nmap, nuclei, nikto, ffuf, …). Only with owner permission!
  --rps <n>               Built-in checks: max requests/sec per host (default ${DEFAULT_RPS})
  --tool-rps <n>          External tools: max requests/sec (default ${DEFAULT_TOOL_RPS})
  --wordlist <file>       Wordlist for ffuf/gobuster
  --tool-timeout <sec>    Max seconds per tool
  --no-links              Skip broken-link checking
  --max-links <n>         Links to check (default 60)
  --allow-private         Allow scanning private/internal IPs (localhost, 10.x, 192.168.x …)
  --no-sign               Don't sign the report
  -v, --verbose           Stream tool output
  --fail-on <sev>         Exit code 2 if any failing finding ≥ severity (critical|high|medium|low) — for CI
  -h, --help              Show help

Examples:
  webscan example.com
  webscan https://example.com -t passive --rps 5
  webscan https://client-site.com -t full --authorized -o audit.json
  webscan keys create "Aman (dev team)" --scopes read,scan
  webscan verify reports/client.com-2026-11-11.json
`;

function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], next = () => argv[++i];
    switch (a) {
      case '-o': case '--out': o.out = next(); break;
      case '--json': o.json = true; break;
      case '-m': case '--modules': o.modules = next().split(',').map(s => s.trim()); break;
      case '-t': case '--tools': o.tools = next(); break;
      case '--authorized': o.authorized = true; break;
      case '--rps': o.rps = Number(next()); break;
      case '--tool-rps': o.toolRps = Number(next()); break;
      case '--wordlist': o.wordlist = next(); break;
      case '--tool-timeout': o.toolTimeout = Number(next()); break;
      case '--no-links': o.links = false; break;
      case '--max-links': o.maxLinks = Number(next()); break;
      case '--allow-private': o.allowPrivate = true; break;
      case '--no-sign': o.sign = false; break;
      case '-v': case '--verbose': o.verbose = true; break;
      case '--fail-on': o.failOn = next(); break;
      case '--install-help': o.installHelp = true; break;
      case '--scopes': o.scopes = next().split(',').map(s => s.trim()).filter(Boolean); break;
      case '--pubkey': o.pubkey = next(); break;
      case '-h': case '--help': o.help = true; break;
      default: o._.push(a);
    }
  }
  return o;
}

const c = process.stdout.isTTY && !process.env.NO_COLOR
  ? { r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m`, d: s => `\x1b[2m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`, m: s => `\x1b[35m${s}\x1b[0m` }
  : Object.fromEntries(['r', 'y', 'g', 'b', 'd', 'c', 'm'].map(k => [k, s => s]));

const SEV = { critical: c.m('CRIT'), high: c.r('HIGH'), medium: c.y('MED '), low: c.c('LOW '), info: c.d('INFO') };
const ST = { pass: c.g('✔ PASS'), warn: c.y('▲ WARN'), fail: c.r('✖ FAIL'), info: c.d('• INFO'), error: c.r('! ERR ') };

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.help || !o._.length) { console.log(HELP); return; }
  const cmd = o._[0];

  if (cmd === 'tools') return cmdTools(o);
  if (cmd === 'keys') return cmdKeys(o);
  if (cmd === 'verify') return cmdVerify(o);
  if (cmd === 'public-key') return cmdPublicKey(o);

  for (const [k, v] of [['--rps', o.rps], ['--tool-rps', o.toolRps]]) {
    if (v !== undefined && !(v > 0 && v <= 1000)) throw new Error(`${k} must be between 0.1 and 1000`);
  }
  const log = o.json ? (m) => process.stderr.write(c.d(m) + '\n') : (m) => console.log(c.d('  ' + m));
  if (o.tools && o.tools !== 'none' && o.tools !== 'passive' && !o.authorized) {
    log('Note: active tools in your selection are skipped unless you pass --authorized.');
  }
  const report = await scan(cmd, {
    modules: o.modules, tools: o.tools || [], authorized: o.authorized, wordlist: o.wordlist, toolTimeout: o.toolTimeout,
    links: o.links, maxLinks: o.maxLinks, allowPrivate: o.allowPrivate, verbose: o.verbose,
    rps: o.rps, toolRps: o.toolRps, sign: o.sign,
  }, { log });

  const outFile = o.out || path.join(process.cwd(), 'reports', `${report.target.host}-${report.scannedAt.replace(/[:.]/g, '-')}.json`);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2));

  if (o.json) { process.stdout.write(JSON.stringify(report, null, 2) + '\n'); }
  else printReport(report, outFile);

  if (o.failOn) {
    const rank = { critical: 4, high: 3, medium: 2, low: 1 };
    const min = rank[o.failOn] || 3;
    if (report.findings.some(f => f.status === 'fail' && (rank[f.severity] || 0) >= min)) process.exitCode = 2;
  }
}

function cmdTools(o) {
  const inv = toolInventory();
  if (o.json) { console.log(JSON.stringify(inv, null, 2)); return; }
  console.log(c.b(`\n${inv.filter(t => t.installed).length}/${inv.length} tools installed\n`));
  let cat = '';
  for (const t of inv) {
    if (t.category !== cat) { cat = t.category; console.log(c.b(`\n ${cat}`)); }
    console.log(`  ${t.installed ? c.g('●') : c.d('○')} ${t.id.padEnd(13)} ${t.name.padEnd(26)} ${t.intrusive ? c.y('active ') : c.g('passive')}  ${t.installed ? c.d(t.path) : o.installHelp ? c.d(t.install) : c.d('not installed')}`);
  }
  console.log(c.d(`\nProfiles: passive = ${PROFILES.passive.length} tools, full = ${PROFILES.full.length} tools. Run scripts/install-tools.sh (Linux/macOS) or scripts/install-tools.ps1 (Windows) to install everything.\n`));
}

async function cmdKeys(o) {
  const sub = o._[1];
  if (sub === 'create') {
    const name = o._.slice(2).join(' ').trim();
    if (!name) throw new Error('Usage: webscan keys create <name> [--scopes read,scan,active,admin]');
    const k = await createKey(name, o.scopes || ['read', 'scan']);
    if (o.json) { console.log(JSON.stringify(k, null, 2)); return; }
    console.log(`\n${c.g('✔')} Created key ${c.b(k.id)} for "${k.name}"  scopes: ${k.scopes.join(', ')}\n`);
    console.log(`  ${c.b('API key')}         ${k.apiKey}`);
    console.log(`  ${c.b('Signing secret')}  ${k.signingSecret}`);
    console.log(c.y('\n  ⚠ Copy both now — they are not shown again. Only a scrypt hash of the API key is stored.'));
    console.log(c.d(`\n  Browser UI:   paste the API key on the sign-in screen`));
    console.log(c.d(`  Simple API:   Authorization: Bearer ${k.apiKey.slice(0, 18)}…`));
    console.log(c.d(`  Signed API:   WEBSCAN_KEY_ID=${k.id} WEBSCAN_SIGNING_SECRET=<secret> node scripts/signed-client.mjs GET /api/whoami\n`));
    return;
  }
  if (sub === 'list') {
    const keys = listKeys();
    if (o.json) { console.log(JSON.stringify(keys, null, 2)); return; }
    if (!keys.length) { console.log(c.d(`\nNo API keys yet (data dir: ${DATA_DIR}). Create one: webscan keys create "<name>"\n`)); return; }
    console.log(c.b(`\n ${'ID'.padEnd(10)}${'NAME'.padEnd(26)}${'SCOPES'.padEnd(26)}${'CREATED'.padEnd(13)}${'LAST USED'.padEnd(18)}STATUS`));
    for (const k of keys) {
      console.log(` ${k.id.padEnd(10)}${k.name.slice(0, 24).padEnd(26)}${k.scopes.join(',').padEnd(26)}${k.createdAt.slice(0, 10).padEnd(13)}${(k.lastUsedAt ? k.lastUsedAt.slice(0, 16).replace('T', ' ') : '—').padEnd(18)}${k.revoked ? c.r('revoked') : c.g('active')}`);
    }
    console.log(c.d(`\n Valid scopes: ${SCOPES.join(', ')}  ·  data dir: ${DATA_DIR}\n`));
    return;
  }
  if (sub === 'revoke') {
    const id = o._[2];
    if (!id) throw new Error('Usage: webscan keys revoke <id>');
    console.log(revokeKey(id) ? `${c.g('✔')} Key ${id} revoked` : `Key ${id} was already revoked`);
    return;
  }
  throw new Error('Usage: webscan keys create|list|revoke');
}

function cmdVerify(o) {
  const file = o._[1];
  if (!file) throw new Error('Usage: webscan verify <report.json> [--pubkey <file>]');
  const report = JSON.parse(fs.readFileSync(file, 'utf8'));
  const pem = o.pubkey ? fs.readFileSync(o.pubkey, 'utf8') : undefined;
  const r = verifyReport(report, pem);
  if (o.json) { console.log(JSON.stringify(r, null, 2)); }
  else {
    console.log(`\n ${r.valid ? c.g('✔ VALID') : c.r('✖ INVALID')}  ${r.reason}`);
    if (r.signed) {
      console.log(c.d(`   content hash   ${r.hashMatches ? 'matches' : 'MISMATCH'}  (${r.hash})`));
      console.log(c.d(`   signature      ${r.signatureValid ? 'valid' : 'INVALID'}  Ed25519, key ${r.signedBy}`));
      console.log(c.d(`   signed at      ${r.signedAt}`));
      console.log(c.d(`   verified with  ${o.pubkey ? o.pubkey : 'this installation\'s key'} (${r.fingerprint})`));
    }
    console.log('');
  }
  if (!r.valid) process.exitCode = 3;
}

function cmdPublicKey(o) {
  const k = signingKeys();
  if (o.out) { fs.writeFileSync(o.out, k.publicPem); console.log(`${c.g('✔')} Wrote ${o.out}  (${k.fingerprint})`); return; }
  console.log(k.publicPem.trim());
  console.error(c.d(`fingerprint ${k.fingerprint}`));
}

function printReport(r, outFile) {
  const s = r.score;
  const gc = s.grade === 'A' || s.grade === 'B' ? c.g : s.grade === 'C' ? c.y : c.r;
  console.log('\n' + c.b(`══ ${r.target.finalUrl} ══`));
  console.log(`  Score ${gc(c.b(`${s.overall}/100  Grade ${s.grade}`))}   security ${s.security}  ·  health ${s.health}`);
  console.log(`  Issues: ${c.m(r.summary.critical + ' critical')}  ${c.r(r.summary.high + ' high')}  ${c.y(r.summary.medium + ' medium')}  ${c.c(r.summary.low + ' low')}   (${r.summary.pass} passed)`);
  if (r.technologies.length) console.log(`  Tech: ${r.technologies.join(', ')}`);
  let cat = '';
  const byCat = [...r.findings].sort((a, b) => a.category.localeCompare(b.category));
  for (const f of byCat) {
    if (f.category !== cat) { cat = f.category; console.log('\n' + c.b(` ${cat}`)); }
    console.log(`  ${ST[f.status] || f.status} ${f.status === 'pass' || f.status === 'info' ? '    ' : SEV[f.severity]} ${f.title}${f.detail ? c.d(' — ' + String(f.detail).replace(/\n/g, ' ').slice(0, 160)) : ''}`);
    if (f.fix && (f.status === 'fail' || f.status === 'warn')) console.log(c.d(`         ↳ ${f.fix}`));
  }
  if (r.tools.length) {
    console.log('\n' + c.b(' External tools'));
    for (const t of r.tools) {
      const st = { ok: c.g('ok'), timeout: c.y('timeout'), error: c.r('error'), skipped: c.d('skipped'), not_installed: c.d('not installed') }[t.status];
      console.log(`  ${t.name.padEnd(26)} ${st.padEnd(14)} ${c.d(t.summary || t.reason || t.error || (t.status === 'not_installed' ? t.install : ''))}`);
    }
  }
  if (r.osint.subdomains.length) console.log(`\n  Subdomains (${r.osint.subdomains.length}): ${c.d(r.osint.subdomains.slice(0, 20).join(', '))}${r.osint.subdomains.length > 20 ? ' …' : ''}`);
  if (r.integrity) console.log(`\n  ${c.g('🔒 Signed')} ${c.d(`sha256 ${r.integrity.hash.slice(0, 16)}… · key ${r.integrity.publicKeyFingerprint}`)}`);
  console.log(`\n  JSON report: ${outFile}\n`);
}

main().then(() => flushUsage()).catch((e) => { console.error(c.r('Error: ' + e.message)); process.exit(1); });
