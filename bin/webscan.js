#!/usr/bin/env node
// SJ WebScan CLI
import fs from 'node:fs';
import path from 'node:path';
import { scan, MODULES, VERSION } from '../src/scanner.js';
import { toolInventory, PROFILES } from '../src/tools/runner.js';

const HELP = `
SJ WebScan v${VERSION} — website vulnerability & health scanner

Usage:
  webscan <url> [options]        Scan a website
  webscan tools                  List the 27 supported tools and install status
  webscan tools --install-help   Print install commands for missing tools

Options:
  -o, --out <file>        Write JSON report to file (default: reports/<host>-<time>.json)
  --json                  Print the JSON report to stdout (no pretty output)
  -m, --modules <list>    Built-in modules (default all): ${MODULES.join(',')}
  -t, --tools <list>      External tools: none | passive | full | comma list (e.g. subfinder,nuclei)
  --authorized            Allow ACTIVE tools (nmap, nuclei, nikto, ffuf, …). Only with owner permission!
  --wordlist <file>       Wordlist for ffuf/gobuster
  --tool-timeout <sec>    Max seconds per tool
  --no-links              Skip broken-link checking
  --max-links <n>         Links to check (default 60)
  --allow-private         Allow scanning private/internal IPs (localhost, 10.x, 192.168.x …)
  -v, --verbose           Stream tool output
  --fail-on <sev>         Exit code 2 if any failing finding ≥ severity (critical|high|medium|low) — for CI
  -h, --help              Show help

Examples:
  webscan example.com
  webscan https://example.com -t passive
  webscan https://client-site.com -t full --authorized -o audit.json
  webscan example.com --json --no-links | jq '.score'
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
      case '--wordlist': o.wordlist = next(); break;
      case '--tool-timeout': o.toolTimeout = Number(next()); break;
      case '--no-links': o.links = false; break;
      case '--max-links': o.maxLinks = Number(next()); break;
      case '--allow-private': o.allowPrivate = true; break;
      case '-v': case '--verbose': o.verbose = true; break;
      case '--fail-on': o.failOn = next(); break;
      case '--install-help': o.installHelp = true; break;
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

  if (o._[0] === 'tools') {
    const inv = toolInventory();
    if (o.json) { console.log(JSON.stringify(inv, null, 2)); return; }
    console.log(c.b(`\n${inv.filter(t => t.installed).length}/${inv.length} tools installed\n`));
    let cat = '';
    for (const t of inv) {
      if (t.category !== cat) { cat = t.category; console.log(c.b(`\n ${cat}`)); }
      console.log(`  ${t.installed ? c.g('●') : c.d('○')} ${t.id.padEnd(13)} ${t.name.padEnd(26)} ${t.intrusive ? c.y('active ') : c.g('passive')}  ${t.installed ? c.d(t.path) : o.installHelp ? c.d(t.install) : c.d('not installed')}`);
    }
    console.log(c.d(`\nProfiles: passive = ${PROFILES.passive.length} tools, full = ${PROFILES.full.length} tools. Run scripts/install-tools.sh to install everything.\n`));
    return;
  }

  const input = o._[0];
  const log = o.json ? (m) => process.stderr.write(c.d(m) + '\n') : (m) => console.log(c.d('  ' + m));
  if (o.tools && o.tools !== 'none' && o.tools !== 'passive' && !o.authorized) {
    log('Note: active tools in your selection are skipped unless you pass --authorized.');
  }
  const report = await scan(input, {
    modules: o.modules, tools: o.tools || [], authorized: o.authorized, wordlist: o.wordlist, toolTimeout: o.toolTimeout,
    links: o.links, maxLinks: o.maxLinks, allowPrivate: o.allowPrivate, verbose: o.verbose,
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
  console.log(`\n  JSON report: ${outFile}\n`);
}

main().catch((e) => { console.error(c.r('Error: ' + e.message)); process.exit(1); });
