// Orchestrator: runs built-in checks + external tools and produces the JSON report
import { normalizeTarget, assertPublicTarget } from './target.js';
import { request } from './http.js';
import { tlsChecks } from './checks/tls.js';
import { headerChecks } from './checks/headers.js';
import { exposureChecks } from './checks/exposure.js';
import { cmsChecks } from './checks/cms.js';
import { healthChecks } from './checks/health.js';
import { dnsChecks } from './checks/dns.js';
import { runTools, PROFILES } from './tools/runner.js';
import { TOOLS } from './tools/registry.js';

export const VERSION = '1.0.0';
export const MODULES = ['tls', 'headers', 'exposure', 'cms', 'health', 'dns'];
const WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
const HEALTH_CATS = new Set(['Health', 'Performance']);

export async function scan(input, opts = {}, ev = {}) {
  const log = ev.log || (() => {});
  const t0 = Date.now();
  const target = normalizeTarget(input);
  await assertPublicTarget(target.host, opts.allowPrivate);
  log(`Target: ${target.url}`);

  // Fetch homepage manually following redirects (records chain + re-checks SSRF on each hop)
  let url = target.url, home, chain = [];
  for (let i = 0; i < 10; i++) {
    home = await request(url, { redirect: 'manual', timeout: opts.timeout || 20000 });
    if (!home.ok) break;
    const loc = home.headers.get('location');
    if (home.status >= 300 && home.status < 400 && loc) {
      const next = new URL(loc, url);
      await assertPublicTarget(next.hostname, opts.allowPrivate);
      chain.push(`${home.status} ${next.href}`);
      url = next.href;
      continue;
    }
    break;
  }
  // Broken/expired/self-signed certificate: keep scanning (the TLS module reports it) instead of aborting
  if (!home.ok && /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME|ERR_TLS/i.test(home.error || '')) {
    log(`⚠ Certificate problem (${home.error}) — continuing with certificate verification disabled so the remaining checks can run`);
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    process.emitWarning = (() => { const orig = process.emitWarning; return (w, ...a) => (String(w).includes('NODE_TLS_REJECT_UNAUTHORIZED') ? undefined : orig.call(process, w, ...a)); })();
    home = await request(url, { redirect: 'manual', timeout: opts.timeout || 20000 });
    chain = [];
    for (let i = 0; i < 10 && home.ok && home.status >= 300 && home.status < 400 && home.headers.get('location'); i++) {
      const next = new URL(home.headers.get('location'), url);
      await assertPublicTarget(next.hostname, opts.allowPrivate);
      chain.push(`${home.status} ${next.href}`); url = next.href;
      home = await request(url, { redirect: 'manual', timeout: opts.timeout || 20000 });
    }
  }
  if (!home.ok) throw new Error(`Could not reach ${target.url}: ${home.error}`);
  home.url = url;
  const finalUrl = new URL(url);
  const ctx = { target, home, redirectChain: chain, finalOrigin: finalUrl.origin, allowPrivate: opts.allowPrivate };
  if (finalUrl.hostname !== target.host) log(`Redirected to ${url}`);

  const modules = opts.modules?.length ? opts.modules : MODULES;
  const findings = [];
  const runners = {
    tls: () => tlsChecks({ ...ctx, target: { ...target, host: finalUrl.hostname, protocol: finalUrl.protocol.slice(0, -1), port: finalUrl.port ? +finalUrl.port : 443 } }),
    headers: () => headerChecks(ctx),
    exposure: () => exposureChecks(ctx),
    cms: () => cmsChecks(ctx),
    health: () => healthChecks(ctx, { links: opts.links !== false, maxLinks: opts.maxLinks }),
    dns: () => dnsChecks(ctx),
  };
  // cms first (sets ctx.tech used by tools), the rest in parallel
  const order = ['cms', ...modules.filter(m => m !== 'cms')].filter(m => modules.includes(m));
  if (order[0] === 'cms') {
    ev.stage?.('cms'); log('Running built-in module: cms');
    findings.push(...await safeRun('cms', runners.cms, log));
  }
  await Promise.all(order.filter(m => m !== 'cms').map(async (m) => {
    ev.stage?.(m); log(`Running built-in module: ${m}`);
    const r = await safeRun(m, runners[m], log);
    findings.push(...r);
    ev.findings?.(r);
  }));

  // External tools
  let toolIds = opts.tools || [];
  if (typeof toolIds === 'string') toolIds = PROFILES[toolIds] || toolIds.split(',').map(s => s.trim()).filter(Boolean);
  const unknown = toolIds.filter(id => !TOOLS.some(t => t.id === id));
  if (unknown.length) log(`⚠ Unknown tool id(s) ignored: ${unknown.join(', ')}`);
  let toolResults = [];
  if (toolIds.length) {
    ev.stage?.('tools');
    log(`Running ${toolIds.length} external tool(s)${opts.authorized ? ' (active scanning AUTHORIZED)' : ' (passive only — active tools skipped)'}`);
    toolResults = await runTools(toolIds, { ...target, url, origin: finalUrl.origin }, ctx, opts, log, ev.tool);
    for (const r of toolResults) {
      for (const tf of r.findings || []) {
        findings.push({ id: `tool.${r.id}.${(tf.template || tf.title).toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60)}`,
          category: `Tool: ${r.name}`, title: tf.title, status: ['critical', 'high', 'medium'].includes(tf.severity) ? 'fail' : 'warn',
          severity: WEIGHT[tf.severity] !== undefined ? tf.severity : 'info', detail: tf.detail, fix: tf.fix, source: r.id });
      }
    }
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const stOrder = { fail: 0, warn: 1, error: 2, info: 3, pass: 4 };
  findings.sort((a, b) => (stOrder[a.status] - stOrder[b.status]) || (sevOrder[a.severity] - sevOrder[b.severity]));

  const report = {
    scanner: 'SJ WebScan', version: VERSION, scannedAt: new Date().toISOString(), durationMs: Date.now() - t0,
    target: { input, url: target.url, finalUrl: url, host: finalUrl.hostname, domain: target.domain, redirectChain: chain },
    technologies: ctx.tech || [],
    score: score(findings),
    summary: summarize(findings, toolResults),
    findings,
    tools: toolResults,
    osint: { subdomains: ctx.subdomains || [], emails: ctx.emails || [] },
    options: { modules, tools: toolIds, authorized: !!opts.authorized },
    disclaimer: 'Automated results — verify before acting. Active scanning must only be performed on systems you own or have written permission to test.',
  };
  log(`Done in ${(report.durationMs / 1000).toFixed(1)}s — score ${report.score.overall}/100 (${report.score.grade})`);
  return report;
}

async function safeRun(name, fn, log) {
  try { return await fn(); }
  catch (e) {
    log(`✖ module ${name} failed: ${e.message}`);
    return [{ id: `${name}.error`, category: 'Scanner', title: `Module "${name}" error`, status: 'error', severity: 'info', detail: e.message }];
  }
}

function score(findings) {
  // Penalty points decay the score exponentially so it never hits a meaningless 0
  // and a handful of small issues costs roughly the same as a linear deduction.
  const calc = (list) => {
    let penalty = 0;
    for (const f of list) {
      if (f.status === 'fail') penalty += WEIGHT[f.severity] || 0;
      else if (f.status === 'warn') penalty += (WEIGHT[f.severity] || 0) / 2;
    }
    return Math.round(100 * Math.exp(-penalty / 90));
  };
  const security = calc(findings.filter(f => !HEALTH_CATS.has(f.category)));
  const health = calc(findings.filter(f => HEALTH_CATS.has(f.category)));
  const overall = Math.round(security * 0.7 + health * 0.3);
  // Any critical finding caps the grade at D
  const hasCritical = findings.some(f => f.severity === 'critical' && f.status === 'fail');
  const capped = hasCritical ? Math.min(overall, 60) : overall;
  const grade = capped >= 90 ? 'A' : capped >= 80 ? 'B' : capped >= 70 ? 'C' : capped >= 60 ? 'D' : 'F';
  return { overall: capped, grade, security, health };
}

function summarize(findings, tools) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, pass: 0, warn: 0, fail: 0, info: 0, total: findings.length };
  for (const f of findings) {
    s[f.status] = (s[f.status] || 0) + 1;
    if (f.status === 'fail' || f.status === 'warn') s[f.severity] = (s[f.severity] || 0) + 1;
  }
  s.tools = { ran: tools.filter(t => ['ok', 'timeout'].includes(t.status)).length, notInstalled: tools.filter(t => t.status === 'not_installed').length, skipped: tools.filter(t => t.status === 'skipped').length, errors: tools.filter(t => t.status === 'error').length };
  return s;
}
