// HTTPS redirect, security headers, information leakage, cookie flags, CORS
import { request } from '../http.js';

const F = (o) => ({ category: 'Security headers', ...o });

export async function headerChecks(ctx) {
  const f = [];
  const { target, home } = ctx;
  const h = home.headers;
  const isHttps = home.url.startsWith('https://');

  // HTTP -> HTTPS redirect
  const http = await request(`http://${target.host}/`, { redirect: 'manual', readBody: false, timeout: 10000 });
  if (!http.ok) {
    f.push({ id: 'https.redirect', category: 'SSL/TLS', title: 'HTTP → HTTPS redirect', status: 'info', severity: 'info', detail: `Port 80 not reachable (${http.error})` });
  } else {
    const loc = http.headers.get('location') || '';
    const good = [301, 302, 307, 308].includes(http.status) && loc.startsWith('https://');
    f.push({ id: 'https.redirect', category: 'SSL/TLS', title: 'HTTP → HTTPS redirect', status: good ? ([301, 308].includes(http.status) ? 'pass' : 'warn') : 'fail',
      severity: good ? 'low' : 'high',
      detail: good ? `HTTP ${http.status} → ${loc}` : `http:// returned ${http.status} without redirecting to HTTPS`,
      fix: good && [301, 308].includes(http.status) ? undefined : 'Permanently redirect (301) all http:// requests to https://.' });
  }

  if (!isHttps) {
    f.push(F({ id: 'https.final', title: 'Site served over HTTPS', status: 'fail', severity: 'high', detail: `Final URL is ${home.url}`, fix: 'Serve the site over HTTPS only.' }));
  }

  // HSTS
  const hsts = h.get('strict-transport-security');
  if (isHttps) {
    const maxAge = Number((hsts || '').match(/max-age=(\d+)/i)?.[1] || 0);
    f.push(F({ id: 'hdr.hsts', title: 'Strict-Transport-Security (HSTS)',
      status: !hsts ? 'fail' : maxAge < 15552000 ? 'warn' : 'pass', severity: !hsts ? 'medium' : 'low',
      detail: hsts || 'Missing',
      fix: !hsts || maxAge < 15552000 ? 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains' : undefined }));
  }

  // CSP
  const csp = h.get('content-security-policy');
  const cspRO = h.get('content-security-policy-report-only');
  let cspStatus = 'pass', cspSev = 'info', cspDetail = csp;
  if (!csp) { cspStatus = cspRO ? 'warn' : 'fail'; cspSev = 'medium'; cspDetail = cspRO ? `Report-only: ${cspRO}` : 'Missing'; }
  else if (/'unsafe-inline'|'unsafe-eval'|\*\s|\*;|\*$/.test(csp) && !/'nonce-|'strict-dynamic'/.test(csp)) { cspStatus = 'warn'; cspSev = 'low'; cspDetail = `Weak policy (unsafe-inline/eval or wildcard): ${csp}`; }
  f.push(F({ id: 'hdr.csp', title: 'Content-Security-Policy', status: cspStatus, severity: cspSev, detail: cspDetail?.slice(0, 400),
    fix: cspStatus === 'pass' ? undefined : "Define a CSP, e.g. default-src 'self'; script-src 'self' <trusted CDNs>; object-src 'none'; frame-ancestors 'self'. Start with Report-Only to tune it." }));

  // Clickjacking
  const xfo = h.get('x-frame-options');
  const fa = /frame-ancestors/i.test(csp || '');
  f.push(F({ id: 'hdr.xfo', title: 'Clickjacking protection', status: xfo || fa ? 'pass' : 'fail', severity: xfo || fa ? 'info' : 'medium',
    detail: xfo ? `X-Frame-Options: ${xfo}` : fa ? 'CSP frame-ancestors set' : 'No X-Frame-Options or frame-ancestors',
    fix: xfo || fa ? undefined : 'Add X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors \'self\').' }));

  const simple = [
    ['x-content-type-options', 'X-Content-Type-Options', v => /nosniff/i.test(v), 'low', 'Add: X-Content-Type-Options: nosniff'],
    ['referrer-policy', 'Referrer-Policy', v => !/unsafe-url/i.test(v), 'low', 'Add: Referrer-Policy: strict-origin-when-cross-origin'],
    ['permissions-policy', 'Permissions-Policy', () => true, 'low', 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()'],
    ['cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', () => true, 'info', 'Optional: Cross-Origin-Opener-Policy: same-origin'],
  ];
  for (const [key, name, okFn, sev, fix] of simple) {
    const v = h.get(key);
    const good = v && okFn(v);
    f.push(F({ id: `hdr.${key}`, title: name, status: good ? 'pass' : (sev === 'info' ? 'info' : 'warn'), severity: good ? 'info' : sev, detail: v || 'Missing', fix: good ? undefined : fix }));
  }

  // Information disclosure
  const leaks = [];
  for (const k of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-runtime', 'x-debug-token', 'x-debug-token-link']) {
    const v = h.get(k);
    if (v) leaks.push(`${k}: ${v}`);
  }
  const versioned = leaks.filter(l => /\d+\.\d+/.test(l) || /x-debug/i.test(l));
  f.push({ id: 'info.headers', category: 'Information disclosure', title: 'Server / framework version disclosure',
    status: versioned.length ? 'warn' : 'pass', severity: versioned.length ? 'low' : 'info',
    detail: leaks.length ? leaks.join(' | ') : 'No technology headers exposed',
    fix: versioned.length ? 'Hide versions: nginx server_tokens off; Apache ServerTokens Prod + ServerSignature Off; PHP expose_php = Off.' : undefined });

  // Cookies
  const cookies = home.setCookies || [];
  if (cookies.length) {
    const issues = [];
    for (const c of cookies) {
      const name = c.split('=')[0].trim();
      const lc = c.toLowerCase();
      const miss = [];
      if (isHttps && !/;\s*secure/.test(lc)) miss.push('Secure');
      if (!/;\s*httponly/.test(lc) && /sess|token|auth|sid|laravel|wordpress_logged|phpsessid/i.test(name)) miss.push('HttpOnly');
      if (!/;\s*samesite=/.test(lc)) miss.push('SameSite');
      if (miss.length) issues.push(`${name} (missing ${miss.join(', ')})`);
    }
    f.push({ id: 'cookies.flags', category: 'Cookies', title: 'Cookie security flags', status: issues.length ? 'warn' : 'pass',
      severity: issues.some(i => /HttpOnly|Secure/.test(i)) ? 'medium' : issues.length ? 'low' : 'info',
      detail: issues.length ? issues.join('; ') : `${cookies.length} cookie(s), all flagged correctly`,
      fix: issues.length ? 'Set Secure; HttpOnly (session/auth cookies); SameSite=Lax or Strict. Laravel: config/session.php secure=true, same_site=lax.' : undefined });
  }

  // CORS
  const cors = await request(home.url, { headers: { Origin: 'https://evil.example' }, readBody: false, timeout: 10000 });
  const acao = cors.headers.get('access-control-allow-origin');
  const acac = cors.headers.get('access-control-allow-credentials');
  if (acao) {
    const reflect = acao === 'https://evil.example';
    const bad = reflect || (acao === '*' && acac === 'true');
    f.push({ id: 'cors', category: 'Security headers', title: 'CORS policy', status: bad ? 'fail' : acao === '*' ? 'warn' : 'pass',
      severity: bad ? (acac === 'true' ? 'high' : 'medium') : acao === '*' ? 'low' : 'info',
      detail: `Access-Control-Allow-Origin: ${acao}${acac ? `; Allow-Credentials: ${acac}` : ''}${reflect ? ' (reflects arbitrary Origin)' : ''}`,
      fix: bad || acao === '*' ? 'Only allow specific trusted origins; never reflect Origin together with Allow-Credentials: true.' : undefined });
  }
  return f;
}
