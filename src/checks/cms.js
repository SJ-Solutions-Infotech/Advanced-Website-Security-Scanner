// Technology / CMS fingerprinting, WordPress-specific checks, outdated JavaScript libraries
import { request } from '../http.js';

const TECH = [
  ['WordPress', (b, h, c) => /wp-content\/|wp-includes\/|<meta name="generator" content="WordPress/i.test(b)],
  ['WooCommerce', (b) => /woocommerce/i.test(b)],
  ['Elementor', (b) => /elementor/i.test(b)],
  ['Joomla', (b) => /\/media\/jui\/|content="Joomla/i.test(b)],
  ['Drupal', (b, h) => /Drupal\.settings|\/sites\/default\/files|content="Drupal/i.test(b) || h.has('x-drupal-cache')],
  ['Magento', (b) => /Mage\.Cookies|\/static\/version\d+\/frontend\//i.test(b)],
  ['Shopify', (b, h) => /cdn\.shopify\.com/i.test(b) || h.has('x-shopify-stage')],
  ['Wix', (b) => /static\.wixstatic\.com|wix-code/i.test(b)],
  ['Laravel', (b, h, c) => c.some(x => /^(laravel_session|XSRF-TOKEN)=/i.test(x))],
  ['CodeIgniter', (b, h, c) => c.some(x => /^ci_session=/i.test(x))],
  ['PHP', (b, h, c) => /php/i.test(h.get('x-powered-by') || '') || c.some(x => /^PHPSESSID=/i.test(x))],
  ['ASP.NET', (b, h, c) => h.has('x-aspnet-version') || /__VIEWSTATE/.test(b) || c.some(x => /ASP\.NET_SessionId/i.test(x))],
  ['Next.js', (b, h) => /__NEXT_DATA__|\/_next\/static/.test(b) || /next\.js/i.test(h.get('x-powered-by') || '')],
  ['Nuxt', (b) => /__NUXT__|\/_nuxt\//.test(b)],
  ['React', (b) => /data-reactroot|react(-dom)?(\.production)?(\.min)?\.js/i.test(b)],
  ['Vue.js', (b) => /vue(\.runtime)?(\.global)?(\.prod)?(\.min)?\.js|data-v-[0-9a-f]{8}/i.test(b)],
  ['Angular', (b) => /ng-version=|angular(\.min)?\.js/i.test(b)],
  ['Alpine.js', (b) => /alpinejs|x-data=/i.test(b)],
  ['Bootstrap', (b) => /bootstrap(\.bundle)?(\.min)?\.(css|js)/i.test(b)],
  ['Tailwind CSS', (b) => /tailwind/i.test(b)],
  ['Cloudflare', (b, h) => h.has('cf-ray') || /cloudflare/i.test(h.get('server') || '')],
  ['Google Analytics / GTM', (b) => /googletagmanager\.com|google-analytics\.com/i.test(b)],
  ['reCAPTCHA', (b) => /recaptcha/i.test(b)],
  ['LiteSpeed', (b, h) => /litespeed/i.test(h.get('server') || '')],
  ['nginx', (b, h) => /nginx/i.test(h.get('server') || '')],
  ['Apache', (b, h) => /apache/i.test(h.get('server') || '')],
];

// Library, regex capturing version from URL or banner, first safe version, advisory
const LIBS = [
  ['jQuery', [/jquery[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, /jquery\.js\?ver=(\d+\.\d+\.\d+)/i, /jQuery v(\d+\.\d+\.\d+)/], '3.5.0', 'CVE-2020-11022/11023 (XSS in htmlPrefilter)'],
  ['jQuery Migrate', [/jquery-migrate[.-]?(\d+\.\d+\.\d+)/i, /jquery-migrate(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)/i], '3.0.0', 'Old migrate builds re-enable unsafe jQuery behaviour'],
  ['jQuery UI', [/jquery-ui[.-]?(\d+\.\d+\.\d+)/i, /jquery\/ui\/[\w.-]+\.js\?ver=(\d+\.\d+\.\d+)/i], '1.13.2', 'CVE-2021-41182/41183/41184, CVE-2022-31160 (XSS)'],
  ['Bootstrap', [/bootstrap[.@/-]?(\d+\.\d+\.\d+)/i, /Bootstrap v(\d+\.\d+\.\d+)/], '4.3.1', 'CVE-2019-8331 (XSS in tooltip/popover)'],
  ['AngularJS', [/angular(?:js)?[.@/-]?(1\.\d+\.\d+)/i], '9.0.0', 'AngularJS 1.x is end-of-life with unpatched XSS/ReDoS CVEs'],
  ['Lodash', [/lodash[.@/-]?(\d+\.\d+\.\d+)/i], '4.17.21', 'CVE-2021-23337 (command injection), CVE-2020-8203 (prototype pollution)'],
  ['Moment.js', [/moment[.@/-]?(\d+\.\d+\.\d+)/i], '2.29.4', 'CVE-2022-31129 (ReDoS), CVE-2022-24785 (path traversal)'],
  ['Handlebars', [/handlebars[.@/-]?(\d+\.\d+\.\d+)/i], '4.7.7', 'CVE-2021-23369 (RCE via template compilation)'],
  ['DOMPurify', [/dompurify[.@/-]?(\d+\.\d+\.\d+)/i], '3.1.3', 'Multiple mXSS bypasses before 3.1.3'],
  ['Swiper', [/swiper[.@/-]?(\d+\.\d+\.\d+)/i], '6.5.1', 'CVE-2021-23370 (prototype pollution)'],
  ['Select2', [/select2[.@/-]?(\d+\.\d+\.\d+)/i], '4.0.6', 'XSS in older versions'],
];

export function cmpVer(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

export async function cmsChecks(ctx) {
  const { home } = ctx;
  const base = ctx.finalOrigin;
  const body = home.text || '';
  const f = [];

  const tech = TECH.filter(([, fn]) => { try { return fn(body, home.headers, home.setCookies || []); } catch { return false; } }).map(([n]) => n);
  const gen = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)?.[1];
  ctx.tech = tech;
  f.push({ id: 'tech.stack', category: 'Technology', title: 'Detected technologies', status: 'info', severity: 'info',
    detail: tech.length ? tech.join(', ') + (gen ? ` | generator: ${gen}` : '') : 'Nothing fingerprinted' });

  // ---- WordPress ----
  if (tech.includes('WordPress')) {
    let ver = gen?.match(/WordPress\s+([\d.]+)/i)?.[1];
    if (!ver) {
      const feed = await request(base + '/feed/', { timeout: 10000, maxBody: 64 * 1024 });
      ver = feed.text.match(/wordpress\.org\/\?v=([\d.]+)/i)?.[1];
    }
    if (!ver) ver = body.match(/wp-(?:includes|emoji)[^"']*\?ver=(\d+\.\d+(?:\.\d+)?)/i)?.[1];
    const latest = await latestWp();
    let st = 'info', sev = 'info', det = ver ? `WordPress ${ver}` : 'Version hidden (good)';
    if (ver && latest) {
      det += ` (latest ${latest})`;
      if (cmpVer(ver, latest) < 0) { st = 'warn'; sev = ver.split('.')[0] !== latest.split('.')[0] || Number(ver.split('.')[1]) < Number(latest.split('.')[1]) - 1 ? 'high' : 'medium'; }
      else { st = 'pass'; }
    } else if (ver) {
      st = 'warn'; sev = 'low'; det += ' (could not reach api.wordpress.org to compare with latest)';
    }
    if (ver) det += ' — version is publicly disclosed';
    f.push({ id: 'wp.version', category: 'CMS', title: 'WordPress core version', status: st, severity: sev, detail: det,
      fix: st === 'warn' ? 'Update WordPress core, then remove the generator tag (remove_action(\'wp_head\',\'wp_generator\')).' : undefined });

    // Users REST endpoint
    const u = await request(base + '/wp-json/wp/v2/users', { timeout: 10000, maxBody: 128 * 1024 });
    let users = [];
    try { users = JSON.parse(u.text).filter(x => x.slug).map(x => x.slug); } catch {}
    f.push({ id: 'wp.users', category: 'CMS', title: 'WordPress user enumeration (REST API)', status: users.length ? 'fail' : 'pass', severity: users.length ? 'medium' : 'info',
      detail: users.length ? `Usernames exposed via /wp-json/wp/v2/users: ${users.slice(0, 10).join(', ')}` : 'Users endpoint not exposing usernames',
      fix: users.length ? 'Restrict the users endpoint (security plugin, or rest_endpoints filter unsetting /wp/v2/users for unauthenticated users).' : undefined });

    const authorEnum = await request(base + '/?author=1', { redirect: 'manual', readBody: false, timeout: 10000 });
    const loc = authorEnum.headers.get('location') || '';
    const slug = loc.match(/\/author\/([^/]+)/)?.[1];
    if (slug) f.push({ id: 'wp.author', category: 'CMS', title: 'WordPress author enumeration (?author=1)', status: 'warn', severity: 'low', detail: `Redirects to /author/${slug}/`, fix: 'Block ?author= scans via security plugin or rewrite rule.' });

    // xmlrpc
    const x = await request(base + '/xmlrpc.php', { timeout: 10000, maxBody: 8 * 1024 });
    const xmlrpc = /XML-RPC server accepts POST requests only/i.test(x.text);
    f.push({ id: 'wp.xmlrpc', category: 'CMS', title: 'XML-RPC enabled', status: xmlrpc ? 'warn' : 'pass', severity: xmlrpc ? 'medium' : 'info',
      detail: xmlrpc ? '/xmlrpc.php is enabled (brute-force amplification / pingback DDoS vector)' : 'xmlrpc.php disabled or blocked',
      fix: xmlrpc ? 'Disable XML-RPC (add_filter(\'xmlrpc_enabled\', \'__return_false\') or block /xmlrpc.php at the server) unless Jetpack/app needs it.' : undefined });

    // Login page & readme
    const readme = await request(base + '/readme.html', { timeout: 8000, maxBody: 16 * 1024 });
    if (readme.status === 200 && /WordPress/i.test(readme.text)) f.push({ id: 'wp.readme', category: 'CMS', title: 'readme.html present', status: 'warn', severity: 'low', detail: `${base}/readme.html reveals WordPress install`, fix: 'Delete readme.html and license.txt from the web root.' });
    const login = await request(base + '/wp-login.php', { redirect: 'manual', readBody: false, timeout: 8000 });
    if (login.status === 200) f.push({ id: 'wp.login', category: 'CMS', title: 'Default login URL exposed', status: 'info', severity: 'info', detail: '/wp-login.php reachable — ensure rate limiting / 2FA', fix: 'Add login rate-limiting, 2FA, and optionally move or restrict wp-login.php.' });

    // Plugins & themes from page source
    const plugins = {};
    for (const m of body.matchAll(/wp-content\/plugins\/([a-z0-9_-]+)\/[^"'\s]*?(?:\?ver=([\d.]+))?["'\s]/gi)) {
      plugins[m[1]] = plugins[m[1]] || m[2] || '?';
    }
    const themes = [...new Set([...body.matchAll(/wp-content\/themes\/([a-z0-9_-]+)\//gi)].map(m => m[1]))];
    if (Object.keys(plugins).length || themes.length) {
      f.push({ id: 'wp.components', category: 'CMS', title: 'WordPress plugins/themes visible in source', status: 'info', severity: 'info',
        detail: `Plugins: ${Object.entries(plugins).map(([k, v]) => `${k}${v !== '?' ? '@' + v : ''}`).join(', ') || '-'} | Themes: ${themes.join(', ') || '-'}`,
        fix: 'Keep every plugin/theme updated; run the wpscan tool (with an API token) for CVE matching.' });
    }
  }

  // ---- Laravel debug mode ----
  if (tech.includes('Laravel') || tech.includes('PHP')) {
    const d = await request(base + '/__sjscan_debug_probe_' + Date.now(), { timeout: 10000, maxBody: 256 * 1024 });
    if (/Whoops!|Ignition|laravel\/framework|Symfony\\Component\\HttpKernel\\Exception|vendor\/laravel/i.test(d.text)) {
      f.push({ id: 'laravel.debug', category: 'CMS', title: 'Debug mode / stack traces exposed', status: 'fail', severity: 'high',
        detail: 'Error pages reveal framework stack traces (APP_DEBUG=true?)', fix: 'Set APP_DEBUG=false and APP_ENV=production in .env, then php artisan config:cache.' });
    }
  }

  // ---- Outdated JS libraries ----
  const scripts = [...body.matchAll(/<(?:script|link)[^>]+(?:src|href)=["']([^"']+)["']/gi)].map(m => m[1]);
  const haystack = scripts.join('\n') + '\n' + body.slice(0, 200000);
  const vuln = [], ok = [];
  for (const [name, regs, safe, adv] of LIBS) {
    let ver;
    for (const r of regs) { ver = haystack.match(r)?.[1]; if (ver) break; }
    if (!ver) continue;
    if (name === 'AngularJS' || cmpVer(ver, safe) < 0) vuln.push(`${name} ${ver} (< ${name === 'AngularJS' ? 'EOL' : safe}: ${adv})`);
    else ok.push(`${name} ${ver}`);
  }
  if (vuln.length || ok.length) {
    f.push({ id: 'js.libs', category: 'Vulnerable components', title: 'JavaScript library versions', status: vuln.length ? 'fail' : 'pass',
      severity: vuln.length ? 'medium' : 'info', detail: vuln.length ? vuln.join(' | ') : `Up to date: ${ok.join(', ')}`,
      fix: vuln.length ? 'Upgrade the listed libraries to the safe versions (or newer) and re-test.' : undefined });
  }

  // Third-party scripts without Subresource Integrity
  const ext = [...body.matchAll(/<script[^>]+src=["'](https?:\/\/[^"']+)["'][^>]*>/gi)]
    .filter(m => !m[1].includes(ctx.target.host) && !/integrity=/i.test(m[0])).map(m => new URL(m[1]).host);
  const uniq = [...new Set(ext)];
  if (uniq.length) f.push({ id: 'js.sri', category: 'Vulnerable components', title: 'Third-party scripts without SRI', status: 'info', severity: 'info',
    detail: `${ext.length} external script(s) from: ${uniq.slice(0, 12).join(', ')}`, fix: 'Add integrity="sha384-…" crossorigin="anonymous" to static CDN scripts.' });

  return f;
}

let wpCache;
async function latestWp() {
  if (wpCache !== undefined) return wpCache;
  const r = await request('https://api.wordpress.org/core/version-check/1.7/', { timeout: 8000 });
  try { wpCache = JSON.parse(r.text).offers[0].current; } catch { wpCache = null; }
  return wpCache;
}
