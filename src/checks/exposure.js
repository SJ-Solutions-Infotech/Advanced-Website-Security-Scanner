// Exposed sensitive files, directory listing, security.txt, robots/sitemap.
// Uses content signatures + a soft-404 baseline to avoid false positives.
import { request, pool } from '../http.js';

// [path, severity, title, signature regex that must match the body]
const SENSITIVE = [
  ['/.env', 'critical', 'Environment file (.env)', /^(APP_|DB_|MAIL_|AWS_|SECRET|REDIS_|[A-Z_]{3,}=)/m],
  ['/.env.backup', 'critical', 'Environment backup', /^[A-Z_]{3,}=/m],
  ['/.env.example', 'low', '.env.example', /^[A-Z_]{3,}=/m],
  ['/.git/HEAD', 'critical', 'Git repository (.git)', /^ref:\s*refs\//],
  ['/.git/config', 'critical', 'Git config', /\[core\]/],
  ['/.svn/entries', 'high', 'SVN metadata', /^\d+\s*$|svn:/m],
  ['/.hg/hgrc', 'high', 'Mercurial metadata', /\[paths\]/],
  ['/.DS_Store', 'low', '.DS_Store file', /Bud1/],
  ['/.htpasswd', 'high', '.htpasswd', /^[\w.-]+:[$\w./]{10,}/m],
  ['/.htaccess', 'low', '.htaccess readable', /(RewriteEngine|Deny from|Require all|<IfModule)/i],
  ['/wp-config.php.bak', 'critical', 'wp-config backup', /DB_PASSWORD|DB_NAME/],
  ['/wp-config.php~', 'critical', 'wp-config editor backup', /DB_PASSWORD|DB_NAME/],
  ['/wp-config.php.save', 'critical', 'wp-config save file', /DB_PASSWORD|DB_NAME/],
  ['/wp-config.old', 'critical', 'wp-config old copy', /DB_PASSWORD|DB_NAME/],
  ['/config.php.bak', 'high', 'config.php backup', /<\?php|password/i],
  ['/phpinfo.php', 'high', 'phpinfo() page', /PHP Version|phpinfo\(\)/],
  ['/info.php', 'high', 'phpinfo() page', /PHP Version|phpinfo\(\)/],
  ['/test.php', 'medium', 'phpinfo()/test page', /PHP Version/],
  ['/storage/logs/laravel.log', 'high', 'Laravel log', /\[\d{4}-\d{2}-\d{2} [\d:]+\]\s+\w+\.(ERROR|INFO|DEBUG|WARNING)/],
  ['/wp-content/debug.log', 'high', 'WordPress debug.log', /PHP (Fatal|Warning|Notice|Deprecated)/],
  ['/debug.log', 'medium', 'debug.log', /PHP (Fatal|Warning|Notice)|\[\d{2}-\w{3}-\d{4}/],
  ['/error_log', 'medium', 'PHP error_log', /PHP (Fatal|Warning|Notice|Parse)/],
  ['/backup.sql', 'critical', 'SQL dump', /(CREATE TABLE|INSERT INTO|mysqldump)/i],
  ['/database.sql', 'critical', 'SQL dump', /(CREATE TABLE|INSERT INTO|mysqldump)/i],
  ['/dump.sql', 'critical', 'SQL dump', /(CREATE TABLE|INSERT INTO|mysqldump)/i],
  ['/db.sql', 'critical', 'SQL dump', /(CREATE TABLE|INSERT INTO|mysqldump)/i],
  ['/backup.zip', 'critical', 'Backup archive', /^PK\x03\x04/],
  ['/backup.tar.gz', 'critical', 'Backup archive', /^\x1f\x8b/],
  ['/site.zip', 'critical', 'Site archive', /^PK\x03\x04/],
  ['/composer.json', 'low', 'composer.json', /"require"\s*:/],
  ['/composer.lock', 'low', 'composer.lock (dependency versions)', /"packages"\s*:/],
  ['/package.json', 'low', 'package.json', /"(dependencies|devDependencies)"\s*:/],
  ['/server-status', 'medium', 'Apache server-status', /Apache Server Status/i],
  ['/server-info', 'medium', 'Apache server-info', /Apache Server Information/i],
  ['/adminer.php', 'high', 'Adminer DB tool', /adminer/i],
  ['/phpmyadmin/', 'medium', 'phpMyAdmin', /phpMyAdmin/],
  ['/_profiler/', 'high', 'Symfony profiler', /Symfony Profiler/i],
  ['/telescope', 'high', 'Laravel Telescope', /Telescope/],
  ['/horizon', 'medium', 'Laravel Horizon', /Horizon/],
  ['/actuator/env', 'critical', 'Spring actuator env', /"propertySources"/],
  ['/.vscode/sftp.json', 'critical', 'VS Code SFTP credentials', /"(password|host)"\s*:/],
  ['/sftp-config.json', 'critical', 'Sublime SFTP credentials', /"(password|host)"\s*:/],
  ['/.idea/workspace.xml', 'low', 'JetBrains workspace', /<project version/],
  ['/docker-compose.yml', 'medium', 'docker-compose.yml', /services:/],
  ['/id_rsa', 'critical', 'Private SSH key', /BEGIN (OPENSSH|RSA) PRIVATE KEY/],
];

const LISTING_DIRS = ['/uploads/', '/wp-content/uploads/', '/images/', '/assets/', '/backup/', '/files/', '/storage/', '/vendor/'];

export async function exposureChecks(ctx) {
  const { origin } = ctx.target;
  const base = ctx.finalOrigin || origin;
  const f = [];

  // Soft-404 baseline: what does a guaranteed-missing path look like?
  const rnd = `/__sjscan_${Math.random().toString(36).slice(2)}.txt`;
  const baseline = await request(base + rnd, { timeout: 10000 });
  const soft404 = baseline.status === 200;

  const hits = [];
  await pool(SENSITIVE, 6, async ([path, sev, title, sig]) => {
    const r = await request(base + path, { redirect: 'manual', timeout: 10000, maxBody: 256 * 1024 });
    if (r.status !== 200 || !r.text) return;
    if (soft404 && Math.abs(r.bytes - baseline.bytes) < 32) return;
    if (!sig.test(r.text)) return;
    hits.push({ path, sev, title, bytes: r.bytes, snippet: redact(r.text.slice(0, 160)) });
  });

  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  hits.sort((a, b) => order[a.sev] - order[b.sev]);
  for (const h of hits) {
    f.push({ id: `expose${h.path}`, category: 'Exposed files', title: `${h.title} publicly accessible`, status: h.sev === 'low' ? 'warn' : 'fail', severity: h.sev,
      detail: `${base}${h.path} (${h.bytes} bytes)`, evidence: h.snippet,
      fix: 'Remove the file from the web root or block it (nginx: location ~ /\\.(?!well-known) { deny all; }  Apache: <FilesMatch> deny). Rotate any credentials it contained.' });
  }
  if (!hits.length) {
    f.push({ id: 'expose.none', category: 'Exposed files', title: 'Sensitive file exposure', status: 'pass', severity: 'info', detail: `${SENSITIVE.length} common sensitive paths checked, none exposed` });
  }

  // Directory listing
  const listed = [];
  await pool(LISTING_DIRS, 4, async (d) => {
    const r = await request(base + d, { timeout: 10000, maxBody: 128 * 1024 });
    if (r.status === 200 && /<title>Index of \/|Directory listing for|<h1>Index of/i.test(r.text)) listed.push(d);
  });
  f.push({ id: 'dirlisting', category: 'Exposed files', title: 'Directory listing', status: listed.length ? 'fail' : 'pass', severity: listed.length ? 'medium' : 'info',
    detail: listed.length ? `Listing enabled: ${listed.join(', ')}` : 'No directory listing on common folders',
    fix: listed.length ? 'Disable autoindex (nginx: autoindex off; Apache: Options -Indexes).' : undefined });

  // security.txt
  const st = await request(base + '/.well-known/security.txt', { timeout: 8000, maxBody: 32 * 1024 });
  const hasSt = st.status === 200 && /^contact:/im.test(st.text);
  f.push({ id: 'securitytxt', category: 'Best practice', title: 'security.txt', status: hasSt ? 'pass' : 'info', severity: 'info',
    detail: hasSt ? 'Present' : 'Not found', fix: hasSt ? undefined : 'Publish /.well-known/security.txt with a Contact: line (RFC 9116).' });

  // robots.txt / sitemap
  const robots = await request(base + '/robots.txt', { timeout: 8000, maxBody: 64 * 1024 });
  const hasRobots = robots.status === 200 && /user-agent|disallow|sitemap/i.test(robots.text);
  const disallows = hasRobots ? [...robots.text.matchAll(/^disallow:\s*(\S+)/gim)].map(m => m[1]) : [];
  const interesting = disallows.filter(p => /admin|backup|private|secret|config|db|test|staging|old|tmp|dev/i.test(p));
  f.push({ id: 'robots', category: 'Health', title: 'robots.txt', status: hasRobots ? 'pass' : 'warn', severity: hasRobots ? 'info' : 'low',
    detail: hasRobots ? `${disallows.length} Disallow rule(s)${interesting.length ? `; sensitive-looking paths revealed: ${interesting.slice(0, 10).join(', ')}` : ''}` : 'Missing' });
  const smUrl = robots.text.match(/^sitemap:\s*(\S+)/im)?.[1] || base + '/sitemap.xml';
  const sm = await request(smUrl, { timeout: 10000, maxBody: 512 * 1024 });
  const hasSm = sm.status === 200 && /<(urlset|sitemapindex)/i.test(sm.text);
  f.push({ id: 'sitemap', category: 'Health', title: 'XML sitemap', status: hasSm ? 'pass' : 'warn', severity: hasSm ? 'info' : 'low',
    detail: hasSm ? `${smUrl} (${(sm.text.match(/<loc>/g) || []).length} entries)` : 'No sitemap found' });

  return f;
}

function redact(s) {
  return s.replace(/((?:PASS(?:WORD)?|SECRET|KEY|TOKEN)[A-Z_]*\s*[=:]\s*)\S+/gi, '$1***REDACTED***').replace(/[^\x20-\x7e\n]/g, '.');
}
