// Performance, caching, compression, mixed content, broken links, basic page health
import { request, pool } from '../http.js';

export async function healthChecks(ctx, opts = {}) {
  const { home } = ctx;
  const body = home.text || '';
  const h = home.headers;
  const f = [];
  const C = 'Performance';

  f.push({ id: 'perf.status', category: 'Health', title: 'Homepage status', status: home.status >= 200 && home.status < 400 ? 'pass' : 'fail',
    severity: home.status >= 500 ? 'high' : home.status >= 400 ? 'medium' : 'info', detail: `HTTP ${home.status} at ${home.url}${ctx.redirectChain?.length ? ` (via ${ctx.redirectChain.length} redirect(s): ${ctx.redirectChain.join(' → ')})` : ''}` });

  // Average TTFB over 3 samples
  const samples = [home.ttfb];
  for (let i = 0; i < 2; i++) { const r = await request(home.url, { timeout: 20000 }); if (r.ok) samples.push(r.ttfb); }
  const ttfb = Math.round(samples.reduce((a, b) => a + b, 0) / samples.length);
  f.push({ id: 'perf.ttfb', category: C, title: 'Time to first byte (avg of 3)', status: ttfb < 600 ? 'pass' : ttfb < 1500 ? 'warn' : 'fail',
    severity: ttfb < 600 ? 'info' : ttfb < 1500 ? 'low' : 'medium', detail: `${ttfb} ms (samples: ${samples.join(', ')} ms) — measured from the scanner's location`,
    fix: ttfb >= 600 ? 'Enable full-page caching (LiteSpeed Cache / WP Rocket / Laravel response cache), OPcache, a CDN, and check slow DB queries.' : undefined });

  f.push({ id: 'perf.load', category: C, title: 'HTML download time', status: home.total < 2000 ? 'pass' : home.total < 4000 ? 'warn' : 'fail', severity: home.total < 2000 ? 'info' : 'low', detail: `${home.total} ms` });

  const kb = Math.round(home.bytes / 1024);
  f.push({ id: 'perf.size', category: C, title: 'HTML document size', status: kb < 200 ? 'pass' : kb < 600 ? 'warn' : 'fail', severity: kb < 200 ? 'info' : 'low',
    detail: `${kb} KB (uncompressed)`, fix: kb >= 200 ? 'Reduce inline CSS/JS/SVG, page-builder bloat and inline base64 images.' : undefined });

  // Compression
  const comp = await request(home.url, { headers: { 'Accept-Encoding': 'br, gzip, deflate' }, readBody: false, timeout: 15000 });
  const enc = comp.headers.get('content-encoding') || h.get('content-encoding');
  f.push({ id: 'perf.compression', category: C, title: 'Text compression', status: enc ? 'pass' : 'fail', severity: enc ? 'info' : 'medium',
    detail: enc ? `content-encoding: ${enc}` : 'No gzip/brotli compression on HTML', fix: enc ? undefined : 'Enable gzip or brotli (nginx gzip on; Apache mod_deflate).' });

  // Caching on static assets
  const assets = [...body.matchAll(/<(?:link|script|img)[^>]+(?:href|src)=["']([^"'#]+\.(?:css|js|png|jpe?g|webp|svg|woff2?)(?:\?[^"']*)?)["']/gi)]
    .map(m => { try { return new URL(m[1], home.url).href; } catch { return null; } })
    .filter(u => u && new URL(u).host === new URL(home.url).host);
  const sample = [...new Set(assets)].slice(0, 8);
  if (sample.length) {
    const noCache = [];
    let totalBytes = 0;
    await pool(sample, 4, async (u) => {
      const r = await request(u, { timeout: 15000 });
      totalBytes += r.bytes;
      const cc = r.headers.get('cache-control') || '';
      const age = Number(cc.match(/max-age=(\d+)/)?.[1] || 0);
      if (!r.headers.get('expires') && age < 86400) noCache.push(u.split('/').pop().slice(0, 60));
    });
    f.push({ id: 'perf.cache', category: C, title: 'Static asset caching', status: noCache.length === 0 ? 'pass' : noCache.length <= sample.length / 2 ? 'warn' : 'fail',
      severity: noCache.length ? 'low' : 'info', detail: noCache.length ? `${noCache.length}/${sample.length} sampled assets have < 1 day cache: ${noCache.join(', ')}` : `All ${sample.length} sampled assets cached ≥ 1 day`,
      fix: noCache.length ? 'Set Cache-Control: public, max-age=31536000, immutable on versioned CSS/JS/images/fonts.' : undefined });
  }
  const counts = {
    scripts: (body.match(/<script[^>]+src=/gi) || []).length,
    styles: (body.match(/<link[^>]+stylesheet/gi) || []).length,
    images: (body.match(/<img\b/gi) || []).length,
  };
  f.push({ id: 'perf.requests', category: C, title: 'Page resources', status: counts.scripts + counts.styles > 40 ? 'warn' : 'info', severity: counts.scripts + counts.styles > 40 ? 'low' : 'info',
    detail: `${counts.scripts} scripts, ${counts.styles} stylesheets, ${counts.images} images`, fix: counts.scripts + counts.styles > 40 ? 'Combine/defer scripts and remove unused plugins.' : undefined });
  const lazy = (body.match(/<img[^>]+loading=["']lazy/gi) || []).length;
  if (counts.images > 5) f.push({ id: 'perf.lazy', category: C, title: 'Image lazy-loading', status: lazy ? 'pass' : 'warn', severity: lazy ? 'info' : 'low', detail: `${lazy}/${counts.images} images use loading="lazy"` });

  // Mixed content
  if (home.url.startsWith('https://')) {
    const mixed = [...new Set([...body.matchAll(/<(?:script|link|img|iframe|source|video|audio|embed)[^>]+(?:src|href)=["'](http:\/\/[^"']+)["']/gi)].map(m => m[1]))];
    f.push({ id: 'mixed', category: 'SSL/TLS', title: 'Mixed content', status: mixed.length ? 'fail' : 'pass', severity: mixed.length ? 'medium' : 'info',
      detail: mixed.length ? `${mixed.length} http:// resource(s): ${mixed.slice(0, 8).join(', ')}` : 'No insecure resources on the homepage',
      fix: mixed.length ? 'Change resource URLs to https:// (WordPress: Better Search Replace http://domain → https://domain) and add CSP upgrade-insecure-requests.' : undefined });
  }

  // Basic page health
  const title = body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim();
  const desc = body.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)/i)?.[1];
  const viewport = /<meta[^>]+name=["']viewport/i.test(body);
  const lang = body.match(/<html[^>]+lang=["']([^"']+)/i)?.[1];
  const canonical = body.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)/i)?.[1];
  const issues = [];
  if (!title) issues.push('missing <title>');
  if (!desc) issues.push('missing meta description');
  if (!viewport) issues.push('missing viewport meta (not mobile-friendly)');
  if (!lang) issues.push('missing <html lang>');
  f.push({ id: 'page.basics', category: 'Health', title: 'Page basics', status: issues.length ? 'warn' : 'pass', severity: issues.length ? 'low' : 'info',
    detail: issues.length ? issues.join('; ') : `title="${title.slice(0, 70)}"; lang=${lang}; canonical=${canonical || '-'}` });

  // Broken links
  if (opts.links !== false) {
    const max = opts.maxLinks || 60;
    const links = [...new Set([...body.matchAll(/<a[^>]+href=["']([^"'#]+)["']/gi)]
      .map(m => { try { return new URL(m[1], home.url).href; } catch { return null; } })
      .filter(u => u && /^https?:/.test(u)))].slice(0, max);
    const broken = [];
    await pool(links, 6, async (u) => {
      let r = await request(u, { method: 'HEAD', timeout: 12000, readBody: false });
      if (!r.ok || [403, 405, 501].includes(r.status)) r = await request(u, { timeout: 12000, maxBody: 1024 });
      if (!r.ok || r.status >= 400) broken.push(`${u} → ${r.status || r.error}`);
    });
    f.push({ id: 'links.broken', category: 'Health', title: 'Broken links (homepage)', status: broken.length ? 'warn' : 'pass', severity: broken.length ? 'low' : 'info',
      detail: broken.length ? `${broken.length}/${links.length} broken: ${broken.slice(0, 15).join(' | ')}` : `${links.length} links checked, none broken`,
      evidence: broken.length > 15 ? broken.join('\n') : undefined });
  }
  return f;
}
