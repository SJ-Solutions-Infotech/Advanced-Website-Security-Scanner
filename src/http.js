// Thin fetch wrapper: timeouts, timing, body size cap, manual redirects
export const UA = 'Mozilla/5.0 (compatible; SJ-WebScan/1.0; +https://sjweb4u.com)';
const MAX_BODY = 3 * 1024 * 1024;

export async function request(url, opts = {}) {
  const { method = 'GET', timeout = 15000, redirect = 'follow', headers = {}, body, maxBody = MAX_BODY, readBody = true } = opts;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  const t0 = performance.now();
  try {
    const res = await fetch(url, {
      method, redirect, body, signal: ctrl.signal,
      headers: { 'User-Agent': UA, 'Accept': '*/*', ...headers },
    });
    const ttfb = performance.now() - t0;
    let text = '';
    let bytes = 0;
    if (readBody && method !== 'HEAD' && res.body) {
      const reader = res.body.getReader();
      const chunks = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.length;
        if (bytes <= maxBody) chunks.push(value);
        else { await reader.cancel().catch(() => {}); break; }
      }
      text = new TextDecoder('utf-8', { fatal: false }).decode(Buffer.concat(chunks.map(c => Buffer.from(c))));
    }
    const total = performance.now() - t0;
    return {
      ok: true, url: res.url || url, status: res.status, headers: res.headers,
      setCookies: typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [],
      text, bytes, ttfb: Math.round(ttfb), total: Math.round(total), redirected: res.redirected,
    };
  } catch (e) {
    return { ok: false, url, status: 0, error: e.name === 'AbortError' ? `Timeout after ${timeout}ms` : (e.cause?.code || e.message), headers: new Headers(), setCookies: [], text: '', bytes: 0 };
  } finally {
    clearTimeout(timer);
  }
}

// Run async fns with limited concurrency
export async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  });
  await Promise.all(workers);
  return out;
}
