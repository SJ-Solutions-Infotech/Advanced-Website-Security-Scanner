// Target parsing + SSRF guard (blocks private/internal addresses unless explicitly allowed)
import dns from 'node:dns/promises';
import net from 'node:net';

export function normalizeTarget(input) {
  if (!input || typeof input !== 'string') throw new Error('Target URL is required');
  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  let u;
  try { u = new URL(raw); } catch { throw new Error(`Invalid URL: ${input}`); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http/https targets are supported');
  if (!/^[a-z0-9.-]+$/i.test(u.hostname) && !net.isIP(u.hostname.replace(/^\[|\]$/g, ''))) {
    throw new Error(`Invalid hostname: ${u.hostname}`);
  }
  u.hash = '';
  return {
    url: u.origin + (u.pathname || '/') + (u.search || ''),
    origin: u.origin,
    host: u.hostname.replace(/^\[|\]$/g, ''),
    port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
    protocol: u.protocol.replace(':', ''),
    // registrable-ish domain (good enough for OSINT tools; strips leading www.)
    domain: u.hostname.replace(/^www\./i, ''),
  };
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l.startsWith('::ffff:')) return isPrivateIp(l.slice(7));
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
  }
  return true;
}

export async function assertPublicTarget(host, allowPrivate = false) {
  if (allowPrivate) return;
  const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true }).catch(() => [])).map(r => r.address);
  if (!ips.length) throw new Error(`Could not resolve ${host}`);
  const bad = ips.filter(isPrivateIp);
  if (bad.length) {
    throw new Error(`${host} resolves to a private/internal address (${bad.join(', ')}). Use --allow-private (CLI) or ALLOW_PRIVATE=1 (server) to scan internal hosts.`);
  }
}
