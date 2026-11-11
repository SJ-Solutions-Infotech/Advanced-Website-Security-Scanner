// SSL/TLS certificate, protocol and HTTP/2 checks (native node:tls, no external tools)
import tls from 'node:tls';

function handshake(host, port, extra = {}) {
  return new Promise((resolve) => {
    const sock = tls.connect({
      host, port, servername: host, rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1'], timeout: 10000, ...extra,
    });
    const done = (r) => { try { sock.destroy(); } catch {} resolve(r); };
    sock.once('secureConnect', () => done({
      ok: true, authorized: sock.authorized, authError: sock.authorizationError,
      protocol: sock.getProtocol(), alpn: sock.alpnProtocol, cipher: sock.getCipher(),
      cert: sock.getPeerCertificate(false),
    }));
    sock.once('timeout', () => done({ ok: false, error: 'timeout' }));
    sock.once('error', (e) => done({ ok: false, error: e.code || e.message }));
  });
}

export async function tlsChecks(ctx) {
  const { host } = ctx.target;
  const port = ctx.target.protocol === 'https' ? ctx.target.port : 443;
  const f = [];
  const r = await handshake(host, port);
  if (!r.ok) {
    f.push({ id: 'tls.handshake', category: 'SSL/TLS', title: 'HTTPS available', status: 'fail', severity: 'high',
      detail: `TLS handshake on port ${port} failed: ${r.error}`, fix: 'Install a valid TLS certificate (e.g. Let\'s Encrypt) and serve the site over HTTPS.' });
    return f;
  }
  const c = r.cert || {};
  const validTo = c.valid_to ? new Date(c.valid_to) : null;
  const days = validTo ? Math.floor((validTo - Date.now()) / 86400000) : null;

  f.push({ id: 'tls.trusted', category: 'SSL/TLS', title: 'Certificate trusted', status: r.authorized ? 'pass' : 'fail',
    severity: r.authorized ? 'info' : 'high',
    detail: r.authorized ? `Issued by ${c.issuer?.O || c.issuer?.CN || 'unknown'}` : `Certificate not trusted: ${r.authError}`,
    fix: r.authorized ? undefined : 'Use a certificate from a public CA, include the full intermediate chain, and make sure the hostname is in the SAN list.' });

  if (days !== null) {
    f.push({ id: 'tls.expiry', category: 'SSL/TLS', title: 'Certificate expiry',
      status: days < 0 ? 'fail' : days < 14 ? 'fail' : days < 30 ? 'warn' : 'pass',
      severity: days < 14 ? 'high' : days < 30 ? 'medium' : 'info',
      detail: days < 0 ? `Expired ${-days} days ago (${validTo.toISOString().slice(0, 10)})` : `Expires in ${days} days (${validTo.toISOString().slice(0, 10)})`,
      fix: days < 30 ? 'Renew the certificate and enable auto-renewal (certbot renew / hosting panel AutoSSL).' : undefined });
  }

  f.push({ id: 'tls.protocol', category: 'SSL/TLS', title: 'Negotiated protocol', status: ['TLSv1.3', 'TLSv1.2'].includes(r.protocol) ? 'pass' : 'fail',
    severity: ['TLSv1.3', 'TLSv1.2'].includes(r.protocol) ? 'info' : 'high',
    detail: `${r.protocol} / ${r.cipher?.name}` });

  // Legacy protocol support (TLS 1.0 / 1.1)
  const legacy = await handshake(host, port, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0', ALPNProtocols: undefined });
  f.push({ id: 'tls.legacy', category: 'SSL/TLS', title: 'Legacy TLS 1.0/1.1 disabled', status: legacy.ok ? 'warn' : 'pass',
    severity: legacy.ok ? 'medium' : 'info',
    detail: legacy.ok ? `Server still accepts ${legacy.protocol}` : 'TLS 1.0/1.1 rejected',
    fix: legacy.ok ? 'Disable TLS 1.0 and 1.1 (nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3).' : undefined });

  f.push({ id: 'tls.http2', category: 'Performance', title: 'HTTP/2 support', status: r.alpn === 'h2' ? 'pass' : 'warn',
    severity: r.alpn === 'h2' ? 'info' : 'low',
    detail: r.alpn ? `ALPN negotiated ${r.alpn}` : 'No ALPN / HTTP/1.1 only',
    fix: r.alpn === 'h2' ? undefined : 'Enable HTTP/2 on the web server or CDN for faster multiplexed loading.' });

  if (c.subject) {
    f.push({ id: 'tls.details', category: 'SSL/TLS', title: 'Certificate details', status: 'info', severity: 'info',
      detail: `CN=${c.subject.CN || '-'}; SAN=${(c.subjectaltname || '').slice(0, 300)}; key=${c.bits || '?'} bits; serial=${c.serialNumber || '?'}` });
  }
  return f;
}
