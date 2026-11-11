// DNS records, email security (SPF / DMARC / DKIM hint), CAA
import dns from 'node:dns/promises';

const safe = (p) => p.catch(() => []);

export async function dnsChecks(ctx) {
  const domain = ctx.target.domain;
  const f = [];
  const C = 'DNS & Email';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) return f;

  const [a, aaaa, mx, ns, txt, caa, dmarc] = await Promise.all([
    safe(dns.resolve4(domain)), safe(dns.resolve6(domain)), safe(dns.resolveMx(domain)), safe(dns.resolveNs(domain)),
    safe(dns.resolveTxt(domain)), safe(dns.resolveCaa(domain)), safe(dns.resolveTxt('_dmarc.' + domain)),
  ]);
  ctx.dns = { a, aaaa, mx, ns };

  f.push({ id: 'dns.records', category: C, title: 'DNS records', status: a.length || aaaa.length ? 'info' : 'fail', severity: a.length || aaaa.length ? 'info' : 'high',
    detail: `A: ${a.join(', ') || '-'} | AAAA: ${aaaa.join(', ') || '-'} | NS: ${ns.join(', ') || '-'} | MX: ${mx.map(m => `${m.priority} ${m.exchange}`).join(', ') || '-'}` });

  if (ns.length === 1) f.push({ id: 'dns.ns', category: C, title: 'Nameserver redundancy', status: 'warn', severity: 'low', detail: 'Only one NS record', fix: 'Use at least two nameservers on separate networks.' });

  const txts = txt.map(t => t.join(''));
  const spf = txts.filter(t => /^v=spf1/i.test(t));
  let spfStatus = 'pass', spfSev = 'info', spfDetail = spf[0], spfFix;
  if (!spf.length) { spfStatus = mx.length ? 'fail' : 'warn'; spfSev = mx.length ? 'medium' : 'low'; spfDetail = 'No SPF record'; spfFix = mx.length ? 'Add a TXT record like: v=spf1 include:_spf.google.com ~all (match your mail provider).' : 'Domain sends no mail? Add "v=spf1 -all" to stop spoofing.'; }
  else if (spf.length > 1) { spfStatus = 'fail'; spfSev = 'medium'; spfDetail = `${spf.length} SPF records (invalid — must be exactly one)`; spfFix = 'Merge into a single SPF TXT record.'; }
  else if (/\+all/i.test(spf[0])) { spfStatus = 'fail'; spfSev = 'high'; spfFix = 'Never use +all — it authorises the whole internet to send mail as you.'; }
  else if (/\?all/i.test(spf[0]) || !/[~-]all/i.test(spf[0])) { spfStatus = 'warn'; spfSev = 'low'; spfFix = 'End SPF with ~all or -all.'; }
  f.push({ id: 'dns.spf', category: C, title: 'SPF (email spoofing protection)', status: spfStatus, severity: spfSev, detail: spfDetail, fix: spfFix });

  const dm = dmarc.map(t => t.join('')).find(t => /^v=DMARC1/i.test(t));
  const pol = dm?.match(/;\s*p=(\w+)/i)?.[1]?.toLowerCase();
  f.push({ id: 'dns.dmarc', category: C, title: 'DMARC policy', status: !dm ? 'fail' : pol === 'none' ? 'warn' : 'pass',
    severity: !dm ? 'medium' : pol === 'none' ? 'low' : 'info', detail: dm || 'No DMARC record at _dmarc.' + domain,
    fix: !dm ? `Add TXT _dmarc.${domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}` : pol === 'none' ? 'Move from p=none to p=quarantine/reject once reports look clean.' : undefined });

  f.push({ id: 'dns.caa', category: C, title: 'CAA record', status: caa.length ? 'pass' : 'info', severity: 'info',
    detail: caa.length ? caa.map(c => `${Object.keys(c).filter(k => k !== 'critical').map(k => `${k} ${c[k]}`).join(' ')}`).join('; ') : 'No CAA — any CA may issue certificates',
    fix: caa.length ? undefined : 'Optional: add CAA records (e.g. 0 issue "letsencrypt.org") to restrict who can issue certificates.' });

  const verif = txts.filter(t => /verification|verify|site-verification/i.test(t)).map(t => t.split(/[=:]/)[0]);
  if (verif.length) f.push({ id: 'dns.txt', category: C, title: 'TXT verification records (OSINT)', status: 'info', severity: 'info', detail: `Services: ${[...new Set(verif)].join(', ')}` });
  return f;
}
