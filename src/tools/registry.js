// Registry of 27 trusted open-source OSINT / recon / vulnerability tools.
// Each entry builds an argv array (never a shell string) and optionally parses output.
//
//   passive (intrusive:false) — OSINT / fingerprinting, safe to run against any site
//   active  (intrusive:true)  — port scans, vuln templates, brute-force content discovery.
//                               Only run with --authorized (written permission from the owner).

import fs from 'node:fs';

const lines = (s) => s.split('\n').map(l => l.trim()).filter(Boolean);
const uniqLines = (s) => [...new Set(lines(s))];
const tail = (s, n = 40) => lines(s).slice(-n).join('\n');
const hostsOnly = (domain) => (s) => {
  const items = [...new Set(lines(s).map(l => l.toLowerCase().replace(/^\*\./, '')).filter(l => /^[a-z0-9.-]+$/.test(l) && l.endsWith(domain)))].sort();
  return { summary: `${items.length} subdomain(s)`, items, subdomains: items };
};

export function defaultWordlist() {
  const candidates = [
    process.env.WEBSCAN_WORDLIST,
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/dirb/wordlists/common.txt',
    new URL('../../wordlists/common.txt', import.meta.url).pathname,
  ].filter(Boolean);
  return candidates.find(p => { try { return fs.statSync(p).isFile(); } catch { return false; } });
}

export const TOOLS = [
  // ───────────── OSINT / passive recon ─────────────
  {
    id: 'whois', name: 'whois', category: 'OSINT', intrusive: false, bins: ['whois'],
    homepage: 'https://github.com/rfc1036/whois', install: 'apt install whois',
    args: (t) => [t.domain], timeout: 30,
    parse: (out) => {
      const pick = (re) => out.match(re)?.[1]?.trim();
      const reg = pick(/Registrar:\s*(.+)/i);
      const created = pick(/Creation Date:\s*(.+)/i) || pick(/created:\s*(.+)/i);
      const expires = pick(/(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|expires):\s*(.+)/i);
      const ns = [...new Set([...out.matchAll(/Name Server:\s*(\S+)/gi)].map(m => m[1].toLowerCase()))];
      const findings = [];
      if (expires) {
        const days = Math.floor((new Date(expires) - Date.now()) / 86400000);
        if (!isNaN(days) && days < 30) findings.push({ title: `Domain expires in ${days} days`, severity: days < 7 ? 'high' : 'medium', detail: expires, fix: 'Renew the domain and enable auto-renew.' });
      }
      return { summary: `Registrar: ${reg || '?'} | Created: ${created || '?'} | Expires: ${expires || '?'}`, items: ns, findings };
    },
  },
  {
    id: 'dig', name: 'dig (BIND)', category: 'OSINT', intrusive: false, bins: ['dig'],
    homepage: 'https://www.isc.org/bind/', install: 'apt install dnsutils',
    args: (t) => ['+noall', '+answer', t.domain, 'A', t.domain, 'AAAA', t.domain, 'MX', t.domain, 'NS', t.domain, 'TXT', t.domain, 'SOA', 'www.' + t.domain, 'CNAME'], timeout: 30,
    parse: (out) => ({ summary: `${lines(out).length} record(s)`, items: lines(out) }),
  },
  {
    id: 'dnsrecon', name: 'DNSRecon', category: 'OSINT', intrusive: false, bins: ['dnsrecon'],
    homepage: 'https://github.com/darkoperator/dnsrecon', install: 'pipx install dnsrecon  (or apt install dnsrecon)',
    args: (t) => ['-d', t.domain, '-t', 'std,axfr'], timeout: 180,
    parse: (out) => {
      const findings = [];
      if (/Zone Transfer was successful/i.test(out)) findings.push({ title: 'DNS zone transfer (AXFR) allowed', severity: 'high', detail: 'A nameserver allows AXFR, leaking the full DNS zone.', fix: 'Restrict zone transfers to secondary nameservers only (allow-transfer).' });
      return { summary: findings.length ? 'AXFR allowed!' : tail(out, 3), items: lines(out).filter(l => /^\[\*\]\s+(A|AAAA|MX|NS|SOA|TXT|SRV|CNAME)\b/.test(l)).map(l => l.replace(/^\[\*\]\s+/, '')), findings };
    },
  },
  {
    id: 'subfinder', name: 'Subfinder', category: 'OSINT', intrusive: false, bins: ['subfinder'],
    homepage: 'https://github.com/projectdiscovery/subfinder', install: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    args: (t) => ['-d', t.domain, '-silent', '-all'], timeout: 300, parse: (out, t) => hostsOnly(t.domain)(out),
  },
  {
    id: 'amass', name: 'OWASP Amass', category: 'OSINT', intrusive: false, bins: ['amass'],
    homepage: 'https://github.com/owasp-amass/amass', install: 'go install -v github.com/owasp-amass/amass/v4/...@master  (or apt install amass)',
    args: (t) => ['enum', '-passive', '-d', t.domain, '-timeout', '5'], timeout: 420,
    parse: (out, t) => hostsOnly(t.domain)(lines(out).map(l => l.split(/\s+/)[0]).join('\n')),
  },
  {
    id: 'assetfinder', name: 'assetfinder', category: 'OSINT', intrusive: false, bins: ['assetfinder'],
    homepage: 'https://github.com/tomnomnom/assetfinder', install: 'go install github.com/tomnomnom/assetfinder@latest',
    args: (t) => ['--subs-only', t.domain], timeout: 180, parse: (out, t) => hostsOnly(t.domain)(out),
  },
  {
    id: 'theharvester', name: 'theHarvester', category: 'OSINT', intrusive: false, bins: ['theHarvester', 'theharvester'],
    homepage: 'https://github.com/laramies/theHarvester', install: 'apt install theharvester  (or pipx install theHarvester)',
    args: (t) => ['-d', t.domain, '-b', process.env.HARVESTER_SOURCES || 'crtsh,hackertarget,rapiddns,otx,duckduckgo', '-l', '200'], timeout: 300,
    parse: (out, t) => {
      const emails = [...new Set(out.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [])].filter(e => !/cmartorella|edge-security/i.test(e));
      const hosts = [...new Set((out.match(new RegExp(`[a-z0-9.-]+\\.${t.domain.replace(/\./g, '\\.')}`, 'gi')) || []).map(h => h.toLowerCase()))];
      return { summary: `${emails.length} email(s), ${hosts.length} host(s)`, items: [...emails, ...hosts], subdomains: hosts, emails };
    },
  },
  {
    id: 'waybackurls', name: 'waybackurls', category: 'OSINT', intrusive: false, bins: ['waybackurls'],
    homepage: 'https://github.com/tomnomnom/waybackurls', install: 'go install github.com/tomnomnom/waybackurls@latest',
    args: (t) => [t.domain], timeout: 240, parse: urlsParser,
  },
  {
    id: 'gau', name: 'gau (GetAllUrls)', category: 'OSINT', intrusive: false, bins: ['gau'],
    homepage: 'https://github.com/lc/gau', install: 'go install github.com/lc/gau/v2/cmd/gau@latest',
    args: (t) => ['--threads', '5', t.domain], timeout: 300, parse: urlsParser,
  },
  {
    id: 'dnsx', name: 'dnsx', category: 'OSINT', intrusive: false, bins: ['dnsx'],
    homepage: 'https://github.com/projectdiscovery/dnsx', install: 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    // feeds the target + any subdomains discovered by earlier tools via stdin
    stdin: (t, ctx) => [t.domain, ...(ctx.subdomains || [])].join('\n'),
    args: () => ['-silent', '-a', '-aaaa', '-cname', '-resp'], timeout: 300,
    parse: (out) => {
      const items = uniqLines(out);
      const dangling = items.filter(l => /CNAME\].*(s3\.amazonaws|herokuapp|github\.io|azurewebsites|cloudapp|wpengine|pantheonsite|shopify|zendesk|ghost\.io|surge\.sh|bitbucket\.io|netlify)/i.test(l));
      return { summary: `${items.length} resolved record(s)`, items, findings: dangling.length ? [{ title: 'CNAMEs pointing to third-party services (check for subdomain takeover)', severity: 'medium', detail: dangling.slice(0, 20).join('\n'), fix: 'Confirm each third-party resource still exists; remove DNS records for decommissioned services.' }] : [] };
    },
  },

  // ───────────── Fingerprinting / recon ─────────────
  {
    id: 'httpx', name: 'httpx (ProjectDiscovery)', category: 'Recon', intrusive: false, bins: ['httpx-pd', 'httpx'],
    homepage: 'https://github.com/projectdiscovery/httpx', install: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    stdin: (t, ctx) => [t.url, ...(ctx.subdomains || []).slice(0, 200)].join('\n'),
    args: () => ['-silent', '-json', '-title', '-tech-detect', '-status-code', '-web-server', '-ip', '-cdn', '-follow-redirects'], timeout: 300,
    parse: (out) => {
      const rows = lines(out).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      return { summary: `${rows.length} live host(s)`, items: rows.map(r => `${r.url} [${r.status_code || r['status-code']}] ${r.title || ''} {${(r.tech || r.technologies || []).join(', ')}} ${r.webserver || ''}`.trim()) };
    },
    validate: (out, err) => /Usage:.*httpx \[OPTIONS\] URL/i.test(err + out) ? 'Found the Python "httpx" CLI, not ProjectDiscovery httpx. Install PD httpx (or symlink it as httpx-pd).' : null,
  },
  {
    id: 'whatweb', name: 'WhatWeb', category: 'Recon', intrusive: false, bins: ['whatweb'],
    homepage: 'https://github.com/urbanadventurer/WhatWeb', install: 'apt install whatweb',
    args: (t) => ['--color=never', '--no-errors', '-a', '1', t.url], timeout: 120,
    parse: (out) => ({ summary: tail(out, 2).slice(0, 300), items: lines(out).flatMap(l => l.split(/,\s(?=[A-Z])/)).slice(0, 80) }),
  },
  {
    id: 'wafw00f', name: 'WAFW00F', category: 'Recon', intrusive: true, bins: ['wafw00f'],
    homepage: 'https://github.com/EnableSecurity/wafw00f', install: 'pipx install wafw00f  (or apt install wafw00f)',
    args: (t) => [t.url], timeout: 120,
    parse: (out) => {
      const waf = out.match(/is behind (.+?) WAF/i)?.[1] || (/No WAF detected/i.test(out) ? 'None detected' : 'Unknown');
      return { summary: `WAF: ${waf.replace(/\x1b\[[0-9;]*m/g, '')}`, items: lines(out).filter(l => /\[\+\]|\[-\]|\[~\]/.test(l)) };
    },
  },
  {
    id: 'katana', name: 'Katana crawler', category: 'Recon', intrusive: true, bins: ['katana'],
    homepage: 'https://github.com/projectdiscovery/katana', install: 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    args: (t) => ['-u', t.url, '-d', '3', '-jc', '-silent', '-rl', '30', '-ct', '240'], timeout: 300, parse: urlsParser,
  },
  {
    id: 'naabu', name: 'Naabu port scanner', category: 'Recon', intrusive: true, bins: ['naabu'],
    homepage: 'https://github.com/projectdiscovery/naabu', install: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest  (needs libpcap-dev)',
    args: (t) => ['-host', t.host, '-top-ports', '1000', '-silent', '-rate', '500'], timeout: 300, parse: portsParser,
  },
  {
    id: 'nmap', name: 'Nmap', category: 'Recon', intrusive: true, bins: ['nmap'],
    homepage: 'https://nmap.org', install: 'apt install nmap',
    args: (t) => ['-Pn', '-sV', '-T4', '--top-ports', '200', '--open', '--script', 'default,vulners', t.host], timeout: 900,
    parse: (out) => {
      const ports = lines(out).filter(l => /^\d+\/(tcp|udp)\s+open/.test(l));
      const risky = ports.filter(p => /^(21|23|25|110|143|445|1433|1521|2375|3306|3389|5432|5900|6379|8080|9200|11211|27017)\//.test(p));
      const cves = [...new Set(out.match(/CVE-\d{4}-\d{4,}/g) || [])];
      const findings = [];
      if (risky.length) findings.push({ title: 'Sensitive services exposed to the internet', severity: 'high', detail: risky.join('\n'), fix: 'Firewall database/admin/remote-desktop ports; allow only trusted IPs or VPN.' });
      if (cves.length) findings.push({ title: `${cves.length} CVE(s) matched to service versions (nmap vulners)`, severity: 'medium', detail: cves.slice(0, 40).join(', '), fix: 'Verify and patch the affected services.' });
      return { summary: `${ports.length} open port(s)`, items: ports, findings };
    },
  },

  // ───────────── TLS ─────────────
  {
    id: 'testssl', name: 'testssl.sh', category: 'TLS', intrusive: false, bins: ['testssl.sh', 'testssl'],
    homepage: 'https://github.com/testssl/testssl.sh', install: 'apt install testssl.sh  (or git clone --depth 1 https://github.com/testssl/testssl.sh)',
    args: (t) => ['--quiet', '--color', '0', '--warnings', 'off', '--fast', '--sneaky', `${t.host}:${t.protocol === 'https' ? t.port : 443}`], timeout: 600,
    parse: (out) => {
      const bad = lines(out).filter(l => /\b(VULNERABLE|NOT ok|offered \(NOT ok\)|CRITICAL|HIGH)\b/.test(l) && !/not vulnerable/i.test(l));
      const grade = out.match(/Overall Grade\s+(\S+)/)?.[1];
      return { summary: `${grade ? 'Grade ' + grade + ' | ' : ''}${bad.length} issue line(s)`, items: bad.slice(0, 60),
        findings: bad.length ? [{ title: 'TLS weaknesses reported by testssl.sh', severity: /VULNERABLE|CRITICAL/.test(bad.join()) ? 'high' : 'medium', detail: bad.slice(0, 25).join('\n'), fix: 'Disable the flagged protocols/ciphers; use Mozilla SSL Config Generator "intermediate" profile.' }] : [] };
    },
  },
  {
    id: 'sslyze', name: 'SSLyze', category: 'TLS', intrusive: false, bins: ['sslyze'],
    homepage: 'https://github.com/nabla-c0d3/sslyze', install: 'pipx install sslyze',
    args: (t) => [`${t.host}:${t.protocol === 'https' ? t.port : 443}`, '--mozilla_config=intermediate'], timeout: 300,
    parse: (out) => {
      const fail = /FAILED - Not compliant/i.test(out) || /not compliant/i.test(out);
      const reasons = lines(out).filter(l => /^\s*\*\s|\bshould\b|must/i.test(l)).slice(0, 30);
      return { summary: fail ? 'Not compliant with Mozilla intermediate config' : 'Compliant with Mozilla intermediate config', items: reasons,
        findings: fail ? [{ title: 'TLS config not compliant with Mozilla "intermediate" (SSLyze)', severity: 'medium', detail: reasons.join('\n'), fix: 'Apply https://ssl-config.mozilla.org intermediate settings.' }] : [] };
    },
  },
  {
    id: 'sslscan', name: 'sslscan', category: 'TLS', intrusive: false, bins: ['sslscan'],
    homepage: 'https://github.com/rbsec/sslscan', install: 'apt install sslscan',
    args: (t) => ['--no-colour', `${t.host}:${t.protocol === 'https' ? t.port : 443}`], timeout: 180,
    parse: (out) => {
      const enabled = lines(out).filter(l => /^(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+enabled/i.test(l));
      const weak = lines(out).filter(l => /^(Accepted|Preferred).*\b(RC4|DES|NULL|EXP|MD5|anon)\b/i.test(l));
      return { summary: `${enabled.length} legacy protocol(s), ${weak.length} weak cipher(s)`, items: [...enabled, ...weak],
        findings: enabled.length || weak.length ? [{ title: 'Legacy protocols / weak ciphers accepted (sslscan)', severity: weak.length ? 'high' : 'medium', detail: [...enabled, ...weak].join('\n'), fix: 'Disable SSLv3/TLS1.0/1.1 and weak cipher suites.' }] : [] };
    },
  },

  // ───────────── Vulnerability scanners ─────────────
  {
    id: 'nuclei', name: 'Nuclei', category: 'Vulnerability', intrusive: true, bins: ['nuclei'],
    homepage: 'https://github.com/projectdiscovery/nuclei', install: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates',
    args: (t) => ['-u', t.url, '-silent', '-jsonl', '-severity', 'low,medium,high,critical', '-rl', '50', '-c', '20', '-etags', 'dos,fuzz,intrusive', '-ni'], timeout: 1500,
    parse: (out) => {
      const rows = lines(out).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const findings = rows.map(r => ({
        title: r.info?.name || r['template-id'], severity: r.info?.severity || 'info',
        detail: `${r['matched-at'] || r.host}${r['extracted-results'] ? ' → ' + r['extracted-results'].join(', ') : ''}${r.info?.classification?.['cve-id'] ? ' [' + r.info.classification['cve-id'].join(', ') + ']' : ''}`,
        fix: r.info?.remediation || (r.info?.reference ? 'See: ' + [].concat(r.info.reference).slice(0, 2).join(' ') : undefined),
        template: r['template-id'],
      }));
      return { summary: `${findings.length} finding(s)`, items: findings.map(f => `[${f.severity}] ${f.title} — ${f.detail}`), findings };
    },
  },
  {
    id: 'nikto', name: 'Nikto', category: 'Vulnerability', intrusive: true, bins: ['nikto', 'nikto.pl'],
    homepage: 'https://github.com/sullo/nikto', install: 'apt install nikto',
    args: (t) => ['-h', t.url, '-nointeractive', '-ask', 'no', '-maxtime', '900s', '-Tuning', 'x6'], timeout: 1000,
    parse: (out) => {
      const items = lines(out).filter(l => l.startsWith('+ ') && !/Target (IP|Hostname|Port)|Start Time|End Time|host\(s\) tested|requests:/i.test(l)).map(l => l.slice(2));
      return { summary: `${items.length} observation(s)`, items,
        findings: items.filter(i => /OSVDB|CVE-|backdoor|default file|directory indexing|vulnerable|password|admin/i.test(i)).slice(0, 40).map(i => ({ title: 'Nikto: ' + i.slice(0, 120), severity: /CVE-|backdoor|password/i.test(i) ? 'high' : 'medium', detail: i })) };
    },
  },
  {
    id: 'zap', name: 'OWASP ZAP baseline', category: 'Vulnerability', intrusive: true, bins: ['zap-baseline.py', 'zap-baseline'],
    homepage: 'https://www.zaproxy.org/docs/docker/baseline-scan/', install: 'docker pull ghcr.io/zaproxy/zaproxy:stable  (then alias zap-baseline.py="docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py")',
    args: (t) => ['-t', t.url, '-I', '-m', '3'], timeout: 1200, okExitCodes: [0, 1, 2],
    parse: (out) => {
      const rows = lines(out).filter(l => /^(WARN-NEW|FAIL-NEW|WARN-INPROG|FAIL-INPROG):/.test(l));
      return { summary: tail(out, 1), items: rows,
        findings: rows.map(r => ({ title: 'ZAP: ' + r.replace(/^[A-Z-]+:\s*/, '').replace(/\s*\[\d+\].*$/, '').replace(/\s*x \d+$/, ''), severity: r.startsWith('FAIL') ? 'high' : 'low', detail: r })) };
    },
  },
  {
    id: 'wpscan', name: 'WPScan', category: 'CMS', intrusive: true, bins: ['wpscan'], onlyIf: (ctx) => ctx.tech?.includes('WordPress'),
    homepage: 'https://github.com/wpscanteam/wpscan', install: 'gem install wpscan  (free API token: https://wpscan.com — set WPSCAN_API_TOKEN)',
    args: (t) => ['--url', t.url, '--no-banner', '--random-user-agent', '--format', 'cli-no-colour', '--disable-tls-checks', '-e', 'vp,vt,u1-5,cb,dbe', '--plugins-detection', 'passive',
      ...(process.env.WPSCAN_API_TOKEN ? ['--api-token', process.env.WPSCAN_API_TOKEN] : [])], timeout: 1200, okExitCodes: [0, 5],
    parse: (out) => {
      const vulns = [...out.matchAll(/\|\s*\[!\]\s*Title:\s*(.+)/g)].map(m => m[1].trim());
      const outdated = lines(out).filter(l => /out of date|Insecure/i.test(l));
      return { summary: `${vulns.length} known vulnerability(ies), ${outdated.length} outdated/insecure component line(s)${process.env.WPSCAN_API_TOKEN ? '' : ' (no API token → no CVE data)'}`,
        items: [...outdated, ...vulns], findings: vulns.map(v => ({ title: 'WPScan: ' + v, severity: /unauth|RCE|SQL|Remote Code|Arbitrary File|Privilege/i.test(v) ? 'high' : 'medium', detail: v, fix: 'Update the affected plugin/theme/core to the fixed version.' })) };
    },
  },
  {
    id: 'droopescan', name: 'droopescan', category: 'CMS', intrusive: true, bins: ['droopescan'], onlyIf: (ctx) => ctx.tech?.some(x => ['Drupal', 'Joomla', 'WordPress'].includes(x)),
    homepage: 'https://github.com/SamJoan/droopescan', install: 'pipx install droopescan',
    args: (t) => ['scan', '-u', t.url, '-e', 'v,i,t'], timeout: 600,
    parse: (out) => ({ summary: tail(out, 2), items: lines(out).slice(0, 80) }),
  },

  // ───────────── Content discovery (wordlist-based) ─────────────
  {
    id: 'ffuf', name: 'ffuf', category: 'Content discovery', intrusive: true, bins: ['ffuf'], needsWordlist: true,
    homepage: 'https://github.com/ffuf/ffuf', install: 'go install github.com/ffuf/ffuf/v2@latest',
    args: (t, o) => ['-u', `${t.origin}/FUZZ`, '-w', o.wordlist, '-mc', '200,204,301,302,307,401,403', '-ac', '-t', '20', '-rate', '50', '-s'], timeout: 900,
    parse: (out, t) => ({ summary: `${uniqLines(out).length} path(s) found`, items: uniqLines(out).map(p => `${t.origin}/${p}`) }),
  },
  {
    id: 'gobuster', name: 'Gobuster', category: 'Content discovery', intrusive: true, bins: ['gobuster'], needsWordlist: true,
    homepage: 'https://github.com/OJ/gobuster', install: 'apt install gobuster  (or go install github.com/OJ/gobuster/v3@latest)',
    args: (t, o) => ['dir', '-u', t.origin, '-w', o.wordlist, '-q', '-t', '20', '--no-color', '-k', '--delay', '20ms'], timeout: 900,
    parse: (out) => ({ summary: `${lines(out).length} path(s) found`, items: lines(out) }),
    validate: (out, err) => /the server returns a status code that matches the provided options for non existing urls/i.test(err + out) ? 'Wildcard responses — site returns 200 for every path, so gobuster results are meaningless (ffuf -ac handles this).' : null,
  },
  {
    id: 'dirsearch', name: 'dirsearch', category: 'Content discovery', intrusive: true, bins: ['dirsearch'],
    homepage: 'https://github.com/maurosoria/dirsearch', install: 'pipx install dirsearch',
    args: (t) => ['-u', t.origin, '-q', '--no-color', '-t', '15', '--delay', '0.05', '-x', '404,429,500-599', '--format', 'plain'], timeout: 900,
    parse: (out) => {
      const items = lines(out).filter(l => /^\d{3}\s/.test(l) || /^\[\d/.test(l));
      return { summary: `${items.length} path(s) found`, items };
    },
  },
];

function urlsParser(out) {
  const urls = uniqLines(out).filter(u => /^https?:\/\//.test(u));
  const juicy = urls.filter(u => /\.(env|sql|bak|old|zip|tar|gz|log|conf|config|ini|ya?ml|json|xml|txt|backup|swp)(\?|$)|[?&](token|key|api_key|apikey|secret|password|pass|auth|session)=/i.test(u));
  const params = urls.filter(u => u.includes('?'));
  return {
    summary: `${urls.length} URL(s), ${params.length} with parameters, ${juicy.length} interesting`,
    items: [...juicy, ...urls.filter(u => !juicy.includes(u))].slice(0, 500),
    findings: juicy.length ? [{ title: 'Potentially sensitive URLs found in archives/crawl', severity: 'low', detail: juicy.slice(0, 25).join('\n'), fix: 'Check whether these files/keys are still live; rotate any exposed secrets and remove the files.' }] : [],
  };
}

function portsParser(out) {
  const items = uniqLines(out);
  const risky = items.filter(l => /:(21|23|25|445|1433|1521|2375|3306|3389|5432|5900|6379|9200|11211|27017)$/.test(l));
  return { summary: `${items.length} open port(s)`, items, findings: risky.length ? [{ title: 'Sensitive ports open', severity: 'high', detail: risky.join('\n'), fix: 'Firewall these ports or restrict to trusted IPs.' }] : [] };
}
