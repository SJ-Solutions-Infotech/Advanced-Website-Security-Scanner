# SJ WebScan

A website vulnerability and health scanner with a **CLI** and a **web UI**. It produces a **JSON report**.

- **Built-in checks.** These are passive and need zero dependencies, only Node ≥ 18.17. They cover SSL/TLS, security headers, cookies, CORS, exposed files, directory listing, CMS and WordPress checks, outdated JS libraries, performance, broken links, mixed content, DNS and email (SPF/DMARC/CAA).
- **27 open-source tools.** WebScan can run these if they're installed. It handles orchestration, parsing and normalising their output into findings, and merging those findings into the score.

```
node bin/webscan.js example.com                 # built-in checks only
node bin/webscan.js example.com -t passive      # + all installed passive OSINT tools
node bin/webscan.js client.com -t full --authorized -o audit.json   # + active scanners (with permission!)
npm start                                       # web UI → http://127.0.0.1:8080
```

## Install

```bash
cd webscan
node bin/webscan.js tools                 # what's installed
sudo -E bash scripts/install-tools.sh     # install the 27 tools (Debian / Ubuntu / Kali)
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
export WPSCAN_API_TOKEN=xxxx              # optional, free at wpscan.com → WordPress CVE data
```

Kali Linux already ships most of the tools. Without any tools installed, the built-in checks still run fully.

## The 27 tools

| Category | Tool | Mode | What it adds |
|---|---|---|---|
| OSINT | whois | passive | registrar, creation/expiry date (flags domains expiring < 30 days) |
| OSINT | dig | passive | raw DNS records |
| OSINT | DNSRecon | passive | standard enumeration + **zone-transfer (AXFR) test** |
| OSINT | Subfinder | passive | subdomains from passive sources |
| OSINT | OWASP Amass | passive | subdomains (passive mode) |
| OSINT | assetfinder | passive | subdomains |
| OSINT | theHarvester | passive | emails + hosts |
| OSINT | waybackurls | passive | archived URLs, flags juicy files / tokens in URLs |
| OSINT | gau | passive | URLs from Wayback, Common Crawl, OTX, URLScan |
| OSINT | dnsx | passive | resolves all discovered subdomains, flags possible **subdomain takeover** CNAMEs |
| Recon | httpx (PD) | passive | probes live hosts: title, tech, server, CDN |
| Recon | WhatWeb | passive | deep tech fingerprinting |
| Recon | WAFW00F | active | WAF detection |
| Recon | Katana | active | JS-aware crawler (rate-limited) |
| Recon | Naabu | active | fast top-1000 port scan |
| Recon | Nmap | active | service versions + `vulners` CVE matching, flags exposed DB/RDP/etc. |
| TLS | testssl.sh | passive | full TLS audit (Heartbleed, ROBOT, weak ciphers…) |
| TLS | SSLyze | passive | Mozilla "intermediate" compliance |
| TLS | sslscan | passive | legacy protocols / weak ciphers |
| Vulnerability | Nuclei | active | thousands of CVE/misconfig templates (dos/fuzz/intrusive tags excluded) |
| Vulnerability | Nikto | active | classic web-server checks |
| Vulnerability | OWASP ZAP baseline | active | spider + passive scan (Docker) |
| CMS | WPScan | active | WordPress plugins/themes/users + CVEs (only runs if WordPress is detected) |
| CMS | droopescan | active | Drupal/Joomla/WordPress fingerprinting |
| Content discovery | ffuf | active | path brute-force with auto-calibration |
| Content discovery | Gobuster | active | path brute-force |
| Content discovery | dirsearch | active | path brute-force |

- **Passive** tools only query public data sources or make ordinary requests. They're safe on any site.
- **Active** tools send attack-like traffic. They're **skipped unless you pass `--authorized`** (or tick the box in the UI). Only use active tools on sites you own or have written permission to test.
- Execution order is passive collectors first, then dnsx/httpx (which receive the discovered subdomains), then active tools (2 at a time).

## CLI

```
webscan <url> [options]
  -o, --out <file>      JSON report path (default reports/<host>-<time>.json)
  --json                JSON to stdout (logs go to stderr) — pipe into jq
  -m, --modules <list>  tls,headers,exposure,cms,health,dns
  -t, --tools <list>    none | passive | full | subfinder,nuclei,...
  --authorized          allow active tools
  --wordlist <file>     for ffuf/gobuster (default: SecLists/dirb if present, else bundled wordlists/common.txt)
  --tool-timeout <sec>  cap per tool
  --no-links            skip broken-link check;  --max-links <n> (default 60)
  --allow-private       allow localhost / private IPs
  -v, --verbose         stream tool output live
  --fail-on <sev>       exit 2 if any failing finding ≥ severity (for CI pipelines)
webscan tools [--install-help] [--json]
```

## Web UI

```bash
npm start                                   # binds to 127.0.0.1:8080
HOST=0.0.0.0 WEBSCAN_TOKEN=long-secret npm start   # if exposing on a server
```

| Env | Default | |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `8080` | |
| `WEBSCAN_TOKEN` | – | requires `Authorization: Bearer <token>` (the UI prompts for it). **Set it whenever the UI is reachable from the network.** An open scanner can be abused to attack other sites. |
| `ALLOW_ACTIVE` | `1` | set `0` to hard-disable active tools from the UI |
| `ALLOW_PRIVATE` | `0` | allow scanning internal IPs (SSRF protection is on by default) |
| `MAX_SCANS` | `2` | concurrent scans |

To expose it publicly, put it behind nginx with HTTPS. Disable buffering for `/api/scan/*/events` (`proxy_buffering off;`) so live progress streams.

### API

| Method | Path | |
|---|---|---|
| GET | `/api/meta` | version, modules |
| GET | `/api/tools` | tool inventory |
| POST | `/api/scan` | `{ url, modules?, tools?, authorized?, links?, maxLinks? }` → `{ id }` |
| GET | `/api/scan/:id/events` | Server-Sent Events: `log`, `stage`, `tool`, `done`, `error` |
| GET | `/api/scan/:id` | status + report |
| GET | `/api/reports` | saved reports |
| GET / DELETE | `/api/reports/:file` | read (`?download`) / delete |

## JSON report

```jsonc
{
  "scanner": "SJ WebScan", "version": "1.0.0", "scannedAt": "…", "durationMs": 18234,
  "target": { "url": "…", "finalUrl": "…", "host": "…", "domain": "…", "redirectChain": [] },
  "technologies": ["WordPress", "PHP", "LiteSpeed"],
  "score": { "overall": 72, "grade": "C", "security": 68, "health": 81 },
  "summary": { "critical": 0, "high": 1, "medium": 4, "low": 6, "pass": 22, "warn": 7, "fail": 4, "tools": { … } },
  "findings": [
    { "id": "hdr.csp", "category": "Security headers", "title": "Content-Security-Policy",
      "status": "fail", "severity": "medium", "detail": "Missing", "fix": "Define a CSP…", "source": "nuclei?" }
  ],
  "tools": [ { "id": "nuclei", "status": "ok", "command": "…", "durationMs": 81000, "summary": "…", "items": [], "findings": [], "raw": "…" } ],
  "osint": { "subdomains": [], "emails": [] }
}
```

- `status` is one of `pass | warn | fail | info | error`. `severity` is one of `critical | high | medium | low | info`.
- **Scoring.** Each fail costs its severity weight (critical 25, high 12, medium 6, low 2), and a warn costs half that. The score is `100·e^(−penalty/90)`. Overall = 70 % security + 30 % health. Any critical finding caps the overall score at 60 (grade D).

## How false positives are kept low

- Exposed-file checks require a **content signature**, for example `.git/HEAD` must start with `ref:` and `.env` must contain `KEY=` lines. They also compare against a random-path **soft-404 baseline**.
- Secrets found in evidence are **redacted** in the report.
- Expired, self-signed or mismatched certificates are reported, and the scan still continues.

## Project layout

```
bin/webscan.js          CLI
server.js               web UI server (zero deps, SSE)
public/index.html       UI
src/scanner.js          orchestrator + scoring
src/checks/*.js         built-in modules
src/tools/registry.js   27 tool definitions (argv builder + parser) — add your own here
src/tools/runner.js     safe exec (no shell, timeouts, output caps)
scripts/install-tools.sh
wordlists/common.txt
```

**To add a tool**, append an object to `TOOLS` in `src/tools/registry.js`. It needs these fields: `id`, `bins`, `intrusive`, `args(target)`, `parse(stdout)`. `parse` returns `{ summary, items, findings }`.

---
Built by SJ Web Solutions. The results are automated, so verify findings manually before you report them to a client.
