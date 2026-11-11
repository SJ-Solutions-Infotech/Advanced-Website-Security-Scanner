# SJ WebScan

A website vulnerability and health scanner with a **CLI** and a **web UI**. It produces a **JSON report**.

- **Built-in checks.** These are passive and need zero dependencies, only Node ≥ 18.17. They cover SSL/TLS, security headers, cookies, CORS, exposed files, directory listing, CMS and WordPress checks, outdated JS libraries, performance, broken links, mixed content, DNS and email (SPF/DMARC/CAA).
- **27 open-source tools.** WebScan can run these if they're installed. It handles orchestration, parsing and normalising their output into findings, and merging those findings into the score.
- **Security.** API keys are stored as scrypt hashes, with scopes. You can use HMAC-signed requests with replay protection, and there are rate limits and lockouts. Reports are signed with Ed25519 so tampering can be detected. Requests to the scanned site are throttled. Details are in [Web UI and API security](#web-ui-and-api-security).

```
node bin/webscan.js example.com                 # built-in checks only
node bin/webscan.js example.com -t passive      # + all installed passive OSINT tools
node bin/webscan.js client.com -t full --authorized -o audit.json   # + active scanners (with permission!)
npm start                                       # web UI → http://127.0.0.1:8080
node bin/webscan.js keys create "Samar" --scopes read,scan,active,admin   # before exposing the UI
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

### Windows

```powershell
cd webscan
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\install-tools.ps1              # add -WithDocker to also install Docker Desktop
# close PowerShell, open a new one (PATH refresh), then:
node bin\webscan.js tools
```

The installer uses winget for Go, Python, Git, Strawberry Perl, Nmap and Npcap, then installs the remaining tools with `go install` and `pipx`. Nikto and testssl.sh are cloned into `C:\tools`. If Docker is available, the scanner runs **ZAP, WPScan and testssl.sh** through it automatically. 25 of the 27 tools work on Windows. **whatweb** and **dig** need WSL.


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
  --rps <n>             built-in checks: max requests/sec per host (default 10)
  --tool-rps <n>        external tools: max requests/sec (default 50)
  --no-sign             don't sign the report
  --wordlist <file>     for ffuf/gobuster (default: SecLists/dirb if present, else bundled wordlists/common.txt)
  --tool-timeout <sec>  cap per tool
  --no-links            skip broken-link check;  --max-links <n> (default 60)
  --allow-private       allow localhost / private IPs
  -v, --verbose         stream tool output live
  --fail-on <sev>       exit 2 if any failing finding ≥ severity (for CI pipelines)
webscan tools [--install-help] [--json]
webscan keys create <name> [--scopes read,scan,active,admin] | keys list | keys revoke <id>
webscan verify <report.json> [--pubkey <file>]
webscan public-key [--out <file>]
```

## Web UI and API security

### 1. Create API keys

```bash
node bin/webscan.js keys create "Samar (admin)" --scopes read,scan,active,admin
node bin/webscan.js keys create "Dev team"                     # default scopes: read,scan
node bin/webscan.js keys create "Client portal" --scopes read
node bin/webscan.js keys list
node bin/webscan.js keys revoke 1d85bad3                        # takes effect immediately, sessions too
```

Each key is printed **once**:

- an **API key** (`sjwk_<id>_<secret>`). You use it for the browser sign-in and for `Authorization: Bearer`.
- a **signing secret** (`sjss_…`). You use it for HMAC-signed requests.

The server stores only a **scrypt hash** of the API key, in `data/keys.json` with `chmod 600`. The signing secret isn't stored at all. It's re-derived from a 32-byte master key with HMAC-SHA256.

| Scope | Allows |
|---|---|
| `read` | tools list, own scan status/stream, reports, verify |
| `scan` | start scans (passive tools only) |
| `active` | start scans with `authorized: true` (nmap, nuclei, nikto, ZAP, ffuf …) |
| `admin` | everything, plus seeing all scans and deleting reports |

If no keys exist, the server runs with auth **off**, but only when it's bound to `127.0.0.1`. It **refuses to start** on a public interface until you create a key (`ALLOW_NO_AUTH=1` overrides this; not recommended).

### 2. Ways to authenticate

| Method | Header | Used by |
|---|---|---|
| Browser session | `Authorization: Session <token>` | the web UI. You paste the key once and it's exchanged for an 8 h signed session token in `sessionStorage`. The key itself is never stored in the browser. |
| Bearer API key | `Authorization: Bearer sjwk_…` | simple scripts, curl |
| **HMAC signature** | `X-WebScan-Key/-Timestamp/-Nonce/-Signature` | servers and integrations. The key never travels over the wire. |
| SSE ticket | `?ticket=sjtkt…` | live progress stream. It lasts 60 s, works once, and is bound to one scan. This replaces the old `?token=`, which leaked into access logs. |

**HMAC signing:**

```
stringToSign = METHOD + "\n" + PATH?QUERY + "\n" + UNIX_SECONDS + "\n" + NONCE + "\n" + hex(SHA256(body))
X-WebScan-Signature = hex(HMAC-SHA256(signingSecret, stringToSign))
```

The server rejects four kinds of signed request:

- **Stale:** the timestamp is outside ±300 s.
- **Replayed:** the nonce was already used.
- **Tampered:** the body or path was changed after signing.
- **Revoked:** the key has been revoked.

Set `REQUIRE_HMAC=1` to stop accepting raw Bearer keys entirely. Browser sessions still work. A ready-made client is included:

```bash
export WEBSCAN_URL=https://scan.sjweb4u.com WEBSCAN_KEY_ID=1d85bad3 WEBSCAN_SIGNING_SECRET=sjss_…
node scripts/signed-client.mjs GET /api/whoami
node scripts/signed-client.mjs scan https://client-site.com      # start, wait, print score + report hash
```

You can also sign from PHP or Laravel:

```php
$ts = time(); $nonce = bin2hex(random_bytes(16)); $body = json_encode(['url' => 'https://example.com']);
$sig = hash_hmac('sha256', implode("\n", ['POST', '/api/scan', $ts, $nonce, hash('sha256', $body)]), $secret);
Http::withHeaders(['X-WebScan-Key' => $keyId, 'X-WebScan-Timestamp' => $ts, 'X-WebScan-Nonce' => $nonce, 'X-WebScan-Signature' => $sig])
    ->withBody($body, 'application/json')->post("$base/api/scan");
```

### 3. Rate limiting

| Limit | Default | Env |
|---|---|---|
| API requests per IP | 120 / min | `RL_API_PER_MIN` |
| New scans per key (per IP when auth is off) | 10 / hour | `RL_SCANS_PER_HOUR` |
| Sign-in attempts per IP | 10 / 15 min | `RL_LOGIN_PER_15MIN` |
| Failed auths before IP lockout | 5 in 15 min → locked 15 min | `LOCKOUT_FAILURES`, `LOCKOUT_MINUTES` |
| Concurrent scans | 2 server-wide, 1 per key | `MAX_SCANS`, `MAX_SCANS_PER_CLIENT` |
| **Built-in checks → scanned site** | 10 req/s per host | `WEBSCAN_RPS` / `--rps` |
| **External tools → scanned site** | 50 req/s | `WEBSCAN_TOOL_RPS` / `--tool-rps` (nuclei `-rl`, ffuf `-rate`, katana `-rl`, dirsearch `--max-rate`, gobuster threads × delay) |

The limits use a sliding window. Blocked requests get **429**, along with `Retry-After`, `X-RateLimit-Limit/-Remaining/-Reset` and `X-Scan-Quota-*` headers. API clients can't raise the target throttle; only the server's env sets it. Behind nginx, set `TRUST_PROXY=1` so limits apply to the real client IP from `X-Forwarded-For`. Only do that when nginx is the only thing that can reach the port.

### 4. Signed reports (integrity hashing)

Every report gets an `integrity` block:

- **Hash:** SHA-256 of the canonical JSON (keys sorted).
- **Signature:** an **Ed25519 signature** made with `data/report-signing.key`.
- **Accountability:** `options.requestedBy` records which key ran the scan.

If anyone changes even one character, verification fails.

```bash
node bin/webscan.js verify reports/client.com-….json          # ✔ VALID / ✖ INVALID (exit 3)
node bin/webscan.js public-key --out sjweb-scanner.pub          # give this to clients
node scripts/verify-report.mjs report.json sjweb-scanner.pub    # standalone: clients need only Node, no install
```

In the UI, signed reports show 🔒. **Verify signature** re-checks the open report. The **Verify a report** panel checks any uploaded JSON file.

### 5. Other hardening

- **UI script pinned:** the UI is served with a CSP that only allows its own inline script, pinned by SHA-256 hash (`script-src 'sha256-…'`, no `unsafe-inline` or `unsafe-eval`).
- **Scan visibility:** users only see their own scans. Admins see all of them.
- **Audit log:** `data/audit.log` (JSONL) records key create/revoke, auth failures, lockouts, sessions, scan start/finish with requester and IP, rate-limit hits and report deletions.
- **Data files:** everything in `data/` is `600` inside a `700` directory, and all writes are atomic. **Back up `data/`.** It holds your keys, master key and report-signing key. Losing `report-signing.key` means new reports get a new fingerprint. `WEBSCAN_MASTER_KEY` (64 hex chars) can supply the master key from a secrets manager instead.

### Server settings

```bash
npm start                                              # 127.0.0.1:8080
HOST=0.0.0.0 TRUST_PROXY=1 REQUIRE_HMAC=1 npm start    # production behind nginx
```

| Env | Default | |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `8080` | |
| `TRUST_PROXY` | `0` | use `X-Forwarded-For` for client IP |
| `REQUIRE_HMAC` | `0` | reject raw Bearer API keys |
| `SESSION_TTL_HOURS` | `8` | browser session lifetime |
| `ALLOW_ACTIVE` | `1` | `0` hard-disables active tools |
| `ALLOW_PRIVATE` | `0` | allow scanning internal IPs (SSRF protection is on by default) |
| `WEBSCAN_DATA_DIR` | `./data` | keys, secrets, signing key, audit log |
| `HMAC_MAX_SKEW` | `300` | allowed clock difference (s) |

Put it behind nginx with HTTPS, and disable buffering for `/api/scan/*/events` (`proxy_buffering off;`) so live progress streams. `WEBSCAN_TOKEN` from v1.0 is no longer used. Create a key instead.

### API

| Method | Path | Scope | |
|---|---|---|---|
| GET | `/api/meta` | public | version, limits, signing-key fingerprint |
| GET | `/api/public-key` | public | report-signing public key (`?pem` downloads it) |
| POST | `/api/session` | public | `{ apiKey }` → `{ token, expiresIn, scopes }` |
| GET | `/api/whoami` | any | identity, scopes, scans left this hour |
| GET | `/api/tools` | read | tool inventory |
| POST | `/api/scan` | scan (+active) | `{ url, modules?, tools?, authorized?, links?, maxLinks? }` → `{ id }` |
| POST | `/api/scan/:id/ticket` | read | one-time 60 s ticket for the event stream |
| GET | `/api/scan/:id/events` | ticket / read | Server-Sent Events: `log`, `stage`, `tool`, `done`, `failed` |
| GET | `/api/scan/:id` | read | status + report |
| GET | `/api/reports` | read | saved reports (signed, requestedBy) |
| GET | `/api/reports/:file` | read | report (`?download`) |
| DELETE | `/api/reports/:file` | admin | delete |
| POST | `/api/verify` | read | body = report JSON → hash/signature check |

## JSON report

```jsonc
{
  "scanner": "SJ WebScan", "version": "1.1.0", "scannedAt": "…", "durationMs": 18234,
  "target": { "url": "…", "finalUrl": "…", "host": "…", "domain": "…", "redirectChain": [] },
  "technologies": ["WordPress", "PHP", "LiteSpeed"],
  "score": { "overall": 72, "grade": "C", "security": 68, "health": 81 },
  "summary": { "critical": 0, "high": 1, "medium": 4, "low": 6, "pass": 22, "warn": 7, "fail": 4, "tools": { … } },
  "findings": [
    { "id": "hdr.csp", "category": "Security headers", "title": "Content-Security-Policy",
      "status": "fail", "severity": "medium", "detail": "Missing", "fix": "Define a CSP…", "source": "nuclei?" }
  ],
  "tools": [ { "id": "nuclei", "status": "ok", "command": "…", "durationMs": 81000, "summary": "…", "items": [], "findings": [], "raw": "…" } ],
  "osint": { "subdomains": [], "emails": [] },
  "options": { "rps": 10, "toolRps": 50, "authorized": false, "requestedBy": "Dev team (736dd8a7)" },
  "integrity": { "algorithm": "SHA-256", "hash": "6b88…", "signatureAlgorithm": "Ed25519", "signature": "…", "publicKeyFingerprint": "SHA256:oIDx…", "signedAt": "…" }
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
server.js               web UI + API server (zero deps, SSE, auth, rate limits)
public/index.html       UI
src/scanner.js          orchestrator + scoring
src/checks/*.js         built-in modules
src/tools/registry.js   27 tool definitions (argv builder + parser) — add your own here
src/tools/runner.js     safe exec (no shell, timeouts, output caps)
src/security/keys.js    scrypt-hashed API keys, scopes, sessions, SSE tickets
src/security/hmac.js    HMAC request signing + replay protection
src/security/ratelimit.js  sliding-window limiter, lockout, per-host throttle
src/security/integrity.js  SHA-256 + Ed25519 report signing / verification
src/security/store.js   data dir, master key, audit log
scripts/signed-client.mjs  HMAC API client (standalone)
scripts/verify-report.mjs  report verifier for clients (standalone)
scripts/install-tools.sh / install-tools.ps1
wordlists/common.txt
```

**To add a tool**, append an object to `TOOLS` in `src/tools/registry.js`. It needs these fields: `id`, `bins`, `intrusive`, `args(target, { wordlist, rps })`, `parse(stdout)`. `parse` returns `{ summary, items, findings }`.

---
Built by SJ Web Solutions. The results are automated, so verify findings manually before you report them to a client.
