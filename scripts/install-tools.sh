#!/usr/bin/env bash
# Installs the 27 external tools used by SJ WebScan on Debian/Ubuntu/Kali.
# Run: sudo -E bash scripts/install-tools.sh   (Go tools are installed for the invoking user)
# Every step is independent — one failure doesn't stop the rest.
set -u
GREEN='\033[32m'; RED='\033[31m'; DIM='\033[2m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✔${NC} $*"; }
fail() { echo -e "${RED}✖${NC} $*"; }
step() { echo -e "\n${DIM}── $* ──${NC}"; }
try()  { "$@" >/tmp/webscan-install.log 2>&1 && ok "$*" || fail "$*  (see /tmp/webscan-install.log)"; }

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
REAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
as_user() { if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then sudo -u "$REAL_USER" -H env PATH="$PATH:/usr/local/go/bin:$USER_HOME/go/bin:$USER_HOME/.local/bin" "$@"; else "$@"; fi; }

step "APT packages"
$SUDO apt-get update -qq
for p in whois dnsutils nmap nikto whatweb sslscan gobuster libpcap-dev pipx ruby-full build-essential git curl unzip seclists dnsrecon wafw00f theharvester amass testssl.sh; do
  if $SUDO apt-get install -y -qq "$p" >/dev/null 2>&1; then ok "apt $p"; else fail "apt $p (not in your distro repos — fallback below if available)"; fi
done

step "Go toolchain"
if ! command -v go >/dev/null && [ ! -x /usr/local/go/bin/go ]; then
  GOV=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)
  ARCH=$(dpkg --print-architecture); [ "$ARCH" = "amd64" ] || [ "$ARCH" = "arm64" ] || ARCH=amd64
  try bash -c "curl -fsSL https://go.dev/dl/${GOV}.linux-${ARCH}.tar.gz | $SUDO tar -C /usr/local -xz"
fi
export PATH="$PATH:/usr/local/go/bin:$USER_HOME/go/bin"

step "Go tools (ProjectDiscovery, tomnomnom, ffuf, …)"
GO_TOOLS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/katana/cmd/katana@latest
  github.com/tomnomnom/assetfinder@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/ffuf/ffuf/v2@latest
)
for t in "${GO_TOOLS[@]}"; do try as_user go install -v "$t"; done
command -v amass >/dev/null || try as_user go install -v github.com/owasp-amass/amass/v4/...@master
command -v gobuster >/dev/null || try as_user go install github.com/OJ/gobuster/v3@latest
# The Python 'httpx' package ships a CLI with the same name — provide an unambiguous alias.
[ -x "$USER_HOME/go/bin/httpx" ] && ln -sf "$USER_HOME/go/bin/httpx" "$USER_HOME/go/bin/httpx-pd" && ok "httpx-pd alias"
try as_user "$USER_HOME/go/bin/nuclei" -update-templates -silent

step "Python tools (pipx)"
for p in sslyze droopescan dirsearch wafw00f theHarvester dnsrecon; do
  command -v "$p" >/dev/null || command -v "$(echo "$p" | tr 'A-Z' 'a-z')" >/dev/null || try as_user pipx install "$p"
done
as_user pipx ensurepath >/dev/null 2>&1 || true

step "Ruby tools"
command -v wpscan >/dev/null || try $SUDO gem install wpscan

step "testssl.sh fallback"
if ! command -v testssl.sh >/dev/null && ! command -v testssl >/dev/null; then
  try $SUDO git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh
fi

step "OWASP ZAP baseline (Docker)"
if command -v docker >/dev/null; then
  try docker pull ghcr.io/zaproxy/zaproxy:stable
  cat <<'EOF' | $SUDO tee /usr/local/bin/zap-baseline.py >/dev/null
#!/usr/bin/env bash
exec docker run --rm --network host -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py "$@"
EOF
  $SUDO chmod +x /usr/local/bin/zap-baseline.py && ok "zap-baseline.py wrapper"
else
  fail "docker not installed — skipping ZAP (install Docker, then re-run)"
fi

echo -e "\n${GREEN}Done.${NC} Add Go/pipx bins to PATH if needed:\n  export PATH=\"\$PATH:$USER_HOME/go/bin:$USER_HOME/.local/bin\"\nThen check:  node bin/webscan.js tools"
echo "Optional: export WPSCAN_API_TOKEN=<free token from wpscan.com> for WordPress CVE data."
