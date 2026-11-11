# SJ WebScan - Windows installer for the external tools.
#
# Run in PowerShell (as Administrator recommended):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\scripts\install-tools.ps1                # everything except Docker
#   .\scripts\install-tools.ps1 -WithDocker    # also install Docker Desktop (for ZAP, WPScan, testssl fallback)
#
# Each step is independent: a failure is reported and the script continues.
# 25 of 27 tools work on Windows. Not supported natively: whatweb (Ruby/Linux) and dig (use WSL for those).

param([switch]$WithDocker)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Log = Join-Path $env:TEMP 'webscan-install.log'
$Tools = 'C:\tools'
$script:okCount = 0; $script:failCount = 0

function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green; $script:okCount++ }
function Fail($m) { Write-Host "  [X]  $m" -ForegroundColor Red; $script:failCount++ }
function Step($m) { Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Has($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Add-UserPath($dir) {
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $p = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $p) { $p = '' }
  if (($p -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ';' + $dir).TrimStart(';'), 'User')
  }
  if (($env:Path -split ';') -notcontains $dir) { $env:Path += ";$dir" }
}

function Run($label, [scriptblock]$block) {
  try {
    & $block *>> $Log
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { Fail "$label (exit $LASTEXITCODE, see $Log)" } else { Ok $label }
  } catch { Fail "$label ($($_.Exception.Message))" }
  $global:LASTEXITCODE = 0
}

function Winget($id, [switch]$Interactive) {
  if (-not (Has 'winget')) { Fail "winget missing - install 'App Installer' from the Microsoft Store, then re-run"; return }
  $wargs = @('install', '-e', '--id', $id, '--accept-source-agreements', '--accept-package-agreements')
  if (-not $Interactive) { $wargs += '--silent' }
  & winget @wargs *>> $Log
  # -1978335189 = already installed / no upgrade available
  if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189 -or $LASTEXITCODE -eq -1978335135) { Ok "winget $id" } else { Fail "winget $id (exit $LASTEXITCODE, see $Log)" }
  $global:LASTEXITCODE = 0
}

# Download the latest GitHub release asset matching $pattern, unzip to C:\tools\<name>, add the exe's folder to PATH
function Get-GitHubRelease($repo, $pattern, $name, $exe) {
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'sj-webscan' }
    $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) { Fail "$name - no Windows asset in latest $repo release"; return }
    $zip = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
    $dest = Join-Path $Tools $name
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Expand-Archive -Path $zip -DestinationPath $dest -Force
    $found = Get-ChildItem -Path $dest -Recurse -Filter $exe | Select-Object -First 1
    if (-not $found) { Fail "$name - $exe not found in archive"; return }
    Add-UserPath $found.DirectoryName
    Ok "$name $($rel.tag_name) -> $($found.FullName)"
  } catch { Fail "$name ($($_.Exception.Message))" }
}

New-Item -ItemType Directory -Force -Path $Tools, "$Tools\bin" | Out-Null
Add-UserPath "$Tools\bin"
"--- SJ WebScan install $(Get-Date) ---" | Out-File $Log

Step 'Base runtimes (winget)'
if (-not (Has 'node')) { Winget 'OpenJS.NodeJS.LTS' } else { Ok "Node.js $(node -v) already installed" }
if (-not (Has 'git'))  { Winget 'Git.Git' } else { Ok 'Git already installed' }
if (-not (Has 'go'))   { Winget 'GoLang.Go' } else { Ok "Go already installed" }
if (-not (Has 'py') -and -not (Has 'python')) { Winget 'Python.Python.3.12' } else { Ok 'Python already installed' }
if (-not (Has 'perl')) { Winget 'StrawberryPerl.StrawberryPerl' } else { Ok 'Perl already installed' }
if (-not (Has 'nmap')) {
  Write-Host '  Nmap installer will open - keep "Npcap" ticked (naabu needs it too).' -ForegroundColor Yellow
  Winget 'Insecure.Nmap' -Interactive
} else { Ok 'Nmap already installed' }
Refresh-Path
Add-UserPath "$Tools\bin"

Step 'Go tools (subfinder, httpx, dnsx, nuclei, katana, amass, ffuf, gobuster, ...)'
$goExe = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $goExe -and (Test-Path 'C:\Program Files\Go\bin\go.exe')) { $goExe = 'C:\Program Files\Go\bin\go.exe' }
if ($goExe) {
  Add-UserPath (Join-Path $env:USERPROFILE 'go\bin')
  $goTools = @(
    'github.com/likexian/whois/cmd/whois@latest',
    'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'github.com/projectdiscovery/katana/cmd/katana@latest',
    'github.com/tomnomnom/assetfinder@latest',
    'github.com/tomnomnom/waybackurls@latest',
    'github.com/lc/gau/v2/cmd/gau@latest',
    'github.com/ffuf/ffuf/v2@latest',
    'github.com/OJ/gobuster/v3@latest',
    'github.com/owasp-amass/amass/v4/...@master'
  )
  foreach ($t in $goTools) { Run "go install $t" { & $goExe install -v $t } }
  $nuclei = Join-Path $env:USERPROFILE 'go\bin\nuclei.exe'
  if (Test-Path $nuclei) { Run 'nuclei templates' { & $nuclei -update-templates -silent } }
} else { Fail 'Go not found - open a NEW PowerShell window and re-run this script' }

Step 'Prebuilt binaries (naabu, sslscan)'
Get-GitHubRelease 'projectdiscovery/naabu' 'windows_amd64\.zip$' 'naabu' 'naabu.exe'
Get-GitHubRelease 'rbsec/sslscan' '(?i)win.*\.zip$' 'sslscan' 'sslscan.exe'

Step 'Python tools via pipx (sslyze, wafw00f, dirsearch, droopescan, dnsrecon, theHarvester)'
$py = if (Has 'py') { 'py' } elseif (Has 'python') { 'python' } else { $null }
if ($py) {
  Run 'pipx' { & $py -m pip install --user --upgrade pipx }
  & $py -m pipx ensurepath *>> $Log
  Add-UserPath (Join-Path $env:USERPROFILE '.local\bin')
  $pkgs = @('sslyze', 'wafw00f', 'dirsearch', 'droopescan',
            'git+https://github.com/darkoperator/dnsrecon.git',
            'git+https://github.com/laramies/theHarvester.git')
  foreach ($p in $pkgs) { Run "pipx install $p" { & $py -m pipx install --force $p } }
} else { Fail 'Python not found - open a NEW PowerShell window and re-run this script' }

Step 'Git-based tools (nikto, testssl.sh)'
if (Has 'git') {
  foreach ($r in @(@('https://github.com/sullo/nikto', "$Tools\nikto"), @('https://github.com/testssl/testssl.sh', "$Tools\testssl.sh"))) {
    $url = $r[0]; $dir = $r[1]
    if (Test-Path "$dir\.git") { Run "git pull $dir" { git -C $dir pull --ff-only } }
    else { Run "git clone $url" { git clone --depth 1 $url $dir } }
  }
  Add-UserPath "$Tools\nikto\program"
  Add-UserPath "$Tools\testssl.sh"
  if (-not (Test-Path 'C:\Program Files\Git\bin\bash.exe')) { Fail 'Git Bash not found - testssl.sh needs it (or Docker)' }
} else { Fail 'git not found - open a NEW PowerShell window and re-run this script' }

Step 'Docker (OWASP ZAP, WPScan, testssl fallback)'
if ($WithDocker -and -not (Has 'docker')) {
  Winget 'Docker.DockerDesktop'
  Write-Host '  Restart Windows, start Docker Desktop once, then re-run this script to pull the images.' -ForegroundColor Yellow
}
Refresh-Path
if (Has 'docker') {
  & docker info *> $null
  if ($LASTEXITCODE -eq 0) {
    foreach ($img in @('ghcr.io/zaproxy/zaproxy:stable', 'wpscanteam/wpscan', 'drwetter/testssl.sh')) { Run "docker pull $img" { docker pull $img } }
  } else { Fail 'Docker is installed but not running - start Docker Desktop and re-run' }
  $global:LASTEXITCODE = 0
} else {
  Write-Host '  Docker not installed - ZAP and WPScan will show as "not installed". Re-run with -WithDocker to add them.' -ForegroundColor Yellow
}

Write-Host "`nDone: $script:okCount ok, $script:failCount failed. Log: $Log" -ForegroundColor Cyan
Write-Host 'IMPORTANT: close this window and open a NEW PowerShell so PATH changes apply, then run:' -ForegroundColor Yellow
Write-Host '  node bin\webscan.js tools'
Write-Host 'Optional: setx WPSCAN_API_TOKEN "your-token"   (free token from wpscan.com)'
