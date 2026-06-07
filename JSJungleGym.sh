#!/usr/bin/env bash

#===============================================================================
# 🎪 JSJungleGym.sh v3.1 - Automated JS Dependency Extraction & Static Analysis
# somehow SCA and SAST for black box
# 🚀 NEW: --spa flag for Playwright-powered SPA scanning (React/Vue/Angular)
# 🔐 CHANGED: Trivy replaces Snyk for vulnerability scanning (no token needed)
# 🧹 NEW: Docker images cleaned up automatically after scan
#
# Usage:
#   ./JSJungleGym.sh <target_url>           # Standard mode
#   ./JSJungleGym.sh --spa <target_url>     # SPA/Headless mode
#   ./JSJungleGym.sh --help                 # Show help

set -uo pipefail
# NOTE: -e removed intentionally so individual step failures don't abort the scan

# ---------------------------- CONFIGURATION -----------------------------------
WORKSPACE="./jsjungle_workspace"
SRC_DIR="$WORKSPACE/src"
REPORTS_DIR="$WORKSPACE/reports"
LINK_FINDER="$REPORTS_DIR/first_step_link_finder.txt"
RAW_CURL_LOG="$REPORTS_DIR/raw_js_responses.txt"
PY_ANALYSIS="$REPORTS_DIR/python_analysis.txt"
HORUSEC_OUT="$REPORTS_DIR/horufind.txt"
TRIVY_OUT="$REPORTS_DIR/trivy_vulns.txt"

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DELAY_SEC=1
TIMEOUT_SEC=15
SPA_MODE=false

# Docker images used (tracked for cleanup)
# Using ArvanCloud mirror: docker.arvancloud.ir/aquasec/trivy
TRIVY_IMAGE="docker.arvancloud.ir/aquasec/trivy:latest"

# ---------------------------- HELP & USAGE ------------------------------------
show_help() {
cat << EOF

🎪 JSJungleGym.sh v3.1 - Automated JS Security Workflow

USAGE:
  ./JSJungleGym.sh [OPTIONS] <target_url>

OPTIONS:
  --spa       Enable Playwright headless browser mode for SPAs (React/Vue/Angular)
  --help      Show this help message

EXAMPLES:
  # Standard crawl (fast, regex-based)
  ./JSJungleGym.sh https://example.com

  # SPA mode (slower, executes JS, handles dynamic imports)
  ./JSJungleGym.sh --spa https://app.example.com

  # Local testing with self-signed cert
  ./JSJungleGym.sh http://127.0.0.1:3000

OUTPUT FILES (in ./jsjungle_workspace/reports/):
  first_step_link_finder.txt  → Extracted JS URLs
  raw_js_responses.txt        → curl -vv headers & bodies
  python_analysis.txt         → Credentials & library versions
  horufind.txt                → Horusec SAST findings
  trivy_vulns.txt             → Trivy dependency vulnerability report

⚠️  LEGAL: Only use against systems you own or have explicit written authorization to test.
EOF
  exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --spa)
      SPA_MODE=true
      shift
      ;;
    --help|-h)
      show_help
      ;;
    -*)
      echo "[!] 🔴 Unknown option: $1"
      echo "[!] 💡 Use --help for usage information"
      exit 1
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

# ---------------------------- URL VALIDATION ----------------------------------
if [[ -z "${TARGET:-}" ]]; then
  echo "[!] 🔴 Usage: $0 [--spa] <https://target.com>"
  echo "[!] 💡 Use --help for full options"
  exit 1
fi

# Fix common URL typos
TARGET=$(echo "$TARGET" | sed -E 's|^(https?)://:|\1://|g; s|^(https?)//:|\1://|g')

# Strip any accidentally doubled slashes after scheme
TARGET=$(echo "$TARGET" | sed -E 's|^(https?://)//+|\1|g')

# Basic URL validation — allow localhost and IPs without a dot
if ! [[ "$TARGET" =~ ^https?://(localhost|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[^[:space:]]+\.[^[:space:]]+)(:[0-9]+)?(/.*)?$ ]]; then
  echo "[!] 🔴 Invalid URL format: $TARGET"
  echo "[!] 💡 Example: https://example.com or http://localhost:3000"
  exit 1
fi

echo "[*] 🎯 Target: $TARGET"
echo "[*] 📁 Workspace: $WORKSPACE"
[[ "$SPA_MODE" == "true" ]] && echo "[*] 🎭 Mode: SPA/Playwright (headless browser)"

# ---------------------------- DIRECTORY & DEPENDENCY SETUP --------------------
mkdir -p "$SRC_DIR" "$REPORTS_DIR" || {
  echo "[!] 🔴 Failed to create workspace. Check permissions."
  exit 1
}

for cmd in curl python3 horusec docker; do
  command -v "$cmd" &>/dev/null || { echo "[!] 🔴 $cmd required but not installed."; exit 1; }
done

# Check Playwright for SPA mode
if [[ "$SPA_MODE" == "true" ]]; then
  if ! command -v node &>/dev/null; then
    echo "[!] 🔴 Playwright mode requires Node.js. Install Node.js first."
    echo "[!] 💡 Or run without --spa for standard regex-based extraction."
    exit 1
  fi

  # Check if playwright package is available
  echo "[*] 📦 Checking Playwright availability..."

  # Determine install location
  PLAYWRIGHT_SCRIPT=""
  if node -e "require('playwright')" 2>/dev/null; then
    PLAYWRIGHT_SCRIPT="require('playwright')"
    echo "[+] ✅ Playwright found (global/local node_modules)"
  else
    echo "[*] 📦 Installing Playwright (this may take a minute)..."
    # Use a temp dir to install playwright so we don't pollute cwd
    PLAYWRIGHT_INSTALL_DIR="$WORKSPACE/.playwright_pkg"
    mkdir -p "$PLAYWRIGHT_INSTALL_DIR"
    cd "$PLAYWRIGHT_INSTALL_DIR"
    if timeout 120 npm install playwright --save-quiet 2>/tmp/pw_install.log; then
      # Install chromium browser binary
      echo "[*] 📦 Installing Chromium browser..."
      if timeout 300 node node_modules/.bin/playwright install chromium 2>/tmp/pw_browser.log; then
        echo "[+] ✅ Playwright + Chromium installed"
        PLAYWRIGHT_INSTALL_DIR="$(pwd)"
      else
        echo "[!] ⚠️  Chromium install failed: $(tail -1 /tmp/pw_browser.log)"
        echo "[!] ⚠️  Falling back to standard mode."
        SPA_MODE=false
      fi
    else
      echo "[!] ⚠️  Playwright npm install failed: $(tail -1 /tmp/pw_install.log)"
      echo "[!] ⚠️  Falling back to standard mode."
      SPA_MODE=false
    fi
    cd - >/dev/null
  fi
fi

# ---------------------------- DOCKER IMAGE PREFETCH ---------------------------
# Pull Trivy image once upfront so we can track and clean it later
echo "[*] 🐳 Pulling Trivy Docker image..."
if docker pull "$TRIVY_IMAGE" 2>/dev/null; then
  echo "[+] ✅ Trivy image ready"
  TRIVY_IMAGE_PULLED=true
else
  echo "[!] ⚠️  Could not pull Trivy image. Scan will attempt anyway."
  TRIVY_IMAGE_PULLED=false
fi

# ---------------------------- EMBEDDED PYTHON TOOLS ---------------------------

# 🐍 extract_js.py - Standard regex-based extractor
cat << 'PY_EXTRACT' > "$WORKSPACE/extract_js.py"
import sys, re, requests, urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    url = sys.argv[1].strip().rstrip('/')
    if url.startswith('//'): url = 'http:' + url
    headers = {"User-Agent": "Mozilla/5.0 (compatible; JSJungleGym/1.0)"}
    try:
        res = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
        res.raise_for_status()
        patterns = [
            r'(?:src|href|url)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'["\'](/[^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'(?:import|require)\s*\(\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']\s*\)',
            r'["\']((?:https?:)?//[^"\']+\.js(?:\?[^"\']*)?)["\']'
        ]
        found = set()
        for pat in patterns:
            matches = re.findall(pat, res.text, re.IGNORECASE)
            for m in matches:
                clean = m.split('?')[0]
                if clean.endswith('.js'):
                    full = urljoin(url, m)
                    if full.startswith(('http://', 'https://')):
                        found.add(full)
        for js_url in sorted(found):
            print(js_url)
    except Exception as e:
        print(f"[!] Extraction failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_js.py <url>", file=sys.stderr)
        sys.exit(1)
    main()
PY_EXTRACT

# 🎭 spa_extractor.js - Playwright SPA extractor
cat << 'PLAYWRIGHT_EXTRACT' > "$WORKSPACE/spa_extractor.js"
// Resolve playwright from either cwd node_modules or the install dir passed as env
const playwrightPath = process.env.PLAYWRIGHT_PKG_DIR
  ? process.env.PLAYWRIGHT_PKG_DIR + '/node_modules/playwright'
  : 'playwright';

let playwright;
try {
  playwright = require(playwrightPath);
} catch (e) {
  // Try local node_modules relative to script location
  try {
    playwright = require(require('path').join(__dirname, '..', '.playwright_pkg', 'node_modules', 'playwright'));
  } catch (e2) {
    console.error('[!] Could not load playwright module. Run: npm install playwright');
    process.exit(1);
  }
}

const { chromium } = playwright;
const { URL } = require('url');

(async () => {
  const target = process.argv[2];
  if (!target) {
    console.error("Usage: node spa_extractor.js <url>");
    process.exit(1);
  }

  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors']
    });

    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (compatible; JSJungleGym/1.0)',
      ignoreHTTPSErrors: true,
      viewport: { width: 1920, height: 1080 }
    });

    const page = await context.newPage();

    // Collect JS URLs via network interception (more reliable than DOM scraping)
    const networkJsUrls = new Set();
    page.on('request', req => {
      const url = req.url();
      if (url.match(/\.js(\?|$)/)) networkJsUrls.add(url.split('?')[0]);
    });

    // Navigate with a generous timeout; use domcontentloaded first, then wait
    try {
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 });
    } catch (navErr) {
      console.error(`[!] Navigation warning: ${navErr.message}`);
      // Continue anyway — partial load is still useful
    }

    // Wait for network to settle (up to 5s)
    try {
      await page.waitForLoadState('networkidle', { timeout: 8000 });
    } catch (_) { /* timeout is fine */ }

    // Scroll to trigger lazy-loaded scripts
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)).catch(() => {});
    await page.waitForTimeout(2000);

    // Also scrape DOM for script src attributes
    const domUrls = await page.evaluate(() => {
      const urls = [];
      document.querySelectorAll('script[src]').forEach(e => urls.push(e.src));
      document.querySelectorAll('link[href]').forEach(e => {
        if (e.href && e.href.endsWith('.js')) urls.push(e.href);
      });
      return urls;
    }).catch(() => []);

    // Merge both sources
    const allUrls = new Set([...networkJsUrls]);
    domUrls.forEach(u => {
      try {
        const abs = new URL(u, target).href.split('?')[0];
        if (abs.endsWith('.js')) allUrls.add(abs);
      } catch (_) {}
    });

    [...allUrls].sort().forEach(url => console.log(url));

  } catch (err) {
    console.error(`[!] SPA extraction failed: ${err.message}`);
    process.exit(1);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
})();
PLAYWRIGHT_EXTRACT

# 🐍 analyze_js.py - Credential & version hunter
cat << 'PY_ANALYZE' > "$WORKSPACE/analyze_js.py"
import sys, os, re

CRED_PATTERNS = [
    r'(?i)(?:password|passwd|pwd|pass|token|secret|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["\']([^"\'\\s]{6,})["\']',
    r'(?i)(?:username|user[_-]?name|login|email|account[_-]?id|userid)\s*[:=]\s*["\']([^"\'\\s]{4,})["\']',
    r'(?i)(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([^"\'\\s]+)["\']',
    r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
]

VERSION_PATTERNS = [
    r'(?i)([a-zA-Z][a-zA-Z0-9._\-]*)\s*[vV]?\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?)',
    r'(?i)(?:version|ver)\s*[:=]?\s*["\']?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?)["\']?\s*,?\s*["\']?([a-zA-Z][a-zA-Z0-9._\-]*)["\']?',
]

def main():
    src_dir = sys.argv[1]
    if not os.path.isdir(src_dir):
        print(f"[!] Directory not found: {src_dir}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] 🔍 Scanning JS files in: {src_dir}")
    for root, _, files in os.walk(src_dir):
        for fname in files:
            if not fname.lower().endswith('.js'): continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    content = f.read(3*1024*1024)
            except: continue
            for pat in CRED_PATTERNS:
                for match in re.finditer(pat, content):
                    snippet = match.group(0).strip()
                    if not re.search(r'(?:var|let|const)\s+' + re.escape(snippet.split('=')[0].strip()), content, re.I):
                        print(f"[CREDENTIAL] {fname}: {snippet}")
            for pat in VERSION_PATTERNS:
                for match in re.finditer(pat, content):
                    groups = match.groups()
                    if len(groups) == 2 and groups[0] and groups[1]:
                        lib, ver = groups[0].strip(), groups[1].strip()
                        if len(lib) < 30 and re.match(r'^[a-zA-Z]', lib):
                            print(f"[VERSION] {lib} v{ver}")
                    elif len(groups) == 3 and groups[0] and groups[2]:
                        ver, lib = groups[0].strip(), groups[2].strip()
                        if len(lib) < 30 and re.match(r'^[a-zA-Z]', lib):
                            print(f"[VERSION] {lib} v{ver}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_js.py <src_directory>", file=sys.stderr)
        sys.exit(1)
    main()
PY_ANALYZE

# ---------------------------- WORKFLOW EXECUTION ------------------------------
echo ""
echo "[🎪 JSJungleGym v3.1 Starting Scan]"
echo "================================================"

# [1/6] Extract JS dependencies (Standard or SPA mode)
echo "[1/6] 🕷️  Crawling & Extracting JS Dependencies..."

if [[ "$SPA_MODE" == "true" ]]; then
  echo "[*] 🎭 Using Playwright for SPA extraction..."
  # Pass the playwright install dir via env if we installed it ourselves
  PLAYWRIGHT_PKG_DIR="${PLAYWRIGHT_INSTALL_DIR:-}" \
    node "$WORKSPACE/spa_extractor.js" "$TARGET" > "$LINK_FINDER" 2>/tmp/spa_err.log || {
    echo "[!] ⚠️  SPA extraction failed ($(tail -1 /tmp/spa_err.log 2>/dev/null)). Falling back to standard regex mode..."
    python3 "$WORKSPACE/extract_js.py" "$TARGET" > "$LINK_FINDER" 2>&1 || true
  }
else
  python3 "$WORKSPACE/extract_js.py" "$TARGET" > "$LINK_FINDER" 2>&1 || true
fi

TOTAL_JS=$(grep -c . "$LINK_FINDER" 2>/dev/null || echo 0)
echo "[+] 📦 Found $TOTAL_JS JavaScript endpoints"

# [2/6] Download JS files with curl -vv
echo "[2/6] 📥 Downloading JS files with curl -vv..."
> "$RAW_CURL_LOG"
DOWNLOADED=0

if [[ -s "$LINK_FINDER" ]]; then
  while IFS= read -r js_url || [[ -n "$js_url" ]]; do
    [[ -z "$js_url" || "$js_url" =~ ^# ]] && continue
    fname=$(echo "$js_url" | sed 's/?.*//' | xargs basename 2>/dev/null || echo "js_$DOWNLOADED.js")
    [[ "$fname" == "/" || -z "$fname" || "$fname" == "." ]] && fname="unknown_$DOWNLOADED.js"
    [[ ! "$fname" =~ \.js$ ]] && fname="${fname}.js"

    echo -e "\n[+] Fetching: $js_url" >> "$RAW_CURL_LOG"
    if curl -vv -s -k -A "$UA" --max-time "$TIMEOUT_SEC" --retry 2 \
        -o "$SRC_DIR/$fname" "$js_url" 2>> "$RAW_CURL_LOG"; then
      DOWNLOADED=$((DOWNLOADED + 1))
    else
      echo "[!] Failed: $js_url" >> "$RAW_CURL_LOG"
    fi
    sleep "$DELAY_SEC"
  done < "$LINK_FINDER"
fi

echo "[+] ✅ Downloaded $DOWNLOADED JS files to $SRC_DIR"

# [3/6] Python static analysis
echo "[3/6] 🐍 Running Python Credential & Version Analysis..."
if [[ -d "$SRC_DIR" ]] && [[ -n "$(ls -A "$SRC_DIR" 2>/dev/null)" ]]; then
  python3 "$WORKSPACE/analyze_js.py" "$SRC_DIR" > "$PY_ANALYSIS" 2>&1 || true
else
  echo "[*] ⚠️  No JS files to analyze. Skipping Python scan." > "$PY_ANALYSIS"
fi

PY_RESULTS=$(grep -c . "$PY_ANALYSIS" 2>/dev/null || echo 0)
echo "[+] 🔍 Found $PY_RESULTS potential findings (creds/versions)"

# [4/6] Horusec scan
echo "[4/6] 🔍 Running Horusec SAST..."
cd "$WORKSPACE"
mkdir -p "$REPORTS_DIR"
if horusec start -p ./src -D true -o text -O ./temp_horusec.txt &>/dev/null; then
  mv ./temp_horusec.txt "$HORUSEC_OUT" 2>/dev/null || cp ./temp_horusec.txt "$HORUSEC_OUT" 2>/dev/null || touch "$HORUSEC_OUT"
else
  echo "[!] ⚠️  Horusec scan failed or produced no output" > "$HORUSEC_OUT"
fi
cd ..
echo "[+] 📄 Horusec report: $HORUSEC_OUT"

# [5/6] Trivy scan via Docker
# Trivy (https://github.com/aquasecurity/trivy) replaces Snyk — no token required.
# It scans the collected JS source directory for known CVEs in dependency manifests
# (package.json, package-lock.json, yarn.lock) and performs filesystem scanning.
echo "[5/6] 🐳 Running Trivy Vulnerability Scan (Docker)..."
cd "$WORKSPACE"
mkdir -p "$REPORTS_DIR"

TRIVY_REPORT_PATH="$(pwd)/reports/trivy_vulns.txt"

# Trivy filesystem scan — works without any token, no internet call needed for local files
# --exit-code 0 ensures docker run exits 0 even when vulns are found (so we don't abort)
# --no-progress keeps output clean in non-interactive mode
docker run --rm \
  -v "$(pwd)/src":/scan:ro \
  "$TRIVY_IMAGE" \
  fs /scan \
  --exit-code 0 \
  --no-progress \
  --format table \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  2>&1 | tee "$TRIVY_REPORT_PATH" || {
    echo "[!] ⚠️  Trivy scan failed. Check Docker and try: docker pull $TRIVY_IMAGE" > "$TRIVY_REPORT_PATH"
  }

cd ..
echo "[+] 📄 Trivy report: $TRIVY_OUT"

# ---------------------------- DOCKER CLEANUP ----------------------------------
echo "[*] 🧹 Cleaning up Docker images to save disk space..."

# Remove Trivy image
if [[ "${TRIVY_IMAGE_PULLED:-false}" == "true" ]]; then
  if docker rmi "$TRIVY_IMAGE" --force 2>/dev/null; then
    echo "[+] 🗑️  Removed Docker image: $TRIVY_IMAGE"
  else
    echo "[!] ⚠️  Could not remove $TRIVY_IMAGE (may still be in use by another container)"
  fi
fi

# Also prune any dangling/intermediate images from this session
docker image prune -f 2>/dev/null && echo "[+] 🗑️  Pruned dangling Docker images" || true

# ---------------------------- FINAL SUMMARY -----------------------------------
echo ""
echo "[6/6] 📊 Scan Complete! Reports Generated:"
echo "================================================"
echo "  🗂️  $LINK_FINDER      → Extracted JS URLs"
echo "  🗂️  $RAW_CURL_LOG     → Raw curl -vv output"
echo "  🗂️  $PY_ANALYSIS      → Python: Credentials & Versions"
echo "  🗂️  $HORUSEC_OUT      → Horusec: SAST Findings"
echo "  🗂️  $TRIVY_OUT        → Trivy: Dependency Vulns"
echo "================================================"
echo ""

if [[ "$TOTAL_JS" -eq 0 ]]; then
  echo "⚠️  No JS files found. Troubleshooting tips:"
  echo "  • Test connectivity:  curl -I $TARGET"
  echo "  • Fix URL:            https:// not https//:"
  echo "  • SPA site?           Try: ./JSJungleGym.sh --spa $TARGET"
  echo "  • Site blocks bots?   Add headers or use --spa"
elif [[ "$PY_RESULTS" -gt 0 ]]; then
  echo "🔍 Review python_analysis.txt for credentials/versions!"
  echo "  • False positives happen in minified code — triage manually"
  echo "  • Version matches help prioritize CVE patching"
fi

echo ""
echo "🎪🌿💀 JSJungleGym: 'Stay curious, stay dangerous'"
