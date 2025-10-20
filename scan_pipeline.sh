#!/usr/bin/env bash
set -euo pipefail

# scan_pipeline.sh
# Usage: ./scan_pipeline.sh <TARGET_URL>

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <TARGET_URL>"
    exit 1
fi

TARGET="$1"
DATE=$(date +%F_%H%M%S)
OUTDIR="results/$DATE"
mkdir -p "$OUTDIR"

echo "[+] Target: $TARGET"
echo "[+] Output dir: $OUTDIR"


# NMAP (top 1000 ports)
echo "[+] Running nmap (top 1000 ports)"
if ! command -v nmap >/dev/null 2>&1; then
    echo "[!] nmap not found. Install nmap and re-run."
else
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        sudo nmap -sS -sV --top-ports 1000 -oA "$OUTDIR/nmap_top" vulnweb.com || true
        sudo nmap -sS -sV --script vuln -p- -T4 -oA "$OUTDIR/nmap_vuln" vulnweb.com || true
        sudo nmap -p- --min-rate 1000 -sS -sV --script vuln -oA "$OUTDIR/nmap_all" vulnweb.com || true
    else
        nmap -sS -sV --top-ports 1000 -oA "$OUTDIR/nmap_top" vulnweb.com || true
        nmap -sS -sV --script vuln -p- -T4 -oA "$OUTDIR/nmap_vuln" vulnweb.com || true
        nmap -p- --min-rate 1000 -sS -sV --script vuln -oA "$OUTDIR/nmap_all" vulnweb.com || true
    fi
fi


# FFUF directory discovery (optional)
echo "[+] Running ffuf directory discovery"
if command -v ffuf >/dev/null 2>&1; then
    WL="/usr/share/wordlists/dirb/common.txt"
    if [ ! -f "$WL" ]; then
        echo "[-] Wordlist $WL not found, using a small inline list"
        WL_TMP="$OUTDIR/ffuf_small_wl.txt"
        cat > "$WL_TMP" <<'WL'
admin
login
uploads
images
assets
css
js
api
wp-admin
WL
        WL="$WL_TMP"
    fi

    ffuf -u "$TARGET/FUZZ" -w "$WL" -o "$OUTDIR/ffuf_dirs.json" -of json -t 25 || true
else
    echo "ffuf not installed, skipping dir discovery"
fi


# Nikto (optional)
echo "[+] Running nikto"
if command -v nikto >/dev/null 2>&1; then
    nikto -h "$TARGET" -output "$OUTDIR/nikto.txt" || true
else
    echo "nikto not installed, skipping"
fi


# ZAP: baseline or API scan
echo "[+] Running ZAP baseline scan (if available) or API scan"
if command -v zap-baseline.py >/dev/null 2>&1; then
    zap-baseline.py -t "$TARGET" -r "$OUTDIR/zap_report.html" -l "$OUTDIR/zap_report.log" || true
else
    echo "ZAP baseline not found. Checking for running ZAP daemon at 127.0.0.1:8080..."
    ZAP_HOST="${ZAP_HOST:-127.0.0.1}"
    ZAP_PORT="${ZAP_PORT:-8080}"
    ZAP_APIKEY="${ZAP_APIKEY:-changeme}"

    if command -v curl >/dev/null 2>&1 && curl -sS "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/version/?apikey=${ZAP_APIKEY}" >/dev/null 2>&1; then
        echo "[+] ZAP daemon reachable at ${ZAP_HOST}:${ZAP_PORT}, running API scan..."
        if python3 -c 'import zapv2' >/dev/null 2>&1; then
            # pass TARGET, OUTDIR, ZAP_HOST, ZAP_PORT, ZAP_APIKEY as sys.argv
            python3 - "$TARGET" "$OUTDIR" "$ZAP_HOST" "$ZAP_PORT" "$ZAP_APIKEY" <<'PY'
import sys, time, json
from zapv2 import ZAPv2

TARGET = sys.argv[1]
OUTDIR = sys.argv[2]
ZAP_HOST = sys.argv[3]
ZAP_PORT = sys.argv[4]
APIKEY = sys.argv[5]

BASE = f"http://{ZAP_HOST}:{ZAP_PORT}"
zap = ZAPv2(apikey=APIKEY, proxies={'http': BASE, 'https': BASE})

print('Starting ZAP spider for:', TARGET)
spider_scan_id = zap.spider.scan(TARGET)

# Wait for spider to finish
while int(zap.spider.status(spider_scan_id)) < 100:
    print('Spider progress %:', zap.spider.status(spider_scan_id))
    time.sleep(2)

print('Spider complete. Starting active scan...')
ascan_id = zap.ascan.scan(TARGET)

# Wait for active scan to finish
while int(zap.ascan.status(ascan_id)) < 100:
    print('AScan progress %:', zap.ascan.status(ascan_id))
    time.sleep(5)

alerts = zap.core.alerts(baseurl=TARGET)
out_path = OUTDIR.rstrip('/') + '/zap_alerts.json'
with open(out_path, 'w', encoding='utf-8') as fh:
    json.dump(alerts, fh, ensure_ascii=False, indent=2)

print('ZAP scan completed, alerts saved to', out_path)
PY
        else
            echo "python zapv2 module not found; install with: pip install python-owasp-zap-v2.4"
        fi
    else
        echo "ZAP daemon not reachable at ${ZAP_HOST}:${ZAP_PORT}. To run ZAP quickly with Docker:"
        echo "  docker run -u zap -p 8080:8080 -d --name zap-daemon owasp/zap2docker-weekly \\"
        echo "    zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=${ZAP_APIKEY}"
        echo "Skipping ZAP API scan for now."
    fi
fi


# Build params.txt automatically (for sqlmap)
echo "[+] Building params.txt automatically"
PARAMS_FILE="$OUTDIR/params.txt"
TMPDIR="$(mktemp -d)"
FOUND="$TMPDIR/found_urls.txt"
WGET_DIR="$TMPDIR/wget_mirror"

# Shell-safe BASE_URL extraction (no embedded python)
HOST="$(printf '%s' "$TARGET" | sed -E 's#^https?://##; s#/.*$##')"
SCHEME="$(printf '%s' "$TARGET" | sed -nE 's#^(https?)://.*#\1#p')"
if [ -z "$SCHEME" ]; then
    SCHEME="http"
fi
BASE_URL="${SCHEME}://${HOST}"

touch "$FOUND"

# Historical URLs via waybackurls or gau
if command -v waybackurls >/dev/null 2>&1; then
    echo "[*] Collecting historical URLs via waybackurls..."
    waybackurls "$TARGET" 2>/dev/null | grep '\?' >> "$FOUND" || true
elif command -v gau >/dev/null 2>&1; then
    echo "[*] Collecting historical URLs via gau..."
    gau "$TARGET" 2>/dev/null | grep '\?' >> "$FOUND" || true
else
    echo "[-] waybackurls/gau not installed, skipping historical URL collection"
fi

# Lightweight wget crawl
if command -v wget >/dev/null 2>&1; then
    echo "[*] Crawling site with wget (depth 2)..."
    mkdir -p "$WGET_DIR"
    wget --quiet --recursive --no-parent --level=2 --convert-links --adjust-extension --page-requisites --span-hosts "$TARGET" -P "$WGET_DIR" || true
    grep -RhoP "https?://[^\"' >]+" "$WGET_DIR" 2>/dev/null | grep '\?' >> "$FOUND" || true
else
    echo "[-] wget not found; skipping wget crawl"
fi

# Fetch homepage and extract links
if command -v curl >/dev/null 2>&1; then
    echo "[*] Fetching homepage and extracting links..."
    HOME_HTML="$TMPDIR/home.html"
    HOME_HTML1="$TMPDIR/home.html1"
    HOME_HTML2="$TMPDIR/home.html2"
    curl -sL "$TARGET" -o "$HOME_HTML" || true
    curl -s -D - "$TARGET" -o "$HOME_HTML1" || true
    curl -I "$TARGET" -o "$HOME_HTML2" || true
    grep -oP 'https?://[^"'\'' >]+' "$HOME_HTML" 2>/dev/null | grep '\?' >> "$FOUND" || true

    awk 'BEGIN{RS=">";FS="<"} { for(i=1;i<=NF;i++) if ($i ~ /href=/) print $i }' "$HOME_HTML" \
        | grep -oP 'href\s*=\s*["'\'']?([^"'\'' >]+)' 2>/dev/null \
        | sed -E 's/href\s*=\s*["'\'']?//g' \
        | grep '\?' \
        | while read -r u; do
            case "$u" in
                http* ) echo "$u" >> "$FOUND" ;;
                /* ) printf "%s%s\n" "$BASE_URL" "$u" >> "$FOUND" ;;
                * ) printf "%s/%s\n" "$BASE_URL" "$u" >> "$FOUND" ;;
            esac
        done
else
    echo "[-] curl not found; skipping homepage fetch"
fi

# Candidate generation: append common param names
COMMON_PARAMS="$TMPDIR/params_list.txt"
cat > "$COMMON_PARAMS" <<'EOF'
id
page
p
q
search
s
query
user
uid
username
product
prod
cat
category
lang
locale
view
item
article
post
name
term
tag
type
action
ref
refid
sort
order
limit
offset
start
count
file
download
token
session
sessionid
EOF

CAND_BASES=("$BASE_URL" "$BASE_URL/index.php" "$BASE_URL/search")
if [ -d "$WGET_DIR" ]; then
    while read -r u; do
        CAND_BASES+=("$u")
    done < <(grep -RhoP "https?://[^\"' >]+" "$WGET_DIR" 2>/dev/null | sed 's/[?#].*$//' | sort -u || true)
fi

for base in "${CAND_BASES[@]}"; do
    for param in $(cat "$COMMON_PARAMS"); do
        if printf "%s" "$base" | grep -q '\?'; then
            echo "${base}&${param}=1" >> "$FOUND"
        else
            echo "${base}?${param}=1" >> "$FOUND"
        fi
    done
done

# Optional light ffuf param probe
if command -v ffuf >/dev/null 2>&1; then
    echo "[*] Running light ffuf param probe..."
    FF_WORDLIST="$TMPDIR/ff_param_names.txt"
    cp "$COMMON_PARAMS" "$FF_WORDLIST"
    ffuf -u "${TARGET}?FUZZ=1" -w "$FF_WORDLIST" -mc all -s -o "$TMPDIR/ffuf_params.json" -of json -t 25 || true
    ffuf -u "${TARGET}?FUZZ" -w /path/to/seclists/Discovery/Web-Content/ -t 50 -mc 200,301,302,403 -o "$TMPDIR/ffuf_deep.json" -of json || true
    ffuf -u "$TARGET/FUZZ" -w /path/to/seclists/Discovery/Web-Content/common.txt -t 50 -mc 200,301,302,403 -o "$OUTDIR/ffuf_more.json" -of json || true
    ffuf -u "$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.bak -t 50 -o "$OUTDIR/ffuf_page.json" -of json || true

    if [ -f "$TMPDIR/ffuf_params.json" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -r '.results[]?.url' "$TMPDIR/ffuf_params.json" | grep '\?' >> "$FOUND" || true
        else
            grep -oP '"url":\s*"[^\"]+"' "$TMPDIR/ffuf_params.json" 2>/dev/null | sed -E 's/"url":\s*"//' | sed 's/"$//' | grep '\?' >> "$FOUND" || true
        fi
    fi
fi

# Normalize & dedupe, write params.txt
echo "[*] Normalizing and deduplicating candidate URLs..."
python3 - "$FOUND" "$BASE_URL" <<'PY' > "$PARAMS_FILE"
import sys, urllib.parse
found = sys.argv[1]
base = sys.argv[2]
seen = set()
with open(found, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        u = line.strip()
        if not u:
            continue
        if u.lower().startswith(("javascript:","mailto:")):
            continue
        if u.startswith("/"):
            u = base.rstrip("/") + u
        if "?" not in u:
            continue
        try:
            p = urllib.parse.urlparse(u)
            norm = urllib.parse.urlunparse((p.scheme or 'http', p.netloc, p.path or '/', p.params, p.query, ''))
        except Exception:
            norm = u
        if norm not in seen:
            seen.add(norm)
for u in sorted(seen):
    if u.startswith("http://") or u.startswith("https://"):
        print(u)
PY

# ensure only http(s) lines
grep -E '^https?://' "$PARAMS_FILE" > "$PARAMS_FILE.tmp" || true
mv "$PARAMS_FILE.tmp" "$PARAMS_FILE" || true

COUNT=$(wc -l < "$PARAMS_FILE" 2>/dev/null || echo 0)
echo "[+] params.txt created at: $PARAMS_FILE ($COUNT entries)"

# cleanup tmp files
rm -rf "$TMPDIR" || true


# SQLMap automated runs
if [ -f "$PARAMS_FILE" ]; then
    echo "[+] Running sqlmap on parameters from $PARAMS_FILE"
    mkdir -p "$OUTDIR/sqlmap"
    while IFS= read -r p || [ -n "$p" ]; do
        case "$p" in
            ""|\#*) continue ;;
        esac
        echo "[*] Testing: $p"
        sqlmap -u "${p}" --batch --level=2 --risk=1 --output-dir="$OUTDIR/sqlmap" || true
    done < "$PARAMS_FILE"
else
    echo "No params.txt file found; skipping sqlmap automated runs. Create params.txt with URLs to test."
fi

# Host info
echo "[+] Saving host info"
{
    uname -a
    python3 -V 2>&1
} > "$OUTDIR/host_info.txt" || true


# Archive results
echo "[+] Creating results archive"
if command -v tar >/dev/null 2>&1; then
    tar -czf "${OUTDIR}.tar.gz" -C "results" "${DATE}" || true
    echo "[+] Archive created: ${OUTDIR}.tar.gz"
else
    echo "tar not found; skipping archive creation"
fi

echo "[+] Pipeline complete. Results: $OUTDIR (also ${OUTDIR}.tar.gz)"

echo "[*] Generating final reports..."
export RESULTS_DIR="$OUTDIR"

