#!/usr/bin/env bash
set -euo pipefail

# Usage: build_params.sh TARGET [OUTDIR]
TARGET="${1:-}"
OUTDIR="${2:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <TARGET_URL> [OUTDIR]"
    exit 1
fi

DATE=$(date +%F_%H%M%S)
if [ -z "$OUTDIR" ]; then
    OUTDIR="results/$DATE"
fi
mkdir -p "$OUTDIR"

PARAMS_FILE="$OUTDIR/params.txt"
TMPDIR="$(mktemp -d)"
FOUND="$TMPDIR/found_urls.txt"

echo "[+] Target: $TARGET"
echo "[+] Output dir: $OUTDIR"
echo "[+] Temp dir: $TMPDIR"

# Helper: normalize URL (strip fragments, keep scheme://host/path?query)
normalize_url() {
    python3 - <<PY - "$1"
import sys
from urllib.parse import urlparse, urlunparse
s = sys.argv[1]
try:
    p = urlparse(s)
    normalized = urlunparse((p.scheme or 'http', p.netloc, p.path or '/', p.params, p.query, ''))
    print(normalized)
except Exception:
    print(s)
PY
}

#  Use waybackurls/gau if available (historical URLs)
echo "[*] Gathering historical URLs (waybackurls/gau) if available..."
if command -v waybackurls >/dev/null 2>&1; then
    echo "[+] running waybackurls"
    waybackurls "$TARGET" 2>/dev/null | grep '\?' >> "$FOUND" || true
elif command -v gau >/dev/null 2>&1; then
    echo "[+] running gau"
    gau "$TARGET" 2>/dev/null | grep '\?' >> "$FOUND" || true
else
    echo "[-] waybackurls/gau not installed, skipping historical URL collection"
fi

# Crawl site with wget and extract links with '?'
echo "[*] Crawling site with wget (depth 2) and extracting links..."
WGET_DIR="$TMPDIR/wget_mirror"
mkdir -p "$WGET_DIR"
if command -v wget >/dev/null 2>&1; then
    wget --quiet --recursive --no-parent --level=2 --convert-links --adjust-extension --page-requisites --span-hosts "$TARGET" -P "$WGET_DIR" || true
    grep -RhoP "https?://[^\"' >]+" "$WGET_DIR" 2>/dev/null | grep '\?' >> "$FOUND" || true
else
    echo "[-] wget not found, skipping wget crawl"
fi

# Simple HTTP fetch of homepage and extract hrefs (fallback)
echo "[*] Fetching main page and extracting links..."
if command -v curl >/dev/null 2>&1; then
    HOME_HTML="$TMPDIR/home.html"
    curl -sL "$TARGET" -o "$HOME_HTML" || true
    grep -oP 'https?://[^"'\'' >]+' "$HOME_HTML" 2>/dev/null | grep '\?' >> "$FOUND" || true
    
    awk 'BEGIN{RS=">";FS="<"} { for(i=1;i<=NF;i++) if ($i ~ /href=/) print $i }' "$HOME_HTML" \
        | grep -oP 'href\s*=\s*["'\'']?([^"'\'' >]+)' 2>/dev/null \
        | sed -E 's/href\s*=\s*["'\'']?//g' \
        | grep '\?' \
        | while read -r u; do
            case "$u" in
                http* ) echo "$u" >> "$FOUND" ;;
                /* ) printf "%s%s\n" "$(python3 - <<PY
from urllib.parse import urlparse
u="$TARGET"
p=urlparse(u)
print(p.scheme + "://" + p.netloc)
PY
)" "$u" >> "$FOUND" ;;
                * ) printf "%s/%s\n" "$(python3 - <<PY
from urllib.parse import urlparse
u="$TARGET"
p=urlparse(u)
print(p.scheme + "://" + p.netloc)
PY
)" "$u" >> "$FOUND" ;;
            esac
        done
else
    echo "[-] curl not found, skipping homepage fetch"
fi

# Param names fuzzing: build candidate URLs by appending common param names with sample values
echo "[*] Generating candidate paramized URLs from common parameter names..."
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
term_id
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
file_id
token
session
sessionid
EOF


# Extract base host and path from TARGET
BASE_URL="$(python3 - <<PY
from urllib.parse import urlparse
import sys
u=sys.argv[1]
p=urlparse(u)
scheme = p.scheme if p.scheme else 'http'
host = p.netloc
print(f\"{scheme}://{host}\")
PY
)" "$TARGET"

# Add some common endpoints
CAND_BASES=("$BASE_URL" "$BASE_URL/index.php" "$BASE_URL/search" )

# include any paths discovered in wget that don't have '?'
if [ -d "$WGET_DIR" ]; then
    # try to find .php, .asp, .aspx, /path style files
    grep -RhoP "https?://[^\"' >]+" "$WGET_DIR" 2>/dev/null | sed 's/[?#].*$//' | sort -u \
        | while read -r u; do
            CAND_BASES+=("$u")
        done
fi

# Create candidate URLs by appending param=value
for base in "${CAND_BASES[@]}"; do
    for param in $(cat "$COMMON_PARAMS"); do
        # avoid duplicate question marks if base already has '?'
        if printf "%s" "$base" | grep -q '\?'; then
            echo "${base}&${param}=1" >> "$FOUND"
        else
            echo "${base}?${param}=1" >> "$FOUND"
        fi
    done
done

#use ffuf parameter discovery if ffuf exists and user wants it
if command -v ffuf >/dev/null 2>&1; then
    echo "[*] Running a light ffuf param-name probe (requires wordlist); this may generate noise."
    FF_WORDLIST="$TMPDIR/ff_param_names.txt"
    cp "$COMMON_PARAMS" "$FF_WORDLIST"

    ffuf -u "${TARGET}?FUZZ=1" -w "$FF_WORDLIST" -mc all -s -o "$TMPDIR/ffuf_params.json" -of json -t 25 || true

    if [ -f "$TMPDIR/ffuf_params.json" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -r '.results[]?.url' "$TMPDIR/ffuf_params.json" | grep '\?' >> "$FOUND" || true
        else
            grep -oP '"url":\s*"[^\"]+"' "$TMPDIR/ffuf_params.json" 2>/dev/null | sed -E 's/"url":\s*"//' | sed 's/"$//' | grep '\?' >> "$FOUND" || true
        fi
    fi
else
    echo "[-] ffuf not found; skipped active param probing"
fi

# Normalize, dedupe and keep only URLs that actually contain '?'
echo "[*] Normalizing and deduplicating results..."
touch "$FOUND"

python3 - <<PY > "$PARAMS_FILE"
import sys,urllib.parse
seen=set()
with open("$FOUND","r",encoding="utf-8",errors="ignore") as f:
    for line in f:
        u=line.strip()
        if not u: 
            continue
        # skip javascript: and mailto:
        if u.lower().startswith(("javascript:","mailto:")):
            continue
        # if no scheme, try to prefix base
        if u.startswith("/"):
            base = "$BASE_URL"
            u = base.rstrip("/") + u
        if "?" not in u:
            continue
        try:
            p=urllib.parse.urlparse(u)
            norm=urllib.parse.urlunparse((p.scheme or 'http', p.netloc, p.path or '/', p.params, p.query, ''))
        except Exception:
            norm=u
        if norm not in seen:
            seen.add(norm)
for u in sorted(seen):
    print(u)
PY

# Finally, filter params file to keep only http(s) lines and dedupe (safe-guard)
grep -E '^https?://' "$PARAMS_FILE" > "$PARAMS_FILE.tmp" || true
mv "$PARAMS_FILE.tmp" "$PARAMS_FILE" || true

COUNT=$(wc -l < "$PARAMS_FILE" 2>/dev/null || echo 0)
echo "[+] Done. params.txt created at: $PARAMS_FILE ($COUNT entries)"


rm -rf "$TMPDIR"

exit 0

