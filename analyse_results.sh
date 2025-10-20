#!/usr/bin/env bash
set -euo pipefail


# Validate args
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <RESULTS_DIR>"
    exit 1
fi

OUTDIR="$1"

# Ensure the results directory exists
if [ ! -d "$OUTDIR" ]; then
    echo "Error: Directory '$OUTDIR' not found."
    exit 1
fi

# Create 'analyse' output directory
ANALYSE_DIR="$OUTDIR/analyse"
mkdir -p "$ANALYSE_DIR"

echo "[+] Saving analysis results to: $ANALYSE_DIR"


# Summary of open ports & services
if [ -f "$OUTDIR/nmap_top.nmap" ]; then
    grep -i "open" "$OUTDIR/nmap_top.nmap" > "$ANALYSE_DIR/open_ports_and_services.txt" || true
    echo "[✔] open_ports_and_services.txt created"
else
    echo " No nmap_top.nmap file found."
fi


# Greppable ports from .gnmap
if [ -f "$OUTDIR/nmap_top.gnmap" ]; then
    cat "$OUTDIR/nmap_top.gnmap" > "$ANALYSE_DIR/greppable_ports_from_gnmap.txt"
    awk -F'Ports: ' '{print $2}' "$OUTDIR/nmap_top.gnmap" > "$ANALYSE_DIR/parsed_ports_from_gnmap.txt"
    echo " greppable_ports_from_gnmap.txt + parsed_ports_from_gnmap.txt created"
else
    echo "  No nmap_top.gnmap file found."
fi


# Services & versions from XML
if [ -f "$OUTDIR/nmap_top.xml" ]; then
    xmlstarlet sel -t -m "//port[state/@state='open']" \
        -v "concat('port/',../@protocol,':',@portid,' -> ',service/@name,' ',service/@product,' ',service/@version)" \
        -n "$OUTDIR/nmap_top.xml" > "$ANALYSE_DIR/services_and_versions_from_xml.txt"
    echo " services_and_versions_from_xml.txt created"
else
    echo " No nmap_top.xml file found."
fi

if [ -f "$OUTDIR/nmap_top.xml" ]; then
    xmlstarlet sel -t -m "//script" \
        -v "concat('script:',@id,' -> ',.)" -n "$OUTDIR/nmap_top.xml" \
        > "$ANALYSE_DIR/nse_script_outputs.txt"
    echo "[✔] nse_script_outputs.txt created"
else
    echo "Skipping NSE extraction (no XML)."
fi


# Nikto findings
if [ -f "$OUTDIR/nikto.txt" ]; then
    grep -E "OSVDB|\+|Server:|9898|_WARNING_|+___" -n "$OUTDIR/nikto.txt" > "$ANALYSE_DIR/nikto_findings.txt" || \
    sed -n '1,200p' "$OUTDIR/nikto.txt" > "$ANALYSE_DIR/nikto_findings.txt"
    echo "[✔] nikto_findings.txt created"
else
    echo " No nikto.txt found."
fi

# FFUF results (JSON and fallback)
if [ -f "$OUTDIR/ffuf_dirs.json" ]; then
    if command -v jq &>/dev/null; then
        jq -r '.results[] | [.url, .status, .length] | @tsv' "$OUTDIR/ffuf_dirs.json" \
            | column -t > "$ANALYSE_DIR/ffuf_discovered_paths.txt"
    else
        grep -oP '"url":\s*"[^\"]+"' "$OUTDIR/ffuf_dirs.json" \
            | sed -E 's/"url":\s*"//' | sed 's/"$//' \
            > "$ANALYSE_DIR/ffuf_discovered_paths.txt"
    fi
    echo " ffuf_discovered_paths.txt created"
else
    echo " No ffuf_dirs.json found."
fi


# Summary info
echo "Analysis generated on: $(date)" > "$ANALYSE_DIR/_summary.txt"
ls -lh "$ANALYSE_DIR" >> "$ANALYSE_DIR/_summary.txt"

echo
echo " All analysis files saved under: $ANALYSE_DIR"
