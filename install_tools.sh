#!/usr/bin/env bash
set -euo pipefail
echo "[+] Installing essential tools..."
sudo apt update -y
sudo apt install -y nmap nikto ffuf sqlmap jq xmlstarlet python3-pip wget curl
pip install python-owasp-zap-v2.4 xmltodict jinja2 pandas matplotlib xlsxwriter
echo "[✔] All tools installed successfully!"
