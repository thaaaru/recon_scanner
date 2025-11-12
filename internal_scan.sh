#!/bin/bash
# Internal automated scan script
# This runs INSIDE the Docker container after Tor and leak detection

set -euo pipefail

TARGET="$1"
SCAN_TYPE="${2:-full}"  # full, quick, or ports

echo "[*] Internal scan starting..."
echo "[*] Target: ${TARGET}"
echo "[*] Scan type: ${SCAN_TYPE}"
echo ""

case "${SCAN_TYPE}" in
    "full")
        echo "[*] Running full reconnaissance..."

        # Port scan
        echo "[1/4] Port scanning..."
        proxychains4 -q nmap -Pn -sT -p80,443,8080,8443,3000 "${TARGET}" 2>/dev/null || true

        # DNS queries
        echo "[2/4] DNS enumeration..."
        proxychains4 -q dig "${TARGET}" A +short 2>/dev/null || true
        proxychains4 -q dig "${TARGET}" MX +short 2>/dev/null || true
        proxychains4 -q dig "${TARGET}" NS +short 2>/dev/null || true

        # HTTP headers
        echo "[3/4] HTTP headers..."
        proxychains4 -q curl -I -L "https://${TARGET}" 2>/dev/null || true

        # IP info
        echo "[4/4] IP information..."
        IP=$(proxychains4 -q dig "${TARGET}" A +short 2>/dev/null | head -1)
        if [ -n "${IP}" ]; then
            proxychains4 -q curl -s "https://ipinfo.io/${IP}" 2>/dev/null || true
        fi
        ;;

    "quick")
        echo "[*] Running quick scan..."
        proxychains4 -q nmap -Pn -sT -F "${TARGET}" 2>/dev/null || true
        proxychains4 -q curl -I "https://${TARGET}" 2>/dev/null || true
        ;;

    "ports")
        echo "[*] Running port scan only..."
        proxychains4 -q nmap -Pn -sT -p- "${TARGET}" 2>/dev/null || true
        ;;

    *)
        echo "[-] Unknown scan type: ${SCAN_TYPE}"
        echo "Usage: $0 <target> [full|quick|ports]"
        exit 1
        ;;
esac

echo ""
echo "[+] Scan completed!"
