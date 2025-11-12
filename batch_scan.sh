#!/bin/bash
# Batch scanner - reads targets from file

set -euo pipefail

TARGETS_FILE="${1:-targets.txt}"
SCAN_TYPE="${2:-quick}"  # full, quick, or ports

if [ ! -f "${TARGETS_FILE}" ]; then
    echo "[-] Targets file not found: ${TARGETS_FILE}"
    echo ""
    echo "Usage: $0 <targets_file> [scan_type]"
    echo ""
    echo "Example:"
    echo "  echo 'example.com' > targets.txt"
    echo "  echo 'testsite.com' >> targets.txt"
    echo "  $0 targets.txt quick"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                    BATCH RECONNAISSANCE SCANNER                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Targets file: ${TARGETS_FILE}"
echo "[*] Scan type: ${SCAN_TYPE}"
echo "[*] Results: ./results/"
echo ""

# Count targets
target_count=$(grep -v '^#' "${TARGETS_FILE}" | grep -v '^[[:space:]]*$' | wc -l)
echo "[*] Found ${target_count} targets"
echo ""

current=0

# Read targets from file
while IFS= read -r target || [ -n "${target}" ]; do
    # Skip comments and empty lines
    [[ "${target}" =~ ^#.*$ ]] && continue
    [[ -z "${target}" ]] && continue

    current=$((current + 1))

    echo "════════════════════════════════════════════════════════════════════"
    echo "[${current}/${target_count}] Target: ${target}"
    echo "════════════════════════════════════════════════════════════════════"

    # Run scan inside container
    if sudo docker run --rm -v "$(pwd)/results:/results" recon-tor -- \
       bash /usr/local/bin/internal_scan.sh "${target}" "${SCAN_TYPE}"; then
        echo "[+] Completed: ${target}"
    else
        echo "[-] Failed: ${target} (exit code: $?)"
    fi

    echo ""

    # Pause between scans
    if [ ${current} -lt ${target_count} ]; then
        echo "[*] Waiting 10 seconds before next target..."
        sleep 10
    fi

done < "${TARGETS_FILE}"

echo "════════════════════════════════════════════════════════════════════"
echo "[+] Batch scan completed!"
echo "[*] Scanned: ${target_count} targets"
echo "[*] Results: ./results/"
echo "════════════════════════════════════════════════════════════════════"
