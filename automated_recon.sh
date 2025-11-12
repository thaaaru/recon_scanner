#!/bin/bash
# Automated reconnaissance script using Docker
# Runs on HOST machine, launches Docker containers for each scan

set -euo pipefail

# Configuration
TARGETS=(
    "example.com"
    "testphp.vulnweb.com"
)

PORTS="80,443,8080,8443,3000,3306,5432"
IMAGE_NAME="recon-tor"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║               AUTOMATED RECONNAISSANCE SCANNER                       ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Targets: ${#TARGETS[@]}"
echo "[*] Docker Image: ${IMAGE_NAME}"
echo "[*] Results Directory: $(pwd)/results"
echo ""

# Check if Docker image exists
if ! docker image inspect "${IMAGE_NAME}" > /dev/null 2>&1; then
    echo "[-] Docker image '${IMAGE_NAME}' not found!"
    echo "[*] Building image..."
    docker build -t "${IMAGE_NAME}" .
fi

# Create results directory
mkdir -p results

# Scan each target
for target in "${TARGETS[@]}"; do
    echo "════════════════════════════════════════════════════════════════════"
    echo "[*] Target: ${target}"
    echo "════════════════════════════════════════════════════════════════════"
    echo ""

    # 1. Port Scan
    echo "[1/3] Running port scan..."
    if docker run --rm -v "$(pwd)/results:/results" "${IMAGE_NAME}" -- \
       nmap -Pn -sT -p"${PORTS}" "${target}"; then
        echo "[+] Port scan completed"
    else
        exit_code=$?
        echo "[-] Port scan failed (exit code: ${exit_code})"
        case ${exit_code} in
            2) echo "    → Tor timeout - try increasing TOR_TIMEOUT_SECS" ;;
            3) echo "    → Leak detected - check network configuration" ;;
            4) echo "    → Invalid command format" ;;
        esac
    fi
    echo ""

    # 2. DNS Enumeration
    echo "[2/3] Running DNS enumeration..."
    if docker run --rm -v "$(pwd)/results:/results" "${IMAGE_NAME}" -- \
       dig "${target}" ANY +noall +answer; then
        echo "[+] DNS enumeration completed"
    else
        echo "[-] DNS enumeration failed (exit code: $?)"
    fi
    echo ""

    # 3. HTTP Headers
    echo "[3/3] Grabbing HTTP headers..."
    if docker run --rm -v "$(pwd)/results:/results" "${IMAGE_NAME}" -- \
       curl -I -L "https://${target}"; then
        echo "[+] HTTP headers retrieved"
    else
        echo "[-] HTTP request failed (exit code: $?)"
    fi
    echo ""

    echo "[✓] Completed: ${target}"
    echo ""

    # Brief pause between targets to avoid overwhelming Tor
    sleep 5
done

echo "════════════════════════════════════════════════════════════════════"
echo "[+] All scans completed!"
echo "[*] Results saved in: ./results/"
echo ""
echo "View results:"
echo "  ls -lah results/"
echo "  cat results/\$(ls -t results/ | head -1)"
echo "════════════════════════════════════════════════════════════════════"
