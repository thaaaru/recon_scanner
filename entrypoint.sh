#!/bin/bash
# Entrypoint for Tor+Proxychains reconnaissance container
# Orchestrates Tor startup, leak detection, and scan execution

set -euo pipefail

# Exit codes
EXIT_SUCCESS=0
EXIT_ERROR=1
EXIT_TOR_TIMEOUT=2
EXIT_LEAK_DETECTED=3
EXIT_ILLEGAL_INVOCATION=4

# Configuration from environment
TOR_TIMEOUT_SECS="${TOR_TIMEOUT_SECS:-60}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TOR_LOG="/tmp/tor.log"
TOR_PID=""

# Cleanup function
cleanup() {
    local exit_code=$?
    echo "[*] Cleaning up..."

    if [ -n "${TOR_PID}" ] && kill -0 "${TOR_PID}" 2>/dev/null; then
        echo "[*] Stopping Tor (PID: ${TOR_PID})..."
        kill "${TOR_PID}" 2>/dev/null || true
        wait "${TOR_PID}" 2>/dev/null || true
    fi

    rm -f "${TOR_LOG}" 2>/dev/null || true
    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

# Print ethical warning
print_warning() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                         ⚠️  LEGAL WARNING ⚠️                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Do not use this image to scan systems without explicit permission.  ║
║  Unauthorized scanning is illegal and unethical.                     ║
║  The author is not responsible for misuse.                           ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
}

# Start Tor daemon
start_tor() {
    echo "[*] Starting Tor daemon..."

    # Start Tor in background, logging to file
    tor -f /etc/tor/torrc > "${TOR_LOG}" 2>&1 &
    TOR_PID=$!

    echo "[+] Tor started (PID: ${TOR_PID})"
}

# Wait for Tor to bootstrap
wait_for_tor() {
    echo "[*] Waiting for Tor to bootstrap (timeout: ${TOR_TIMEOUT_SECS}s)..."

    local elapsed=0
    local bootstrap_complete=false

    while [ "${elapsed}" -lt "${TOR_TIMEOUT_SECS}" ]; do
        # Check if Tor process is still running
        if ! kill -0 "${TOR_PID}" 2>/dev/null; then
            echo "[!] Tor process died unexpectedly"
            cat "${TOR_LOG}" 2>/dev/null || true
            exit "${EXIT_TOR_TIMEOUT}"
        fi

        # Check if SOCKS port is listening
        if ss -ltn | grep -q '127.0.0.1:9050'; then
            # Check for 100% bootstrap in logs
            if grep -q 'Bootstrapped 100%' "${TOR_LOG}" 2>/dev/null; then
                bootstrap_complete=true
                break
            fi
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    if [ "${bootstrap_complete}" = false ]; then
        echo "[!] Tor failed to bootstrap within ${TOR_TIMEOUT_SECS} seconds"
        echo "[!] Tor log tail:"
        tail -20 "${TOR_LOG}" 2>/dev/null || true
        exit "${EXIT_TOR_TIMEOUT}"
    fi

    echo "[+] Tor bootstrapped successfully (100%)"
}

# Show help
show_help() {
    cat << 'EOF'
Usage: docker run [OPTIONS] recon-tor [-- SCAN_COMMAND]

Environment Variables:
  TOR_TIMEOUT_SECS    Seconds to wait for Tor bootstrap (default: 60)
  LEAK_TEST_URL       URL for IP leak testing (default: https://ipinfo.io/ip)
  RESULTS_DIR         Directory for scan results (default: /results)

Exit Codes:
  0   Success
  1   Generic error
  2   Tor timeout or not listening
  3   DNS/IP leak detected
  4   Missing target or illegal invocation

Examples:
  docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -Pn -sT target.com
  docker run --rm -v $(pwd)/results:/results recon-tor -- curl https://example.com

Notes:
  - All commands run through proxychains4
  - Leak detection must pass before scan execution
  - Results saved to /results/<timestamp>.log
EOF
}

# Main execution
main() {
    print_warning
    echo ""

    # Handle help
    if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        exit "${EXIT_SUCCESS}"
    fi

    # Validate invocation - must have -- separator or command
    if [ "$1" != "--" ]; then
        echo "[!] Error: Commands must be preceded by '--' separator"
        echo "[!] Example: docker run recon-tor -- nmap -sT target.com"
        exit "${EXIT_ILLEGAL_INVOCATION}"
    fi

    shift  # Remove '--' separator

    # Check if command provided
    if [ $# -eq 0 ]; then
        echo "[!] Error: No scan command provided"
        echo "[!] Usage: docker run recon-tor -- <command> <args>"
        exit "${EXIT_ILLEGAL_INVOCATION}"
    fi

    # Basic target validation (look for something that might be a target)
    local scan_cmd="$*"
    if ! echo "${scan_cmd}" | grep -qE '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'; then
        echo "[!] Error: No target detected in command"
        echo "[!] Command: ${scan_cmd}"
        echo "[!] Do not scan without permission."
        exit "${EXIT_ILLEGAL_INVOCATION}"
    fi

    # Create results directory
    mkdir -p "${RESULTS_DIR}" 2>/dev/null || true

    # Start Tor
    start_tor

    # Wait for Tor to be ready
    wait_for_tor

    # Perform leak detection
    echo "[*] Running DNS/IP leak detection..."
    if ! /usr/local/bin/check_leak.sh; then
        echo "[!] Leak detection failed - aborting scan"
        exit "${EXIT_LEAK_DETECTED}"
    fi

    # Execute scan via wrapper
    echo "[*] Leak detection passed - executing scan"
    exec /usr/local/bin/scan_wrapper.sh "$@"
}

main "$@"
