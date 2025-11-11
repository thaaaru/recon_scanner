#!/bin/bash
# Scan wrapper - executes commands via proxychains4 and logs output
# All reconnaissance commands MUST go through this wrapper

set -euo pipefail

# Configuration
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${RESULTS_DIR}/${TIMESTAMP}.log"

# Exit codes
EXIT_SUCCESS=0
EXIT_ERROR=1

log_info() {
    echo "[*] $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo "[+] $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[!] $1" | tee -a "${LOG_FILE}"
}

# Verify proxychains is available
check_proxychains() {
    if ! command -v proxychains4 &>/dev/null; then
        log_error "proxychains4 not found in PATH"
        return 1
    fi

    if [ ! -f /etc/proxychains4.conf ]; then
        log_error "proxychains4 configuration not found"
        return 1
    fi

    return 0
}

# Main execution
main() {
    if [ $# -eq 0 ]; then
        log_error "No command provided to scan wrapper"
        exit "${EXIT_ERROR}"
    fi

    # Create results directory if it doesn't exist
    mkdir -p "${RESULTS_DIR}" 2>/dev/null || true

    # Verify proxychains
    if ! check_proxychains; then
        exit "${EXIT_ERROR}"
    fi

    # Log scan details
    {
        echo "════════════════════════════════════════════════════════════"
        echo "RECON SCAN LOG"
        echo "════════════════════════════════════════════════════════════"
        echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Command: $*"
        echo "Log file: ${LOG_FILE}"
        echo "════════════════════════════════════════════════════════════"
        echo ""
    } | tee -a "${LOG_FILE}"

    log_info "Executing via proxychains4..."
    log_info "All traffic will be routed through Tor"
    echo ""

    # Execute command via proxychains4
    # Stream output to both stdout and log file
    local exit_code=0
    if proxychains4 -q "$@" 2>&1 | tee -a "${LOG_FILE}"; then
        exit_code=0
    else
        exit_code=$?
    fi

    echo ""
    {
        echo "════════════════════════════════════════════════════════════"
        echo "SCAN COMPLETED"
        echo "════════════════════════════════════════════════════════════"
        echo "Exit code: ${exit_code}"
        echo "Duration: $SECONDS seconds"
        echo "Results saved to: ${LOG_FILE}"
        echo "════════════════════════════════════════════════════════════"
    } | tee -a "${LOG_FILE}"

    if [ "${exit_code}" -eq 0 ]; then
        log_success "Scan completed successfully"
        exit "${EXIT_SUCCESS}"
    else
        log_error "Scan failed with exit code ${exit_code}"
        exit "${exit_code}"
    fi
}

main "$@"
