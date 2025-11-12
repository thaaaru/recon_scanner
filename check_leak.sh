#!/bin/bash
# DNS and IP leak detection script
# Returns 0 if no leaks detected, non-zero otherwise

set -euo pipefail

# Configuration
LEAK_TEST_URL="${LEAK_TEST_URL:-https://ipinfo.io/ip}"
DNS_TEST_URL="https://whoami.akamai.net"
TIMEOUT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "[*] $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Test 1: IP Address Leak Detection
test_ip_leak() {
    log_info "Test 1/2: IP Address Leak Detection"

    # Get direct IP (should fail or timeout in isolated container)
    log_info "Fetching direct IP address..."
    local direct_ip=""
    direct_ip=$(curl -s --connect-timeout 5 "${LEAK_TEST_URL}" 2>/dev/null || echo "TIMEOUT")

    if [ "${direct_ip}" = "TIMEOUT" ] || [ -z "${direct_ip}" ]; then
        log_info "Direct connection: TIMEOUT (expected in isolated container)"
        direct_ip="NONE"
    else
        log_warn "Direct connection: ${direct_ip} (should be blocked)"
    fi

    # Get Tor IP
    log_info "Fetching IP through Tor SOCKS proxy..."
    local tor_ip=""
    tor_ip=$(curl --socks5-hostname 127.0.0.1:9050 -s --connect-timeout "${TIMEOUT}" "${LEAK_TEST_URL}" 2>/dev/null || echo "")

    if [ -z "${tor_ip}" ]; then
        log_error "Failed to fetch IP through Tor proxy"
        log_error "Check: Is Tor listening on 127.0.0.1:9050?"
        return 1
    fi

    log_success "Tor IP: ${tor_ip}"

    # Compare IPs
    if [ "${direct_ip}" != "NONE" ] && [ "${direct_ip}" != "TIMEOUT" ] && [ "${direct_ip}" = "${tor_ip}" ]; then
        log_error "IP LEAK DETECTED: Direct IP matches Tor IP!"
        log_error "Direct: ${direct_ip} | Tor: ${tor_ip}"
        return 1
    fi

    log_success "IP leak test PASSED"
    return 0
}

# Test 2: DNS Leak Detection
test_dns_leak() {
    log_info "Test 2/2: DNS Leak Detection"

    # Test DNS resolution through Tor using multiple methods
    log_info "Testing DNS resolution through Tor..."

    # Try multiple DNS test endpoints (some may block Tor)
    local dns_test_urls=(
        "https://icanhazip.com"
        "${DNS_TEST_URL}"
        "https://api.ipify.org"
    )

    local tor_response=""
    local test_url=""

    # Try each URL until one succeeds
    for url in "${dns_test_urls[@]}"; do
        log_info "Attempting DNS test with: ${url}"
        tor_response=$(curl --socks5-hostname 127.0.0.1:9050 -s --connect-timeout "${TIMEOUT}" "${url}" 2>/dev/null || echo "")

        if [ -n "${tor_response}" ]; then
            test_url="${url}"
            log_success "DNS resolution through Tor successful: ${tor_response}"
            break
        else
            log_warn "Failed to resolve ${url} through Tor, trying next..."
        fi
    done

    # If all URLs failed, report error
    if [ -z "${tor_response}" ]; then
        log_error "Failed to resolve DNS through Tor (tried ${#dns_test_urls[@]} endpoints)"
        log_error "This may indicate:"
        log_error "  - Tor SOCKS proxy DNS resolution issue"
        log_error "  - All test endpoints blocking Tor exit nodes"
        log_error "  - Network connectivity problem"
        return 1
    fi

    # Verify DNS isolation by checking direct connection is blocked
    log_info "Verifying DNS isolation..."
    local direct_dns=""
    direct_dns=$(timeout 5 curl -s --connect-timeout 3 "${test_url}" 2>/dev/null || echo "TIMEOUT")

    if [ "${direct_dns}" != "TIMEOUT" ] && [ -n "${direct_dns}" ]; then
        # If we can fetch directly, compare with Tor result
        if [ "${direct_dns}" = "${tor_response}" ]; then
            log_error "DNS LEAK DETECTED: Direct DNS matches Tor DNS!"
            log_error "Direct: ${direct_dns} | Tor: ${tor_response}"
            return 1
        fi
        log_info "Direct DNS (non-Tor): ${direct_dns}"
        log_warn "Warning: Direct DNS resolution succeeded (network not fully isolated)"
    else
        log_success "Direct DNS connection: TIMEOUT (properly isolated)"
    fi

    log_success "DNS leak test PASSED"
    return 0
}

# Test 3: Verify SOCKS proxy functionality
test_socks_proxy() {
    log_info "Test 3/3: SOCKS Proxy Verification"

    # Check if port 9050 is listening
    if ! ss -ltn | grep -q '127.0.0.1:9050'; then
        log_error "Tor SOCKS proxy not listening on 127.0.0.1:9050"
        return 1
    fi

    log_success "Tor SOCKS proxy listening on 127.0.0.1:9050"

    # Test connection to SOCKS port
    if ! nc -z 127.0.0.1 9050 2>/dev/null; then
        log_error "Cannot connect to Tor SOCKS proxy"
        return 1
    fi

    log_success "SOCKS proxy connection test PASSED"
    return 0
}

# Main execution
main() {
    local leak_detected=0

    echo "════════════════════════════════════════════════════════════"
    echo "            DNS/IP LEAK DETECTION SUITE"
    echo "════════════════════════════════════════════════════════════"
    echo ""

    # Run all tests
    if ! test_socks_proxy; then
        leak_detected=1
    fi

    echo ""

    if ! test_ip_leak; then
        leak_detected=1
    fi

    echo ""

    if ! test_dns_leak; then
        leak_detected=1
    fi

    echo ""
    echo "════════════════════════════════════════════════════════════"

    if [ "${leak_detected}" -eq 0 ]; then
        log_success "ALL LEAK TESTS PASSED - Safe to proceed"
        echo "════════════════════════════════════════════════════════════"
        return 0
    else
        log_error "LEAK DETECTED - ABORTING SCAN"
        log_error "Do not proceed with reconnaissance"
        echo "════════════════════════════════════════════════════════════"
        return 1
    fi
}

main "$@"
