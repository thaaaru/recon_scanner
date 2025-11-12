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

# Common ports list
COMMON_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,1723,3306,3389,5432,5900,8000,8080,8443,8888,27017"
WEB_PORTS="80,443,8000,8008,8080,8443,8888,9000,9090,3000,4000,5000"

case "${SCAN_TYPE}" in
    "full")
        echo "════════════════════════════════════════════════════════════════════"
        echo "                    FULL RECONNAISSANCE SCAN"
        echo "════════════════════════════════════════════════════════════════════"
        echo ""

        # 1. DNS Enumeration (detailed)
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [1/7] DNS ENUMERATION                                          │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "[*] A Records:"
        proxychains4 -q dig "${TARGET}" A +noall +answer 2>/dev/null || echo "  No A records found"
        echo ""
        echo "[*] AAAA Records (IPv6):"
        proxychains4 -q dig "${TARGET}" AAAA +noall +answer 2>/dev/null || echo "  No AAAA records found"
        echo ""
        echo "[*] MX Records:"
        proxychains4 -q dig "${TARGET}" MX +noall +answer 2>/dev/null || echo "  No MX records found"
        echo ""
        echo "[*] NS Records:"
        proxychains4 -q dig "${TARGET}" NS +noall +answer 2>/dev/null || echo "  No NS records found"
        echo ""
        echo "[*] TXT Records:"
        proxychains4 -q dig "${TARGET}" TXT +noall +answer 2>/dev/null || echo "  No TXT records found"
        echo ""
        echo "[*] SOA Record:"
        proxychains4 -q dig "${TARGET}" SOA +noall +answer 2>/dev/null || echo "  No SOA record found"
        echo ""

        # 2. Comprehensive port scan with service detection
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [2/7] PORT SCAN - Common Ports (Service Detection)            │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "[*] Scanning ports: ${COMMON_PORTS}"
        echo "[*] This may take several minutes through Tor..."
        proxychains4 -q nmap -Pn -sT -sV --version-intensity 7 -p"${COMMON_PORTS}" "${TARGET}" 2>/dev/null || echo "[-] Port scan failed"
        echo ""

        # 3. NSE Script Scanning - Comprehensive
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [3/7] NSE VULNERABILITY & SERVICE DETECTION                   │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""

        echo "[*] HTTP Enumeration & Vulnerability Detection..."
        echo "[*] Running 10+ NSE scripts (this may take 5-10 minutes)..."
        proxychains4 -q nmap -Pn -sT -p"${WEB_PORTS}" \
            --script=http-enum,http-headers,http-methods,http-robots.txt,http-title,http-server-header \
            --script=http-security-headers,http-cors,http-csrf,http-git \
            --script=http-shellshock,http-sql-injection,http-stored-xss,http-dombased-xss \
            --script=http-vuln-* \
            "${TARGET}" 2>/dev/null || echo "[-] HTTP NSE scan failed"
        echo ""

        echo "[*] Default Scripts + Service Detection on Web Ports..."
        proxychains4 -q nmap -Pn -sT -sC -sV -p"${WEB_PORTS}" "${TARGET}" 2>/dev/null || echo "[-] Default NSE scan failed"
        echo ""

        echo "[*] SSH Service Detection (if port 22 is open)..."
        proxychains4 -q nmap -Pn -sT -p22 \
            --script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos \
            "${TARGET}" 2>/dev/null || echo "  Port 22 not accessible"
        echo ""

        echo "[*] FTP Service Detection (if port 21 is open)..."
        proxychains4 -q nmap -Pn -sT -p21 \
            --script=ftp-anon,ftp-bounce,ftp-syst \
            "${TARGET}" 2>/dev/null || echo "  Port 21 not accessible"
        echo ""

        echo "[*] SMTP Service Detection (if port 25/587 is open)..."
        proxychains4 -q nmap -Pn -sT -p25,587 \
            --script=smtp-commands,smtp-enum-users,smtp-open-relay \
            "${TARGET}" 2>/dev/null || echo "  SMTP ports not accessible"
        echo ""

        echo "[*] MySQL Service Detection (if port 3306 is open)..."
        proxychains4 -q nmap -Pn -sT -p3306 \
            --script=mysql-info,mysql-empty-password,mysql-enum \
            "${TARGET}" 2>/dev/null || echo "  Port 3306 not accessible"
        echo ""

        echo "[*] DNS Service Detection (if port 53 is open)..."
        proxychains4 -q nmap -Pn -sT -p53 \
            --script=dns-recursion,dns-service-discovery,dns-zone-transfer \
            "${TARGET}" 2>/dev/null || echo "  Port 53 not accessible"
        echo ""

        # 4. SSL/TLS Certificate information
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [4/7] SSL/TLS CERTIFICATE ANALYSIS                            │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "[*] HTTPS (Port 443):"
        proxychains4 -q nmap -Pn -sT -p443 --script ssl-cert,ssl-enum-ciphers "${TARGET}" 2>/dev/null || echo "  No SSL/TLS on port 443"
        echo ""
        echo "[*] Alternative HTTPS (Port 8443):"
        proxychains4 -q nmap -Pn -sT -p8443 --script ssl-cert,ssl-enum-ciphers "${TARGET}" 2>/dev/null || echo "  No SSL/TLS on port 8443"
        echo ""

        # 5. HTTP/HTTPS Headers and Technology Detection
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [5/7] HTTP/HTTPS HEADERS & TECHNOLOGY DETECTION               │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "[*] HTTPS Headers (Port 443):"
        proxychains4 -q curl -I -L -k --max-time 30 "https://${TARGET}" 2>/dev/null || echo "  Failed to retrieve HTTPS headers"
        echo ""
        echo "[*] HTTP Headers (Port 80):"
        proxychains4 -q curl -I -L --max-time 30 "http://${TARGET}" 2>/dev/null || echo "  Failed to retrieve HTTP headers"
        echo ""
        echo "[*] Verbose connection details (HTTPS):"
        proxychains4 -q curl -v --head -k --max-time 30 "https://${TARGET}" 2>&1 | grep -E "(Server:|X-Powered-By:|X-AspNet-Version:|X-Framework:|Content-Type:|Set-Cookie:)" || echo "  No technology headers found"
        echo ""

        # 6. IP Geolocation and Network Info
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [6/7] IP GEOLOCATION & NETWORK INFORMATION                    │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        IP=$(proxychains4 -q dig "${TARGET}" A +short 2>/dev/null | head -1)
        if [ -n "${IP}" ]; then
            echo "[*] Resolved IP: ${IP}"
            echo ""
            echo "[*] IP Information:"
            proxychains4 -q curl -s --max-time 20 "https://ipinfo.io/${IP}" 2>/dev/null || echo "  Failed to retrieve IP info"
            echo ""
        else
            echo "[-] Could not resolve IP address"
            echo ""
        fi

        # 7. HTTP Response Analysis
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│ [7/7] HTTP RESPONSE ANALYSIS                                   │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "[*] Checking robots.txt:"
        proxychains4 -q curl -s --max-time 15 "https://${TARGET}/robots.txt" 2>/dev/null | head -20 || echo "  No robots.txt found"
        echo ""
        echo "[*] Checking security.txt:"
        proxychains4 -q curl -s --max-time 15 "https://${TARGET}/.well-known/security.txt" 2>/dev/null || echo "  No security.txt found"
        echo ""
        ;;

    "quick")
        echo "════════════════════════════════════════════════════════════════════"
        echo "                       QUICK SCAN"
        echo "════════════════════════════════════════════════════════════════════"
        echo ""

        echo "[*] Fast port scan with service detection..."
        proxychains4 -q nmap -Pn -sT -sV -F --version-intensity 5 "${TARGET}" 2>/dev/null || echo "[-] Port scan failed"
        echo ""

        echo "[*] Quick NSE scripts on common web ports..."
        proxychains4 -q nmap -Pn -sT -p80,443,8080,8443 \
            --script=http-title,http-headers,http-server-header,http-methods \
            "${TARGET}" 2>/dev/null || echo "[-] NSE scan failed"
        echo ""

        echo "[*] HTTPS Headers:"
        proxychains4 -q curl -I -L -k --max-time 20 "https://${TARGET}" 2>/dev/null || echo "[-] Failed to retrieve headers"
        echo ""

        echo "[*] Basic DNS lookup:"
        proxychains4 -q dig "${TARGET}" A +short 2>/dev/null || echo "[-] DNS lookup failed"
        echo ""
        ;;

    "ports")
        echo "════════════════════════════════════════════════════════════════════"
        echo "                  COMPREHENSIVE PORT SCAN"
        echo "════════════════════════════════════════════════════════════════════"
        echo ""
        echo "[!] Warning: Full port scan (1-65535) through Tor is VERY slow"
        echo "[!] This may take 30-60 minutes or more"
        echo ""
        echo "[*] Scanning all TCP ports with service detection..."
        proxychains4 -q nmap -Pn -sT -sV --version-intensity 7 -p- -v "${TARGET}" 2>/dev/null || echo "[-] Port scan failed"
        echo ""
        ;;

    *)
        echo "[-] Unknown scan type: ${SCAN_TYPE}"
        echo ""
        echo "Usage: $0 <target> [full|quick|ports]"
        echo ""
        echo "Scan types:"
        echo "  full   - Comprehensive reconnaissance (DNS, ports, services, SSL, headers)"
        echo "  quick  - Fast scan of common ports with service detection"
        echo "  ports  - Full TCP port range scan (1-65535) with service versions"
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "[+] Scan completed!"
echo "════════════════════════════════════════════════════════════════════"
