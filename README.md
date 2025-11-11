# 🔍 Recon Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10%2B-blue.svg)](https://www.docker.com/)
[![Tor](https://img.shields.io/badge/Tor-Enabled-green.svg)](https://www.torproject.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20ARM%20%7C%20x86-lightgrey.svg)](https://github.com/yourusername/recon_scanner)

Advanced reconnaissance tool for authorized security testing with built-in Tor anonymity and comprehensive leak detection.

## ⚠️ LEGAL WARNING

```
╔══════════════════════════════════════════════════════════════════════╗
║                         AUTHORIZED USE ONLY                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  This tool is for authorized security testing and educational       ║
║  purposes ONLY. Unauthorized scanning is ILLEGAL.                   ║
║                                                                      ║
║  You MUST have explicit written permission before scanning any      ║
║  system you do not own. The authors are NOT responsible for misuse. ║
╚══════════════════════════════════════════════════════════════════════╝
```

**By using this tool, you agree to comply with all applicable laws and obtain proper authorization.**

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/recon_scanner.git
cd recon_scanner

# Build Docker image
docker build -t recon-tor .

# Run scan (all traffic via Tor)
docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -Pn -sT target.com
```

### Native Installation

```bash
# Clone and install
git clone https://github.com/yourusername/recon_scanner.git
cd recon_scanner
sudo bash install_recon_tools.sh

# Run scanner
recon
```

---

## ✨ Features

### 🔒 Security & Anonymity
- **Mandatory Tor routing** - All traffic through Tor network
- **Leak detection** - DNS and IP leak checks before scans
- **Strict proxy chain** - Fails if Tor is down (no accidental leaks)
- **Non-root execution** - Runs as unprivileged user
- **Exit code validation** - Standardized codes for automation

### 🌐 Reconnaissance Capabilities

#### Docker Version (Minimal)
- Port scanning (nmap)
- DNS enumeration (dig, nslookup)
- HTTP/HTTPS requests (curl)
- Banner grabbing (netcat)
- Socket inspection (ss)

#### Python Version (Comprehensive)
- **Subdomain Discovery**: Amass, Assetfinder, SecurityTrails API
- **DNS Enumeration**: A, AAAA, MX, NS, TXT, SOA, CNAME records
- **Port Scanning**: Multi-threaded with service detection
- **Web Technology Detection**: 50+ frameworks, CMS, CDN, analytics
- **SSL/TLS Analysis**: Certificate inspection and validation
- **WHOIS Lookup**: Domain registration details
- **IP Range Resolution**: CIDR and network information
- **File Hash Collection**: SHA256, MD5 checksums
- **VirusTotal Integration**: URL and file scanning
- **HTTP Header Analysis**: Server fingerprinting

### 🎨 User Experience
- Interactive CLI with color output
- Automated and manual scan modes
- JSON and text export formats
- Real-time proxy status indicator
- Detailed error messages

---

## 📦 Installation

### Option 1: Docker (Isolated & Secure)

**Requirements:**
- Docker 20.10+
- 2GB free disk space

**Build:**
```bash
docker build -t recon-tor .
```

**For full Python version with all tools:**
```bash
docker build -f Dockerfile.full -t recon-tor:full .
```

### Option 2: Native Installation

**Requirements:**
- Linux (Debian/Ubuntu/Kali recommended)
- Python 3.7+
- Go 1.21+ (for subdomain tools)
- sudo privileges

**Install:**
```bash
sudo bash install_recon_tools.sh
```

This installs:
- Tor + Proxychains
- Python dependencies
- Amass & Assetfinder
- System tools (nmap, etc.)

---

## 🔧 Usage

### Docker Mode

#### Basic Scans
```bash
# Port scan
docker run --rm -v $(pwd)/results:/results recon-tor -- \
  nmap -Pn -sT -p80,443 target.com

# DNS enumeration
docker run --rm -v $(pwd)/results:/results recon-tor -- \
  dig target.com ANY +noall +answer

# HTTP headers
docker run --rm -v $(pwd)/results:/results recon-tor -- \
  curl -I https://target.com

# Banner grab
docker run --rm -v $(pwd)/results:/results recon-tor -- \
  nc -v target.com 80
```

#### Environment Variables
```bash
# Increase Tor timeout
docker run --rm -e TOR_TIMEOUT_SECS=120 \
  -v $(pwd)/results:/results recon-tor -- nmap target.com

# Custom leak test URL
docker run --rm -e LEAK_TEST_URL="https://ipinfo.io/ip" \
  -v $(pwd)/results:/results recon-tor -- curl https://target.com
```

### Python Mode

#### Automated Reconnaissance
```bash
# Start scanner
recon

# Select [1] Automated Process
# Enter target domain
```

#### Manual Mode
```bash
recon

# Select [2] Manual Process
# Choose specific scan type:
# [1] Full Reconnaissance
# [2] DNS Enumeration Only
# [3] Port Scanning Only
# [4] Subdomain Discovery
# [5] Web Technology Detection
# etc.
```

#### Enable Tor Proxy
```bash
recon

# Select [3] Enable Proxy
# Tool will verify:
# - Proxychains installed ✓
# - Tor running ✓
# - No leaks detected ✓
```

---

## 📊 Exit Codes (Docker)

| Code | Meaning | Action |
|------|---------|--------|
| **0** | Success | Scan completed |
| **1** | Error | Check logs |
| **2** | Tor Timeout | Increase `TOR_TIMEOUT_SECS` |
| **3** | Leak Detected | Check network isolation |
| **4** | Invalid Command | Use `-- command` format |

---

## 🛡️ Security Architecture

### Docker Container Flow
```
┌─────────────────────────────────────────────────┐
│  1. Start Tor Daemon                            │
│     └─> Wait for 100% bootstrap                 │
├─────────────────────────────────────────────────┤
│  2. Leak Detection Tests                        │
│     ├─> SOCKS proxy check                       │
│     ├─> IP leak test (direct vs Tor)            │
│     └─> DNS leak test                           │
├─────────────────────────────────────────────────┤
│  3. Execute Scan                                 │
│     └─> proxychains4 -> Tor SOCKS5 -> Internet  │
├─────────────────────────────────────────────────┤
│  4. Save Results                                 │
│     └─> /results/<timestamp>.log                │
└─────────────────────────────────────────────────┘
```

### Leak Detection
1. **SOCKS Verification**: Confirms Tor listening on 127.0.0.1:9050
2. **IP Comparison**: Direct IP vs Tor IP must differ
3. **DNS Isolation**: DNS queries must go through Tor

**If any test fails, scan aborts with exit code 3.**

---

## 📂 Project Structure

```
recon_scanner/
├── Dockerfile              # Minimal Docker image
├── Dockerfile.full         # Full image with Python tools
├── entrypoint.sh          # Container orchestrator
├── check_leak.sh          # Leak detection suite
├── scan_wrapper.sh        # Scan execution wrapper
├── proxychains.conf       # Tor proxy configuration
├── recon.py               # Python reconnaissance tool
├── requirements.txt       # Python dependencies
├── install_recon_tools.sh # Native installation script
├── api_keys.txt.example   # API key template
├── README.md              # This file
├── README_DOCKER.md       # Docker-specific docs
├── PROXY_USAGE.md         # Proxy configuration guide
├── LICENSE                # MIT License
├── CONTRIBUTING.md        # Contribution guidelines
├── SECURITY.md            # Security policy
└── .gitignore            # Git ignore rules
```

---

## 🔑 API Keys (Optional)

For enhanced features, create `api_keys.txt`:

```bash
# Copy example
cp api_keys.txt.example api_keys.txt

# Add your keys
SECURITY_TRAILS_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

**⚠️ Never commit `api_keys.txt` to Git!**

---

## 🧪 Testing

### Docker
```bash
# Build
docker build -t recon-tor .

# Test help
docker run --rm recon-tor --help

# Test valid scan
docker run --rm -v $(pwd)/results:/results recon-tor -- \
  curl https://check.torproject.org
echo $?  # Should be 0

# Test invalid (no target)
docker run --rm recon-tor -- echo "test"
echo $?  # Should be 4
```

### Python
```bash
# Install
sudo bash install_recon_tools.sh

# Test Tor
sudo systemctl status tor

# Test proxychains
proxychains4 curl https://ipinfo.io/ip

# Run scanner
recon
```

---

## 🐛 Troubleshooting

### Docker Issues

**Tor won't bootstrap:**
```bash
# Increase timeout
docker run --rm -e TOR_TIMEOUT_SECS=120 -v $(pwd)/results:/results recon-tor -- nmap target.com

# Check Tor logs
docker run --rm --entrypoint /bin/bash recon-tor -c "tor -f /etc/tor/torrc"
```

**Leak detection fails:**
```bash
# Test network isolation
docker run --rm --network none recon-tor -- curl https://example.com
# Should fail (expected)

# Test with host network (insecure, for debugging only)
docker run --rm --network host recon-tor -- curl https://ipinfo.io/ip
```

**Permission denied on results:**
```bash
# Fix ownership
sudo chown -R $(id -u):$(id -g) results/
```

### Python Issues

**Tor not running:**
```bash
sudo systemctl start tor
sudo systemctl status tor
```

**Proxychains not found:**
```bash
# Reinstall
sudo apt install proxychains4

# Verify
which proxychains4
```

**Module import errors:**
```bash
# Reinstall dependencies
pip3 install -r requirements.txt --break-system-packages  # Kali
pip3 install -r requirements.txt  # Other distros
```

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas for contribution:**
- Additional scan modules
- Performance optimizations
- Bug fixes
- Documentation improvements
- Test coverage

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

**TL;DR:** Free to use, modify, distribute. No warranty. Use responsibly.

---

## 🙏 Credits

### Original Author
- Anubhav Mohandas (Native Python implementation)

### Contributors
- Tor+Docker integration
- Leak detection system
- Security hardening

### Tools & Libraries
- [Tor Project](https://www.torproject.org/)
- [Proxychains](https://github.com/haad/proxychains)
- [OWASP Amass](https://github.com/OWASP/Amass)
- [Nmap](https://nmap.org/)
- [dnspython](https://www.dnspython.org/)

---

## 📚 Documentation

- [Docker Usage Guide](README_DOCKER.md)
- [Proxy Configuration](PROXY_USAGE.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

---

## 🔗 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Tor Project Documentation](https://2019.www.torproject.org/docs/documentation.html.en)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Bug Bounty Programs](https://www.bugcrowd.com/bug-bounty-list/)

---

## ⭐ Star History

If you find this tool useful, please consider starring the repository!

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/recon_scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/recon_scanner/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting

---

## 🎯 Roadmap

- [ ] Additional subdomain enumeration methods
- [ ] HTTP/2 and HTTP/3 support
- [ ] GraphQL endpoint discovery
- [ ] API fuzzing capabilities
- [ ] CI/CD integration examples
- [ ] Kubernetes deployment manifests
- [ ] Web UI for results visualization

---

**Remember: With great power comes great responsibility. Always get authorization before testing!**
