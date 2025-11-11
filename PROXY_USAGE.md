# 🔒 Proxy Usage Guide - Recon Scanner

## Overview

The Recon Scanner now supports anonymous scanning through Tor and Proxychains. This feature allows you to route all reconnaissance traffic through the Tor network, providing anonymity during authorized security assessments.

## ⚠️ Important Legal Notice

**ONLY use this feature for:**
- Authorized penetration testing engagements
- Security research on systems you own or have explicit permission to test
- CTF competitions and educational purposes
- Red team exercises with proper authorization

**DO NOT use for:**
- Unauthorized scanning or reconnaissance
- Malicious purposes
- Bypassing legal restrictions
- Any activity without proper authorization

## 🛠️ Installation

### Automated Installation (Recommended)

The installation script automatically installs and configures Tor and Proxychains:

```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/recon_scanner.git
cd recon_scanner

# Run installation script
sudo bash install_recon_tools.sh
```

The script will:
1. Install Tor service
2. Install Proxychains (proxychains4 or proxychains-ng)
3. Configure Proxychains to use Tor SOCKS5 proxy
4. Start and enable Tor service
5. Install PySocks for Python SOCKS support

### Manual Installation

If you prefer to install manually:

```bash
# Install Tor
sudo apt install tor

# Install Proxychains
sudo apt install proxychains4

# Install Python dependencies
pip3 install PySocks

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor
```

#### Configure Proxychains

Edit `/etc/proxychains4.conf` (or `/etc/proxychains.conf`):

```
# Enable quiet mode
quiet_mode

# Use dynamic chain
dynamic_chain

# Proxy DNS requests
proxy_dns

# Configure timeouts
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Tor SOCKS5 proxy
socks5 127.0.0.1 9050
```

## 🚀 Usage

### Starting the Tool

```bash
# Start the recon scanner
recon

# Or with sudo if needed
sudo recon
```

### Enabling Proxy Mode

1. **From Main Menu:**
   - Select option `[3] Enable Proxy`
   - The tool will automatically:
     - Check if Proxychains is installed
     - Verify Tor service is running
     - Test the proxy connection
     - Display your direct IP vs proxy IP

2. **Successful Output:**
   ```
   [*] Checking proxy configuration...
   [+] Proxychains found: proxychains4
   [+] Tor service is running
   [*] Testing proxy connection...
   [+] Proxy is working!
   [*] Direct IP: 1.2.3.4 | Proxy IP: 5.6.7.8
   [*] Proxy mode enabled
   ```

3. **Banner Update:**
   - The banner will show `[PROXY: ON]` in green when enabled
   - Shows `[PROXY: OFF]` in red when disabled

### Disabling Proxy Mode

- Select option `[3] Disable Proxy` from the main menu
- All subsequent scans will use your direct connection

### What Traffic is Proxied?

When proxy mode is enabled, the following operations are routed through Tor:

1. **Subdomain Enumeration:**
   - Amass commands
   - Assetfinder commands
   - SecurityTrails API calls

2. **HTTP/HTTPS Requests:**
   - Web technology detection
   - HTTP header fetching
   - VirusTotal API calls
   - All requests library calls

3. **Tool Status:**
   - Scan output shows `[via Proxy]` indicator when running through proxy

## 🔍 Verifying Proxy Connection

### Manual Verification

Test Tor connection manually:

```bash
# Check Tor service status
sudo systemctl status tor

# Test with curl
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip

# Test with proxychains
proxychains4 curl https://api.ipify.org
```

### Automatic Verification

The tool automatically verifies:
- ✅ Proxychains installation
- ✅ Tor service status
- ✅ Proxy connectivity
- ✅ IP address change verification

## ⚙️ Configuration

### Tor Configuration

Edit `/etc/tor/torrc` for advanced Tor settings:

```bash
# Change SOCKS port (default: 9050)
SOCKSPort 9050

# Enable control port
ControlPort 9051

# Set bandwidth limits (optional)
RelayBandwidthRate 100 KB
RelayBandwidthBurst 200 KB
```

After changes:
```bash
sudo systemctl restart tor
```

### Proxychains Configuration

Edit `/etc/proxychains4.conf`:

```
# For faster connection (use first available proxy)
strict_chain

# For better anonymity (random proxy order)
random_chain

# Add multiple proxies
[ProxyList]
socks5 127.0.0.1 9050
socks5 127.0.0.1 9051
```

## 🐛 Troubleshooting

### Proxy Won't Enable

**Problem:** Proxychains not found
```bash
# Check installation
which proxychains4
which proxychains

# Reinstall if needed
sudo apt install proxychains4
```

**Problem:** Tor service not running
```bash
# Check status
sudo systemctl status tor

# Start service
sudo systemctl start tor

# Check logs
sudo journalctl -u tor -f
```

**Problem:** Connection test fails
```bash
# Check if port 9050 is listening
sudo netstat -tulpn | grep 9050

# Or with ss
sudo ss -tulpn | grep 9050

# Test manually
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

### Slow Performance

Tor introduces latency. To improve:

1. **Use faster Tor circuits:**
   ```bash
   # Edit /etc/tor/torrc
   ExcludeNodes {US},{GB}
   ExcludeExitNodes {US},{GB}
   StrictNodes 1
   ```

2. **Increase timeouts in recon.py:**
   ```python
   # In recon.py (already configured)
   tcp_read_time_out 15000
   tcp_connect_time_out 8000
   ```

3. **Use selective proxy:**
   - Enable proxy only for sensitive scans
   - Disable for routine operations

### DNS Leaks

Ensure DNS is proxied:

```bash
# In /etc/proxychains4.conf
proxy_dns  # Must be enabled
```

Test for DNS leaks:
```bash
proxychains4 dig example.com
```

## 📊 Performance Impact

Expected performance with proxy enabled:

| Operation | Normal | With Proxy | Increase |
|-----------|--------|------------|----------|
| DNS Lookup | 50ms | 500ms | 10x |
| HTTP Request | 100ms | 2-5s | 20-50x |
| Subdomain Enum | 1 min | 5-10 min | 5-10x |
| Port Scan | 2 min | 10-20 min | 5-10x |

**Recommendation:** Use proxy for initial reconnaissance, disable for bulk operations.

## 🔐 Security Best Practices

1. **Always verify proxy before sensitive operations:**
   - Check IP change confirmation
   - Verify Tor circuit is active

2. **Rotate Tor identity periodically:**
   ```bash
   # Send NEWNYM signal to Tor
   (echo authenticate ''; echo signal newnym; echo quit) | nc 127.0.0.1 9051
   ```

3. **Use with VPN for additional security:**
   - VPN → Tor → Target (double anonymity)
   - Configure VPN before enabling proxy mode

4. **Monitor for leaks:**
   - Check DNS leaks
   - Verify all traffic routes through Tor
   - Use Wireshark to monitor network traffic

5. **Operational Security:**
   - Don't mix proxy and non-proxy scans on same target
   - Use separate sessions for different engagements
   - Clear logs after authorized testing

## 🔧 Advanced Usage

### Custom Proxy Chains

Edit `/etc/proxychains4.conf` to add multiple proxies:

```
[ProxyList]
socks5 127.0.0.1 9050    # Tor
socks5 your.proxy.com 1080  # Additional proxy
```

### Scripted Proxy Control

Enable/disable proxy programmatically:

```python
from recon import ProxyManager

# Check status
status = ProxyManager.get_proxy_status()
print(f"Proxy working: {status['proxy_working']}")

# Enable proxy
ProxyManager.enable_proxy()

# Disable proxy
ProxyManager.disable_proxy()
```

### Integration with Other Tools

Use proxychains with external tools:

```bash
# Run nmap through proxy
proxychains4 nmap -sT target.com

# Run curl through proxy
proxychains4 curl https://target.com

# Run any command through proxy
proxychains4 <your-command>
```

## 📝 Logging and Monitoring

Monitor Tor connections:

```bash
# Watch Tor logs
sudo journalctl -u tor -f

# Check connection count
sudo netstat -anp | grep tor | wc -l

# Monitor bandwidth
sudo iftop -f "port 9050"
```

## ❓ FAQ

**Q: Will this make me completely anonymous?**
A: No security measure is 100%. Tor provides strong anonymity but isn't perfect. Use multiple layers (VPN + Tor) for better protection.

**Q: Can I use other proxy services?**
A: Yes, edit proxychains.conf to add other SOCKS5/HTTP proxies.

**Q: Does this work on all operating systems?**
A: Tested on Linux (Debian/Ubuntu/Kali). May require adjustments for other systems.

**Q: Will API keys be exposed through Tor?**
A: API keys are sent through Tor when proxy is enabled, but they're still visible to the API provider.

**Q: Can I use this for port scanning?**
A: Port scanning through Tor is possible but very slow and discouraged by Tor project. Use responsibly.

**Q: How do I know if proxy is working?**
A: Check the banner status, look for `[via Proxy]` indicators, and verify IP change in connection test.

## 🆘 Support

If you encounter issues:

1. Check this documentation first
2. Verify Tor and Proxychains installation
3. Review system logs
4. Open an issue on GitHub with:
   - Error messages
   - System information
   - Steps to reproduce

## 📚 References

- [Tor Project](https://www.torproject.org/)
- [Proxychains Documentation](https://github.com/haad/proxychains)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Remember:** With great power comes great responsibility. Always obtain proper authorization before conducting security assessments.
