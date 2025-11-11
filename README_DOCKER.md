# Tor+Proxychains Reconnaissance Container

Production-ready Docker container for conducting authorized reconnaissance through Tor. All traffic is routed through Tor with mandatory leak detection before any scan execution.

## ⚠️ Legal Notice

**ONLY use this container for:**
- Authorized penetration testing with explicit permission
- Security research on systems you own
- Educational purposes and CTF competitions
- Red team exercises with proper authorization

**Unauthorized scanning is illegal. The author is not responsible for misuse.**

## Features

- ✅ All traffic routed through Tor via proxychains4
- ✅ Mandatory DNS and IP leak detection before scans
- ✅ Strict chain enforcement (fails if Tor is down)
- ✅ Non-root execution for security
- ✅ Minimal attack surface (no exposed ports)
- ✅ Automated Tor bootstrap verification
- ✅ Results logging with timestamps
- ✅ Clear exit codes for automation

## Quick Start

### Build

```bash
docker build -t recon-tor .
```

### Run

```bash
# Basic nmap scan
docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -Pn -sT target.example.com

# HTTP request
docker run --rm -v $(pwd)/results:/results recon-tor -- curl -I https://example.com

# DNS enumeration
docker run --rm -v $(pwd)/results:/results recon-tor -- dig example.com ANY
```

## Architecture

```
entrypoint.sh
    ├─> Start Tor daemon
    ├─> Wait for bootstrap 100%
    ├─> check_leak.sh
    │   ├─> Test IP leak (direct vs Tor IP)
    │   ├─> Test DNS leak
    │   └─> Verify SOCKS proxy
    └─> scan_wrapper.sh
        └─> proxychains4 <your-command>
            └─> Tor SOCKS5 (127.0.0.1:9050)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TOR_TIMEOUT_SECS` | `60` | Seconds to wait for Tor bootstrap |
| `LEAK_TEST_URL` | `https://ipinfo.io/ip` | URL for IP leak testing |
| `RESULTS_DIR` | `/results` | Directory for scan output logs |

Example with custom timeout:

```bash
docker run --rm -e TOR_TIMEOUT_SECS=120 -v $(pwd)/results:/results recon-tor -- nmap -sT target.com
```

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| `0` | Success | Scan completed without errors |
| `1` | Generic Error | Unexpected failure or tool error |
| `2` | Tor Timeout | Tor failed to bootstrap within timeout |
| `3` | Leak Detected | DNS or IP leak detected, scan aborted |
| `4` | Illegal Invocation | Missing target or invalid command |

## Leak Detection

The container performs three mandatory checks before any scan:

### 1. SOCKS Proxy Verification
- Verifies Tor is listening on `127.0.0.1:9050`
- Tests connection to SOCKS port

### 2. IP Leak Detection
- Fetches direct IP (should timeout in isolated container)
- Fetches IP through Tor SOCKS proxy
- Compares results (must be different)

### 3. DNS Leak Detection
- Tests DNS resolution through Tor
- Verifies DNS queries are proxied
- Ensures DNS isolation

**If any check fails, the scan is aborted with exit code 3.**

## Command Format

All commands must use the `--` separator:

```bash
docker run recon-tor -- <command> <args>
```

### Valid Examples

```bash
# Port scan
docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -Pn -sT -p80,443 target.com

# Banner grab
docker run --rm -v $(pwd)/results:/results recon-tor -- nc target.com 80

# HTTP headers
docker run --rm -v $(pwd)/results:/results recon-tor -- curl -I https://target.com

# DNS query
docker run --rm -v $(pwd)/results:/results recon-tor -- dig target.com
```

### Invalid Examples

```bash
# Missing -- separator (exit code 4)
docker run recon-tor nmap -sT target.com

# No target detected (exit code 4)
docker run recon-tor -- echo "hello"

# No command (exit code 4)
docker run recon-tor --
```

## Results

Results are saved to `/results/<timestamp>.log`:

```bash
# Mount local directory
docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -sT target.com

# Results appear in ./results/20250111_143022.log
```

Each log contains:
- Timestamp and command executed
- Full scan output
- Exit code and duration
- Confirmation of Tor routing

## Security Features

1. **Non-root execution**: All scans run as user `scanner` (UID 1000)
2. **No exposed ports**: Container exposes no network ports
3. **Strict chain**: Proxychains uses strict mode (fails if Tor down)
4. **Proxy DNS**: All DNS queries routed through Tor
5. **Leak detection**: Mandatory checks before execution
6. **Minimal image**: Only essential tools installed
7. **Read-only filesystem**: Can run with `--read-only` flag (except /results)

## Troubleshooting

### Tor fails to bootstrap (exit code 2)

```bash
# Increase timeout
docker run --rm -e TOR_TIMEOUT_SECS=120 -v $(pwd)/results:/results recon-tor -- nmap target.com

# Check Tor logs (if container doesn't exit)
docker exec <container-id> cat /tmp/tor.log
```

### Leak detection fails (exit code 3)

```bash
# Verify network isolation
docker run --rm --network none recon-tor -- curl https://example.com

# Check if direct internet access is blocked
docker run --rm recon-tor -- timeout 3 curl https://ipinfo.io/ip
# Should timeout or fail
```

### No target detected (exit code 4)

```bash
# Ensure command includes a domain or IP
docker run recon-tor -- nmap -sT 192.168.1.1  # ✓ Valid
docker run recon-tor -- nmap -sT             # ✗ Invalid
```

### Slow performance

Tor introduces latency (5-10x slower than direct). This is expected:

```bash
# Use faster scan profiles
docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -T4 -F target.com

# Avoid intensive scans through Tor
# Tor Project discourages port scanning entire ranges
```

## Advanced Usage

### Custom Tor Configuration

Mount custom `torrc`:

```bash
docker run --rm -v $(pwd)/custom-torrc:/etc/tor/torrc \
  -v $(pwd)/results:/results recon-tor -- nmap -sT target.com
```

### Debugging Proxychains

Remove `quiet_mode` from `proxychains.conf` and rebuild:

```bash
# Edit proxychains.conf, comment out:
# quiet_mode

# Rebuild
docker build -t recon-tor:debug .

# Run with verbose output
docker run --rm -v $(pwd)/results:/results recon-tor:debug -- curl https://example.com
```

### Network Isolation

Run with no network (Tor won't work, for testing):

```bash
docker run --rm --network none recon-tor -- echo "test"
# Should fail at Tor bootstrap
```

### Read-only Filesystem

```bash
docker run --rm --read-only -v $(pwd)/results:/results \
  --tmpfs /tmp --tmpfs /home/scanner/.tor \
  recon-tor -- nmap -sT target.com
```

## Performance Expectations

| Operation | Normal | Via Tor | Overhead |
|-----------|--------|---------|----------|
| HTTP request | 100ms | 2-5s | 20-50x |
| DNS query | 50ms | 500ms-2s | 10-40x |
| Port scan (1000 ports) | 2 min | 15-30 min | 7-15x |
| Banner grab | 1s | 5-10s | 5-10x |

**Note**: Tor circuits vary. Some may be faster/slower.

## Limitations

1. **Tor Project Guidelines**: Avoid scanning entire networks or high-volume operations
2. **Exit Node Restrictions**: Some Tor exit nodes block certain ports
3. **Performance**: Not suitable for time-sensitive or high-volume scans
4. **UDP Traffic**: Tor only supports TCP; UDP scans (like `-sU`) won't work
5. **ICMP**: Ping scans (`-sn`, `-PE`) won't work through Tor

## Best Practices

1. **Use selectively**: Enable Tor for initial reconnaissance, not bulk operations
2. **Respect rate limits**: Don't abuse Tor network with aggressive scans
3. **Verify results**: Cross-check critical findings without Tor
4. **Document authorization**: Keep proof of permission for all scans
5. **Monitor logs**: Review `/results/` logs for anomalies
6. **Rotate circuits**: Restart container between unrelated scans
7. **Use VPN**: Consider VPN → Tor for additional anonymity layer

## Integration Examples

### Shell script

```bash
#!/bin/bash
set -euo pipefail

TARGETS=("target1.com" "target2.com" "target3.com")

for target in "${TARGETS[@]}"; do
    echo "Scanning ${target}..."
    docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -Pn -sT "${target}"

    if [ $? -eq 0 ]; then
        echo "✓ ${target} scan completed"
    else
        echo "✗ ${target} scan failed"
    fi
done
```

### CI/CD Pipeline

```yaml
# .gitlab-ci.yml example
recon-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t recon-tor .
    - docker run --rm -v $(pwd)/results:/results recon-tor -- nmap -Pn target.com
  artifacts:
    paths:
      - results/
```

## Development

### File Structure

```
.
├── Dockerfile              # Container definition
├── entrypoint.sh          # Main orchestrator
├── check_leak.sh          # Leak detection suite
├── scan_wrapper.sh        # Scan execution wrapper
├── proxychains.conf       # Proxychains configuration
└── README.md              # This file
```

### Testing

```bash
# Build
docker build -t recon-tor .

# Test help
docker run --rm recon-tor --help

# Test leak detection (should pass)
docker run --rm recon-tor -- curl https://check.torproject.org

# Test invalid invocation (exit code 4)
docker run --rm recon-tor nmap target.com
echo $?  # Should print 4

# Test with no target (exit code 4)
docker run --rm recon-tor -- echo "test"
echo $?  # Should print 4
```

## Support

For issues or questions:
1. Check this README first
2. Review container logs
3. Test with `--help` flag
4. Open issue on GitHub with full output

## License

Use at your own risk. Always obtain proper authorization before security testing.

---

**Remember**: This tool is designed for authorized security testing only. Unauthorized use may violate computer fraud and abuse laws.
