# Contributing to Recon Scanner

Thank you for considering contributing to Recon Scanner! This document provides guidelines and instructions for contributing.

## 🤝 Code of Conduct

By participating in this project, you agree to:
- Be respectful and constructive
- Focus on ethical security research
- Never promote or assist with unauthorized system access
- Follow responsible disclosure practices

## 🎯 How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
- Check existing [Issues](https://github.com/yourusername/recon_scanner/issues)
- Test with the latest version
- Verify it's not a configuration issue

**Bug Report Should Include:**
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Docker version, Python version)
- Relevant logs or error messages
- Screenshots if applicable

**Example:**
```markdown
**Bug:** Tor fails to bootstrap on ARM architecture

**Steps to Reproduce:**
1. Build Docker image on Raspberry Pi 4
2. Run: docker run recon-tor -- nmap target.com
3. Observe timeout error

**Expected:** Tor bootstraps within 60 seconds
**Actual:** Timeout after 60 seconds with "Bootstrap 45%" in logs

**Environment:**
- OS: Raspberry Pi OS 11 (Bullseye)
- Architecture: ARM64
- Docker: 20.10.21
```

### Suggesting Enhancements

**Enhancement Proposals:**
- Use issue tracker with "enhancement" label
- Explain the problem it solves
- Describe proposed solution
- Consider backwards compatibility

### Pull Requests

**Before Starting:**
1. Open an issue to discuss major changes
2. Fork the repository
3. Create a feature branch: `git checkout -b feature/your-feature-name`

**Development Workflow:**

```bash
# Fork and clone
git clone https://github.com/yourusername/recon_scanner.git
cd recon_scanner

# Create feature branch
git checkout -b feature/add-new-scan-module

# Make changes
# ... edit files ...

# Test Docker build
docker build -t recon-tor:test .

# Test functionality
docker run --rm -v $(pwd)/results:/results recon-tor:test -- curl https://example.com

# Commit with clear message
git add .
git commit -m "Add GraphQL endpoint discovery module

- Implements query introspection
- Adds schema extraction
- Includes tests and documentation"

# Push to your fork
git push origin feature/add-new-scan-module

# Open Pull Request on GitHub
```

**PR Requirements:**
- ✅ Clear description of changes
- ✅ Tests pass (if applicable)
- ✅ Documentation updated
- ✅ Follows code style
- ✅ No API keys or secrets committed
- ✅ Signed commits (recommended)

## 📝 Development Guidelines

### Code Style

**Python:**
- Follow PEP 8
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings to functions/classes

**Shell Scripts:**
- Use `#!/bin/bash` shebang
- Add `set -euo pipefail` for safety
- Comment complex logic
- Use lowercase for variables
- Quote all variables: `"${VAR}"`

**Example Python:**
```python
def scan_target(domain: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Perform reconnaissance scan on target domain.

    Args:
        domain: Target domain to scan
        timeout: Scan timeout in seconds

    Returns:
        Dictionary containing scan results

    Raises:
        ValueError: If domain is invalid
        TimeoutError: If scan exceeds timeout
    """
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")

    results = {}
    # ... scan logic ...
    return results
```

**Example Shell:**
```bash
#!/bin/bash
# DNS enumeration wrapper
set -euo pipefail

scan_dns() {
    local domain="${1}"
    local record_type="${2:-A}"

    if [ -z "${domain}" ]; then
        echo "[!] Error: Domain required" >&2
        return 1
    fi

    dig "${domain}" "${record_type}" +noall +answer
}
```

### Docker Best Practices

- Minimize layers (combine RUN commands)
- Remove caches: `&& rm -rf /var/lib/apt/lists/*`
- Use specific base image tags (not `latest`)
- Run as non-root user
- Document exposed ports (even if none)
- Use multi-stage builds if needed

### Security Guidelines

**DO:**
- ✅ Run as non-root
- ✅ Validate all user inputs
- ✅ Use parameterized queries/commands
- ✅ Implement proper error handling
- ✅ Log security-relevant events
- ✅ Use HTTPS for external requests

**DON'T:**
- ❌ Commit secrets or API keys
- ❌ Use `eval()` or `exec()` with user input
- ❌ Run shell commands without validation
- ❌ Disable security features
- ❌ Store sensitive data in logs
- ❌ Trust external input

### Testing

**Docker Tests:**
```bash
# Build
docker build -t recon-tor:test .

# Test help
docker run --rm recon-tor:test --help

# Test valid scan
docker run --rm -v $(pwd)/results:/results recon-tor:test -- \
  curl https://check.torproject.org

# Test invalid invocation
docker run --rm recon-tor:test -- echo "test"
[ $? -eq 4 ] && echo "✓ Exit code correct" || echo "✗ Exit code wrong"

# Test Tor bootstrap
docker run --rm -e TOR_TIMEOUT_SECS=30 recon-tor:test -- curl https://example.com
```

**Python Tests:**
```bash
# Install dev dependencies
pip3 install pytest pytest-cov

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=recon --cov-report=html
```

### Documentation

**All contributions should include:**
- Code comments for complex logic
- Docstrings for functions/classes
- README updates if behavior changes
- Examples in documentation

**Documentation Structure:**
- `README.md` - Main project documentation
- `README_DOCKER.md` - Docker-specific guide
- `PROXY_USAGE.md` - Proxy configuration
- `CONTRIBUTING.md` - This file
- `SECURITY.md` - Security policy

## 🐛 Debugging Tips

### Docker Debugging

```bash
# Run with shell access
docker run --rm -it --entrypoint /bin/bash recon-tor

# Check Tor logs
docker run --rm recon-tor -c "cat /tmp/tor.log"

# Test leak detection manually
docker run --rm recon-tor --entrypoint /usr/local/bin/check_leak.sh
```

### Python Debugging

```bash
# Run with verbose output
python3 -u recon.py

# Check imports
python3 -c "import dns.resolver; print('OK')"

# Test specific function
python3 -c "from recon import ProxyManager; print(ProxyManager.check_tor())"
```

## 📋 Contribution Checklist

Before submitting PR:

- [ ] Code follows style guidelines
- [ ] Comments added to complex code
- [ ] Documentation updated
- [ ] Tests added/updated (if applicable)
- [ ] All tests pass
- [ ] No secrets or API keys committed
- [ ] `.gitignore` updated if needed
- [ ] Commit messages are clear
- [ ] PR description is detailed

## 🏆 Recognition

Contributors will be:
- Listed in README.md credits
- Mentioned in release notes
- Thanked in commit messages

Significant contributions may result in:
- Maintainer access
- Project leadership roles
- Speaking opportunities

## 📞 Questions?

- Open a [Discussion](https://github.com/yourusername/recon_scanner/discussions)
- Comment on relevant [Issue](https://github.com/yourusername/recon_scanner/issues)
- Contact maintainers (see README)

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Recon Scanner better! 🙏
