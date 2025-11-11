# Security Policy

## 🛡️ Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Recon Scanner, please report it responsibly.

### Reporting Process

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please:

1. **Email:** Send details to [security@yourdomain.com](mailto:security@yourdomain.com)
2. **PGP Key:** Use our PGP key for sensitive information (see below)
3. **Response Time:** Expect acknowledgment within 48 hours

### What to Include

Please provide:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)
- Your contact information

**Example Report:**
```
Subject: [SECURITY] Command Injection in scan_wrapper.sh

Description:
User-supplied input in scan_wrapper.sh is not properly sanitized,
allowing command injection via specially crafted domain names.

Steps to Reproduce:
1. Run: docker run recon-tor -- nmap "target.com; rm -rf /"
2. Observe that additional commands are executed

Impact:
High - Allows arbitrary command execution in container context

Suggested Fix:
Validate input against domain regex before passing to shell

Reporter: John Doe (john@example.com)
```

### What Happens Next

1. **Acknowledgment:** We confirm receipt within 48 hours
2. **Triage:** We assess severity and validity (1-5 business days)
3. **Fix Development:** We develop and test a fix
4. **Disclosure:** We coordinate disclosure timeline with you
5. **Release:** We release patched version
6. **Credit:** We credit you in release notes (unless you prefer anonymity)

## 🏆 Bug Bounty

Currently, we do not offer monetary rewards. However:
- You will be credited in release notes
- Significant findings may earn maintainer status
- Your contribution helps the security community

## 🔐 PGP Key

For encrypted communications:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Your PGP public key here]
-----END PGP PUBLIC KEY BLOCK-----
```

Key fingerprint: `XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX`

## 🎯 Vulnerability Scope

### In Scope

✅ **High Priority:**
- Command injection vulnerabilities
- Privilege escalation in container
- Docker escape vulnerabilities
- Tor/proxy bypass mechanisms
- DNS/IP leak vulnerabilities
- Authentication/authorization flaws

✅ **Medium Priority:**
- Information disclosure
- Denial of service
- Insecure defaults
- Dependency vulnerabilities

### Out of Scope

❌ **Not Accepted:**
- Social engineering attacks
- Physical attacks
- Issues in third-party dependencies (report to upstream)
- Theoretical vulnerabilities without PoC
- Self-XSS or similar low-impact issues
- Rate limiting issues
- Descriptive error messages (unless leaking secrets)

## 🔒 Security Best Practices

### For Users

**Docker:**
- Always pull/build from official sources
- Run with minimal privileges
- Use read-only filesystem when possible
- Isolate container networking
- Regularly update to latest version

```bash
# Secure run example
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /home/scanner/.tor \
  --security-opt=no-new-privileges \
  -v $(pwd)/results:/results \
  recon-tor -- nmap target.com
```

**Python:**
- Install in virtual environment
- Don't run as root
- Keep dependencies updated
- Use API keys from environment, not files
- Review code before running

```bash
# Secure installation
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python recon.py
```

### For Developers

**Code Security:**
- Never use `eval()` or `exec()` with user input
- Validate all inputs before use
- Use parameterized queries/commands
- Sanitize outputs in logs (no secrets)
- Implement principle of least privilege

**Docker Security:**
- Run as non-root user
- Don't install unnecessary packages
- Use official base images
- Scan images for vulnerabilities: `docker scan recon-tor`
- Sign images: `docker trust sign`

**Dependency Security:**
- Pin exact versions in requirements.txt
- Regularly update dependencies
- Review changelogs before updating
- Use `pip check` to find conflicts
- Consider using `safety check`

## 🚨 Known Security Considerations

### By Design

**Tor Dependency:**
- Tor circuits can be slow or unstable
- Exit nodes may be compromised
- Not a substitute for VPN in all cases

**Container Limitations:**
- Not a security sandbox
- Kernel vulnerabilities affect container
- Host compromise = container compromise

**Scanning Legality:**
- Tool doesn't enforce authorization
- Users responsible for legal compliance
- No built-in rate limiting

### Mitigations

**Leak Detection:**
- Mandatory IP/DNS checks before scans
- Strict proxy chain (fails if Tor down)
- No direct internet access in container

**Least Privilege:**
- Non-root execution
- No capabilities added
- Minimal installed packages

**Input Validation:**
- Target validation in entrypoint
- Command format enforcement
- Regex-based domain checking

## 📊 Security Audit History

| Date | Type | Findings | Status |
|------|------|----------|--------|
| 2025-01 | Internal Code Review | 3 low, 1 medium | Fixed |
| TBD | External Audit | Pending | - |

## 🔄 Update Policy

### Security Updates

**Critical:** Released within 24-48 hours
**High:** Released within 1 week
**Medium:** Released within 1 month
**Low:** Included in next regular release

### Notification

Security updates announced via:
- GitHub Security Advisories
- Release notes
- README notice
- Email (if subscribed)

### Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ Yes |
| Previous release | ✅ Yes (30 days) |
| Older versions | ❌ No |

**Recommendation:** Always use latest version

## 📝 Security Checklist

Before deploying:

- [ ] Review and understand code
- [ ] Verify image signatures (if available)
- [ ] Run with minimal privileges
- [ ] Enable leak detection
- [ ] Test in isolated environment first
- [ ] Monitor logs for anomalies
- [ ] Keep dependencies updated
- [ ] Have incident response plan
- [ ] Document authorization
- [ ] Review legal requirements

## 🤝 Coordinated Disclosure

We support coordinated disclosure:
- We work with reporters to understand issues
- We provide updates throughout fix process
- We coordinate disclosure timing
- We credit researchers appropriately
- We don't take legal action against good-faith researchers

### Timeline Expectations

- **Day 0:** Vulnerability reported
- **Day 1-2:** Acknowledged
- **Day 3-7:** Triage and severity assessment
- **Day 8-30:** Fix development and testing
- **Day 31-60:** Coordinated disclosure
- **Day 61+:** Public disclosure (if not sooner)

We aim for 60-day disclosure timeline but may adjust based on:
- Severity of issue
- Complexity of fix
- Active exploitation
- Researcher preference

## 📞 Contact

**Security Team:**
- Email: security@yourdomain.com
- PGP: See above
- Response Time: 48 hours

**General Questions:**
- GitHub Issues: For non-security bugs
- Discussions: For feature requests
- Pull Requests: For contributions

## 🙏 Hall of Fame

Thank you to security researchers who've helped improve Recon Scanner:

- [Your name could be here!]

---

**Remember:** Security is a shared responsibility. Help us keep this tool safe for everyone.
