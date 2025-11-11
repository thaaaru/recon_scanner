# GitHub Repository Setup Guide

Complete checklist for publishing Recon Scanner to GitHub.

## ✅ Pre-Upload Checklist

### 1. Review All Files

```bash
# Navigate to project directory
cd /Users/tharaka/tharaAgent/recon_scanner

# List all files
find . -type f ! -path './.git/*' ! -path './results/*' -name '*' | sort

# Check for sensitive data
grep -r "password\|secret\|token" . --exclude-dir=.git --exclude="*.md"

# Verify .gitignore is working
git status --ignored
```

### 2. Remove Sensitive Data

```bash
# Check if api_keys.txt exists (should be in .gitignore)
[ -f api_keys.txt ] && echo "⚠️  WARNING: Remove api_keys.txt!" || echo "✓ No api_keys.txt"

# Check results directory
[ -d results ] && echo "⚠️  WARNING: Clear results/" || echo "✓ No results/"

# Remove temporary files
rm -rf results/ __pycache__/ *.pyc .DS_Store
```

### 3. Verify Required Files Exist

```bash
#!/bin/bash

required_files=(
    "README.md"
    "LICENSE"
    ".gitignore"
    "Dockerfile"
    "entrypoint.sh"
    "check_leak.sh"
    "scan_wrapper.sh"
    "proxychains.conf"
    "requirements.txt"
    "api_keys.txt.example"
    "CONTRIBUTING.md"
    "SECURITY.md"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file"
    else
        echo "✗ $file MISSING"
    fi
done
```

## 📝 Repository Configuration

### 1. Create GitHub Repository

```bash
# Option A: Using GitHub CLI (gh)
gh repo create recon_scanner --public --description "Advanced reconnaissance tool with Tor anonymity"

# Option B: Via web interface
# Go to: https://github.com/new
# - Repository name: recon_scanner
# - Description: Advanced reconnaissance tool with Tor anonymity
# - Public repository
# - DO NOT initialize with README, .gitignore, or license
```

### 2. Initialize Local Repository

```bash
cd /Users/tharaka/tharaAgent/recon_scanner

# Initialize git
git init

# Add all files
git add .

# Verify what will be committed
git status

# Check for accidentally staged secrets
git diff --cached | grep -i "password\|secret\|key\|token"

# First commit
git commit -m "Initial commit: Tor-enabled reconnaissance scanner

- Docker containerization with leak detection
- Python reconnaissance tool with 10+ scan types
- Mandatory Tor routing for all traffic
- Comprehensive documentation and security policies
"

# Add remote
git remote add origin https://github.com/yourusername/recon_scanner.git

# Push to GitHub
git push -u origin main
```

### 3. Repository Settings

#### Enable Features

Via Settings → General:

- ✅ Issues
- ✅ Projects
- ✅ Discussions
- ✅ Wiki (optional)
- ❌ Sponsorships (unless you want donations)

#### Branch Protection

Via Settings → Branches → Add rule:

```
Branch name pattern: main

Protect matching branches:
✅ Require a pull request before merging
  ✅ Require approvals (1)
✅ Require status checks to pass before merging
  ✅ Require branches to be up to date
  Status checks: docker-build-and-test, shellcheck
✅ Require conversation resolution before merging
✅ Do not allow bypassing the above settings
```

#### Security

Via Settings → Security:

```
Code security and analysis:
✅ Dependency graph
✅ Dependabot alerts
✅ Dependabot security updates
✅ Secret scanning
✅ Push protection (prevents pushing secrets)
```

### 4. Add Topics

Via main page → Settings → Topics:

```
security, pentesting, reconnaissance, tor, docker, nmap,
subdomain-enumeration, dns-enumeration, ethical-hacking,
security-tools, infosec, osint, security-scanner
```

### 5. Create Releases

#### Tag First Release

```bash
git tag -a v1.0.0 -m "Release v1.0.0: Initial public release

Features:
- Docker containerization with Tor integration
- Mandatory DNS/IP leak detection
- Python recon scanner with 10+ modules
- Comprehensive documentation

Known Issues:
- None

Breaking Changes:
- N/A (initial release)
"

git push origin v1.0.0
```

#### Create GitHub Release

Via Releases → Create new release:

```
Tag version: v1.0.0
Release title: v1.0.0 - Initial Release
Description:
  [Copy tag message above]

  ## Installation
  ```bash
  docker pull ghcr.io/yourusername/recon-tor:v1.0.0
  # or
  docker build -t recon-tor .
  ```

  ## Quick Start
  ```bash
  docker run --rm -v $(pwd)/results:/results recon-tor -- nmap target.com
  ```

  Full documentation: https://github.com/yourusername/recon_scanner

Attach binaries: (none for this project)
✅ Set as latest release
```

## 🔧 GitHub Actions Setup

The workflow is already configured in `.github/workflows/docker-build.yml`.

### Enable Actions

Via Settings → Actions → General:

```
Actions permissions:
○ Allow all actions and reusable workflows

Workflow permissions:
○ Read and write permissions
✅ Allow GitHub Actions to create and approve pull requests
```

### Add Secrets (if needed)

Via Settings → Secrets and variables → Actions:

```
# Only if you want to test with real API keys (NOT recommended)
# SECURITY_TRAILS_API_KEY
# VIRUSTOTAL_API_KEY
```

## 📢 Post-Publishing

### 1. Update URLs

Replace `yourusername` with your actual GitHub username in:

- `README.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- Badge URLs

```bash
# Find all instances
grep -r "yourusername" . --exclude-dir=.git

# Replace (macOS)
find . -type f ! -path './.git/*' -exec sed -i '' 's/yourusername/actualusername/g' {} +

# Replace (Linux)
find . -type f ! -path './.git/*' -exec sed -i 's/yourusername/actualusername/g' {} +
```

### 2. Add Repository Description

On main page → ⚙️ → Edit:

```
Description:
Advanced reconnaissance tool for authorized security testing with
built-in Tor anonymity and comprehensive leak detection.

Website: https://yourusername.github.io/recon_scanner (if you have docs site)
Topics: [Add topics as listed above]
```

### 3. Create Initial Issues

Via Issues → New issue:

```
Title: Welcome contributors!
Body:
  Thank you for your interest in Recon Scanner!

  We're looking for contributions in:
  - Additional scan modules
  - Performance optimizations
  - Documentation improvements
  - Bug reports and fixes

  Please see CONTRIBUTING.md for guidelines.

Labels: good first issue, help wanted
```

### 4. Enable Discussions

Via Discussions → Set up:

```
Categories:
- General
- Ideas
- Q&A
- Show and tell

Welcome message:
  Welcome to Recon Scanner discussions!
  Use this space to ask questions, share ideas, and showcase your scans.
  Remember: Only scan systems you have permission to test!
```

### 5. Add Community Files

Via Insights → Community → Add:

- ✅ Code of conduct: Use GitHub's template
- ✅ Issue templates: Create from template
- ✅ Pull request template: Create

**Issue Template Example:**

```markdown
---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Build with '...'
2. Run with '...'
3. See error

**Expected behavior**
What you expected to happen.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Docker version: [e.g., 20.10.21]
- Architecture: [e.g., x86_64, arm64]

**Additional context**
Any other context about the problem.
```

## 🚀 Promotion

### Share on Social Media

- Twitter/X with hashtags: #infosec #pentesting #ethicalhacking
- Reddit: r/netsec, r/HowToHack (follow subreddit rules)
- LinkedIn: Share with relevant groups
- Hacker News: Submit to Show HN

### Submit to Lists

- [Awesome Security](https://github.com/sbilly/awesome-security)
- [Awesome Hacking](https://github.com/Hack-with-Github/Awesome-Hacking)
- [Awesome Penetration Testing](https://github.com/enaqx/awesome-pentest)
- [SecTools.org](https://sectools.org/)

### Documentation Site (Optional)

Use GitHub Pages:

```bash
# Create gh-pages branch
git checkout --orphan gh-pages
git rm -rf .
echo "Documentation site" > index.html
git add index.html
git commit -m "Initial docs"
git push origin gh-pages

# Enable in Settings → Pages
# Source: gh-pages branch
```

## ✅ Final Verification

```bash
# 1. Clone your repository (fresh)
cd /tmp
git clone https://github.com/yourusername/recon_scanner.git
cd recon_scanner

# 2. Build Docker image
docker build -t recon-tor:test .

# 3. Test functionality
docker run --rm recon-tor:test --help

# 4. Check for secrets
docker run --rm -v $(pwd):/scan trufflesecurity/trufflehog:latest filesystem /scan

# 5. Verify badges work in README
# Open: https://github.com/yourusername/recon_scanner

# 6. Test clone and run for new users
# Follow README Quick Start instructions
```

## 📊 Monitoring

### GitHub Insights

Monitor via Insights → :

- **Traffic:** Page views, unique visitors, clones
- **Community:** Issues, PRs, discussions
- **Dependency graph:** Vulnerable dependencies
- **Security:** Dependabot alerts

### Star History

Use [Star History](https://star-history.com/) to track growth.

## 🎯 Success Metrics

Track after 30 days:

- [ ] 10+ stars
- [ ] 5+ forks
- [ ] 3+ contributors
- [ ] 10+ issues/discussions
- [ ] Listed on at least 1 awesome list

## 📞 Support

After publishing, respond to:

- Issues within 48 hours
- Pull requests within 1 week
- Security reports within 24 hours (see SECURITY.md)

---

**Congratulations! Your project is now live on GitHub! 🎉**
