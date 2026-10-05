# Security Policy

This repository contains self-contained Python scripts intended to be run
locally. This document explains which versions receive security updates, how
to report a vulnerability, and what to expect when you do.

---

## Supported Versions

This repository does not publish tagged releases. Each script carries its own
version number in its header comment, and fixes are applied to the latest
version on `main`.

| Version          | Supported          |
| ---------------- | ------------------ |
| Latest on `main` | :white_check_mark: |
| Older commits    | :x:                |
| Forks            | :x:                |

If you have an older copy of a script, re-download from `main` before
reporting anything. It may already be fixed.

---

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Two private channels are available:

1. **GitHub Private Vulnerability Reporting** (preferred). Use the
   [Report a vulnerability](https://github.com/Chalwk/python-scripts/security/advisories/new)
   button on the repository's Security tab. This keeps the discussion private,
   tracks the fix, and lets us coordinate disclosure.
2. **Email**. If you'd rather not use GitHub, email
   [chalwk.dev@gmail.com](mailto:chalwk.dev@gmail.com) with "SECURITY" in the
   subject line.

### What to include

- The script and version (the version is in the file's header comment)
- A clear description of the issue
- Steps to reproduce, or a minimal proof of concept
- The impact you believe it has
- Whether you've disclosed it anywhere else

Redact any real API keys, IP addresses, or personal data from what you send.

---

## Scope

### In scope

- Hardcoded secrets, API keys, or credentials in any script
- API keys or tokens leaked into URLs, logs, error output, cache files, or
  temporary files
- Command injection, argument injection, or unsafe use of `subprocess`,
  `eval`, or `exec`
- Path traversal or arbitrary file read/write
- Insecure deserialization (`pickle`, `yaml.load`, etc.)
- Sensitive data persisted to disk without the user's knowledge
- Bypasses of the PII redaction in `ipqs_lookup.py` (`--redact` and the
  sensitive-field detection)
- Vulnerabilities in the Jekyll site (dependency issues, XSS in templates, etc.)

### Out of scope

- Issues that require an attacker to already be running untrusted code on
  your machine
- Rate limiting, uptime, or downtime of third-party APIs (IPQS, GitHub Pages)
- Social engineering
- Denial of service against third-party services
- Typos, cosmetic bugs, or feature requests (open a regular issue for those)
- Findings from automated scanners with no demonstrated impact

If you're not sure whether something is in scope, report it anyway and I'll
tell you.

---

## What to expect

This is a personal project maintained by one person. Realistic timelines:

- **Acknowledgement:** within 7 days
- **Initial assessment:** within 14 days
- **Fix or workaround:** depends on severity, but usually within 30 days for anything confirmed
- **Public disclosure:** coordinated with you. I'll credit you in the advisory
  unless you'd prefer to stay anonymous.

If a report is declined, I'll explain why. If it's a duplicate or already
known, I'll say so.

---

## Using these scripts safely

A few practices worth following regardless of any issue in the code itself:

- **Never hardcode API keys in a script or a committed config file.** Every
  script in this repo reads secrets from environment variables first. Use that.
- **Audit before you run.** These scripts are standard-library-only where
  possible and are written to be read. Open the file. Check what it does.
  Only then run it.
- **Keep your copy current.** Pull from `main` before running a script on
  anything sensitive. Fixes land there first.
- **Check what's cached.** Some scripts (like `ipqs_lookup.py`) write to a
  local cache. Understand what's being stored and where.

---

## Automated security

This repository runs the following GitHub security features on every push:

- CodeQL static analysis
- Dependabot alerts and security updates
- Secret scanning with push protection

Findings from these tools are triaged by the maintainer. If you've spotted
something the automated tools missed, that's exactly what the private
reporting channels above are for.