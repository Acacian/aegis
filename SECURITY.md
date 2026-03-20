# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report security issues by emailing the maintainers directly or using [GitHub's private vulnerability reporting](https://github.com/Acacian/aegis/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

Aegis is a governance layer — it is security-critical by nature. The following are in scope:

- Policy bypass (action executes despite being blocked)
- Audit log tampering or omission
- Approval gate bypass
- Injection via action params or policy YAML

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
