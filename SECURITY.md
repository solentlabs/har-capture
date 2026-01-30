# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in har-capture, please report it privately using GitHub's security advisory feature:

**[Report a vulnerability](https://github.com/solentlabs/har-capture/security/advisories/new)**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity, typically within 30 days

## Scope

This policy covers:
- PII leakage in sanitization (patterns missing sensitive data)
- Credential exposure in HAR files
- Code injection via malicious HAR input
- Dependency vulnerabilities

## Out of Scope

- Vulnerabilities in Playwright or other dependencies (report to those projects)
- Issues requiring physical access
- Social engineering

## Recognition

We appreciate responsible disclosure and will credit reporters in release notes (unless you prefer anonymity).
