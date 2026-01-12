# DAST Automation Skill

Automated Dynamic Application Security Testing (DAST) using Playwright MCP for comprehensive browser-based security scanning.

## Overview

This skill enables Claude Code to perform automated security testing on web applications using Playwright MCP as the primary browser automation engine. It supports both blackbox (unauthenticated) and greybox (authenticated) testing modes.

## Features

- **Playwright MCP Integration**: Browser automation for JavaScript-aware testing
- **Blackbox & Greybox Testing**: Support for both unauthenticated and authenticated scanning
- **Multi-Domain Orchestration**: Parallel scanning of multiple domains
- **Comprehensive Vulnerability Testing**: XSS, SQL Injection, CSRF, IDOR, and more
- **Tool Integration**: Nuclei, OWASP ZAP, Nikto integration
- **Multiple Report Formats**: JSON, HTML, Markdown reports
- **CI/CD Integration**: GitHub Actions, GitLab CI support
- **Continuous Scanning**: Scheduled and continuous security monitoring

## Prerequisites

- Playwright MCP configured in Claude Code
- Python 3.8+
- Optional: Nuclei, OWASP ZAP, Nikto

## Quick Start

### Basic Blackbox Scan

```bash
python3 scripts/playwright_dast_scanner.py \
  --target https://example.com \
  --mode blackbox \
  --output results/scan.json
```

### Greybox Scan with Authentication

```bash
python3 scripts/playwright_dast_scanner.py \
  --target https://app.example.com \
  --mode greybox \
  --auth-url https://app.example.com/login \
  --username user@test.com \
  --password 'password123' \
  --output results/scan.json
```

### Multi-Domain Scan

```bash
# Create domains.txt:
# https://example.com
# https://test.com
# https://demo.com

python3 scripts/dast_orchestrator.py \
  --domains domains.txt \
  --mode blackbox \
  --parallel 5 \
  --output results/
```

### Generate Report

```bash
python3 scripts/report_generator.py \
  --input results/scan.json \
  --format html \
  --output results/report.html
```

## Project Structure

```
dast-automation/
├── SKILL.md                    # Main skill definition
├── README.md                   # This file
├── scripts/                    # Automation scripts
│   ├── playwright_dast_scanner.py  # Main scanner
│   ├── dast_orchestrator.py        # Multi-domain orchestration
│   ├── playwright_crawler.py       # Web crawler
│   ├── vulnerability_tester.py     # Vulnerability testing
│   ├── report_generator.py         # Report generation
│   ├── nuclei_runner.py            # Nuclei integration
│   ├── check_findings.py           # CI/CD validation
│   └── continuous_dast.sh          # Continuous scanning
├── references/                 # Documentation
│   ├── dast_methodology.md
│   ├── playwright_security_patterns.md
│   ├── vulnerability_testing.md
│   ├── tool_configuration.md
│   ├── api_testing.md
│   └── reporting_guide.md
├── assets/                     # Templates and configs
│   ├── config/
│   │   ├── scanning.yaml
│   │   └── scope.yaml
│   ├── payloads/
│   │   ├── xss_payloads.txt
│   │   └── sqli_payloads.txt
│   └── report_templates/
└── results/                    # Scan results (created)
```

## Configuration

### Scanning Configuration

Edit `assets/config/scanning.yaml` to customize:
- Crawler settings (depth, max URLs)
- Rate limiting
- Test configurations
- Stealth mode

### Scope Configuration

Edit `assets/config/scope.yaml` to define:
- In-scope domains
- Out-of-scope paths
- Excluded parameters
- Sensitive operations

## CI/CD Integration

### GitHub Actions

```yaml
name: DAST Scan
on:
  schedule:
    - cron: '0 2 * * *'

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run DAST
        run: |
          python3 scripts/playwright_dast_scanner.py \
            --target ${{ secrets.STAGING_URL }} \
            --output results.json
      - name: Check Findings
        run: |
          python3 scripts/check_findings.py \
            --report results.json \
            --fail-on critical,high
```

### Continuous Scanning

```bash
# Setup cron job for weekly scanning
0 2 * * 1 /path/to/scripts/continuous_dast.sh \
  --target https://production.example.com \
  --email security@example.com
```

## Usage with Claude Code

### Trigger Keywords

- "Scan this domain for vulnerabilities"
- "Run DAST on example.com"
- "Perform security testing on these URLs"
- "Automated penetration test"

### Example Conversation

```
User: Scan https://example.com for vulnerabilities

Claude: I'll perform a blackbox DAST scan on https://example.com using Playwright MCP.

[Performing scan...]

Scan complete! Found 15 potential vulnerabilities:
- 2 High severity
- 5 Medium severity
- 8 Low severity

Full report generated: results/example-com-report.html
```

## Vulnerability Coverage

- **A01: Broken Access Control** - IDOR, privilege escalation
- **A02: Cryptographic Failures** - Weak encryption, cleartext data
- **A03: Injection** - SQL, NoSQL, Command, LDAP injection
- **A04: Insecure Design** - Business logic flaws
- **A05: Security Misconfiguration** - Default credentials, exposed files
- **A06: Vulnerable Components** - Outdated software
- **A07: Authentication Failures** - Weak passwords, session issues
- **A08: Data Integrity Failures** - Deserialization
- **A09: Logging Failures** - Insufficient logging
- **A10: SSRF** - Server-Side Request Forgery

Plus: XSS, CSRF, XXE, Open Redirect, Clickjacking, CORS

## Advanced Features

### Custom Test Profiles

Create custom profiles in `assets/config/profiles/`:

```yaml
name: "API-Focused Testing"
playwright:
  capture_api_calls: true
tests:
  enabled:
    - api_authentication
    - api_authorization
```

### Rate Limiting & Stealth

```yaml
rate_limiting:
  requests_per_second: 5

stealth_mode:
  enabled: true
  random_user_agents: true
```

## Troubleshooting

### Playwright Connection Issues

```bash
# Verify Playwright MCP in Claude Code settings
# Test manually:
python3 -c "import playwright; print('OK')"
```

### Authentication Failures

- Verify credentials manually
- Check for CAPTCHA or 2FA
- Use session cookies directly if needed

### Performance Issues

- Reduce crawl depth
- Limit concurrent requests
- Use focused test profiles

## Best Practices

1. **Scope Verification**: Always confirm authorization
2. **Credential Security**: Never log credentials in plain text
3. **Result Validation**: Manually verify High/Critical findings
4. **Rate Limiting**: Respect application performance
5. **Evidence Collection**: Include screenshots and requests

## Support & Documentation

- Full documentation in `references/` directory
- Example workflows in `SKILL.md`
- Configuration guides in `assets/config/`

## Security Notice

This skill is intended for authorized security testing only. Always obtain explicit permission before testing any application. Unauthorized testing may be illegal.

## License

This skill is provided as-is for security testing purposes. Use responsibly and ethically.
