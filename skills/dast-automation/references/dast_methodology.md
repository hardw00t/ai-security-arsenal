# DAST Methodology - Complete Testing Guide

## Overview

Dynamic Application Security Testing (DAST) is a black-box security testing methodology that analyzes running applications to identify vulnerabilities. This guide provides comprehensive methodology for conducting DAST using Playwright MCP for browser automation.

## DAST Testing Phases

### Phase 1: Reconnaissance & Scope Definition

**Objectives:**
- Define clear testing scope
- Identify all application entry points
- Understand application architecture
- Document test boundaries

**Activities:**
1. Scope validation with stakeholder
2. Create exclusion list (logout, destructive actions)
3. Identify authentication requirements
4. Document sensitive operations to avoid
5. Establish communication channels

**Deliverables:**
- Scope document
- Exclusions list
- Rules of engagement

### Phase 2: Application Crawling

**Objectives:**
- Map entire application surface
- Discover all endpoints, forms, APIs
- Identify authentication mechanisms
- Extract input vectors

**Playwright MCP Approach:**
```
1. Launch browser context
2. Navigate to target URL
3. Execute JavaScript and wait for dynamic content
4. Extract all links (a[href])
5. Extract all forms with inputs
6. Monitor network requests for APIs
7. Click navigation elements to discover hidden pages
8. Recursively crawl discovered URLs within scope
9. Build comprehensive attack surface map
```

**Key Data to Collect:**
- All URLs and endpoints
- Form submissions (action, method, parameters)
- API endpoints (REST, GraphQL, gRPC)
- Input fields (name, type, validation)
- File upload mechanisms
- Authentication flows
- Session management patterns

### Phase 3: Vulnerability Testing

**Objectives:**
- Test all discovered surfaces for vulnerabilities
- Verify security controls
- Identify exploitable weaknesses

**Testing Categories:**

#### A. Injection Attacks

**Cross-Site Scripting (XSS):**
```
Test Types:
- Reflected XSS (input → output in same response)
- Stored XSS (input stored → output later)
- DOM-based XSS (client-side JavaScript vulnerability)

Contexts to Test:
- HTML context: <div>USER_INPUT</div>
- Attribute context: <input value="USER_INPUT">
- JavaScript context: <script>var x = 'USER_INPUT'</script>
- URL context: <a href="USER_INPUT">

Payloads:
- <script>alert(document.domain)</script>
- <img src=x onerror=alert(1)>
- <svg onload=alert(1)>
- " autofocus onfocus=alert(1) x="
- ';alert(1);//

Verification:
- Monitor alert() dialog via Playwright
- Check DOM for unescaped payload
- Verify in response body
```

**SQL Injection:**
```
Test Types:
- Error-based (trigger SQL errors)
- Union-based (extract data via UNION)
- Boolean-based (true/false logic)
- Time-based blind (SLEEP/WAITFOR delays)

Payloads:
- ' OR '1'='1'--
- ' UNION SELECT NULL--
- ' AND SLEEP(5)--
- 1' WAITFOR DELAY '00:00:05'--

Verification:
- SQL error messages in response
- Time delays confirmed (5+ seconds)
- Data extraction successful
- Logic manipulation observed
```

#### B. Authentication & Authorization

**Broken Authentication:**
```
Tests:
- Weak password policy
- No account lockout
- Session fixation
- Predictable session tokens
- Credential stuffing susceptibility

Verification:
- Test password: 123456, password, admin
- Attempt 100+ login attempts (should lock)
- Capture and replay session tokens
- Test session timeout
```

**Broken Access Control:**
```
Tests:
- IDOR (Insecure Direct Object References)
- Horizontal privilege escalation (User A → User B)
- Vertical privilege escalation (User → Admin)
- Missing function-level access control

Test Approach (Greybox):
1. Login as User A
2. Access resource: /api/user/123/profile
3. Login as User B
4. Attempt to access User A's resource
5. Verify authorization enforcement

Common Patterns:
- Sequential IDs: /user/1, /user/2, /user/3
- GUIDs: /document/{uuid}
- Predictable tokens: /order/{timestamp}
```

#### C. Business Logic Flaws

```
Common Scenarios:
- Price manipulation (negative quantities, zero price)
- Workflow bypass (skip payment, skip verification)
- Race conditions (parallel requests)
- Voucher/coupon abuse
- Inventory manipulation

Test Approach with Playwright:
1. Map multi-step workflow (e.g., checkout)
2. Attempt to skip steps
3. Manipulate step order
4. Submit parallel requests
5. Modify hidden fields (price, quantity)
6. Test boundary values (0, -1, MAX_INT)
```

#### D. Security Misconfiguration

```
Tests:
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Directory listing enabled
- Verbose error messages
- Default credentials
- Exposed admin interfaces
- Debug mode enabled
- Unnecessary services/features

Verification:
- Check HTTP headers
- Test common admin paths: /admin, /administrator, /manager
- Trigger errors (invalid input, nonexistent pages)
- Search for: .git, .env, backup files
```

### Phase 4: Validation & Verification

**Objectives:**
- Confirm all findings
- Eliminate false positives
- Assess actual exploitability
- Gather evidence

**Validation Process:**
1. Manually reproduce each finding
2. Verify real security impact
3. Capture evidence (screenshots, requests, responses)
4. Document reproduction steps
5. Rate severity (CVSS)

**False Positive Indicators:**
- Payload reflected but properly encoded
- Security control blocking actual exploitation
- No actual security impact
- WAF/IDS detection without bypass

### Phase 5: Reporting

**Objectives:**
- Communicate findings clearly
- Provide actionable remediation
- Prioritize by risk

**Report Sections:**
1. Executive Summary
   - High-level overview
   - Risk rating
   - Key findings count

2. Findings Details
   - Title and severity
   - Description
   - Reproduction steps
   - Evidence (screenshots, PoC)
   - Impact assessment
   - Remediation guidance
   - References (CWE, OWASP)

3. Technical Appendix
   - Full endpoint list
   - Scan configuration
   - Tool versions
   - Raw scan data

## Blackbox vs Greybox Testing

### Blackbox Testing

**Characteristics:**
- No credentials provided
- Tests only public-facing surfaces
- External attacker perspective
- No application knowledge

**Advantages:**
- Real-world external attacker simulation
- Safe for production environments
- No credential management required

**Limitations:**
- Cannot test authenticated functionality
- Misses internal vulnerabilities
- Limited coverage

**Use Cases:**
- Public-facing websites
- Pre-authentication testing
- External attack surface assessment

### Greybox Testing

**Characteristics:**
- Credentials provided
- Tests authenticated functionality
- Some application knowledge
- Insider threat perspective

**Advantages:**
- Comprehensive coverage
- Tests authenticated surfaces
- Identifies IDOR, access control issues
- Realistic insider threat testing

**Limitations:**
- Requires credential management
- May affect production data
- More complex setup

**Use Cases:**
- Web applications with authentication
- API security testing
- Internal applications
- Comprehensive assessments

## Playwright MCP-Specific Patterns

### Authentication Automation

```javascript
// Claude Code orchestrates via Playwright MCP:
1. Navigate to login page
2. Fill username: await page.fill('#username', 'user@test.com')
3. Fill password: await page.fill('#password', 'password123')
4. Click submit: await page.click('button[type="submit"]')
5. Wait for navigation: await page.waitForNavigation()
6. Verify authentication: await page.waitForSelector('.user-profile')
7. Capture session cookies: const cookies = await context.cookies()
```

### Form Testing

```javascript
// For each form:
1. Navigate to form page
2. Identify all input fields: await page.$$('input, textarea, select')
3. For each field and payload:
   - Fill field with payload
   - Submit form
   - Analyze response
   - Check for vulnerability indicators
4. Reset form or reload page
5. Test next payload
```

### Dynamic Content Handling

```javascript
// Handle SPAs and AJAX:
1. Navigate to page
2. Wait for network idle: await page.waitForLoadState('networkidle')
3. Execute JavaScript: await page.evaluate(() => window.appState)
4. Click elements to trigger AJAX: await page.click('.load-more')
5. Wait for dynamic content: await page.waitForSelector('.new-content')
6. Extract new URLs/forms/APIs
```

### Session Management Testing

```javascript
// Test session security:
1. Login and capture cookies
2. Check cookie flags: HttpOnly, Secure, SameSite
3. Test session timeout:
   - Wait 30 minutes
   - Attempt authenticated action
   - Verify session expired
4. Test concurrent sessions:
   - Login in browser context 1
   - Login same user in context 2
   - Verify first session invalidated
5. Test logout:
   - Perform logout
   - Attempt authenticated action with old cookie
   - Verify access denied
```

## Testing Best Practices

### 1. Respect Rate Limits
```
- Implement delays between requests (1-2 seconds)
- Limit concurrent requests (max 5)
- Monitor application performance
- Stop if service degradation detected
```

### 2. Avoid Destructive Actions
```
Exclude from testing:
- Logout functionality
- Account deletion
- Data deletion endpoints
- Password reset (unless test account)
- Email/notification triggers (spam prevention)
- Payment processing (unless test environment)
```

### 3. Credential Security
```
- Use dedicated test accounts
- Never log credentials in plain text
- Clear session data after testing
- Use environment variables for sensitive data
- Secure report storage (encrypt findings)
```

### 4. Scope Adherence
```
- Never test out-of-scope domains
- Respect robots.txt (unless instructed otherwise)
- Document any scope deviations
- Obtain explicit permission for aggressive testing
```

### 5. Evidence Collection
```
For each finding:
- Screenshot of vulnerability
- Request/response (sanitized)
- Payload used
- Reproduction steps
- Timestamp
```

## Continuous DAST Integration

### CI/CD Integration

```bash
# GitHub Actions workflow
name: DAST Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - name: Run DAST Scan
        run: |
          python3 playwright_dast_scanner.py \
            --target ${{ secrets.STAGING_URL }} \
            --mode blackbox \
            --output results.json

      - name: Check Findings
        run: |
          python3 check_findings.py \
            --report results.json \
            --fail-on critical,high
```

### Scheduled Scanning

```bash
# Cron job for continuous monitoring
# Run weekly scan, compare to baseline, alert on new findings

0 2 * * 1 /path/to/continuous_dast.sh \
  --target https://production.example.com \
  --baseline /path/to/baseline.json \
  --email security@example.com \
  --fail-on critical,high
```

### Baseline Management

```
1. Initial baseline scan (Week 0)
2. Address all findings
3. Create baseline from clean scan
4. Future scans compare to baseline
5. Alert only on NEW findings
6. Update baseline quarterly or after major changes
```

## Troubleshooting

### Common Issues

**1. Playwright Connection Failed**
```
Solution:
- Verify Playwright MCP is running
- Check Claude Code MCP configuration
- Test Playwright manually: python3 -c "import playwright; ..."
```

**2. Authentication Failures**
```
Solution:
- Verify credentials manually
- Check for CAPTCHA or 2FA
- Inspect login flow with browser DevTools
- Use session cookies directly if login flow complex
```

**3. WAF/IDS Blocking**
```
Solution:
- Reduce request rate
- Rotate user agents
- Add random delays
- Coordinate with security team for whitelisting
```

**4. False Positives**
```
Solution:
- Manually verify all HIGH/CRITICAL findings
- Check if security control blocking exploitation
- Verify actual security impact
- Update detection logic to reduce FPs
```

## Metrics & KPIs

### Scan Metrics
- Total URLs discovered
- Total forms tested
- Total APIs tested
- Scan duration
- Coverage percentage

### Finding Metrics
- Critical findings count
- High findings count
- Medium findings count
- Low findings count
- False positive rate
- Time to remediation
- Re-test results

### Trend Analysis
- Findings over time
- New vs recurring findings
- Time to fix trends
- Vulnerability types distribution

## Conclusion

Effective DAST requires:
1. Comprehensive crawling with JavaScript awareness
2. Thorough vulnerability testing across all surfaces
3. Proper authentication handling for greybox testing
4. Validation and evidence collection
5. Clear, actionable reporting
6. Continuous testing integration

Use Playwright MCP for reliable browser automation and JavaScript-heavy application testing.
