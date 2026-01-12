# DAST Reporting Guide

## Report Structure

### Executive Summary
- Target scope
- Scan duration
- Testing methodology
- High-level findings count
- Risk rating
- Recommendations

### Findings Section
Each finding should include:
1. Title (clear, specific)
2. Severity (Critical/High/Medium/Low/Info)
3. CVSS Score
4. Description
5. Technical Details
6. Reproduction Steps
7. Evidence (screenshots, requests/responses)
8. Impact Assessment
9. Remediation Guidance
10. References (CWE, OWASP, CVE)

### Technical Appendix
- Full endpoint list
- Scan configuration
- Tool versions
- Scope definition
- Exclusions
- Limitations

## Severity Rating

### CVSS v3.1 Scoring

**Critical (9.0-10.0):**
- Remote Code Execution
- SQL Injection with data access
- Authentication bypass
- Complete system compromise

**High (7.0-8.9):**
- Privilege escalation
- Stored XSS
- IDOR with sensitive data access
- Weak cryptography with data exposure

**Medium (4.0-6.9):**
- Reflected XSS
- CSRF on sensitive operations
- Information disclosure
- Missing security headers

**Low (0.1-3.9):**
- Verbose error messages
- SSL/TLS configuration issues
- Minor information leakage
- Low-impact CSRF

**Info (0.0):**
- Best practice recommendations
- Security hardening suggestions
- No direct security impact

## Finding Template

```markdown
### [CRITICAL] SQL Injection in Login Form

**Severity**: Critical
**CVSS Score**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE**: CWE-89 (SQL Injection)
**OWASP**: A03:2021 - Injection

**Description:**
The login form at /api/login is vulnerable to SQL injection via the username parameter. An attacker can bypass authentication and gain unauthorized access to the application.

**Technical Details:**
- Endpoint: POST /api/login
- Parameter: username
- Payload: admin' OR '1'='1'--
- Database: MySQL 5.7

**Reproduction Steps:**
1. Navigate to https://example.com/login
2. Enter the following in username field: `admin' OR '1'='1'--`
3. Enter any value in password field
4. Click "Login"
5. Observe successful authentication without valid credentials

**Evidence:**
```http
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"admin' OR '1'='1'--","password":"any"}

HTTP/1.1 200 OK
Set-Cookie: session=abc123...
{"status":"success","user":"admin","token":"..."}
```

Screenshot: evidence/sqli_login_bypass.png

**Impact:**
- Complete authentication bypass
- Unauthorized access to all user accounts
- Potential database compromise
- Data exfiltration risk
- Privilege escalation to administrator

**Affected Assets:**
- Login functionality
- User authentication system
- Database integrity

**Remediation:**
1. Immediate:
   - Use parameterized queries (prepared statements)
   - Never concatenate user input into SQL queries

   Example (Python):
   ```python
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
   ```

2. Additional:
   - Implement input validation
   - Use ORM framework with built-in SQL injection protection
   - Apply principle of least privilege to database user
   - Enable WAF rules for SQL injection patterns
   - Implement logging and monitoring for injection attempts

**Verification:**
After remediation, verify:
1. Parameterized queries implemented
2. All SQL injection payloads blocked
3. Error messages sanitized
4. WAF rules active

**References:**
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---
```

## Report Formats

### JSON Report
```json
{
  "metadata": {
    "scan_date": "2024-01-15T10:30:00Z",
    "target": "https://example.com",
    "mode": "greybox",
    "duration": "2h 15m",
    "scanner": "Playwright DAST v1.0"
  },
  "summary": {
    "total_findings": 25,
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 8,
    "risk_rating": "HIGH"
  },
  "findings": [
    {
      "id": "DAST-001",
      "title": "SQL Injection in Login Form",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "description": "...",
      "reproduction_steps": [...],
      "evidence": {...},
      "remediation": "...",
      "references": [...]
    }
  ]
}
```

### HTML Report Features
- Interactive filtering by severity
- Collapsible findings
- Search functionality
- Evidence gallery
- Export to PDF
- Executive dashboard

### Markdown Report
- Easy to version control
- GitHub/GitLab integration
- Create issues directly
- Track remediation progress

## Report Customization

### Custom Templates

Create custom report templates in `assets/report_templates/`:

```python
# Custom HTML template
custom_template = """
<!DOCTYPE html>
<html>
<head>
    <title>DAST Report - {company_name}</title>
    <style>
        /* Custom branding */
    </style>
</head>
<body>
    <h1>{company_name} Security Assessment</h1>
    <!-- Custom sections -->
</body>
</html>
"""
```

### Branding

```python
# Add company branding
report_config = {
    'company_name': 'Acme Corp',
    'company_logo': 'assets/logo.png',
    'color_scheme': {
        'primary': '#0066cc',
        'critical': '#d32f2f',
        'high': '#f57c00'
    }
}
```

## Metrics and KPIs

### Scan Metrics
```python
metrics = {
    'urls_discovered': 500,
    'forms_tested': 50,
    'apis_tested': 30,
    'payloads_sent': 5000,
    'scan_duration': '2h 15m',
    'coverage_percentage': 85
}
```

### Finding Metrics
```python
finding_metrics = {
    'total_findings': 25,
    'findings_by_severity': {
        'critical': 2,
        'high': 5,
        'medium': 10,
        'low': 8
    },
    'findings_by_category': {
        'injection': 7,
        'broken_auth': 3,
        'sensitive_data': 5,
        'xxe': 2,
        'broken_access': 8
    },
    'false_positive_rate': 5,
    'mean_time_to_remediate': '7 days'
}
```

### Trend Analysis
```python
# Track findings over time
trend_data = {
    'week_1': {'critical': 3, 'high': 8},
    'week_2': {'critical': 2, 'high': 6},
    'week_3': {'critical': 1, 'high': 4},
    'week_4': {'critical': 0, 'high': 2}
}
```

## Report Distribution

### Email Reports
```python
# Email HTML report
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_report(report_html, recipients):
    msg = MIMEMultipart()
    msg['Subject'] = 'DAST Scan Results'
    msg['From'] = 'security@example.com'
    msg['To'] = ', '.join(recipients)

    msg.attach(MIMEText(report_html, 'html'))

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('user', 'pass')
        server.send_message(msg)
```

### Slack Integration
```python
def send_slack_report(summary, webhook_url):
    payload = {
        "text": f"DAST Scan Complete",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*DAST Scan Results*\n"
                            f"Critical: {summary['critical']}\n"
                            f"High: {summary['high']}\n"
                            f"Medium: {summary['medium']}"
                }
            }
        ]
    }

    requests.post(webhook_url, json=payload)
```

### Jira Integration
```python
from jira import JIRA

def create_jira_tickets(findings):
    jira = JIRA(server='https://jira.example.com',
                basic_auth=('user', 'token'))

    for finding in findings:
        if finding['severity'] in ['CRITICAL', 'HIGH']:
            issue = jira.create_issue(
                project='SEC',
                summary=finding['title'],
                description=finding['description'],
                issuetype={'name': 'Bug'},
                priority={'name': finding['severity'].capitalize()}
            )
```

## Executive Reporting

### Executive Summary Template
```markdown
# Security Assessment Summary

**Assessed Application:** {target}
**Assessment Date:** {date}
**Assessment Type:** Dynamic Application Security Testing (DAST)

## Overall Risk Rating: {risk_rating}

## Key Findings
- **Critical Issues:** {critical_count} - Require immediate attention
- **High-Risk Issues:** {high_count} - Should be addressed urgently
- **Medium-Risk Issues:** {medium_count} - Should be remediated soon
- **Low-Risk Issues:** {low_count} - Should be addressed as time permits

## Top 3 Critical Findings
1. {critical_1_title}
   - Impact: {impact}
   - Recommendation: {quick_fix}

2. {critical_2_title}
   - Impact: {impact}
   - Recommendation: {quick_fix}

3. {critical_3_title}
   - Impact: {impact}
   - Recommendation: {quick_fix}

## Risk Score Trend
{trend_chart}

## Recommendations
1. Prioritize remediation of all Critical and High findings
2. Implement automated security testing in CI/CD
3. Conduct regular security assessments
4. Provide security training for development team

## Next Steps
- Review detailed technical findings
- Assign remediation tasks
- Schedule follow-up assessment
```

## Compliance Reporting

### PCI DSS
```markdown
## PCI DSS Compliance Issues

Requirement 6.5.1 (Injection Flaws):
- Finding: SQL Injection (DAST-001)
- Status: Non-Compliant
- Required Action: Implement input validation and parameterized queries

Requirement 6.5.7 (XSS):
- Finding: Reflected XSS (DAST-005)
- Status: Non-Compliant
- Required Action: Implement output encoding
```

### OWASP ASVS
```markdown
## OWASP ASVS Level 2 Assessment

V1: Architecture
- V1.4.1: SQL Injection Protection - FAIL
- V1.4.2: XSS Protection - FAIL

V2: Authentication
- V2.1.1: Password Policy - PASS
- V2.2.1: Session Management - FAIL
```

## Report Generation Usage

```bash
# Generate all formats
python3 scripts/report_generator.py \
  --input scan_results.json \
  --format all \
  --output-dir reports/

# Generate HTML only
python3 scripts/report_generator.py \
  --input scan_results.json \
  --format html \
  --output report.html

# With custom branding
python3 scripts/report_generator.py \
  --input scan_results.json \
  --format html \
  --template assets/report_templates/custom.html \
  --branding config/branding.yaml \
  --output branded_report.html
```

## Best Practices

1. **Clarity**: Use clear, non-technical language for executive summary
2. **Evidence**: Always include screenshots and request/response examples
3. **Context**: Explain business impact, not just technical details
4. **Actionable**: Provide specific remediation steps
5. **Prioritization**: Clear severity ratings and risk assessment
6. **Follow-up**: Include retest results and remediation verification

This completes the DAST reporting guide.
