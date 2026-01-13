---
name: sast-automation
description: "Static Application Security Testing (SAST) automation skill using Semgrep, CodeQL, and custom rules. Performs code-level vulnerability detection, secret scanning, dependency analysis, and security code review. Use when: 'scan this code for vulnerabilities', 'run SAST on the codebase', 'find security bugs in code', 'detect hardcoded secrets', or 'security code review'. (user)"
---

# SAST Automation

This skill enables comprehensive Static Application Security Testing using industry-leading tools including Semgrep, CodeQL, and custom security rules. It covers vulnerability detection, secret scanning, dependency analysis, and automated security code review across multiple programming languages.

## When to Use This Skill

This skill should be invoked when:
- Performing security code reviews
- Running SAST scans on codebases
- Detecting hardcoded secrets and credentials
- Analyzing dependencies for vulnerabilities
- Creating custom security rules
- Integrating security scanning into CI/CD
- Generating security assessment reports
- Performing compliance-focused code analysis

### Trigger Phrases
- "scan this code for vulnerabilities"
- "run SAST on the repository"
- "find security bugs in my code"
- "detect hardcoded secrets"
- "security code review"
- "check for SQL injection in code"
- "create Semgrep rules"
- "dependency vulnerability scan"
- "OWASP code analysis"

---

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| Semgrep | Pattern-based SAST | `pip install semgrep` |
| CodeQL | Query-based analysis | GitHub CLI / Manual |
| Gitleaks | Secret detection | `brew install gitleaks` |
| TruffleHog | Secret scanning | `pip install trufflehog` |
| Bandit | Python security | `pip install bandit` |
| ESLint | JavaScript security | `npm install eslint` |
| Brakeman | Ruby/Rails security | `gem install brakeman` |
| Gosec | Go security | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| SpotBugs | Java security | Maven/Gradle plugin |
| trivy | IaC scanning | `apt install trivy` |

### Environment Setup

```bash
# Install Semgrep
pip install semgrep

# Install secret scanners
pip install gitleaks trufflehog detect-secrets

# Install language-specific tools
pip install bandit                           # Python
npm install -g eslint eslint-plugin-security # JavaScript
gem install brakeman                          # Ruby
go install github.com/securego/gosec/v2/cmd/gosec@latest  # Go

# Download Semgrep rules
semgrep --config auto --download-rules

# Setup CodeQL (requires GitHub CLI)
gh extension install github/gh-codeql
```

---

## Quick Start Guide

### 1. Multi-Language SAST Scan (2 minutes)

```bash
# Semgrep - auto-detect language and run relevant rules
semgrep scan --config auto .

# With severity filtering
semgrep scan --config auto --severity ERROR --severity WARNING .

# Output to JSON
semgrep scan --config auto --json -o results.json .
```

### 2. Secret Detection (1 minute)

```bash
# Gitleaks - scan for secrets
gitleaks detect --source . --report-path secrets.json

# TruffleHog - deep history scan
trufflehog git file://. --json > trufflehog_results.json

# detect-secrets - baseline generation
detect-secrets scan . > .secrets.baseline
```

### 3. Language-Specific Scans (3 minutes)

```bash
# Python
bandit -r . -f json -o bandit_results.json
semgrep scan --config p/python .

# JavaScript/TypeScript
semgrep scan --config p/javascript .
npm audit --json > npm_audit.json
eslint --ext .js,.jsx,.ts,.tsx . -f json -o eslint_results.json

# Java
semgrep scan --config p/java .
# SpotBugs via Maven: mvn spotbugs:spotbugs

# Go
gosec -fmt=json -out=gosec_results.json ./...
semgrep scan --config p/golang .

# Ruby/Rails
brakeman -f json -o brakeman_results.json
semgrep scan --config p/ruby .
```

### 4. Custom Rule Scan

```bash
# Run custom rules
semgrep scan --config rules/custom_rules.yaml .

# Run multiple rule sets
semgrep scan --config auto --config rules/ .
```

---

## Supported Languages & Frameworks

| Language | Semgrep Config | Specialized Tool |
|----------|---------------|------------------|
| Python | `p/python`, `p/django`, `p/flask` | Bandit, PyLint |
| JavaScript | `p/javascript`, `p/react`, `p/nodejs` | ESLint, npm audit |
| TypeScript | `p/typescript` | ESLint, TSLint |
| Java | `p/java`, `p/spring` | SpotBugs, FindSecBugs |
| Go | `p/golang` | Gosec, staticcheck |
| Ruby | `p/ruby`, `p/rails` | Brakeman, RuboCop |
| PHP | `p/php`, `p/symfony` | PHPCS, Psalm |
| C/C++ | `p/c` | Cppcheck, Flawfinder |
| C# | `p/csharp`, `p/dotnet` | Security Code Scan |
| Kotlin | `p/kotlin` | Detekt |
| Swift | `p/swift` | SwiftLint |
| Rust | `p/rust` | Clippy, cargo-audit |

---

## Vulnerability Detection Categories

### OWASP Top 10 Coverage

| Category | Semgrep Rules | Example Patterns |
|----------|--------------|------------------|
| A01: Broken Access Control | `p/owasp-top-ten` | IDOR, path traversal |
| A02: Cryptographic Failures | `p/secrets`, custom | Weak crypto, hardcoded keys |
| A03: Injection | `p/sql-injection` | SQLi, XSS, command injection |
| A04: Insecure Design | Custom rules | Business logic flaws |
| A05: Security Misconfiguration | `p/security-audit` | Debug enabled, CORS |
| A06: Vulnerable Components | Dependency scan | Outdated libraries |
| A07: Auth Failures | Custom rules | Weak auth, session issues |
| A08: Data Integrity Failures | Custom rules | Deserialization, CI/CD |
| A09: Logging Failures | Custom rules | Missing logs, sensitive data |
| A10: SSRF | `p/ssrf` | URL injection, redirects |

### CWE Coverage

| CWE ID | Vulnerability | Detection Method |
|--------|--------------|------------------|
| CWE-89 | SQL Injection | Semgrep patterns |
| CWE-79 | XSS | Semgrep patterns |
| CWE-78 | Command Injection | Semgrep patterns |
| CWE-22 | Path Traversal | Semgrep patterns |
| CWE-798 | Hardcoded Credentials | Gitleaks, TruffleHog |
| CWE-327 | Weak Crypto | Semgrep patterns |
| CWE-502 | Deserialization | Semgrep patterns |
| CWE-611 | XXE | Semgrep patterns |
| CWE-918 | SSRF | Semgrep patterns |
| CWE-200 | Info Exposure | Semgrep patterns |

---

## Detailed Workflows

### Workflow 1: Complete SAST Assessment

```python
# Phase 1: Discovery
# Identify languages and frameworks
python3 scripts/language_detector.py --path /path/to/code

# Phase 2: Semgrep Scan
semgrep scan --config auto --config p/security-audit \
  --json -o semgrep_results.json .

# Phase 3: Secret Scanning
gitleaks detect --source . --report-path secrets.json
trufflehog git file://. --json > trufflehog.json

# Phase 4: Dependency Analysis
# Python
pip-audit --format json > pip_audit.json
# JavaScript
npm audit --json > npm_audit.json
# Java
mvn dependency-check:check

# Phase 5: Language-Specific Scans
bandit -r . -f json -o bandit.json              # Python
gosec -fmt=json -out=gosec.json ./...           # Go
brakeman -f json -o brakeman.json               # Ruby

# Phase 6: Generate Report
python3 scripts/sast_report_generator.py \
  --semgrep semgrep_results.json \
  --secrets secrets.json \
  --output report.html
```

### Workflow 2: Custom Semgrep Rule Creation

```yaml
# rules/custom_sql_injection.yaml
rules:
  - id: sql-injection-string-concat
    message: "Potential SQL injection via string concatenation"
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: |
              $QUERY = "..." + $VAR + "..."
              $CURSOR.execute($QUERY)
          - pattern: |
              $QUERY = f"...{$VAR}..."
              $CURSOR.execute($QUERY)
          - pattern: |
              $CURSOR.execute("..." + $VAR + "...")
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021"
      references:
        - https://owasp.org/www-community/attacks/SQL_Injection

  - id: hardcoded-password
    message: "Hardcoded password detected"
    severity: ERROR
    languages: [python, javascript, java, go]
    pattern-either:
      - pattern: password = "..."
      - pattern: PASSWORD = "..."
      - pattern: passwd = "..."
      - pattern: pwd = "..."
    pattern-not:
      - pattern: password = ""
      - pattern: password = "changeme"
      - pattern: password = os.environ[...]
    metadata:
      cwe: "CWE-798"
      owasp: "A02:2021"
```

### Workflow 3: CI/CD Integration

```yaml
# GitHub Actions - .github/workflows/sast.yml
name: SAST Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten

      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Dependency Check
        run: |
          pip install pip-audit
          pip-audit --format json > pip_audit.json

      - name: Check Results
        run: |
          python3 scripts/check_vulnerabilities.py pip_audit.json
```

### Workflow 4: Secret Detection Deep Dive

```bash
# Step 1: Full repository history scan
trufflehog git file://. --json --include-detectors all > trufflehog_full.json

# Step 2: Pre-commit hook setup
# .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
EOF

pre-commit install

# Step 3: Generate secrets baseline (for known false positives)
detect-secrets scan . > .secrets.baseline

# Step 4: Custom regex patterns for company-specific secrets
gitleaks detect --config gitleaks.toml --source .

# gitleaks.toml example
cat > gitleaks.toml << 'EOF'
[rules]
  [[rules.custom-api-key]]
    description = "Company API Key"
    regex = '''COMPANY_[A-Z0-9]{32}'''
    tags = ["key", "API", "company"]

  [[rules.internal-token]]
    description = "Internal Service Token"
    regex = '''internal_token_[a-f0-9]{40}'''
    tags = ["token", "internal"]
EOF
```

### Workflow 5: CodeQL Analysis

```bash
# Step 1: Create CodeQL database
codeql database create codeql-db --language=python --source-root .

# Step 2: Run security queries
codeql database analyze codeql-db \
  --format=sarif-latest \
  --output=codeql-results.sarif \
  codeql/python-queries:codeql-suites/python-security-and-quality.qls

# Step 3: Custom CodeQL query
cat > queries/custom-sql-injection.ql << 'EOF'
/**
 * @name SQL injection
 * @description User input flows to SQL query
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.", source.getNode(), "user input"
EOF

# Step 4: Run custom query
codeql database analyze codeql-db queries/custom-sql-injection.ql \
  --format=sarif-latest --output=custom-results.sarif
```

---

## Semgrep Rule Reference

### Pre-built Rule Packs

| Pack | Purpose | Usage |
|------|---------|-------|
| `p/security-audit` | General security | `--config p/security-audit` |
| `p/owasp-top-ten` | OWASP Top 10 | `--config p/owasp-top-ten` |
| `p/secrets` | Secret detection | `--config p/secrets` |
| `p/sql-injection` | SQLi patterns | `--config p/sql-injection` |
| `p/xss` | XSS patterns | `--config p/xss` |
| `p/command-injection` | Command injection | `--config p/command-injection` |
| `p/insecure-transport` | HTTP/TLS issues | `--config p/insecure-transport` |
| `p/jwt` | JWT vulnerabilities | `--config p/jwt` |
| `p/ci` | CI/CD security | `--config p/ci` |

### Language-Specific Packs

| Language | Packs |
|----------|-------|
| Python | `p/python`, `p/django`, `p/flask`, `p/fastapi` |
| JavaScript | `p/javascript`, `p/react`, `p/nodejs`, `p/express` |
| Java | `p/java`, `p/spring`, `p/kotlin` |
| Go | `p/golang`, `p/gorilla` |
| Ruby | `p/ruby`, `p/rails` |
| PHP | `p/php`, `p/symfony`, `p/laravel` |

---

## Example Claude Code Interactions

### Example 1: Complete SAST Assessment

```
User: Run a security scan on this Python/Django codebase

Claude: I'll perform a comprehensive SAST assessment on the Django codebase.

[Phase 1: Semgrep Security Scan]

> semgrep scan --config auto --config p/django --config p/security-audit

Scan completed - 847 files scanned

Findings:
[!] CRITICAL: SQL Injection (2 findings)
    - app/views.py:145 - Raw SQL with user input
    - app/models.py:89 - filter() with unsanitized input

[!] HIGH: Hardcoded Secret (3 findings)
    - settings.py:12 - SECRET_KEY hardcoded
    - config.py:34 - DATABASE_PASSWORD in code
    - utils/api.py:5 - API_KEY hardcoded

[!] HIGH: Insecure Deserialization (1 finding)
    - app/serializers.py:67 - pickle.loads() on user data

[!] MEDIUM: Debug Mode Enabled (1 finding)
    - settings.py:8 - DEBUG = True

[Phase 2: Secret Detection]

> gitleaks detect --source .

Found 7 potential secrets:
- AWS Access Key: config/aws.py:3
- GitHub Token: .env.example:12
- Private Key: certs/server.key
- Database URL with password: docker-compose.yml:15

[Phase 3: Dependency Vulnerabilities]

> pip-audit

Found 4 vulnerable dependencies:
- django==3.2.0 - CVE-2023-XXXX (Critical)
- pillow==8.0.0 - CVE-2022-XXXX (High)
- requests==2.25.0 - CVE-2023-XXXX (Medium)
- pyyaml==5.3 - CVE-2020-XXXX (High)

[Summary]

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 8 |
| Medium | 12 |
| Low | 25 |

Priority Fixes:
1. Remove hardcoded SECRET_KEY (use env var)
2. Use parameterized queries for SQL
3. Upgrade django to 4.2.x
4. Replace pickle with JSON serialization

Full report: reports/sast-django-report.html
```

### Example 2: Custom Rule Creation

```
User: Create a Semgrep rule to detect unsafe eval() usage in JavaScript

Claude: I'll create a comprehensive Semgrep rule for detecting unsafe eval() usage.

[Creating Rule: unsafe-eval.yaml]

rules:
  - id: js-unsafe-eval
    message: |
      Detected use of eval() with potentially untrusted input.
      eval() can execute arbitrary JavaScript code, leading to
      Remote Code Execution (RCE) if the input is user-controlled.
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          # Direct eval with variable
          - pattern: eval($VAR)
          # Function constructor (equivalent to eval)
          - pattern: new Function($VAR)
          - pattern: new Function(..., $VAR)
          # setTimeout/setInterval with string
          - pattern: setTimeout($STR, ...)
          - pattern: setInterval($STR, ...)
    pattern-not:
      # Allow eval with literal strings (still risky but intentional)
      - pattern: eval("...")
      - pattern: new Function("...")
    metadata:
      cwe: "CWE-95"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      impact: CRITICAL
      references:
        - https://owasp.org/www-community/attacks/Code_Injection

  - id: js-indirect-eval
    message: |
      Indirect eval() detected. This is still dangerous as it
      executes code in the global scope.
    severity: WARNING
    languages: [javascript, typescript]
    patterns:
      - pattern: (0, eval)($VAR)
      - pattern: window.eval($VAR)
      - pattern: global.eval($VAR)
      - pattern: globalThis.eval($VAR)
    metadata:
      cwe: "CWE-95"

[Testing Rule]

> semgrep scan --config rules/unsafe-eval.yaml test_files/

Test Results:
✓ Detected: eval(userInput)
✓ Detected: new Function(req.body.code)
✓ Detected: setTimeout(userInput, 1000)
✗ Ignored: eval("console.log('safe')")

Rule is working correctly!

[Usage]

# Add to your Semgrep config
semgrep scan --config rules/unsafe-eval.yaml .

# Or add to semgrep.yaml
rules:
  - rules/unsafe-eval.yaml
```

---

## Scripts Reference

| Script | Description | Usage |
|--------|-------------|-------|
| `sast_scanner.py` | Multi-tool SAST orchestrator | `python3 scripts/sast_scanner.py --path /code` |
| `rule_generator.py` | Generate Semgrep rules from patterns | `python3 scripts/rule_generator.py` |
| `secret_aggregator.py` | Aggregate secret scan results | `python3 scripts/secret_aggregator.py` |
| `dependency_checker.py` | Multi-language dependency scan | `python3 scripts/dependency_checker.py` |
| `sast_report_generator.py` | Generate HTML/PDF reports | `python3 scripts/sast_report_generator.py` |
| `ci_integrator.py` | Generate CI/CD configurations | `python3 scripts/ci_integrator.py` |
| `baseline_generator.py` | Generate finding baselines | `python3 scripts/baseline_generator.py` |

---

## Checklists Reference

| Checklist | Purpose |
|-----------|---------|
| [checklists/owasp_code_review.md](checklists/owasp_code_review.md) | OWASP Code Review Guide |
| [checklists/secure_coding.md](checklists/secure_coding.md) | Secure Coding Practices |
| [checklists/secret_detection.md](checklists/secret_detection.md) | Secret Detection Checklist |
| [checklists/dependency_security.md](checklists/dependency_security.md) | Dependency Security |
| [checklists/ci_cd_security.md](checklists/ci_cd_security.md) | CI/CD Security Checklist |

---

## Templates Reference

| Template | Purpose |
|----------|---------|
| [templates/finding_template.md](templates/finding_template.md) | Individual finding report |
| [templates/executive_summary.md](templates/executive_summary.md) | Executive summary |
| [templates/remediation_guide.md](templates/remediation_guide.md) | Fix guidance |
| [templates/semgrep_rule.yaml](templates/semgrep_rule.yaml) | Custom rule template |

---

## Related Resources

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Semgrep Rules Registry](https://semgrep.dev/r)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [CWE Database](https://cwe.mitre.org/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)

---

## Bundled Resources

### scripts/
- `sast_scanner.py` - Multi-tool SAST scanner
- `rule_generator.py` - Semgrep rule generator
- `secret_aggregator.py` - Secret scan aggregator
- `dependency_checker.py` - Dependency vulnerability checker
- `sast_report_generator.py` - Report generator
- `baseline_generator.py` - Finding baseline generator
- `ci_integrator.py` - CI/CD config generator

### rules/
- `sql_injection.yaml` - SQL injection patterns
- `xss.yaml` - XSS patterns
- `command_injection.yaml` - Command injection patterns
- `hardcoded_secrets.yaml` - Secret detection patterns
- `insecure_crypto.yaml` - Weak crypto patterns
- `authentication.yaml` - Auth vulnerability patterns
- `authorization.yaml` - Authz vulnerability patterns
- `deserialization.yaml` - Insecure deserialization
- `ssrf.yaml` - SSRF patterns
- `path_traversal.yaml` - Path traversal patterns
