---
name: sast-orchestration
description: "Static Application Security Testing orchestration skill for running and managing SAST tools across codebases. This skill should be used when performing static code analysis, writing custom security rules, triaging SAST findings, integrating security scanning into CI/CD, or comparing findings across multiple SAST tools. Triggers on requests to scan code for vulnerabilities, write Semgrep/CodeQL rules, analyze SAST results, or set up automated security scanning."
---

# SAST Orchestration

This skill enables comprehensive static application security testing through tool orchestration, custom rule development, finding triage, and CI/CD integration using industry-standard SAST tools.

## When to Use This Skill

This skill should be invoked when:
- Scanning source code for security vulnerabilities
- Writing custom detection rules for Semgrep, CodeQL, or other SAST tools
- Triaging and prioritizing SAST findings
- Setting up automated security scanning in CI/CD pipelines
- Comparing results across multiple SAST tools
- Reducing false positives in security scans

### Trigger Phrases
- "scan this code for vulnerabilities"
- "write a Semgrep rule to detect..."
- "triage these SAST findings"
- "set up security scanning in CI/CD"
- "find SQL injection in this codebase"
- "analyze the security scan results"

---

## SAST Tool Selection Matrix

| Tool | Languages | Strengths | Best For |
|------|-----------|-----------|----------|
| Semgrep | 30+ languages | Fast, custom rules, low FP | Custom patterns, quick scans |
| CodeQL | 10 languages | Deep dataflow, taint tracking | Complex vulnerability chains |
| Bandit | Python | Python-specific, easy setup | Python security audits |
| gosec | Go | Go-specific patterns | Go security scanning |
| Brakeman | Ruby/Rails | Rails-aware analysis | Rails applications |
| SpotBugs + FindSecBugs | Java | Bytecode analysis | Java/JVM apps |
| ESLint + security plugins | JavaScript/TS | IDE integration | Frontend/Node.js |
| PHPStan + security rules | PHP | Type-aware analysis | PHP applications |

---

## Semgrep

### Quick Start

```bash
# Install
pip install semgrep
# or
brew install semgrep

# Run with default security rules
semgrep --config=auto .

# Run specific rule packs
semgrep --config=p/security-audit .
semgrep --config=p/owasp-top-ten .
semgrep --config=p/cwe-top-25 .

# Run with custom rules
semgrep --config=./rules/ .

# Output formats
semgrep --config=auto --json -o results.json .
semgrep --config=auto --sarif -o results.sarif .
```

### Rule Packs for Security

```bash
# Comprehensive security scanning
semgrep --config=p/security-audit \
        --config=p/secrets \
        --config=p/supply-chain \
        --config=p/default .

# Language-specific
semgrep --config=p/python .
semgrep --config=p/javascript .
semgrep --config=p/java .
semgrep --config=p/golang .

# Framework-specific
semgrep --config=p/django .
semgrep --config=p/flask .
semgrep --config=p/react .
semgrep --config=p/nodejs .
```

### Writing Custom Semgrep Rules

```yaml
# Basic pattern matching
rules:
  - id: hardcoded-password
    pattern: password = "..."
    message: Hardcoded password detected
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
      owasp: "A07:2021 - Identification and Authentication Failures"

  # Using metavariables
  - id: sql-injection-format-string
    patterns:
      - pattern: |
          $QUERY = f"...{$USER_INPUT}..."
          $CURSOR.execute($QUERY)
      - pattern: |
          $CURSOR.execute(f"...{$USER_INPUT}...")
    message: SQL injection via f-string
    languages: [python]
    severity: ERROR

  # Pattern with focus
  - id: dangerous-subprocess
    patterns:
      - pattern: subprocess.$METHOD(..., shell=True, ...)
      - metavariable-pattern:
          metavariable: $METHOD
          pattern-either:
            - pattern: run
            - pattern: call
            - pattern: Popen
    message: Subprocess with shell=True is dangerous
    languages: [python]
    severity: WARNING

  # Taint tracking (requires Semgrep Pro for full taint)
  - id: xss-vulnerability
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: render_template_string(...)
      - pattern: Markup(...)
    message: User input flows to unsafe output
    languages: [python]
    severity: ERROR
```

### Advanced Semgrep Patterns

```yaml
rules:
  # Pattern negation - exclude safe patterns
  - id: unsafe-deserialization
    patterns:
      - pattern: pickle_module.loads($DATA)
      - pattern-not-inside: |
          if validate_signature($DATA):
              ...
    message: Unsafe deserialization without validation
    languages: [python]
    severity: ERROR

  # Metavariable comparison
  - id: timing-attack-comparison
    patterns:
      - pattern: $SECRET == $USER_INPUT
      - metavariable-pattern:
          metavariable: $SECRET
          patterns:
            - pattern-either:
                - pattern: password
                - pattern: token
                - pattern: api_key
    message: Use constant-time comparison for secrets
    languages: [python]
    severity: WARNING
    fix: hmac.compare_digest($SECRET, $USER_INPUT)

  # Multiple pattern conjunction
  - id: jwt-none-algorithm
    patterns:
      - pattern-either:
          - pattern: jwt.decode($TOKEN, ..., algorithms=["none"], ...)
          - pattern: jwt.decode($TOKEN, ..., options={"verify_signature": False}, ...)
    message: JWT verification disabled
    languages: [python]
    severity: ERROR

  # Regex-based detection
  - id: aws-access-key
    pattern-regex: 'AKIA[0-9A-Z]{16}'
    message: AWS Access Key ID detected
    languages: [generic]
    severity: ERROR

  # Cross-file analysis
  - id: flask-debug-production
    patterns:
      - pattern-inside: |
          if __name__ == "__main__":
              ...
      - pattern: app.run(..., debug=True, ...)
    paths:
      include:
        - "**/*prod*.py"
        - "**/production/**"
    message: Debug mode enabled in production file
    languages: [python]
    severity: ERROR
```

---

## CodeQL

### Setup and Basic Usage

```bash
# Install CodeQL CLI
# Download from https://github.com/github/codeql-cli-binaries

# Create database
codeql database create ./codeql-db --language=python --source-root=./src

# Run security queries
codeql database analyze ./codeql-db \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest \
  --output=results.sarif

# Run specific query
codeql database analyze ./codeql-db \
  ./custom-queries/sql-injection.ql \
  --format=csv \
  --output=results.csv
```

### Writing CodeQL Queries

```ql
/**
 * @name SQL Injection
 * @description User input flows to SQL query without sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjection
import DataFlow::PathGraph

from SqlInjection::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.", source.getNode(), "user input"
```

```ql
/**
 * @name Hardcoded credentials
 * @kind problem
 * @problem.severity warning
 * @id py/hardcoded-credentials
 */

import python

from Assignment a, StringLiteral s
where
  a.getValue() = s and
  a.getTarget().(Name).getId().regexpMatch("(?i).*(password|secret|key|token|credential).*") and
  s.getText().length() > 5
select a, "Potential hardcoded credential in variable: " + a.getTarget().(Name).getId()
```

### CodeQL for Taint Tracking

```ql
/**
 * @name Command injection
 * @kind path-problem
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Flask request inputs
    source = API::moduleImport("flask").getMember("request").getMember(_).getACall()
  }

  override predicate isSink(DataFlow::Node sink) {
    // subprocess calls
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("subprocess").getMember(_).getACall() and
      sink = call.getArg(0)
    )
    or
    // os.system
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall() and
      sink = call.getArg(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // shlex.quote sanitizes command injection
    node = API::moduleImport("shlex").getMember("quote").getACall()
  }
}
```

---

## Language-Specific SAST Tools

### Python - Bandit

```bash
# Install
pip install bandit

# Basic scan
bandit -r ./src

# With severity filtering
bandit -r ./src -ll  # Medium and above
bandit -r ./src -lll # High only

# Specific tests
bandit -r ./src -t B301,B302,B303  # Specific checks
bandit -r ./src -s B101            # Skip assert check

# Output formats
bandit -r ./src -f json -o bandit-results.json
bandit -r ./src -f sarif -o bandit-results.sarif

# Configuration file
bandit -r ./src -c bandit.yaml
```

```yaml
# bandit.yaml
skips: ['B101']  # Skip assert_used
tests: ['B301', 'B302', 'B303', 'B304', 'B305', 'B306', 'B307', 'B308', 'B309', 'B310', 'B311', 'B312', 'B313', 'B314', 'B315', 'B316', 'B317', 'B318', 'B319', 'B320', 'B321', 'B322', 'B323', 'B324', 'B325']
exclude_dirs: ['tests', 'venv']
```

### Go - gosec

```bash
# Install
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Basic scan
gosec ./...

# With severity filtering
gosec -severity medium ./...

# Specific rules
gosec -include=G101,G102,G103 ./...
gosec -exclude=G104 ./...

# Output formats
gosec -fmt=json -out=results.json ./...
gosec -fmt=sarif -out=results.sarif ./...
```

### JavaScript/TypeScript - ESLint Security

```bash
# Install
npm install --save-dev eslint eslint-plugin-security eslint-plugin-no-unsanitized

# Run
npx eslint --ext .js,.ts ./src
```

```json
// .eslintrc.json
{
  "plugins": ["security", "no-unsanitized"],
  "extends": ["plugin:security/recommended-legacy"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-require": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-child-process": "warn",
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  }
}
```

### Java - SpotBugs + Find Security Bugs

```xml
<!-- pom.xml -->
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <version>4.8.2.0</version>
  <configuration>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
        <version>1.13.0</version>
      </plugin>
    </plugins>
    <effort>Max</effort>
    <threshold>Low</threshold>
  </configuration>
</plugin>
```

```bash
# Run
mvn spotbugs:check

# Generate report
mvn spotbugs:spotbugs
```

---

## Finding Triage Workflow

### Severity Classification

```markdown
## Triage Priority Matrix

| Severity | Exploitability | Data Sensitivity | Priority |
|----------|---------------|------------------|----------|
| Critical | Easy | High | P0 - Immediate |
| High | Easy | Medium | P1 - This sprint |
| High | Difficult | High | P1 - This sprint |
| Medium | Easy | Low | P2 - Next sprint |
| Medium | Difficult | Medium | P2 - Next sprint |
| Low | Any | Any | P3 - Backlog |
```

### False Positive Identification

```markdown
## Common False Positive Patterns

### SQL Injection FPs
- Parameterized queries flagged incorrectly
- ORM methods (SQLAlchemy, Django ORM)
- Constant/hardcoded queries
- Query builders with proper escaping

### XSS FPs
- Auto-escaping template engines (Jinja2 with autoescape)
- React/Vue automatic escaping
- Server-side only code paths
- Sanitization libraries in use

### Command Injection FPs
- Hardcoded command arguments
- Validated/allowlisted inputs
- Proper escaping with shlex.quote

### Crypto FPs
- Test/development environments
- Non-sensitive data encryption
- Legacy code marked for migration
```

### Triage Decision Tree

```markdown
## Triage Process

1. **Is it reachable?**
   - Dead code? → FP
   - Test code only? → Low priority
   - Production path? → Continue

2. **Is user input involved?**
   - Hardcoded values only? → FP
   - Internal-only data? → Reduce severity
   - User-controlled? → Continue

3. **Are there mitigations?**
   - Sanitization present? → Verify effectiveness
   - WAF protection? → Defense-in-depth
   - Authentication required? → Reduce severity

4. **What's the impact?**
   - RCE possible? → Critical
   - Data breach? → High
   - DoS only? → Medium
   - Information disclosure? → Context-dependent
```

---

## Multi-Tool Orchestration

### Parallel Scanning Script

```bash
#!/bin/bash
# sast_scan.sh - Orchestrate multiple SAST tools

PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./sast-results}"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting SAST scan orchestration..."

# Run tools in parallel
(
  echo "[*] Running Semgrep..."
  semgrep --config=auto "$PROJECT_DIR" --json -o "$OUTPUT_DIR/semgrep.json" 2>/dev/null
  echo "[+] Semgrep complete"
) &

(
  echo "[*] Running Bandit..."
  bandit -r "$PROJECT_DIR" -f json -o "$OUTPUT_DIR/bandit.json" 2>/dev/null
  echo "[+] Bandit complete"
) &

(
  echo "[*] Running gitleaks..."
  gitleaks detect --source="$PROJECT_DIR" --report-path="$OUTPUT_DIR/gitleaks.json" --report-format=json 2>/dev/null
  echo "[+] Gitleaks complete"
) &

# Wait for all tools
wait

echo "[+] All scans complete. Results in $OUTPUT_DIR"
```

### Result Aggregation

```python
#!/usr/bin/env python3
"""Aggregate SAST results from multiple tools."""

import json
from pathlib import Path
from collections import defaultdict

def load_semgrep(path):
    """Parse Semgrep JSON output."""
    findings = []
    with open(path) as f:
        data = json.load(f)
    for result in data.get('results', []):
        findings.append({
            'tool': 'semgrep',
            'rule': result.get('check_id'),
            'severity': result.get('extra', {}).get('severity', 'unknown'),
            'file': result.get('path'),
            'line': result.get('start', {}).get('line'),
            'message': result.get('extra', {}).get('message'),
            'cwe': result.get('extra', {}).get('metadata', {}).get('cwe'),
        })
    return findings

def load_bandit(path):
    """Parse Bandit JSON output."""
    findings = []
    with open(path) as f:
        data = json.load(f)
    for result in data.get('results', []):
        findings.append({
            'tool': 'bandit',
            'rule': result.get('test_id'),
            'severity': result.get('issue_severity'),
            'file': result.get('filename'),
            'line': result.get('line_number'),
            'message': result.get('issue_text'),
            'cwe': result.get('issue_cwe', {}).get('id'),
        })
    return findings

def deduplicate(findings):
    """Deduplicate findings across tools."""
    seen = set()
    unique = []
    for f in findings:
        key = (f['file'], f['line'], f.get('cwe'))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def aggregate_results(results_dir):
    """Aggregate all SAST results."""
    findings = []

    semgrep_path = Path(results_dir) / 'semgrep.json'
    if semgrep_path.exists():
        findings.extend(load_semgrep(semgrep_path))

    bandit_path = Path(results_dir) / 'bandit.json'
    if bandit_path.exists():
        findings.extend(load_bandit(bandit_path))

    # Deduplicate and sort by severity
    findings = deduplicate(findings)
    severity_order = {'ERROR': 0, 'HIGH': 0, 'WARNING': 1, 'MEDIUM': 1, 'INFO': 2, 'LOW': 2}
    findings.sort(key=lambda x: severity_order.get(x['severity'].upper(), 3))

    return findings
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: SAST Scanning
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten

      - name: Run CodeQL
        uses: github/codeql-action/analyze@v3
        with:
          languages: python, javascript

      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r . -f sarif -o bandit.sarif || true

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit.sarif
```

### GitLab CI

```yaml
sast:
  stage: test
  image: python:3.11
  before_script:
    - pip install semgrep bandit
  script:
    - semgrep --config=auto . --sarif -o semgrep.sarif || true
    - bandit -r . -f sarif -o bandit.sarif || true
  artifacts:
    reports:
      sast:
        - semgrep.sarif
        - bandit.sarif
    when: always

# Language-specific jobs
semgrep:
  stage: test
  image: returntocorp/semgrep
  script:
    - semgrep ci
  variables:
    SEMGREP_RULES: "p/security-audit p/secrets"
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.52.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/secrets', '--error']

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-ll', '-ii']
        exclude: tests/

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
```

---

## Common Vulnerability Patterns

### Injection Patterns

```yaml
# Semgrep rules for common injections
rules:
  - id: sql-injection-python
    patterns:
      - pattern-either:
          - pattern: cursor.execute("..." + $VAR + "...")
          - pattern: cursor.execute(f"...{$VAR}...")
          - pattern: cursor.execute("...%s..." % $VAR)
          - pattern: cursor.execute("...{}...".format($VAR))
    message: Potential SQL injection
    languages: [python]
    severity: ERROR

  - id: command-injection-python
    patterns:
      - pattern-either:
          - pattern: os.system($CMD)
          - pattern: subprocess.call($CMD, shell=True, ...)
          - pattern: subprocess.run($CMD, shell=True, ...)
    message: Potential command injection
    languages: [python]
    severity: ERROR

  - id: xpath-injection
    patterns:
      - pattern: |
          $TREE.xpath("..." + $INPUT + "...")
    message: Potential XPath injection
    languages: [python]
    severity: ERROR
```

### Authentication/Authorization Patterns

```yaml
rules:
  - id: missing-auth-decorator
    patterns:
      - pattern: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @login_required
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @auth.required
          @app.route(...)
          def $FUNC(...):
              ...
    paths:
      exclude:
        - "**/public/**"
        - "**/health/**"
    message: Route may be missing authentication
    languages: [python]
    severity: WARNING

  - id: jwt-weak-secret
    patterns:
      - pattern: jwt.encode(..., $SECRET, ...)
      - metavariable-regex:
          metavariable: $SECRET
          regex: '".{1,20}"'
    message: JWT secret appears to be weak
    languages: [python]
    severity: WARNING
```

### Crypto Patterns

```yaml
rules:
  - id: weak-hash-algorithm
    patterns:
      - pattern-either:
          - pattern: hashlib.md5(...)
          - pattern: hashlib.sha1(...)
    message: Weak hash algorithm - use SHA-256 or better
    languages: [python]
    severity: WARNING

  - id: weak-cipher
    patterns:
      - pattern-either:
          - pattern: DES.new(...)
          - pattern: ARC4.new(...)
          - pattern: Blowfish.new(...)
    message: Weak cipher algorithm
    languages: [python]
    severity: ERROR

  - id: hardcoded-iv
    patterns:
      - pattern: AES.new(..., iv=$IV, ...)
      - metavariable-regex:
          metavariable: $IV
          regex: 'b".*"'
    message: Hardcoded IV detected - use random IV
    languages: [python]
    severity: ERROR
```

---

## Reporting Template

```markdown
# SAST Scan Report

## Executive Summary
- Scan Date: YYYY-MM-DD
- Repository: [name]
- Commit: [hash]
- Tools Used: Semgrep, CodeQL, Bandit
- Total Findings: X (Critical: Y, High: Z)

## Critical Findings

### [CRITICAL] SQL Injection in user_service.py
- **Location**: src/services/user_service.py:42
- **Tool**: Semgrep (sql-injection-format-string)
- **CWE**: CWE-89
- **Code**:
  ```python
  query = f"SELECT * FROM users WHERE id = {user_id}"
  cursor.execute(query)
  ```
- **Remediation**: Use parameterized queries
  ```python
  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  ```

## Finding Summary by Category

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Injection | 2 | 3 | 1 | 0 |
| Authentication | 0 | 2 | 4 | 1 |
| Cryptography | 1 | 1 | 2 | 0 |
| Secrets | 0 | 5 | 0 | 0 |

## Tool Coverage

| Tool | Findings | FP Rate | Coverage |
|------|----------|---------|----------|
| Semgrep | 45 | 12% | All languages |
| Bandit | 23 | 18% | Python only |
| CodeQL | 12 | 5% | Python, JS |

## Recommendations
1. [P0] Fix all SQL injection vulnerabilities immediately
2. [P1] Rotate exposed secrets and implement secret scanning
3. [P2] Upgrade weak cryptographic algorithms
4. [P3] Add authentication to unprotected endpoints
```

---

## Bundled Resources

### scripts/
- `sast_scan.sh` - Multi-tool orchestration script
- `aggregate_results.py` - Result aggregation and deduplication
- `sarif_to_csv.py` - SARIF to CSV converter

### references/
- `semgrep_rules.md` - Custom Semgrep rule reference
- `cwe_mapping.md` - CWE to tool rule mapping
- `false_positive_patterns.md` - Known FP patterns by tool

### checklists/
- `triage_checklist.md` - Finding triage checklist
- `ci_integration_checklist.md` - CI/CD setup checklist
