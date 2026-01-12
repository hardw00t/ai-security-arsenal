# Tool Configuration Guide

## Playwright MCP Configuration

### Prerequisites
```bash
# Playwright should already be configured as MCP in Claude Code
# Verify configuration in Claude Code settings

# Test Playwright access:
python3 -c "import playwright; print('Playwright accessible')"
```

### Configuration for DAST

Playwright configuration is handled by Claude Code's MCP integration. No additional configuration required for basic DAST scanning.

## Nuclei Configuration

### Installation
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Or using homebrew (macOS)
brew install nuclei

# Update templates
nuclei -update-templates
```

### Configuration
```bash
# Create config file: ~/.config/nuclei/config.yaml
templates:
  - /path/to/nuclei-templates/

rate-limit: 150  # requests per second
bulk-size: 25
concurrency: 10
timeout: 5
retries: 1

# Integration with DAST:
nuclei -l discovered_urls.txt -t nuclei-templates/ -o results.json -json
```

## OWASP ZAP Configuration (Optional)

### Installation
```bash
# Download from: https://www.zaproxy.org/download/

# Or docker:
docker pull owasp/zap2docker-stable
```

### Proxy Configuration
```bash
# Start ZAP API
zap.sh -daemon -port 8080 -config api.key=your-api-key

# Configure Playwright to use ZAP proxy:
const browser = await chromium.launch({
    proxy: {
        server: 'http://localhost:8080'
    }
})
```

### Integration
```python
# Use ZAP API for active scanning
import zapv2

zap = zapv2.ZAP(apikey='your-api-key', proxies={'http': 'http://127.0.0.1:8080'})

# Spider the site
zap.spider.scan(target_url)

# Active scan
zap.ascan.scan(target_url)

# Get results
alerts = zap.core.alerts()
```

## Nikto Configuration (Optional)

### Installation
```bash
# Install Nikto
git clone https://github.com/sullo/nikto
cd nikto/program
./nikto.pl -update

# Or package manager:
apt-get install nikto  # Debian/Ubuntu
brew install nikto  # macOS
```

### Usage
```bash
# Basic scan
nikto -h https://target.com -output results.json -Format json

# With authentication
nikto -h https://target.com -id username:password

# Integration with DAST:
nikto -h https://target.com -output nikto_results.json -Format json
```

## Environment Setup

### Project Structure
```
dast-automation/
├── config/
│   ├── scanning.yaml
│   ├── scope.yaml
│   └── profiles/
│       ├── api-focused.yaml
│       └── web-focused.yaml
├── scripts/
├── results/
└── payloads/
```

### Configuration Files

**config/scanning.yaml:**
```yaml
playwright:
  headless: true
  timeout: 30000
  viewport:
    width: 1920
    height: 1080

crawling:
  max_depth: 3
  max_urls: 500
  javascript_timeout: 30000
  respect_robots_txt: true

rate_limiting:
  requests_per_second: 5
  concurrent_requests: 3

testing:
  xss_payloads_count: 10
  sqli_payloads_count: 8
  timeout_delay: 5
```

**config/scope.yaml:**
```yaml
in_scope:
  - "*.example.com"
  - "api.example.com"

out_of_scope:
  - "logout"
  - "delete-account"
  - "admin.example.com/dangerous"

exclusions:
  paths:
    - "/logout"
    - "/delete/*"
    - "/api/admin/delete"
  parameters:
    - "csrf_token"
    - "_method"
```

**config/profiles/api-focused.yaml:**
```yaml
name: "API-Focused Testing"
description: "Optimized for REST/GraphQL API testing"

playwright:
  crawl_depth: 5
  capture_api_calls: true

tests:
  enabled:
    - api_authentication
    - api_authorization
    - api_injection
    - api_rate_limiting
  disabled:
    - dom_xss
    - clickjacking

reporting:
  format: json
```

## CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/dast.yml
name: DAST Security Scan

on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install Dependencies
        run: |
          pip install playwright
          playwright install chromium

      - name: Run DAST Scan
        run: |
          python3 scripts/playwright_dast_scanner.py \
            --target ${{ secrets.STAGING_URL }} \
            --mode blackbox \
            --output results/dast-report.json

      - name: Check Findings
        run: |
          python3 scripts/check_findings.py \
            --report results/dast-report.json \
            --fail-on critical,high

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: dast-report
          path: results/
```

### GitLab CI
```yaml
# .gitlab-ci.yml
dast_scan:
  stage: test
  image: python:3.9
  before_script:
    - pip install playwright
    - playwright install chromium
  script:
    - python3 scripts/playwright_dast_scanner.py --target $STAGING_URL --output results.json
    - python3 scripts/check_findings.py --report results.json --fail-on critical,high
  artifacts:
    paths:
      - results/
    when: always
  only:
    - schedules
```

## Alert Configuration

### Email Alerts
```bash
# Install mail utility
apt-get install mailutils

# Configure in continuous_dast.sh:
export ALERT_EMAIL="security@example.com"

# Or use dedicated email service:
python3 scripts/send_alert.py \
  --to security@example.com \
  --subject "DAST Findings" \
  --report results/report.json
```

### Slack Integration
```bash
# Configure Slack webhook
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Send notification
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"DAST scan found 3 critical issues"}' \
  $SLACK_WEBHOOK
```

## Performance Tuning

### Optimize Crawling
```yaml
# Fast scan (less thorough)
crawling:
  max_depth: 2
  max_urls: 200
  javascript_timeout: 10000

# Deep scan (more thorough)
crawling:
  max_depth: 5
  max_urls: 2000
  javascript_timeout: 60000
```

### Resource Management
```yaml
# Parallel scans
orchestration:
  max_parallel: 5  # Conservative
  max_parallel: 10  # Aggressive (requires more resources)

# Browser instances
playwright:
  max_contexts: 5
  reuse_contexts: true
```

## Troubleshooting

### Playwright Issues
```bash
# Permission denied
chmod +x scripts/*.py

# Browser not found
playwright install chromium

# Timeout issues
# Increase timeout in config:
playwright:
  timeout: 60000
```

### Nuclei Issues
```bash
# Templates not found
nuclei -update-templates

# Rate limiting
# Reduce rate in config:
rate-limit: 50  # Lower value
```

### Memory Issues
```bash
# Reduce concurrent operations:
orchestration:
  max_parallel: 2

playwright:
  max_contexts: 2
```

## Security Best Practices

### Credential Storage
```bash
# Use environment variables
export DAST_USERNAME="testuser"
export DAST_PASSWORD="testpass"

# Or .env file (add to .gitignore)
DAST_USERNAME=testuser
DAST_PASSWORD=testpass

# Never commit credentials to git
echo ".env" >> .gitignore
echo "config/credentials.yaml" >> .gitignore
```

### Report Security
```bash
# Encrypt sensitive reports
gpg --encrypt --recipient security@example.com report.json

# Secure storage
chmod 600 results/*.json
chown $USER:$USER results/
```

## Recommended Setup

### Development Environment
```bash
1. Clone skill repository
2. Install dependencies:
   pip install playwright requests pyyaml
   playwright install chromium
3. Install Nuclei (optional)
4. Configure scope in config/scope.yaml
5. Run test scan:
   python3 scripts/playwright_dast_scanner.py \
     --target http://testphp.vulnweb.com \
     --mode blackbox \
     --output test-results.json
```

### Production Environment
```bash
1. Dedicated scanning server (isolated)
2. Scheduled scans (cron/CI)
3. Alert configuration (email/Slack)
4. Baseline management
5. Regular template updates
6. Security review of configurations
```

This completes the tool configuration guide for DAST automation.
