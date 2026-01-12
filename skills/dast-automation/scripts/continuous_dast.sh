#!/bin/bash
#
# Continuous DAST Scanner
# Wrapper script for scheduled/continuous security scanning
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-${SCRIPT_DIR}/../results/continuous}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat <<EOF
Usage: $0 --target <URL> [options]

Continuous DAST scanning wrapper for scheduled security testing.

Required:
    --target <URL>          Target URL to scan

Optional:
    --mode <blackbox|greybox>   Scan mode (default: blackbox)
    --baseline <file>       Baseline results for comparison
    --email <address>       Email address for alerts
    --slack <webhook>       Slack webhook URL for notifications
    --fail-on <severity>    Fail on severity levels (default: critical)
    --output-dir <dir>      Output directory (default: results/continuous)

Examples:
    # Basic continuous scan
    $0 --target https://example.com

    # With email alerts
    $0 --target https://example.com --email security@example.com

    # With baseline comparison
    $0 --target https://example.com --baseline baseline.json --email alerts@example.com

Cron example (daily at 2 AM):
    0 2 * * * /path/to/continuous_dast.sh --target https://example.com --email alerts@example.com

EOF
    exit 1
}

send_email_alert() {
    local subject="$1"
    local body="$2"

    if [ -n "$ALERT_EMAIL" ]; then
        log_info "Sending email alert to $ALERT_EMAIL"
        echo "$body" | mail -s "$subject" "$ALERT_EMAIL" || log_warn "Failed to send email"
    fi
}

send_slack_alert() {
    local message="$1"

    if [ -n "$SLACK_WEBHOOK" ]; then
        log_info "Sending Slack notification"
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK" || log_warn "Failed to send Slack notification"
    fi
}

# Parse arguments
TARGET=""
MODE="blackbox"
BASELINE=""
FAIL_ON="critical"

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --baseline)
            BASELINE="$2"
            shift 2
            ;;
        --email)
            ALERT_EMAIL="$2"
            shift 2
            ;;
        --slack)
            SLACK_WEBHOOK="$2"
            shift 2
            ;;
        --fail-on)
            FAIL_ON="$2"
            shift 2
            ;;
        --output-dir)
            RESULTS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [ -z "$TARGET" ]; then
    log_error "Target URL is required"
    usage
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

# Generate output filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||' | tr '/' '_')
OUTPUT_FILE="${RESULTS_DIR}/${DOMAIN}_${TIMESTAMP}.json"
REPORT_FILE="${RESULTS_DIR}/${DOMAIN}_${TIMESTAMP}.html"

log_info "Starting continuous DAST scan"
log_info "Target: $TARGET"
log_info "Mode: $MODE"
log_info "Output: $OUTPUT_FILE"

# Run DAST scan
log_info "Executing scan..."

if python3 "${SCRIPT_DIR}/playwright_dast_scanner.py" \
    --target "$TARGET" \
    --mode "$MODE" \
    --output "$OUTPUT_FILE"; then

    log_info "Scan completed successfully"

    # Generate HTML report
    python3 "${SCRIPT_DIR}/report_generator.py" \
        --input "$OUTPUT_FILE" \
        --format html \
        --output "$REPORT_FILE"

    # Check findings
    if python3 "${SCRIPT_DIR}/check_findings.py" \
        --report "$OUTPUT_FILE" \
        --fail-on "$FAIL_ON"; then

        log_info "No critical issues found"

        # Send success notification
        MESSAGE="DAST Scan PASSED for $TARGET at $(date)"
        send_slack_alert "$MESSAGE"

        exit 0
    else
        log_error "Critical issues found!"

        # Extract summary
        SUMMARY=$(python3 -c "
import json
with open('$OUTPUT_FILE', 'r') as f:
    data = json.load(f)
    summary = data.get('metadata', {}).get('summary', {})
    print(f\"Critical: {summary.get('CRITICAL', 0)}, High: {summary.get('HIGH', 0)}, Medium: {summary.get('MEDIUM', 0)}\")
" 2>/dev/null || echo "Failed to parse summary")

        # Send alert
        SUBJECT="CRITICAL: DAST Scan Found Security Issues - $TARGET"
        BODY="DAST scan found critical security issues at $TARGET

Summary: $SUMMARY

Report: $REPORT_FILE
Results: $OUTPUT_FILE

Scan timestamp: $(date)
"

        send_email_alert "$SUBJECT" "$BODY"
        send_slack_alert "🚨 CRITICAL: DAST Scan found security issues in $TARGET - $SUMMARY"

        exit 1
    fi
else
    log_error "Scan failed"

    # Send failure notification
    SUBJECT="ERROR: DAST Scan Failed - $TARGET"
    BODY="DAST scan failed for $TARGET at $(date)

Check logs for details.
"

    send_email_alert "$SUBJECT" "$BODY"
    send_slack_alert "❌ ERROR: DAST Scan failed for $TARGET"

    exit 2
fi
