#!/usr/bin/env python3
"""
Findings Checker
CI/CD integration script to check scan results and fail builds on critical findings.
"""

import argparse
import json
import sys
from pathlib import Path

class FindingsChecker:
    """
    Check DAST scan findings and enforce severity thresholds for CI/CD
    """

    def __init__(self, results_file, fail_on=None):
        self.results_file = Path(results_file)
        self.fail_on = fail_on or ['critical']
        self.results = self.load_results()

    def load_results(self):
        """Load scan results"""
        try:
            with open(self.results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading results: {e}")
            sys.exit(1)

    def check(self):
        """Check findings against fail criteria"""
        findings = self.results.get('findings', [])
        summary = self.results.get('metadata', {}).get('summary', {})

        print(f"[*] Checking findings from: {self.results_file}")
        print(f"[*] Fail criteria: {', '.join(self.fail_on).upper()}\n")

        # Count findings by severity
        print("Findings Summary:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = summary.get(severity, 0)
            print(f"  {severity}: {count}")

        # Check if we should fail
        should_fail = False
        failing_findings = []

        for finding in findings:
            severity = finding.get('severity', '').lower()
            if severity in self.fail_on:
                should_fail = True
                failing_findings.append(finding)

        if should_fail:
            print(f"\n[!] FAILURE: Found {len(failing_findings)} findings matching fail criteria\n")

            print("Failing Findings:")
            for i, finding in enumerate(failing_findings, 1):
                print(f"\n{i}. [{finding.get('severity')}] {finding.get('type')}")
                print(f"   URL: {finding.get('url')}")
                print(f"   Description: {finding.get('description')}")

            return False
        else:
            print(f"\n[+] SUCCESS: No findings matching fail criteria")
            return True

    def export_summary(self, output_file):
        """Export findings summary for CI/CD"""
        summary = self.results.get('metadata', {}).get('summary', {})

        ci_summary = {
            'status': 'pass' if self.check() else 'fail',
            'total_findings': sum(summary.values()),
            'severity_counts': summary,
            'fail_criteria': self.fail_on
        }

        with open(output_file, 'w') as f:
            json.dump(ci_summary, f, indent=2)

        print(f"\n[+] CI summary exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="DAST Findings Checker for CI/CD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fail on critical findings only
  %(prog)s --report scan_results.json --fail-on critical

  # Fail on critical and high
  %(prog)s --report scan_results.json --fail-on critical,high

  # Check and export CI summary
  %(prog)s --report scan_results.json --fail-on critical,high --ci-summary summary.json
        """
    )

    parser.add_argument('--report', '-r', required=True, help='Scan results JSON file')
    parser.add_argument('--fail-on', help='Comma-separated severity levels to fail on (default: critical)')
    parser.add_argument('--ci-summary', help='Export CI summary to file')

    args = parser.parse_args()

    # Parse fail criteria
    fail_on = ['critical']
    if args.fail_on:
        fail_on = [s.strip().lower() for s in args.fail_on.split(',')]

    print(f"\n{'='*60}")
    print("DAST Findings Checker")
    print(f"{'='*60}\n")

    # Initialize checker
    checker = FindingsChecker(
        results_file=args.report,
        fail_on=fail_on
    )

    # Check findings
    passed = checker.check()

    # Export CI summary if requested
    if args.ci_summary:
        checker.export_summary(args.ci_summary)

    # Exit with appropriate code
    if passed:
        print("\n[+] Check PASSED")
        sys.exit(0)
    else:
        print("\n[!] Check FAILED")
        sys.exit(1)

if __name__ == '__main__':
    main()
