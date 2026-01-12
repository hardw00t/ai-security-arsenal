#!/usr/bin/env python3
"""
Nuclei Runner
Integration wrapper for Nuclei template-based vulnerability scanning.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

class NucleiRunner:
    """
    Wrapper for Nuclei vulnerability scanner integration
    Runs Nuclei against discovered endpoints and parses results
    """

    def __init__(self, targets, templates_path=None, severity=None):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.templates_path = templates_path
        self.severity = severity or ['critical', 'high', 'medium']
        self.results = []

    def run(self, output_file=None):
        """Execute Nuclei scan"""
        print(f"[*] Running Nuclei scan")
        print(f"[*] Targets: {len(self.targets)}")
        print(f"[*] Severity filters: {', '.join(self.severity)}")

        # Create temporary target file
        target_file = Path('/tmp/nuclei_targets.txt')
        with open(target_file, 'w') as f:
            for target in self.targets:
                f.write(f"{target}\n")

        # Build Nuclei command
        cmd = [
            'nuclei',
            '-l', str(target_file),
            '-severity', ','.join(self.severity),
            '-json'
        ]

        if self.templates_path:
            cmd.extend(['-t', self.templates_path])

        if output_file:
            cmd.extend(['-o', output_file])

        print(f"[*] Executing: {' '.join(cmd)}\n")

        try:
            # Run Nuclei
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )

            if result.returncode == 0:
                print("[+] Nuclei scan completed successfully")

                # Parse results
                if output_file:
                    self.parse_results(output_file)
                else:
                    self.parse_output(result.stdout)

                print(f"[+] Found {len(self.results)} vulnerabilities")
                return self.results
            else:
                print(f"[!] Nuclei scan failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print("[!] Nuclei scan timed out")
            return None
        except FileNotFoundError:
            print("[!] Nuclei not found. Install: https://github.com/projectdiscovery/nuclei")
            return None
        finally:
            # Clean up temp file
            if target_file.exists():
                target_file.unlink()

    def parse_results(self, results_file):
        """Parse Nuclei JSON results"""
        try:
            with open(results_file, 'r') as f:
                for line in f:
                    if line.strip():
                        result = json.loads(line)
                        self.results.append(self.format_finding(result))
        except Exception as e:
            print(f"[!] Error parsing results: {e}")

    def parse_output(self, output):
        """Parse Nuclei stdout"""
        for line in output.split('\n'):
            if line.strip():
                try:
                    result = json.loads(line)
                    self.results.append(self.format_finding(result))
                except:
                    pass

    def format_finding(self, nuclei_result):
        """Format Nuclei result to standard finding format"""
        return {
            'type': 'Nuclei',
            'template_id': nuclei_result.get('template-id'),
            'name': nuclei_result.get('info', {}).get('name'),
            'severity': nuclei_result.get('info', {}).get('severity', '').upper(),
            'description': nuclei_result.get('info', {}).get('description'),
            'url': nuclei_result.get('matched-at') or nuclei_result.get('host'),
            'matcher_name': nuclei_result.get('matcher-name'),
            'extracted_results': nuclei_result.get('extracted-results', []),
            'cvss_score': nuclei_result.get('info', {}).get('classification', {}).get('cvss-score'),
            'cve_id': nuclei_result.get('info', {}).get('classification', {}).get('cve-id', []),
            'cwe_id': nuclei_result.get('info', {}).get('classification', {}).get('cwe-id', []),
            'reference': nuclei_result.get('info', {}).get('reference', []),
            'remediation': nuclei_result.get('info', {}).get('remediation'),
            'curl_command': nuclei_result.get('curl-command')
        }

    def export_json(self, output_file):
        """Export results to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results exported to: {output_file}")

    def print_summary(self):
        """Print findings summary"""
        if not self.results:
            print("[*] No vulnerabilities found")
            return

        print(f"\n{'='*60}")
        print("Nuclei Scan Summary")
        print(f"{'='*60}\n")

        # Count by severity
        severity_counts = {}
        for result in self.results:
            severity = result['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print("Findings by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")

        print(f"\nTop Findings:")
        for i, result in enumerate(self.results[:10], 1):
            print(f"{i}. [{result['severity']}] {result['name']}")
            print(f"   URL: {result['url']}")
            if result.get('cve_id'):
                print(f"   CVE: {', '.join(result['cve_id'])}")
            print()

def main():
    parser = argparse.ArgumentParser(
        description="Nuclei Runner - Template-based vulnerability scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single target
  %(prog)s --target https://example.com --output nuclei_results.json

  # Scan multiple targets from file
  %(prog)s --targets targets.txt --severity critical,high --output results.json

  # Use custom templates
  %(prog)s --target https://example.com --templates /path/to/templates/ --output results.json
        """
    )

    parser.add_argument('--target', '-t', help='Single target URL')
    parser.add_argument('--targets', '-T', help='File containing target URLs (one per line)')
    parser.add_argument('--templates', help='Path to Nuclei templates directory')
    parser.add_argument('--severity', '-s', help='Severity filter (comma-separated: critical,high,medium,low,info)')
    parser.add_argument('--output', '-o', help='Output JSON file')

    args = parser.parse_args()

    # Get targets
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.targets:
        try:
            with open(args.targets, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Error: Targets file not found: {args.targets}")
            sys.exit(1)
    else:
        print("[!] Error: Either --target or --targets required")
        parser.print_help()
        sys.exit(1)

    # Parse severity
    severity = None
    if args.severity:
        severity = [s.strip().lower() for s in args.severity.split(',')]

    # Initialize runner
    runner = NucleiRunner(
        targets=targets,
        templates_path=args.templates,
        severity=severity
    )

    # Run scan
    print(f"\n{'='*60}")
    print("Nuclei Vulnerability Scanner")
    print(f"{'='*60}\n")

    results = runner.run(output_file=args.output)

    if results:
        runner.print_summary()

        if args.output:
            print(f"\n[+] Results saved to: {args.output}")
    else:
        print("\n[!] Scan failed or no results")
        sys.exit(1)

if __name__ == '__main__':
    main()
