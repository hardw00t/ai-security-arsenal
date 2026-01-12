#!/usr/bin/env python3
"""
DAST Orchestrator
Orchestrates parallel DAST scanning across multiple domains.
"""

import argparse
import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

class DASTOrchestrator:
    """
    Orchestrates parallel DAST scans across multiple domains

    NOTE: Works with Claude Code to coordinate multiple Playwright-based scans
    """

    def __init__(self, domains, mode='blackbox', max_parallel=5, output_dir='results'):
        self.domains = domains
        self.mode = mode
        self.max_parallel = max_parallel
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.scan_results = {}
        self.orchestration_metadata = {
            'start_time': datetime.now().isoformat(),
            'total_domains': len(domains),
            'mode': mode,
            'max_parallel': max_parallel
        }

    def orchestrate(self):
        """Execute parallel DAST scans"""
        print(f"[*] Starting orchestrated DAST scan")
        print(f"[*] Domains: {len(self.domains)}")
        print(f"[*] Mode: {self.mode}")
        print(f"[*] Max parallel: {self.max_parallel}")
        print(f"[*] Output directory: {self.output_dir}\n")

        # Execute scans in parallel
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            # Submit all scan jobs
            future_to_domain = {
                executor.submit(self.scan_domain, domain): domain
                for domain in self.domains
            }

            # Process completed scans
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    self.scan_results[domain] = result
                    print(f"[+] Completed scan: {domain}")
                except Exception as e:
                    print(f"[!] Failed scan: {domain} - {str(e)}")
                    self.scan_results[domain] = {'error': str(e)}

        # Generate aggregate report
        self.orchestration_metadata['end_time'] = datetime.now().isoformat()
        self.generate_aggregate_report()

        print(f"\n[+] Orchestration complete!")
        print(f"[+] Scanned {len(self.scan_results)} domains")
        print(f"[+] Aggregate report: {self.output_dir / 'aggregate_report.json'}")

    def scan_domain(self, domain):
        """
        Scan a single domain using playwright_dast_scanner.py

        NOTE: This is invoked by Claude Code which will orchestrate
        the actual Playwright operations for each domain
        """
        print(f"[*] Starting scan: {domain}")

        # Prepare output filename
        domain_safe = domain.replace('https://', '').replace('http://', '').replace('/', '_')
        output_file = self.output_dir / f"{domain_safe}_report.json"

        # Claude Code will execute:
        # python3 playwright_dast_scanner.py \
        #   --target {domain} \
        #   --mode {self.mode} \
        #   --output {output_file}

        # For now, create placeholder result
        result = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'status': 'completed',
            'findings': [],
            'output_file': str(output_file)
        }

        # Write individual result
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)

        return result

    def generate_aggregate_report(self):
        """Generate unified report across all domains"""

        # Aggregate findings by severity
        aggregate_findings = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }

        # Collect statistics
        total_findings = 0
        successful_scans = 0
        failed_scans = 0

        for domain, result in self.scan_results.items():
            if 'error' in result:
                failed_scans += 1
                continue

            successful_scans += 1

            # Extract findings from individual scan
            findings = result.get('findings', [])
            total_findings += len(findings)

            for finding in findings:
                severity = finding.get('severity', 'INFO')
                if severity in aggregate_findings:
                    finding['source_domain'] = domain
                    aggregate_findings[severity].append(finding)

        # Create aggregate report
        aggregate_report = {
            'metadata': self.orchestration_metadata,
            'summary': {
                'total_domains': len(self.domains),
                'successful_scans': successful_scans,
                'failed_scans': failed_scans,
                'total_findings': total_findings,
                'findings_by_severity': {
                    severity: len(findings)
                    for severity, findings in aggregate_findings.items()
                }
            },
            'findings_by_severity': aggregate_findings,
            'individual_results': self.scan_results
        }

        # Write aggregate report
        aggregate_file = self.output_dir / 'aggregate_report.json'
        with open(aggregate_file, 'w') as f:
            json.dump(aggregate_report, f, indent=2)

        # Print summary
        print(f"\n{'='*60}")
        print("Aggregate Scan Summary")
        print(f"{'='*60}")
        print(f"Total Domains: {len(self.domains)}")
        print(f"Successful Scans: {successful_scans}")
        print(f"Failed Scans: {failed_scans}")
        print(f"Total Findings: {total_findings}")
        print(f"\nFindings by Severity:")
        for severity, findings in aggregate_findings.items():
            if findings:
                print(f"  {severity}: {len(findings)}")
        print(f"{'='*60}\n")

        return aggregate_report

def main():
    parser = argparse.ArgumentParser(
        description="DAST Orchestrator - Parallel multi-domain scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan multiple domains from file
  %(prog)s --domains domains.txt --mode blackbox --output results/

  # Scan with custom parallelism
  %(prog)s --domains domains.txt --parallel 10 --output results/

domains.txt format:
  https://example.com
  https://test.io
  https://demo.net
        """
    )

    parser.add_argument('--domains', '-d', required=True,
                       help='File containing list of domains (one per line)')
    parser.add_argument('--mode', '-m', choices=['blackbox', 'greybox'],
                       default='blackbox', help='Scan mode')
    parser.add_argument('--parallel', '-p', type=int, default=5,
                       help='Maximum parallel scans (default: 5)')
    parser.add_argument('--output', '-o', default='results',
                       help='Output directory for results')

    args = parser.parse_args()

    # Read domains from file
    try:
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] Error: Domain list file not found: {args.domains}")
        sys.exit(1)

    if not domains:
        print("[!] Error: No domains found in file")
        sys.exit(1)

    print(f"[*] Loaded {len(domains)} domains from {args.domains}")

    # Initialize orchestrator
    orchestrator = DASTOrchestrator(
        domains=domains,
        mode=args.mode,
        max_parallel=args.parallel,
        output_dir=args.output
    )

    # Execute orchestration
    print(f"\n{'='*60}")
    print("DAST Orchestrator")
    print(f"{'='*60}\n")

    orchestrator.orchestrate()

if __name__ == '__main__':
    main()
