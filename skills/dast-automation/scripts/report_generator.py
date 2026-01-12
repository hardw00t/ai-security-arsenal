#!/usr/bin/env python3
"""
DAST Report Generator
Generates comprehensive security reports in multiple formats (JSON, HTML, Markdown, PDF).
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

class DASTReportGenerator:
    """
    Generate comprehensive DAST reports in multiple formats
    """

    def __init__(self, scan_results_file):
        self.results_file = Path(scan_results_file)
        self.results = self.load_results()

        if not self.results:
            raise ValueError(f"Could not load results from {scan_results_file}")

    def load_results(self):
        """Load scan results from JSON"""
        try:
            with open(self.results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading results: {e}")
            return None

    def generate_html(self, output_file):
        """Generate HTML report"""
        metadata = self.results.get('metadata', {})
        findings = self.results.get('findings', [])
        summary = metadata.get('summary', {})

        # HTML template
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DAST Security Assessment Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .metadata {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .severity-box {{
            padding: 20px;
            text-align: center;
            border-radius: 5px;
            color: white;
            font-weight: bold;
        }}
        .critical {{ background-color: #c0392b; }}
        .high {{ background-color: #e74c3c; }}
        .medium {{ background-color: #f39c12; }}
        .low {{ background-color: #3498db; }}
        .info {{ background-color: #95a5a6; }}
        .finding {{
            border-left: 4px solid;
            padding: 15px;
            margin: 15px 0;
            background: #f8f9fa;
            border-radius: 4px;
        }}
        .finding.critical {{ border-color: #c0392b; }}
        .finding.high {{ border-color: #e74c3c; }}
        .finding.medium {{ border-color: #f39c12; }}
        .finding.low {{ border-color: #3498db; }}
        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .finding-meta {{
            color: #7f8c8d;
            margin: 5px 0;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        .remediation {{
            background: #d5f4e6;
            border-left: 4px solid #27ae60;
            padding: 10px;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DAST Security Assessment Report</h1>

        <div class="metadata">
            <strong>Target:</strong> {metadata.get('target', 'N/A')}<br>
            <strong>Scan Date:</strong> {metadata.get('start_time', 'N/A')}<br>
            <strong>Duration:</strong> {metadata.get('duration', 'N/A')}<br>
            <strong>Mode:</strong> {metadata.get('mode', 'N/A').upper()}<br>
            <strong>Scanner:</strong> {metadata.get('scanner', 'N/A')}
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="severity-box critical">
                <div style="font-size: 2em;">{summary.get('CRITICAL', 0)}</div>
                <div>CRITICAL</div>
            </div>
            <div class="severity-box high">
                <div style="font-size: 2em;">{summary.get('HIGH', 0)}</div>
                <div>HIGH</div>
            </div>
            <div class="severity-box medium">
                <div style="font-size: 2em;">{summary.get('MEDIUM', 0)}</div>
                <div>MEDIUM</div>
            </div>
            <div class="severity-box low">
                <div style="font-size: 2em;">{summary.get('LOW', 0)}</div>
                <div>LOW</div>
            </div>
            <div class="severity-box info">
                <div style="font-size: 2em;">{summary.get('INFO', 0)}</div>
                <div>INFO</div>
            </div>
        </div>

        <h2>Findings</h2>
"""

        # Add findings
        if not findings:
            html += '<p><em>No vulnerabilities found.</em></p>'
        else:
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            findings_sorted = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 99))

            for finding in findings_sorted:
                severity = finding.get('severity', 'INFO').lower()
                html += f"""
        <div class="finding {severity}">
            <div class="finding-title">
                [{finding.get('severity', 'INFO')}] {finding.get('type', 'Unknown')} - {finding.get('description', 'No description')}
            </div>
            <div class="finding-meta">
                <strong>URL:</strong> {finding.get('url', 'N/A')}<br>
"""
                if finding.get('parameter'):
                    html += f"                <strong>Parameter:</strong> {finding['parameter']}<br>\n"

                if finding.get('payload'):
                    html += f"""                <strong>Payload:</strong> <code>{finding['payload']}</code><br>
"""

                if finding.get('evidence'):
                    html += f"""            </div>
            <div style="margin-top: 10px;">
                <strong>Evidence:</strong><br>
                <pre>{finding['evidence']}</pre>
            </div>
"""
                else:
                    html += "            </div>\n"

                if finding.get('remediation'):
                    html += f"""            <div class="remediation">
                <strong>Remediation:</strong><br>
                {finding['remediation']}
            </div>
"""

                html += "        </div>\n"

        html += """    </div>
</body>
</html>"""

        # Write HTML file
        with open(output_file, 'w') as f:
            f.write(html)

        print(f"[+] HTML report generated: {output_file}")

    def generate_markdown(self, output_file):
        """Generate Markdown report"""
        metadata = self.results.get('metadata', {})
        findings = self.results.get('findings', [])
        summary = metadata.get('summary', {})

        md = f"""# DAST Security Assessment Report

## Scan Information

- **Target**: {metadata.get('target', 'N/A')}
- **Scan Date**: {metadata.get('start_time', 'N/A')}
- **Duration**: {metadata.get('duration', 'N/A')}
- **Mode**: {metadata.get('mode', 'N/A').upper()}
- **Scanner**: {metadata.get('scanner', 'N/A')}

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {summary.get('CRITICAL', 0)} |
| HIGH     | {summary.get('HIGH', 0)} |
| MEDIUM   | {summary.get('MEDIUM', 0)} |
| LOW      | {summary.get('LOW', 0)} |
| INFO     | {summary.get('INFO', 0)} |

## Findings

"""

        if not findings:
            md += '*No vulnerabilities found.*\n'
        else:
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            findings_sorted = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 99))

            for i, finding in enumerate(findings_sorted, 1):
                md += f"""### {i}. [{finding.get('severity', 'INFO')}] {finding.get('type', 'Unknown')}

**Description**: {finding.get('description', 'No description')}

**URL**: {finding.get('url', 'N/A')}

"""
                if finding.get('parameter'):
                    md += f"**Parameter**: `{finding['parameter']}`\n\n"

                if finding.get('payload'):
                    md += f"**Payload**:\n```\n{finding['payload']}\n```\n\n"

                if finding.get('evidence'):
                    md += f"**Evidence**:\n```\n{finding['evidence']}\n```\n\n"

                if finding.get('remediation'):
                    md += f"**Remediation**: {finding['remediation']}\n\n"

                md += "---\n\n"

        # Write Markdown file
        with open(output_file, 'w') as f:
            f.write(md)

        print(f"[+] Markdown report generated: {output_file}")

    def generate_json(self, output_file):
        """Generate JSON report (already in JSON, but formatted nicely)"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"[+] JSON report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="DAST Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate HTML report
  %(prog)s --input scan_results.json --format html --output report.html

  # Generate all formats
  %(prog)s --input scan_results.json --format all --output-dir reports/
        """
    )

    parser.add_argument('--input', '-i', required=True, help='Input JSON scan results')
    parser.add_argument('--format', '-f', choices=['html', 'markdown', 'json', 'all'],
                       default='html', help='Report format')
    parser.add_argument('--output', '-o', help='Output file (for single format)')
    parser.add_argument('--output-dir', help='Output directory (for all formats)')

    args = parser.parse_args()

    # Load results
    try:
        generator = DASTReportGenerator(args.input)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("DAST Report Generator")
    print(f"{'='*60}\n")

    # Generate reports
    if args.format == 'all':
        # Generate all formats
        output_dir = Path(args.output_dir or 'reports')
        output_dir.mkdir(parents=True, exist_ok=True)

        base_name = Path(args.input).stem

        generator.generate_html(output_dir / f"{base_name}.html")
        generator.generate_markdown(output_dir / f"{base_name}.md")
        generator.generate_json(output_dir / f"{base_name}.json")

        print(f"\n[+] All reports generated in: {output_dir}")
    else:
        # Generate single format
        if not args.output:
            print("[!] Error: --output required for single format")
            sys.exit(1)

        if args.format == 'html':
            generator.generate_html(args.output)
        elif args.format == 'markdown':
            generator.generate_markdown(args.output)
        elif args.format == 'json':
            generator.generate_json(args.output)

if __name__ == '__main__':
    main()
