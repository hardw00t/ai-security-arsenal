#!/usr/bin/env python3
"""
SAST Scanner - Multi-tool Static Application Security Testing
Orchestrates Semgrep, secret detection, and dependency scanning
"""

import argparse
import json
import subprocess
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


class SASTScanner:
    def __init__(self, path: str, output_dir: str = "sast_results", verbose: bool = False):
        self.path = Path(path).resolve()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.findings = []
        self.languages_detected = set()

    def log(self, message: str, level: str = "INFO"):
        if self.verbose or level in ["ERROR", "WARNING"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")

    def detect_languages(self) -> set:
        """Detect programming languages in the codebase"""
        extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.kt': 'kotlin',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.swift': 'swift',
            '.rs': 'rust',
            '.scala': 'scala',
        }

        for file_path in self.path.rglob('*'):
            if file_path.is_file():
                ext = file_path.suffix.lower()
                if ext in extensions:
                    self.languages_detected.add(extensions[ext])

        self.log(f"Detected languages: {', '.join(self.languages_detected)}")
        return self.languages_detected

    def run_semgrep(self, configs: List[str] = None) -> Dict:
        """Run Semgrep security scan"""
        self.log("Starting Semgrep scan...")

        if configs is None:
            configs = ['auto', 'p/security-audit', 'p/secrets']

        config_args = []
        for config in configs:
            config_args.extend(['--config', config])

        output_file = self.output_dir / "semgrep_results.json"

        cmd = [
            'semgrep', 'scan',
            *config_args,
            '--json',
            '-o', str(output_file),
            str(self.path)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)

                findings_count = len(data.get('results', []))
                errors_count = len(data.get('errors', []))

                self.log(f"Semgrep found {findings_count} issues, {errors_count} errors")

                # Add to findings
                for result in data.get('results', []):
                    self.findings.append({
                        'tool': 'semgrep',
                        'rule_id': result.get('check_id'),
                        'severity': self._map_severity(result.get('extra', {}).get('severity', 'INFO')),
                        'message': result.get('extra', {}).get('message', ''),
                        'file': result.get('path'),
                        'line': result.get('start', {}).get('line'),
                        'code': result.get('extra', {}).get('lines', ''),
                        'metadata': result.get('extra', {}).get('metadata', {})
                    })

                return data

        except subprocess.TimeoutExpired:
            self.log("Semgrep scan timed out", "ERROR")
        except Exception as e:
            self.log(f"Semgrep scan failed: {e}", "ERROR")

        return {}

    def run_gitleaks(self) -> Dict:
        """Run Gitleaks secret detection"""
        self.log("Starting Gitleaks scan...")

        output_file = self.output_dir / "gitleaks_results.json"

        cmd = [
            'gitleaks', 'detect',
            '--source', str(self.path),
            '--report-path', str(output_file),
            '--report-format', 'json'
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)

                findings_count = len(data) if isinstance(data, list) else 0
                self.log(f"Gitleaks found {findings_count} secrets")

                # Add to findings
                if isinstance(data, list):
                    for secret in data:
                        self.findings.append({
                            'tool': 'gitleaks',
                            'rule_id': secret.get('RuleID'),
                            'severity': 'HIGH',
                            'message': f"Secret detected: {secret.get('Description', '')}",
                            'file': secret.get('File'),
                            'line': secret.get('StartLine'),
                            'code': secret.get('Secret', '')[:20] + '...',  # Truncate secret
                            'metadata': {
                                'entropy': secret.get('Entropy'),
                                'commit': secret.get('Commit')
                            }
                        })

                return {'findings': data}

        except FileNotFoundError:
            self.log("Gitleaks not installed, skipping", "WARNING")
        except Exception as e:
            self.log(f"Gitleaks scan failed: {e}", "ERROR")

        return {}

    def run_bandit(self) -> Dict:
        """Run Bandit for Python security"""
        if 'python' not in self.languages_detected:
            return {}

        self.log("Starting Bandit scan...")

        output_file = self.output_dir / "bandit_results.json"

        cmd = [
            'bandit',
            '-r', str(self.path),
            '-f', 'json',
            '-o', str(output_file),
            '--ignore-nosec'
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)

                findings_count = len(data.get('results', []))
                self.log(f"Bandit found {findings_count} issues")

                for result in data.get('results', []):
                    self.findings.append({
                        'tool': 'bandit',
                        'rule_id': result.get('test_id'),
                        'severity': self._map_severity(result.get('issue_severity', 'LOW')),
                        'message': result.get('issue_text'),
                        'file': result.get('filename'),
                        'line': result.get('line_number'),
                        'code': result.get('code'),
                        'metadata': {
                            'confidence': result.get('issue_confidence'),
                            'cwe': result.get('issue_cwe', {})
                        }
                    })

                return data

        except FileNotFoundError:
            self.log("Bandit not installed, skipping", "WARNING")
        except Exception as e:
            self.log(f"Bandit scan failed: {e}", "ERROR")

        return {}

    def run_npm_audit(self) -> Dict:
        """Run npm audit for JavaScript dependencies"""
        package_json = self.path / "package.json"
        if not package_json.exists():
            return {}

        self.log("Starting npm audit...")

        output_file = self.output_dir / "npm_audit_results.json"

        cmd = ['npm', 'audit', '--json']

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.path)
            )

            data = json.loads(result.stdout) if result.stdout else {}

            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)

            vulnerabilities = data.get('vulnerabilities', {})
            self.log(f"npm audit found {len(vulnerabilities)} vulnerable packages")

            for pkg_name, vuln in vulnerabilities.items():
                self.findings.append({
                    'tool': 'npm_audit',
                    'rule_id': 'vulnerable-dependency',
                    'severity': self._map_severity(vuln.get('severity', 'low')),
                    'message': f"Vulnerable package: {pkg_name}",
                    'file': 'package.json',
                    'line': None,
                    'code': None,
                    'metadata': {
                        'package': pkg_name,
                        'via': vuln.get('via'),
                        'fixAvailable': vuln.get('fixAvailable')
                    }
                })

            return data

        except FileNotFoundError:
            self.log("npm not installed, skipping", "WARNING")
        except Exception as e:
            self.log(f"npm audit failed: {e}", "ERROR")

        return {}

    def run_pip_audit(self) -> Dict:
        """Run pip-audit for Python dependencies"""
        requirements = self.path / "requirements.txt"
        if not requirements.exists() and 'python' not in self.languages_detected:
            return {}

        self.log("Starting pip-audit...")

        output_file = self.output_dir / "pip_audit_results.json"

        cmd = ['pip-audit', '--format', 'json', '-r', str(requirements)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout:
                data = json.loads(result.stdout)

                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)

                self.log(f"pip-audit found {len(data)} vulnerable packages")

                for vuln in data:
                    self.findings.append({
                        'tool': 'pip_audit',
                        'rule_id': vuln.get('id', 'vulnerable-dependency'),
                        'severity': 'HIGH',
                        'message': f"Vulnerable package: {vuln.get('name')} {vuln.get('version')}",
                        'file': 'requirements.txt',
                        'line': None,
                        'code': None,
                        'metadata': {
                            'package': vuln.get('name'),
                            'version': vuln.get('version'),
                            'fix_versions': vuln.get('fix_versions'),
                            'cve': vuln.get('id')
                        }
                    })

                return {'vulnerabilities': data}

        except FileNotFoundError:
            self.log("pip-audit not installed, skipping", "WARNING")
        except Exception as e:
            self.log(f"pip-audit failed: {e}", "ERROR")

        return {}

    def _map_severity(self, severity: str) -> str:
        """Map tool-specific severity to standard levels"""
        severity = severity.upper()
        mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'MODERATE': 'MEDIUM',
            'LOW': 'LOW',
            'INFO': 'INFO',
            'WARNING': 'MEDIUM',
            'ERROR': 'HIGH'
        }
        return mapping.get(severity, 'INFO')

    def generate_summary(self) -> Dict:
        """Generate summary of all findings"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        tool_counts = {}

        for finding in self.findings:
            severity = finding.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            tool = finding.get('tool', 'unknown')
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        return {
            'scan_path': str(self.path),
            'scan_time': datetime.now().isoformat(),
            'languages_detected': list(self.languages_detected),
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'tool_counts': tool_counts,
            'findings': self.findings
        }

    def run_full_scan(self) -> Dict:
        """Run complete SAST scan"""
        self.log(f"Starting SAST scan on {self.path}")
        start_time = datetime.now()

        # Detect languages
        self.detect_languages()

        # Run scans in parallel where possible
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.run_semgrep): 'semgrep',
                executor.submit(self.run_gitleaks): 'gitleaks',
                executor.submit(self.run_bandit): 'bandit',
                executor.submit(self.run_npm_audit): 'npm_audit',
                executor.submit(self.run_pip_audit): 'pip_audit',
            }

            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log(f"{tool_name} failed: {e}", "ERROR")

        # Generate summary
        summary = self.generate_summary()
        summary['duration_seconds'] = (datetime.now() - start_time).total_seconds()

        # Save summary
        summary_file = self.output_dir / "sast_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        self.log(f"Scan completed in {summary['duration_seconds']:.2f} seconds")
        self.log(f"Total findings: {summary['total_findings']}")
        self.log(f"Critical: {summary['severity_counts']['CRITICAL']}, "
                f"High: {summary['severity_counts']['HIGH']}, "
                f"Medium: {summary['severity_counts']['MEDIUM']}, "
                f"Low: {summary['severity_counts']['LOW']}")

        return summary


def main():
    parser = argparse.ArgumentParser(description='SAST Security Scanner')
    parser.add_argument('--path', '-p', default='.', help='Path to scan')
    parser.add_argument('--output', '-o', default='sast_results', help='Output directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--config', '-c', action='append', help='Semgrep config (can specify multiple)')

    args = parser.parse_args()

    scanner = SASTScanner(
        path=args.path,
        output_dir=args.output,
        verbose=args.verbose
    )

    results = scanner.run_full_scan()

    # Print summary
    print("\n" + "="*60)
    print("SAST SCAN SUMMARY")
    print("="*60)
    print(f"Path: {results['scan_path']}")
    print(f"Languages: {', '.join(results['languages_detected'])}")
    print(f"Duration: {results['duration_seconds']:.2f}s")
    print(f"\nFindings by Severity:")
    for severity, count in results['severity_counts'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    print(f"\nFindings by Tool:")
    for tool, count in results['tool_counts'].items():
        print(f"  {tool}: {count}")
    print("="*60)


if __name__ == '__main__':
    main()
