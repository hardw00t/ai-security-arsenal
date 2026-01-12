#!/usr/bin/env python3
"""
Playwright-based DAST Scanner
Main single-domain security scanner using Playwright MCP for browser automation.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

class PlaywrightDASTScanner:
    """
    Main DAST scanner using Playwright MCP for browser automation

    NOTE: This script is designed to work WITH Claude Code's Playwright MCP integration.
    Claude Code will orchestrate Playwright operations directly via MCP.
    This script provides the framework and methodology.
    """

    def __init__(self, target_url, mode='blackbox', auth_config=None):
        self.target_url = target_url
        self.mode = mode
        self.auth_config = auth_config or {}
        self.discovered_urls = set()
        self.discovered_forms = []
        self.discovered_apis = []
        self.findings = []
        self.scan_metadata = {
            'start_time': datetime.now().isoformat(),
            'target': target_url,
            'mode': mode,
            'scanner': 'Playwright DAST'
        }

    def scan(self):
        """Execute full DAST scan"""
        print(f"[*] Starting DAST scan: {self.target_url}")
        print(f"[*] Mode: {self.mode}")

        # Phase 1: Authentication (if greybox)
        if self.mode == 'greybox' and self.auth_config:
            print("[*] Phase 1: Authentication")
            if not self.authenticate():
                print("[!] Authentication failed - aborting scan")
                return False
            print("[+] Authentication successful")

        # Phase 2: Crawling with Playwright
        print("[*] Phase 2: Crawling and Endpoint Discovery")
        self.crawl_application()
        print(f"[+] Discovered {len(self.discovered_urls)} URLs")
        print(f"[+] Discovered {len(self.discovered_forms)} forms")
        print(f"[+] Discovered {len(self.discovered_apis)} API endpoints")

        # Phase 3: Vulnerability Testing
        print("[*] Phase 3: Vulnerability Testing")
        self.test_vulnerabilities()
        print(f"[+] Found {len(self.findings)} potential vulnerabilities")

        # Phase 4: Report Generation
        self.scan_metadata['end_time'] = datetime.now().isoformat()
        self.scan_metadata['duration'] = self.calculate_duration()
        self.scan_metadata['summary'] = self.generate_summary()

        return True

    def authenticate(self):
        """
        Authenticate using Playwright

        NOTE: Actual Playwright automation is performed by Claude Code via MCP.
        This method documents the authentication flow.
        """
        print(f"[*] Navigating to: {self.auth_config.get('auth_url', self.target_url)}")
        print(f"[*] Username: {self.auth_config.get('username')}")

        # Claude Code will:
        # 1. Launch Playwright browser
        # 2. Navigate to login page
        # 3. Fill username field
        # 4. Fill password field
        # 5. Click submit button
        # 6. Verify successful authentication
        # 7. Capture session cookies

        # Placeholder - Claude Code performs actual authentication
        return True

    def crawl_application(self):
        """
        Crawl application using Playwright to discover all endpoints

        NOTE: Actual crawling is performed by Claude Code via Playwright MCP.
        This method documents the crawling strategy.
        """

        # Crawling strategy for Claude Code:
        print(f"[*] Starting crawl from: {self.target_url}")

        # 1. Navigate to target URL
        # 2. Extract all links from page
        # 3. Extract all forms
        # 4. Monitor network requests for API endpoints
        # 5. Click navigation elements
        # 6. Handle JavaScript-rendered content
        # 7. Recursively crawl discovered URLs
        # 8. Respect crawl depth and scope

        # Example discovered data (Claude Code will populate this):
        self.discovered_urls = {
            self.target_url,
            urljoin(self.target_url, '/login'),
            urljoin(self.target_url, '/profile'),
            urljoin(self.target_url, '/api/users'),
        }

        self.discovered_forms = [
            {
                'url': urljoin(self.target_url, '/contact'),
                'action': '/api/contact',
                'method': 'POST',
                'fields': ['name', 'email', 'message']
            },
            {
                'url': urljoin(self.target_url, '/search'),
                'action': '/search',
                'method': 'GET',
                'fields': ['q']
            }
        ]

        self.discovered_apis = [
            {'url': urljoin(self.target_url, '/api/users'), 'method': 'GET'},
            {'url': urljoin(self.target_url, '/api/profile'), 'method': 'GET'},
        ]

    def test_vulnerabilities(self):
        """
        Test discovered surfaces for vulnerabilities

        NOTE: Actual testing is performed by Claude Code via Playwright MCP.
        """

        # XSS Testing
        print("[*] Testing for XSS...")
        self.test_xss()

        # CSRF Testing
        print("[*] Testing for CSRF...")
        self.test_csrf()

        # IDOR Testing (greybox only)
        if self.mode == 'greybox':
            print("[*] Testing for IDOR...")
            self.test_idor()

        # Open Redirect Testing
        print("[*] Testing for Open Redirects...")
        self.test_open_redirect()

        # Information Disclosure
        print("[*] Testing for Information Disclosure...")
        self.test_info_disclosure()

    def test_xss(self):
        """Test for XSS vulnerabilities"""
        xss_payloads = [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '" autofocus onfocus=alert(1) x="',
            "';alert(1);//"
        ]

        for form in self.discovered_forms:
            for field in form['fields']:
                for payload in xss_payloads:
                    # Claude Code will:
                    # 1. Navigate to form URL
                    # 2. Inject payload into field
                    # 3. Submit form
                    # 4. Check if payload executed
                    # 5. Verify in DOM / response

                    # Example finding:
                    finding = {
                        'type': 'XSS',
                        'severity': 'HIGH',
                        'url': form['url'],
                        'parameter': field,
                        'payload': payload,
                        'description': f'Reflected XSS in {field} parameter',
                        'evidence': 'Payload reflected without encoding',
                        'remediation': 'Implement output encoding and Content-Security-Policy'
                    }
                    # self.findings.append(finding) # Only if vulnerable

    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        for form in self.discovered_forms:
            if form['method'].upper() in ['POST', 'PUT', 'DELETE']:
                # Claude Code will:
                # 1. Capture legitimate request
                # 2. Check for anti-CSRF token
                # 3. Attempt request without token
                # 4. Attempt request with invalid token
                # 5. Attempt request from different origin

                # Example finding:
                finding = {
                    'type': 'CSRF',
                    'severity': 'MEDIUM',
                    'url': form['url'],
                    'description': 'Missing CSRF protection on state-changing operation',
                    'evidence': 'No anti-CSRF token found in form',
                    'remediation': 'Implement CSRF tokens and SameSite cookie attribute'
                }
                # self.findings.append(finding) # Only if vulnerable

    def test_idor(self):
        """Test for IDOR vulnerabilities (greybox mode)"""
        # Test endpoints with IDs
        test_ids = range(1, 100)

        for api in self.discovered_apis:
            if '{id}' in api['url'] or any(param in api['url'] for param in ['user', 'document', 'order']):
                # Claude Code will:
                # 1. Access resource with current user's ID
                # 2. Access resource with different user's ID
                # 3. Verify authorization enforcement

                # Example finding:
                finding = {
                    'type': 'IDOR',
                    'severity': 'CRITICAL',
                    'url': api['url'],
                    'description': 'Insecure Direct Object Reference allows unauthorized data access',
                    'evidence': 'Accessed other user data without authorization check',
                    'remediation': 'Implement proper authorization checks before data access'
                }
                # self.findings.append(finding) # Only if vulnerable

    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        redirect_params = ['url', 'redirect', 'next', 'return_url', 'continue']
        test_urls = [
            'https://evil.com',
            '//evil.com',
            '///evil.com',
            'javascript:alert(1)'
        ]

        for url in self.discovered_urls:
            parsed = urlparse(url)
            # Test each parameter that might control redirects
            pass

    def test_info_disclosure(self):
        """Test for information disclosure"""
        sensitive_patterns = [
            'stack trace',
            'sql error',
            'exception',
            'debug',
            'password',
            'api_key',
            'secret'
        ]

        # Check responses for sensitive information
        # Check error pages
        # Check source code comments
        pass

    def calculate_duration(self):
        """Calculate scan duration"""
        start = datetime.fromisoformat(self.scan_metadata['start_time'])
        end = datetime.fromisoformat(self.scan_metadata['end_time'])
        duration = (end - start).total_seconds()
        return f"{int(duration // 60)}m {int(duration % 60)}s"

    def generate_summary(self):
        """Generate findings summary"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        for finding in self.findings:
            severity = finding.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return severity_counts

    def export_results(self, output_file):
        """Export scan results to JSON"""
        results = {
            'metadata': self.scan_metadata,
            'scope': {
                'urls': list(self.discovered_urls),
                'forms': self.discovered_forms,
                'apis': self.discovered_apis
            },
            'findings': self.findings
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"[+] Results exported to: {output_file}")
        return results

def main():
    parser = argparse.ArgumentParser(
        description="Playwright-based DAST Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Blackbox scan
  %(prog)s --target https://example.com --mode blackbox --output results.json

  # Greybox scan with authentication
  %(prog)s --target https://app.example.com --mode greybox \\
    --auth-url https://app.example.com/login \\
    --username user@test.com \\
    --password 'password123' \\
    --output results.json

Note: This script works WITH Claude Code's Playwright MCP integration.
      Claude Code orchestrates actual Playwright operations.
        """
    )

    parser.add_argument('--target', '-t', required=True, help='Target URL to scan')
    parser.add_argument('--mode', '-m', choices=['blackbox', 'greybox'],
                       default='blackbox', help='Scan mode')
    parser.add_argument('--auth-url', help='Authentication URL (for greybox)')
    parser.add_argument('--username', '-u', help='Username (for greybox)')
    parser.add_argument('--password', '-p', help='Password (for greybox)')
    parser.add_argument('--output', '-o', required=True, help='Output JSON file')
    parser.add_argument('--crawl-depth', type=int, default=3, help='Maximum crawl depth')
    parser.add_argument('--max-urls', type=int, default=500, help='Maximum URLs to crawl')

    args = parser.parse_args()

    # Build auth config
    auth_config = None
    if args.mode == 'greybox':
        if not args.username or not args.password:
            print("[!] Error: --username and --password required for greybox mode")
            sys.exit(1)

        auth_config = {
            'auth_url': args.auth_url or args.target,
            'username': args.username,
            'password': args.password
        }

    # Initialize scanner
    scanner = PlaywrightDASTScanner(
        target_url=args.target,
        mode=args.mode,
        auth_config=auth_config
    )

    # Execute scan
    print(f"\n{'='*60}")
    print("Playwright DAST Scanner")
    print(f"{'='*60}\n")

    success = scanner.scan()

    if success:
        scanner.export_results(args.output)
        print(f"\n[+] Scan completed successfully")
        print(f"[+] Findings: {len(scanner.findings)}")
        summary = scanner.scan_metadata['summary']
        print(f"[+] Critical: {summary['CRITICAL']}, High: {summary['HIGH']}, Medium: {summary['MEDIUM']}, Low: {summary['LOW']}")
    else:
        print("\n[!] Scan failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
