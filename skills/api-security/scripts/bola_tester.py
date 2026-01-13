#!/usr/bin/env python3
"""
BOLA/IDOR Tester - Test for Broken Object Level Authorization vulnerabilities
"""

import argparse
import requests
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
import warnings
warnings.filterwarnings('ignore')


class BOLATester:
    def __init__(self, base_url: str, auth_token: str = None,
                 proxy: str = None, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []

        if self.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.auth_token}'

        if self.proxy:
            self.session.proxies = self.proxy

    def log(self, message: str, level: str = "INFO"):
        if self.verbose or level in ["FINDING", "ERROR"]:
            print(f"[{level}] {message}")

    def test_endpoint(self, endpoint: str, method: str = "GET",
                      original_id: str = None, test_ids: List = None) -> List[Dict]:
        """Test a single endpoint for BOLA/IDOR"""
        findings = []

        if test_ids is None:
            test_ids = self.generate_test_ids(original_id)

        for test_id in test_ids:
            # Replace ID placeholder
            test_url = endpoint.replace('{id}', str(test_id))
            test_url = re.sub(r'/\d+', f'/{test_id}', endpoint)

            try:
                if method.upper() == "GET":
                    resp = self.session.get(
                        urljoin(self.base_url, test_url),
                        timeout=10
                    )
                elif method.upper() == "POST":
                    resp = self.session.post(
                        urljoin(self.base_url, test_url),
                        json={},
                        timeout=10
                    )
                elif method.upper() == "PUT":
                    resp = self.session.put(
                        urljoin(self.base_url, test_url),
                        json={},
                        timeout=10
                    )
                elif method.upper() == "DELETE":
                    resp = self.session.delete(
                        urljoin(self.base_url, test_url),
                        timeout=10
                    )
                else:
                    continue

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data:
                            finding = {
                                "endpoint": test_url,
                                "method": method,
                                "test_id": test_id,
                                "status_code": resp.status_code,
                                "response_size": len(resp.text),
                                "response_preview": str(data)[:500],
                                "severity": "HIGH",
                                "type": "BOLA/IDOR"
                            }
                            findings.append(finding)
                            self.log(f"BOLA found: {method} {test_url} - ID {test_id}", "FINDING")
                    except:
                        pass

            except Exception as e:
                self.log(f"Error testing {test_url}: {e}", "ERROR")

        return findings

    def generate_test_ids(self, original_id: str = None) -> List:
        """Generate test IDs for BOLA testing"""
        test_ids = []

        # Sequential IDs
        if original_id and original_id.isdigit():
            base = int(original_id)
            test_ids.extend([
                base - 1, base + 1, base - 10, base + 10,
                1, 2, 0, 999999, -1
            ])
        else:
            test_ids.extend([1, 2, 3, 10, 100, 1000, 999999, 0, -1])

        # UUID patterns
        test_ids.extend([
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
        ])

        # String IDs
        test_ids.extend(["admin", "root", "test", "user"])

        return list(set(test_ids))

    def test_horizontal_privilege_escalation(self,
                                              user_a_token: str,
                                              user_b_token: str,
                                              endpoints: List[str]) -> List[Dict]:
        """Test horizontal privilege escalation between two users"""
        findings = []

        # First, collect resources accessible by User A
        session_a = requests.Session()
        session_a.headers['Authorization'] = f'Bearer {user_a_token}'
        session_a.verify = False

        session_b = requests.Session()
        session_b.headers['Authorization'] = f'Bearer {user_b_token}'
        session_b.verify = False

        for endpoint in endpoints:
            try:
                # Get User A's resource
                resp_a = session_a.get(
                    urljoin(self.base_url, endpoint),
                    timeout=10
                )

                if resp_a.status_code == 200:
                    # Extract IDs from response
                    try:
                        data_a = resp_a.json()
                        ids_a = self.extract_ids(data_a)

                        # Try to access User A's resources as User B
                        for id_val in ids_a:
                            test_endpoint = re.sub(r'\{[^}]+\}', str(id_val), endpoint)

                            resp_b = session_b.get(
                                urljoin(self.base_url, test_endpoint),
                                timeout=10
                            )

                            if resp_b.status_code == 200:
                                try:
                                    data_b = resp_b.json()
                                    if data_b:
                                        finding = {
                                            "type": "Horizontal Privilege Escalation",
                                            "severity": "CRITICAL",
                                            "endpoint": test_endpoint,
                                            "description": f"User B can access User A's resource (ID: {id_val})",
                                            "user_a_response": str(data_a)[:200],
                                            "user_b_response": str(data_b)[:200]
                                        }
                                        findings.append(finding)
                                        self.log(f"HPE found: {test_endpoint}", "FINDING")
                                except:
                                    pass
                    except:
                        pass
            except Exception as e:
                self.log(f"Error: {e}", "ERROR")

        return findings

    def test_vertical_privilege_escalation(self,
                                            user_token: str,
                                            admin_endpoints: List[str]) -> List[Dict]:
        """Test vertical privilege escalation (user accessing admin functions)"""
        findings = []

        session = requests.Session()
        session.headers['Authorization'] = f'Bearer {user_token}'
        session.verify = False

        for endpoint in admin_endpoints:
            try:
                resp = session.get(
                    urljoin(self.base_url, endpoint),
                    timeout=10
                )

                if resp.status_code == 200:
                    finding = {
                        "type": "Vertical Privilege Escalation",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "description": "Regular user can access admin endpoint",
                        "status_code": resp.status_code,
                        "response_size": len(resp.text)
                    }
                    findings.append(finding)
                    self.log(f"VPE found: {endpoint}", "FINDING")

            except Exception as e:
                self.log(f"Error: {e}", "ERROR")

        return findings

    def extract_ids(self, data, depth: int = 3) -> List:
        """Extract potential IDs from JSON response"""
        ids = []

        if depth <= 0:
            return ids

        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in ['id', 'user_id', 'account_id', 'order_id',
                                   'document_id', 'file_id', 'item_id', 'uuid']:
                    ids.append(value)
                elif isinstance(value, (dict, list)):
                    ids.extend(self.extract_ids(value, depth - 1))
        elif isinstance(data, list):
            for item in data:
                ids.extend(self.extract_ids(item, depth - 1))

        return list(set(ids))

    def test_id_enumeration(self, endpoint: str,
                            start_id: int = 1,
                            end_id: int = 100) -> List[Dict]:
        """Enumerate IDs on an endpoint"""
        findings = []
        valid_ids = []

        self.log(f"Enumerating IDs {start_id}-{end_id} on {endpoint}")

        for test_id in range(start_id, end_id + 1):
            test_url = endpoint.replace('{id}', str(test_id))
            test_url = re.sub(r'/\d+$', f'/{test_id}', endpoint)

            try:
                resp = self.session.get(
                    urljoin(self.base_url, test_url),
                    timeout=5
                )

                if resp.status_code == 200:
                    valid_ids.append(test_id)
                    self.log(f"Valid ID found: {test_id}", "INFO")

            except:
                continue

        if valid_ids:
            finding = {
                "type": "ID Enumeration",
                "severity": "MEDIUM",
                "endpoint": endpoint,
                "description": f"Found {len(valid_ids)} valid IDs",
                "valid_ids": valid_ids[:20],  # First 20
                "total_found": len(valid_ids)
            }
            findings.append(finding)

        return findings

    def test_parameter_pollution(self, endpoint: str,
                                  param_name: str = "id") -> List[Dict]:
        """Test parameter pollution for BOLA bypass"""
        findings = []

        pollution_patterns = [
            f"?{param_name}=1&{param_name}=2",
            f"?{param_name}[]=1&{param_name}[]=2",
            f"?{param_name}=1%00&{param_name}=2",
            f"?{param_name}=2&{param_name}=1",
        ]

        for pattern in pollution_patterns:
            test_url = endpoint + pattern

            try:
                resp = self.session.get(
                    urljoin(self.base_url, test_url),
                    timeout=10
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data:
                            finding = {
                                "type": "Parameter Pollution",
                                "severity": "HIGH",
                                "endpoint": test_url,
                                "description": "Server accepts polluted parameters",
                                "pattern": pattern
                            }
                            findings.append(finding)
                            self.log(f"Pollution worked: {pattern}", "FINDING")
                    except:
                        pass
            except:
                continue

        return findings

    def test_method_override(self, endpoint: str) -> List[Dict]:
        """Test HTTP method override for BOLA bypass"""
        findings = []

        override_headers = [
            {'X-HTTP-Method-Override': 'GET'},
            {'X-HTTP-Method': 'GET'},
            {'X-Method-Override': 'GET'},
        ]

        for headers in override_headers:
            try:
                resp = self.session.post(
                    urljoin(self.base_url, endpoint),
                    headers=headers,
                    timeout=10
                )

                if resp.status_code == 200:
                    finding = {
                        "type": "Method Override",
                        "severity": "MEDIUM",
                        "endpoint": endpoint,
                        "description": "Server accepts HTTP method override",
                        "header": list(headers.keys())[0]
                    }
                    findings.append(finding)
                    self.log(f"Method override accepted: {headers}", "FINDING")

            except:
                continue

        return findings

    def run_comprehensive_test(self, endpoints: List[str]) -> Dict:
        """Run comprehensive BOLA testing"""
        all_findings = []

        self.log(f"Testing {len(endpoints)} endpoints for BOLA/IDOR")

        # Test each endpoint
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

            for endpoint in endpoints:
                futures.append(
                    executor.submit(self.test_endpoint, endpoint)
                )

            for future in as_completed(futures):
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except:
                    pass

        # Summary
        summary = {
            "total_endpoints_tested": len(endpoints),
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.get('severity') == 'CRITICAL']),
            "high": len([f for f in all_findings if f.get('severity') == 'HIGH']),
            "medium": len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
            "findings": all_findings
        }

        return summary


def main():
    parser = argparse.ArgumentParser(description='BOLA/IDOR Vulnerability Tester')
    parser.add_argument('--base-url', '-u', required=True, help='Base API URL')
    parser.add_argument('--endpoint', '-e', help='Specific endpoint to test')
    parser.add_argument('--endpoints-file', '-f', help='File with endpoints to test')
    parser.add_argument('--auth-token', '-t', help='Authorization token')
    parser.add_argument('--user-a-token', help='User A token for horizontal testing')
    parser.add_argument('--user-b-token', help='User B token for horizontal testing')
    parser.add_argument('--id-range', help='ID range to test (e.g., 1-100)')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--output', '-o', help='Output file (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    tester = BOLATester(
        base_url=args.base_url,
        auth_token=args.auth_token,
        proxy=args.proxy,
        verbose=args.verbose
    )

    endpoints = []

    if args.endpoint:
        endpoints.append(args.endpoint)

    if args.endpoints_file:
        with open(args.endpoints_file, 'r') as f:
            endpoints.extend([line.strip() for line in f if line.strip()])

    if not endpoints:
        # Default test endpoints
        endpoints = [
            '/api/users/{id}',
            '/api/users/{id}/profile',
            '/api/orders/{id}',
            '/api/documents/{id}',
            '/api/accounts/{id}',
        ]

    # Run tests
    if args.user_a_token and args.user_b_token:
        findings = tester.test_horizontal_privilege_escalation(
            args.user_a_token,
            args.user_b_token,
            endpoints
        )
        results = {"type": "horizontal_privilege_escalation", "findings": findings}
    else:
        results = tester.run_comprehensive_test(endpoints)

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
