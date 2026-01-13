#!/usr/bin/env python3
"""
API Security Scanner - Comprehensive automated API security testing
Covers OWASP API Security Top 10 2023
"""

import argparse
import json
import requests
import re
import sys
import time
import base64
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Any
import warnings
warnings.filterwarnings('ignore')


class APISecurityScanner:
    def __init__(self, target: str, token: str = None, proxy: str = None, verbose: bool = False):
        self.target = target.rstrip('/')
        self.token = token
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.verbose = verbose
        self.findings = []
        self.endpoints = []
        self.session = requests.Session()
        self.session.verify = False

        if self.token:
            self.session.headers['Authorization'] = f'Bearer {self.token}'

        if self.proxy:
            self.session.proxies = self.proxy

    def log(self, message: str, level: str = "INFO"):
        if self.verbose or level in ["CRITICAL", "HIGH", "FINDING"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")

    def add_finding(self, title: str, severity: str, description: str,
                    endpoint: str = "", evidence: str = "", remediation: str = ""):
        finding = {
            "title": title,
            "severity": severity,
            "description": description,
            "endpoint": endpoint,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.log(f"[{severity}] {title}: {endpoint}", "FINDING")

    # ========== RECONNAISSANCE ==========

    def discover_openapi(self) -> Optional[Dict]:
        """Discover OpenAPI/Swagger documentation"""
        self.log("Searching for API documentation...")

        common_paths = [
            '/swagger.json', '/openapi.json', '/api-docs', '/swagger/v1/swagger.json',
            '/api/swagger.json', '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
            '/docs/swagger.json', '/swagger-ui.html', '/api/docs', '/documentation',
            '/.well-known/openapi.json', '/api/openapi.json', '/graphql', '/graphiql'
        ]

        for path in common_paths:
            try:
                resp = self.session.get(urljoin(self.target, path), timeout=10)
                if resp.status_code == 200:
                    try:
                        spec = resp.json()
                        if 'openapi' in spec or 'swagger' in spec or 'paths' in spec:
                            self.log(f"Found OpenAPI spec at {path}")
                            return spec
                    except:
                        if 'graphql' in path.lower() and ('__schema' in resp.text or 'GraphQL' in resp.text):
                            self.log(f"Found GraphQL endpoint at {path}")
                            return {"graphql": path}
            except:
                continue

        return None

    def extract_endpoints_from_spec(self, spec: Dict) -> List[Dict]:
        """Extract endpoints from OpenAPI specification"""
        endpoints = []

        if 'paths' in spec:
            for path, methods in spec['paths'].items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = {
                            'path': path,
                            'method': method.upper(),
                            'parameters': details.get('parameters', []),
                            'description': details.get('summary', '')
                        }
                        endpoints.append(endpoint)

        self.endpoints = endpoints
        self.log(f"Extracted {len(endpoints)} endpoints from specification")
        return endpoints

    def discover_endpoints_bruteforce(self) -> List[Dict]:
        """Brute force common API endpoints"""
        self.log("Brute forcing common API endpoints...")

        common_endpoints = [
            '/api/users', '/api/user', '/api/admin', '/api/login', '/api/auth',
            '/api/register', '/api/profile', '/api/account', '/api/settings',
            '/api/config', '/api/health', '/api/status', '/api/version',
            '/api/v1/users', '/api/v1/admin', '/api/v2/users', '/users',
            '/admin', '/login', '/auth', '/graphql', '/api/graphql'
        ]

        found = []
        for endpoint in common_endpoints:
            try:
                resp = self.session.get(urljoin(self.target, endpoint), timeout=5)
                if resp.status_code not in [404, 500, 502, 503]:
                    found.append({
                        'path': endpoint,
                        'method': 'GET',
                        'status': resp.status_code
                    })
                    self.log(f"Found endpoint: {endpoint} [{resp.status_code}]")
            except:
                continue

        self.endpoints.extend(found)
        return found

    # ========== AUTHENTICATION TESTING (API2:2023) ==========

    def test_authentication(self):
        """Test authentication mechanisms"""
        self.log("Testing authentication mechanisms...")

        # Test endpoints without authentication
        test_endpoints = ['/api/users', '/api/admin', '/api/config', '/users', '/admin']

        # Remove auth header temporarily
        orig_auth = self.session.headers.get('Authorization')
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

        for endpoint in test_endpoints:
            try:
                resp = self.session.get(urljoin(self.target, endpoint), timeout=5)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data:
                            self.add_finding(
                                "Unauthenticated Access to Sensitive Endpoint",
                                "CRITICAL",
                                f"Endpoint {endpoint} returns data without authentication",
                                endpoint,
                                f"Status: {resp.status_code}, Response size: {len(resp.text)} bytes",
                                "Implement proper authentication for all sensitive endpoints"
                            )
                    except:
                        pass
            except:
                continue

        # Restore auth header
        if orig_auth:
            self.session.headers['Authorization'] = orig_auth

    def analyze_jwt(self, token: str) -> Dict:
        """Analyze JWT token for vulnerabilities"""
        self.log("Analyzing JWT token...")

        vulnerabilities = []

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}

            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            # Check algorithm
            alg = header.get('alg', '')
            if alg.lower() == 'none':
                self.add_finding(
                    "JWT None Algorithm",
                    "CRITICAL",
                    "JWT uses 'none' algorithm - tokens can be forged without signature",
                    "Authentication",
                    f"Algorithm: {alg}",
                    "Use strong algorithms like RS256 or ES256"
                )
            elif alg.lower() == 'hs256':
                self.add_finding(
                    "JWT Weak Algorithm",
                    "MEDIUM",
                    "JWT uses HS256 which is susceptible to brute force if secret is weak",
                    "Authentication",
                    f"Algorithm: {alg}",
                    "Consider using RS256 or ES256 for better security"
                )

            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'ssn', 'credit_card', 'api_key']
            for key in payload.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    self.add_finding(
                        "Sensitive Data in JWT",
                        "HIGH",
                        f"JWT payload contains potentially sensitive field: {key}",
                        "Authentication",
                        f"Field: {key}",
                        "Remove sensitive data from JWT payload"
                    )

            # Check expiration
            if 'exp' not in payload:
                self.add_finding(
                    "JWT Missing Expiration",
                    "MEDIUM",
                    "JWT does not have an expiration claim",
                    "Authentication",
                    "No 'exp' claim found",
                    "Add expiration (exp) claim to all JWTs"
                )

            return {
                "header": header,
                "payload": payload,
                "vulnerabilities": vulnerabilities
            }

        except Exception as e:
            return {"error": str(e)}

    def test_jwt_attacks(self, token: str):
        """Test JWT-specific attacks"""
        self.log("Testing JWT attacks...")

        parts = token.split('.')
        if len(parts) != 3:
            return

        # Test 1: None algorithm attack
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            # Create token with none algorithm
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).decode().rstrip('=')
            none_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            none_token = f"{none_header}.{none_payload}."

            # Test if server accepts none algorithm
            test_session = requests.Session()
            test_session.headers['Authorization'] = f'Bearer {none_token}'
            test_session.verify = False

            for endpoint in ['/api/users', '/api/profile', '/api/me', '/users']:
                try:
                    resp = test_session.get(urljoin(self.target, endpoint), timeout=5)
                    if resp.status_code == 200:
                        self.add_finding(
                            "JWT None Algorithm Accepted",
                            "CRITICAL",
                            "Server accepts JWT tokens with 'none' algorithm",
                            endpoint,
                            f"Forged token accepted: {none_token[:50]}...",
                            "Reject tokens with 'none' algorithm"
                        )
                        break
                except:
                    continue
        except Exception as e:
            self.log(f"JWT none algorithm test failed: {e}", "DEBUG")

    # ========== BOLA TESTING (API1:2023) ==========

    def test_bola(self):
        """Test for Broken Object Level Authorization"""
        self.log("Testing for BOLA/IDOR vulnerabilities...")

        # Find endpoints with ID parameters
        id_patterns = [
            r'/users/(\d+)', r'/user/(\d+)', r'/accounts/(\d+)', r'/orders/(\d+)',
            r'/profiles/(\d+)', r'/documents/(\d+)', r'/files/(\d+)', r'/items/(\d+)',
            r'\?id=(\d+)', r'\?user_id=(\d+)', r'\?account_id=(\d+)'
        ]

        # Test ID manipulation
        test_ids = [1, 2, 0, 999999, -1]

        for endpoint in self.endpoints:
            path = endpoint.get('path', '')

            # Check if endpoint has ID parameter
            for pattern in id_patterns:
                if re.search(pattern, path):
                    # Test with different IDs
                    for test_id in test_ids:
                        test_path = re.sub(r'\{[^}]+\}', str(test_id), path)
                        test_path = re.sub(r'/\d+', f'/{test_id}', path)

                        try:
                            resp = self.session.get(
                                urljoin(self.target, test_path),
                                timeout=5
                            )

                            if resp.status_code == 200:
                                try:
                                    data = resp.json()
                                    if data and isinstance(data, dict):
                                        self.add_finding(
                                            "Potential BOLA/IDOR Vulnerability",
                                            "HIGH",
                                            f"Endpoint returns data for arbitrary ID: {test_id}",
                                            test_path,
                                            f"Response: {str(data)[:200]}...",
                                            "Implement proper authorization checks for object access"
                                        )
                                except:
                                    pass
                        except:
                            continue
                    break

    # ========== BFLA TESTING (API5:2023) ==========

    def test_bfla(self):
        """Test for Broken Function Level Authorization"""
        self.log("Testing for BFLA vulnerabilities...")

        admin_endpoints = [
            '/api/admin', '/api/admin/users', '/admin/settings', '/api/config',
            '/api/system', '/api/debug', '/api/logs', '/api/metrics',
            '/admin', '/manage', '/dashboard', '/api/internal',
            '/api/v1/admin', '/api/admin/config', '/api/users/delete'
        ]

        admin_methods = [
            ('DELETE', '/api/users/1'),
            ('PUT', '/api/users/1'),
            ('POST', '/api/admin/users'),
            ('DELETE', '/api/admin/config'),
        ]

        # Test admin endpoints
        for endpoint in admin_endpoints:
            try:
                resp = self.session.get(urljoin(self.target, endpoint), timeout=5)

                if resp.status_code == 200:
                    self.add_finding(
                        "Admin Endpoint Accessible",
                        "HIGH",
                        f"Administrative endpoint accessible with current token",
                        endpoint,
                        f"Status: {resp.status_code}",
                        "Implement role-based access control for admin functions"
                    )
            except:
                continue

        # Test privileged methods
        for method, endpoint in admin_methods:
            try:
                if method == 'DELETE':
                    resp = self.session.delete(urljoin(self.target, endpoint), timeout=5)
                elif method == 'PUT':
                    resp = self.session.put(urljoin(self.target, endpoint), json={}, timeout=5)
                elif method == 'POST':
                    resp = self.session.post(urljoin(self.target, endpoint), json={}, timeout=5)

                if resp.status_code in [200, 201, 204]:
                    self.add_finding(
                        "Privileged Method Accessible",
                        "HIGH",
                        f"{method} method accessible on sensitive endpoint",
                        endpoint,
                        f"Status: {resp.status_code}",
                        "Implement proper authorization for privileged operations"
                    )
            except:
                continue

    # ========== INJECTION TESTING ==========

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        self.log("Testing for SQL injection...")

        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND '1'='1",
            "1 AND 1=1",
            "' UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
        ]

        for endpoint in self.endpoints:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'GET')

            # Test URL parameters
            if '?' in path or '{' in path:
                for payload in sqli_payloads:
                    test_path = re.sub(r'\{[^}]+\}', payload, path)

                    try:
                        start_time = time.time()

                        if method == 'GET':
                            resp = self.session.get(
                                urljoin(self.target, test_path),
                                timeout=10
                            )
                        else:
                            resp = self.session.post(
                                urljoin(self.target, path),
                                json={"id": payload},
                                timeout=10
                            )

                        elapsed = time.time() - start_time

                        # Check for SQL errors in response
                        sql_errors = [
                            'sql syntax', 'mysql', 'postgresql', 'sqlite',
                            'ora-', 'sql server', 'syntax error'
                        ]

                        if any(err in resp.text.lower() for err in sql_errors):
                            self.add_finding(
                                "SQL Injection - Error Based",
                                "CRITICAL",
                                f"SQL error detected in response",
                                path,
                                f"Payload: {payload}, Error in response",
                                "Use parameterized queries"
                            )
                            break

                        # Check for time-based SQLi
                        if 'SLEEP' in payload or 'WAITFOR' in payload:
                            if elapsed > 4:
                                self.add_finding(
                                    "SQL Injection - Time Based",
                                    "CRITICAL",
                                    f"Time-based SQL injection detected",
                                    path,
                                    f"Payload: {payload}, Delay: {elapsed:.2f}s",
                                    "Use parameterized queries"
                                )
                                break
                    except:
                        continue

    def test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        self.log("Testing for NoSQL injection...")

        nosql_payloads = [
            {"$gt": ""},
            {"$ne": ""},
            {"$regex": ".*"},
            {"$where": "1==1"},
        ]

        login_endpoints = ['/api/login', '/login', '/api/auth', '/auth']

        for endpoint in login_endpoints:
            for payload in nosql_payloads:
                try:
                    resp = self.session.post(
                        urljoin(self.target, endpoint),
                        json={
                            "username": payload,
                            "password": payload
                        },
                        timeout=5
                    )

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data.get('token') or data.get('success'):
                                self.add_finding(
                                    "NoSQL Injection - Authentication Bypass",
                                    "CRITICAL",
                                    "NoSQL injection allows authentication bypass",
                                    endpoint,
                                    f"Payload: {json.dumps(payload)}",
                                    "Validate and sanitize all input, use parameterized queries"
                                )
                                break
                        except:
                            pass
                except:
                    continue

    def test_ssrf(self):
        """Test for Server-Side Request Forgery"""
        self.log("Testing for SSRF vulnerabilities...")

        ssrf_payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://metadata.google.internal/",
        ]

        # Find endpoints that might fetch URLs
        url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'target', 'webhook']

        for endpoint in self.endpoints:
            path = endpoint.get('path', '')

            for param in url_params:
                for payload in ssrf_payloads:
                    try:
                        test_url = f"{path}?{param}={payload}"
                        resp = self.session.get(
                            urljoin(self.target, test_url),
                            timeout=5,
                            allow_redirects=False
                        )

                        # Check for signs of SSRF
                        if any(indicator in resp.text.lower() for indicator in
                               ['root:', 'ami-id', 'instance-id', 'meta-data']):
                            self.add_finding(
                                "Server-Side Request Forgery (SSRF)",
                                "CRITICAL",
                                f"SSRF vulnerability allows access to internal resources",
                                test_url,
                                f"Payload: {payload}",
                                "Validate and whitelist allowed URLs"
                            )
                    except:
                        continue

    # ========== RATE LIMITING TESTING (API4:2023) ==========

    def test_rate_limiting(self):
        """Test for rate limiting"""
        self.log("Testing rate limiting...")

        test_endpoints = ['/api/login', '/login', '/api/auth', '/api/users']

        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target, endpoint)

                # Send rapid requests
                responses = []
                for i in range(50):
                    resp = self.session.get(url, timeout=5)
                    responses.append(resp.status_code)

                # Check if any rate limiting was applied
                rate_limited = any(code == 429 for code in responses)

                if not rate_limited and responses.count(200) > 40:
                    self.add_finding(
                        "Missing Rate Limiting",
                        "MEDIUM",
                        f"No rate limiting detected on endpoint",
                        endpoint,
                        f"50 requests sent, all successful",
                        "Implement rate limiting to prevent brute force attacks"
                    )
            except:
                continue

    # ========== SECURITY MISCONFIGURATION (API8:2023) ==========

    def test_security_headers(self):
        """Test for security headers"""
        self.log("Testing security headers...")

        try:
            resp = self.session.get(self.target, timeout=5)
            headers = resp.headers

            # Check for missing security headers
            required_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None,
                'X-XSS-Protection': '1; mode=block',
            }

            for header, expected_value in required_headers.items():
                if header not in headers:
                    self.add_finding(
                        f"Missing Security Header: {header}",
                        "LOW",
                        f"Security header {header} is not set",
                        self.target,
                        "Header missing from response",
                        f"Add {header} header to API responses"
                    )

            # Check for information disclosure headers
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in info_headers:
                if header in headers:
                    self.add_finding(
                        f"Information Disclosure: {header}",
                        "LOW",
                        f"Header {header} discloses server information",
                        self.target,
                        f"{header}: {headers[header]}",
                        "Remove or mask server identification headers"
                    )

            # Check CORS configuration
            if 'Access-Control-Allow-Origin' in headers:
                origin = headers['Access-Control-Allow-Origin']
                if origin == '*':
                    self.add_finding(
                        "Overly Permissive CORS",
                        "MEDIUM",
                        "CORS allows requests from any origin",
                        self.target,
                        f"Access-Control-Allow-Origin: {origin}",
                        "Restrict CORS to specific trusted origins"
                    )
        except Exception as e:
            self.log(f"Security headers test failed: {e}", "DEBUG")

    def test_debug_endpoints(self):
        """Test for exposed debug endpoints"""
        self.log("Testing for debug endpoints...")

        debug_endpoints = [
            '/debug', '/api/debug', '/api/test', '/test', '/console',
            '/api/internal', '/internal', '/actuator', '/actuator/health',
            '/actuator/env', '/metrics', '/api/metrics', '/.git/config',
            '/phpinfo.php', '/server-status', '/.env', '/config.json',
            '/api/swagger.json', '/api/config', '/trace', '/api/trace'
        ]

        for endpoint in debug_endpoints:
            try:
                resp = self.session.get(urljoin(self.target, endpoint), timeout=5)

                if resp.status_code == 200:
                    self.add_finding(
                        f"Debug Endpoint Exposed: {endpoint}",
                        "MEDIUM" if 'git' not in endpoint else "HIGH",
                        f"Debug/internal endpoint is accessible",
                        endpoint,
                        f"Status: {resp.status_code}, Size: {len(resp.text)} bytes",
                        "Disable or restrict access to debug endpoints in production"
                    )
            except:
                continue

    # ========== GRAPHQL TESTING ==========

    def test_graphql(self):
        """Test GraphQL-specific vulnerabilities"""
        self.log("Testing GraphQL security...")

        graphql_endpoints = ['/graphql', '/api/graphql', '/graphiql', '/v1/graphql']

        for endpoint in graphql_endpoints:
            url = urljoin(self.target, endpoint)

            # Test introspection
            introspection_query = {
                "query": "{__schema{types{name,fields{name}}}}"
            }

            try:
                resp = self.session.post(url, json=introspection_query, timeout=10)

                if resp.status_code == 200 and '__schema' in resp.text:
                    self.add_finding(
                        "GraphQL Introspection Enabled",
                        "MEDIUM",
                        "GraphQL introspection is enabled, exposing schema",
                        endpoint,
                        "Full schema accessible via introspection",
                        "Disable introspection in production"
                    )

                    # Check for sensitive types
                    try:
                        schema = resp.json()
                        types = schema.get('data', {}).get('__schema', {}).get('types', [])
                        sensitive = ['password', 'secret', 'token', 'key', 'ssn', 'credit']

                        for t in types:
                            type_name = t.get('name', '').lower()
                            if any(s in type_name for s in sensitive):
                                self.add_finding(
                                    "Sensitive GraphQL Type Exposed",
                                    "HIGH",
                                    f"Potentially sensitive type in schema: {t.get('name')}",
                                    endpoint,
                                    f"Type: {t.get('name')}",
                                    "Review and restrict access to sensitive types"
                                )
                    except:
                        pass

                    # Test query depth attack
                    depth_query = {
                        "query": "{users{friends{friends{friends{friends{name}}}}}}"
                    }

                    resp = self.session.post(url, json=depth_query, timeout=10)
                    if resp.status_code == 200 and 'errors' not in resp.text.lower():
                        self.add_finding(
                            "GraphQL No Query Depth Limit",
                            "MEDIUM",
                            "GraphQL does not limit query depth (DoS risk)",
                            endpoint,
                            "Deeply nested query executed successfully",
                            "Implement query depth limiting"
                        )
            except:
                continue

    # ========== MAIN SCAN ==========

    def run_scan(self) -> Dict:
        """Run complete API security scan"""
        self.log(f"Starting API security scan on {self.target}")
        start_time = time.time()

        # Phase 1: Reconnaissance
        self.log("=== Phase 1: Reconnaissance ===")
        spec = self.discover_openapi()
        if spec:
            self.extract_endpoints_from_spec(spec)
        self.discover_endpoints_bruteforce()

        # Phase 2: Authentication Testing
        self.log("=== Phase 2: Authentication Testing ===")
        self.test_authentication()
        if self.token:
            self.analyze_jwt(self.token)
            self.test_jwt_attacks(self.token)

        # Phase 3: Authorization Testing
        self.log("=== Phase 3: Authorization Testing ===")
        self.test_bola()
        self.test_bfla()

        # Phase 4: Injection Testing
        self.log("=== Phase 4: Injection Testing ===")
        self.test_sql_injection()
        self.test_nosql_injection()
        self.test_ssrf()

        # Phase 5: Business Logic
        self.log("=== Phase 5: Business Logic Testing ===")
        self.test_rate_limiting()

        # Phase 6: Configuration
        self.log("=== Phase 6: Configuration Testing ===")
        self.test_security_headers()
        self.test_debug_endpoints()

        # Phase 7: GraphQL
        self.log("=== Phase 7: GraphQL Testing ===")
        self.test_graphql()

        elapsed = time.time() - start_time

        # Generate summary
        severity_counts = {
            "CRITICAL": len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            "HIGH": len([f for f in self.findings if f['severity'] == 'HIGH']),
            "MEDIUM": len([f for f in self.findings if f['severity'] == 'MEDIUM']),
            "LOW": len([f for f in self.findings if f['severity'] == 'LOW'])
        }

        results = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "duration_seconds": round(elapsed, 2),
            "endpoints_discovered": len(self.endpoints),
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "findings": self.findings
        }

        self.log(f"Scan completed in {elapsed:.2f} seconds")
        self.log(f"Total findings: {len(self.findings)}")
        self.log(f"Critical: {severity_counts['CRITICAL']}, High: {severity_counts['HIGH']}, "
                f"Medium: {severity_counts['MEDIUM']}, Low: {severity_counts['LOW']}")

        return results

    def generate_report(self, results: Dict, output_file: str):
        """Generate JSON report"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        self.log(f"Report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='API Security Scanner')
    parser.add_argument('--target', '-t', required=True, help='Target API URL')
    parser.add_argument('--token', help='Bearer token for authentication')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--output', '-o', default='api_scan_results.json', help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    scanner = APISecurityScanner(
        target=args.target,
        token=args.token,
        proxy=args.proxy,
        verbose=args.verbose
    )

    results = scanner.run_scan()
    scanner.generate_report(results, args.output)


if __name__ == '__main__':
    main()
