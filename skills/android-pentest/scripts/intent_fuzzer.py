#!/usr/bin/env python3
"""
Intent Fuzzer for Android Applications

Fuzzes exported activities, services, and broadcast receivers
with various payloads to identify vulnerabilities.

Usage: python3 intent_fuzzer.py <package_name>
"""

import subprocess
import sys
import re
import argparse
import time
from typing import Optional


def run_adb(args: list[str], timeout: int = 10) -> tuple[str, str, int]:
    """Execute an ADB command."""
    cmd = ["adb", "shell"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1


def get_exported_components(package_name: str) -> dict:
    """Extract exported components from package."""
    components = {
        "activities": [],
        "services": [],
        "receivers": []
    }

    stdout, _, _ = run_adb(["dumpsys", "package", package_name])

    current_type = None

    for line in stdout.split("\n"):
        line_lower = line.lower()

        # Detect component type
        if "activity" in line_lower and "resolver" not in line_lower:
            current_type = "activities"
        elif "service" in line_lower and "resolver" not in line_lower:
            current_type = "services"
        elif "receiver" in line_lower:
            current_type = "receivers"

        # Look for exported components
        if current_type and "exported=true" in line_lower:
            # Try to find the component name
            match = re.search(rf'{package_name}/([^\s]+)', line)
            if match:
                component = match.group(1)
                if component not in components[current_type]:
                    components[current_type].append(component)

    return components


def get_intent_filters(package_name: str) -> dict:
    """Extract intent filters for components."""
    filters = {}
    stdout, _, _ = run_adb(["dumpsys", "package", package_name])

    current_component = None
    current_filter = {}

    for line in stdout.split("\n"):
        line = line.strip()

        # Component name
        match = re.search(rf'({package_name}/[^\s]+)', line)
        if match:
            if current_component and current_filter:
                filters[current_component] = current_filter.copy()
            current_component = match.group(1)
            current_filter = {"actions": [], "categories": [], "data": []}

        # Intent filter details
        if "Action:" in line:
            action = line.split("Action:")[-1].strip().strip('"')
            if action and current_filter:
                current_filter["actions"].append(action)
        elif "Category:" in line:
            category = line.split("Category:")[-1].strip().strip('"')
            if category and current_filter:
                current_filter["categories"].append(category)
        elif "Scheme:" in line:
            scheme = line.split("Scheme:")[-1].strip().strip('"')
            if scheme and current_filter:
                current_filter["data"].append(f"scheme:{scheme}")

    if current_component and current_filter:
        filters[current_component] = current_filter

    return filters


def fuzz_activity(package_name: str, activity: str, payloads: list[dict]) -> list[dict]:
    """Fuzz an activity with various payloads."""
    findings = []
    full_component = f"{package_name}/{activity}"

    for payload in payloads:
        cmd = ["am", "start", "-n", full_component]

        # Add extras based on payload type
        if "string" in payload:
            cmd.extend(["--es", payload["key"], payload["string"]])
        if "int" in payload:
            cmd.extend(["--ei", payload["key"], str(payload["int"])])
        if "uri" in payload:
            cmd.extend(["-d", payload["uri"]])
        if "action" in payload:
            cmd.extend(["-a", payload["action"]])

        stdout, stderr, rc = run_adb(cmd)

        # Analyze response
        result = {
            "component": activity,
            "payload": payload,
            "success": rc == 0,
            "output": stdout,
            "error": stderr
        }

        # Check for interesting responses
        if "Exception" in stderr or "Error" in stderr:
            result["issue"] = "Exception triggered"
            findings.append(result)
        elif "crash" in stderr.lower():
            result["issue"] = "Potential crash"
            findings.append(result)
        elif rc == 0 and "Starting" in stdout:
            result["issue"] = "Activity launched"
            findings.append(result)

        time.sleep(0.5)  # Avoid overwhelming the device

    return findings


def fuzz_broadcast(package_name: str, receiver: str, payloads: list[dict]) -> list[dict]:
    """Fuzz a broadcast receiver with various payloads."""
    findings = []
    full_component = f"{package_name}/{receiver}"

    for payload in payloads:
        cmd = ["am", "broadcast", "-n", full_component]

        if "action" in payload:
            cmd.extend(["-a", payload["action"]])
        if "string" in payload:
            cmd.extend(["--es", payload["key"], payload["string"]])
        if "int" in payload:
            cmd.extend(["--ei", payload["key"], str(payload["int"])])

        stdout, stderr, rc = run_adb(cmd)

        result = {
            "component": receiver,
            "payload": payload,
            "success": rc == 0,
            "output": stdout,
            "error": stderr
        }

        if "Broadcast completed" in stdout:
            result["issue"] = "Broadcast delivered"
            findings.append(result)
        elif "Exception" in stderr:
            result["issue"] = "Exception triggered"
            findings.append(result)

    return findings


def fuzz_service(package_name: str, service: str, payloads: list[dict]) -> list[dict]:
    """Fuzz a service with various payloads."""
    findings = []
    full_component = f"{package_name}/{service}"

    for payload in payloads:
        cmd = ["am", "startservice", "-n", full_component]

        if "action" in payload:
            cmd.extend(["-a", payload["action"]])
        if "string" in payload:
            cmd.extend(["--es", payload["key"], payload["string"]])

        stdout, stderr, rc = run_adb(cmd)

        result = {
            "component": service,
            "payload": payload,
            "success": rc == 0,
            "output": stdout,
            "error": stderr
        }

        if rc == 0:
            result["issue"] = "Service started"
            findings.append(result)
        elif "Exception" in stderr:
            result["issue"] = "Exception triggered"
            findings.append(result)

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Fuzz Android exported components"
    )
    parser.add_argument("package", help="Target package name")
    parser.add_argument("-c", "--component", help="Specific component to fuzz")
    parser.add_argument("-t", "--type", choices=["activity", "service", "receiver"],
                        help="Component type")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    print("[*] Android Intent Fuzzer")
    print(f"[*] Target: {args.package}")
    print("=" * 50)

    # Define fuzzing payloads
    activity_payloads = [
        # Basic string payloads
        {"key": "data", "string": "test"},
        {"key": "url", "string": "javascript:alert(1)"},
        {"key": "path", "string": "../../../etc/passwd"},
        {"key": "file", "string": "file:///data/data/{}/databases/".format(args.package)},
        {"key": "cmd", "string": "; ls -la"},

        # URI payloads
        {"uri": "file:///etc/passwd"},
        {"uri": "content://com.android.contacts/contacts"},
        {"uri": "javascript:alert(document.cookie)"},

        # Integer payloads
        {"key": "id", "int": -1},
        {"key": "index", "int": 999999},
        {"key": "count", "int": 0},

        # SQL injection via intent
        {"key": "query", "string": "' OR '1'='1"},
        {"key": "id", "string": "1; DROP TABLE users--"},

        # XSS payloads for WebView activities
        {"key": "url", "string": "<script>alert(1)</script>"},
        {"key": "html", "string": "<img src=x onerror=alert(1)>"},
    ]

    broadcast_payloads = [
        {"action": "android.intent.action.BOOT_COMPLETED"},
        {"action": "android.intent.action.USER_PRESENT"},
        {"action": "android.intent.action.PACKAGE_REPLACED"},
        {"key": "command", "string": "execute"},
        {"key": "data", "string": "sensitive_data"},
    ]

    service_payloads = [
        {"action": "START"},
        {"action": "STOP"},
        {"key": "command", "string": "admin"},
        {"key": "token", "string": "bypass"},
    ]

    # Get exported components
    print("[*] Discovering exported components...")
    components = get_exported_components(args.package)

    total = sum(len(v) for v in components.values())
    print(f"[+] Found {total} exported components:")
    print(f"    Activities: {len(components['activities'])}")
    print(f"    Services: {len(components['services'])}")
    print(f"    Receivers: {len(components['receivers'])}")

    all_findings = []

    # Fuzz activities
    if components["activities"] and (not args.type or args.type == "activity"):
        print("\n[*] Fuzzing Activities...")
        for activity in components["activities"]:
            if args.component and args.component not in activity:
                continue
            print(f"  [*] Testing: {activity}")
            findings = fuzz_activity(args.package, activity, activity_payloads)
            all_findings.extend(findings)
            if findings and args.verbose:
                for f in findings:
                    print(f"    [+] {f['issue']}: {f['payload']}")

    # Fuzz services
    if components["services"] and (not args.type or args.type == "service"):
        print("\n[*] Fuzzing Services...")
        for service in components["services"]:
            if args.component and args.component not in service:
                continue
            print(f"  [*] Testing: {service}")
            findings = fuzz_service(args.package, service, service_payloads)
            all_findings.extend(findings)
            if findings and args.verbose:
                for f in findings:
                    print(f"    [+] {f['issue']}: {f['payload']}")

    # Fuzz receivers
    if components["receivers"] and (not args.type or args.type == "receiver"):
        print("\n[*] Fuzzing Broadcast Receivers...")
        for receiver in components["receivers"]:
            if args.component and args.component not in receiver:
                continue
            print(f"  [*] Testing: {receiver}")
            findings = fuzz_broadcast(args.package, receiver, broadcast_payloads)
            all_findings.extend(findings)
            if findings and args.verbose:
                for f in findings:
                    print(f"    [+] {f['issue']}: {f['payload']}")

    # Summary
    print("\n" + "=" * 50)
    print("[*] FUZZING SUMMARY")
    print("=" * 50)

    if all_findings:
        print(f"\n[!] Total findings: {len(all_findings)}")

        # Group by component
        by_component = {}
        for f in all_findings:
            comp = f["component"]
            if comp not in by_component:
                by_component[comp] = []
            by_component[comp].append(f)

        for comp, findings in by_component.items():
            print(f"\n[*] {comp}:")
            for f in findings[:5]:  # Limit output
                print(f"    - {f['issue']}")
                if args.verbose:
                    print(f"      Payload: {f['payload']}")
            if len(findings) > 5:
                print(f"    ... and {len(findings) - 5} more")
    else:
        print("\n[-] No significant findings")

    # Check for crashes via logcat
    print("\n[*] Checking for recent crashes...")
    stdout, _, _ = run_adb(["logcat", "-d", "-t", "50", "*:E"])
    if args.package in stdout and ("FATAL" in stdout or "crash" in stdout.lower()):
        print("[!] Potential crash detected in logcat!")
        if args.verbose:
            print(stdout[:500])


if __name__ == "__main__":
    main()
