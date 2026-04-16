#!/usr/bin/env python3
"""Aggregate multi-tool SARIF into schemas/finding.json-conformant JSON array.

Usage: aggregate_results.py <sarif-dir> <output.json>
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path

CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _cwe_from_rule(rule: dict) -> str | None:
    # Tries tags, properties, shortDescription
    props = rule.get("properties", {})
    for tag in props.get("tags", []):
        m = CWE_RE.search(tag)
        if m:
            return f"CWE-{m.group(1)}"
    for field in ("shortDescription", "fullDescription", "helpUri"):
        text = rule.get(field, {}).get("text", "") if isinstance(rule.get(field), dict) else str(rule.get(field, ""))
        m = CWE_RE.search(text)
        if m:
            return f"CWE-{m.group(1)}"
    return None


def _severity_from_level(level: str | None, security_severity: str | None) -> str:
    if security_severity:
        try:
            s = float(security_severity)
            if s >= 9.0: return "critical"
            if s >= 7.0: return "high"
            if s >= 4.0: return "medium"
            if s >  0.0: return "low"
        except ValueError:
            pass
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level or "warning", "medium")


def load_sarif(path: Path) -> list[dict]:
    with path.open() as f:
        sarif = json.load(f)
    findings: list[dict] = []
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown").lower()
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for r in run.get("results", []):
            rule = rules.get(r.get("ruleId", ""), {})
            locs = r.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            region = phys.get("region", {})
            sec_sev = rule.get("properties", {}).get("security-severity")
            cwe = _cwe_from_rule(rule)

            taint_flow = []
            for cf in r.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        pl = loc.get("location", {}).get("physicalLocation", {})
                        taint_flow.append({
                            "file_path": pl.get("artifactLocation", {}).get("uri"),
                            "line": pl.get("region", {}).get("startLine"),
                            "snippet": loc.get("location", {}).get("message", {}).get("text"),
                        })

            f_obj = {
                "tool": tool,
                "rule_id": r.get("ruleId"),
                "title": r.get("message", {}).get("text", "")[:120],
                "message": r.get("message", {}).get("text", ""),
                "severity": _severity_from_level(r.get("level"), sec_sev),
                "confidence": "suspected",  # refined in triage
                "cwe": cwe,
                "file_path": phys.get("artifactLocation", {}).get("uri"),
                "line": region.get("startLine"),
                "column": region.get("startColumn"),
                "end_line": region.get("endLine"),
                "taint_flow": taint_flow,
                "duplicate_of": [],
                "is_false_positive": False,
                "evidence": {"snippet": region.get("snippet", {}).get("text")},
                "remediation": "",
                "references": [rule.get("helpUri")] if rule.get("helpUri") else [],
            }
            fp = r.get("partialFingerprints", {}).get("primaryLocationLineHash")
            seed = fp or f"{tool}|{f_obj['rule_id']}|{f_obj['file_path']}|{f_obj['line']}"
            f_obj["id"] = hashlib.sha256(seed.encode()).hexdigest()[:16]
            findings.append(f_obj)
    return findings


def deduplicate(findings: list[dict], line_window: int = 3) -> list[dict]:
    """Group by (cwe, file, ±window lines). Mark duplicates in duplicate_of[]."""
    findings.sort(key=lambda f: (f.get("file_path") or "", f.get("line") or 0))
    kept: list[dict] = []
    for f in findings:
        match = None
        for k in kept:
            if k.get("cwe") and f.get("cwe") and k["cwe"] != f["cwe"]:
                continue
            if k.get("file_path") != f.get("file_path"):
                continue
            if abs((k.get("line") or 0) - (f.get("line") or 0)) <= line_window:
                match = k
                break
        if match:
            match["duplicate_of"].append(f["id"])
        else:
            kept.append(f)
    return kept


def main():
    if len(sys.argv) < 3:
        print("usage: aggregate_results.py <sarif-dir> <output.json>", file=sys.stderr)
        sys.exit(2)
    sarif_dir, output = Path(sys.argv[1]), Path(sys.argv[2])
    all_findings: list[dict] = []
    for p in sorted(sarif_dir.glob("*.sarif")):
        try:
            all_findings.extend(load_sarif(p))
        except Exception as e:
            print(f"[!] failed to load {p}: {e}", file=sys.stderr)
    deduped = deduplicate(all_findings)
    with output.open("w") as f:
        json.dump(deduped, f, indent=2)
    print(f"[+] {len(all_findings)} raw -> {len(deduped)} after dedup -> {output}")


if __name__ == "__main__":
    main()
