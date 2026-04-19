---
name: dast-automation
description: Automated Dynamic Application Security Testing (DAST) using Playwright MCP plus standard OS pentest tooling. Performs blackbox or greybox scans on single or multiple domains with orchestrated crawling, vulnerability detection, and structured output. Trigger on requests like "scan this domain", "run DAST on these URLs", "automated pentest", or "security-test the staging app".
---

# DAST Automation with Playwright MCP

Thin router. Specific guidance lives in `workflows/`, `methodology/`, `payloads/`, and `examples/`. Read this file first, then lazy-load only the files you need for the task.

## When to Use

- Operator asks for a DAST / dynamic security scan of one or more web apps.
- Blackbox external scan of a single domain.
- Greybox (authenticated) scan with provided credentials.
- Parallel scanning across a fleet of domains.
- Setting up continuous / scheduled DAST with baseline diffing.
- CI/CD integration to block regressions on new Critical/High issues.

## Trigger Phrases

"scan <domain>", "run DAST", "blackbox scan", "greybox scan", "authenticated pentest", "spider and test this app", "security-test these URLs", "weekly security scan", "continuous DAST".

## When NOT to Use This Skill

- Source-code SAST / dependency CVEs → use `sast-automation` / `sca-automation`.
- Container image CVE scanning → use `container-security`.
- IaC / Terraform / K8s manifest misconfig scanning → use `iac-security`.
- Mobile app runtime testing (Frida, MASTG) → use `mobile-security`.
- Network/host hardening audit without web surface → use `network-audit`.
- Manual bug-bounty research on a single target → use this skill for surface mapping but switch to `hackerone-research` for narrative PoC work.

## Decision Tree

```
Domains = 1 ──→ creds provided? ──→ no  → workflows/blackbox_single_domain.md
                                 └─→ yes → workflows/greybox_authenticated.md

Domains ≥ 2 ──→ one-shot scan ──→ workflows/multi_domain_parallel.md
            └→ recurring schedule ─→ workflows/continuous_scanning.md

Any mode ──→ emit schemas/finding.json → methodology/reporting.md
```

## Parallelism Hints

Independent — run concurrently:

- Phase 0 recon tools: `nmap`, `whatweb`, `ffuf`, `subfinder`, root-level `nuclei`.
- Per-injection-class test batches (XSS, SQLi, SSRF, path traversal, CRLF) after crawl finishes.
- One sub-agent per domain in multi-domain mode.
- One sub-agent per low-priv account when running IDOR diff.

Must be sequential:

- Playwright **login** must complete before greybox crawl starts (storageState is consumed downstream).
- Crawl must complete before Nuclei endpoint overlay.
- Business-logic tests run after authed crawl builds the workflow map.
- Baseline diff runs after the current scan's `output.json` is finalized.

## Sub-Agent Delegation

Spawn sub-agents (via the Task tool) when:

| Scenario | Sub-agent granularity | Cap |
|----------|----------------------|-----|
| Multi-domain scan | One per domain | 5 concurrent |
| Focused single-target triage | One per vuln class (XSS, SQLi, SSRF, IDOR, business-logic) | 5 concurrent |
| IDOR / authz diff | One per account identity | 2–3 (one per tier) |
| Continuous fleet | One per domain per schedule tick | 5 concurrent |

Each sub-agent writes to its own `results/<scope>/` directory and returns a path to `output.json`. The parent aggregates; sub-agents never cross-read each other's output mid-run.

## Reasoning Budget

Extended thinking on:

- Business-logic flaw analysis (pricing, workflow skip, race conditions) — see `payloads/business_logic.txt`.
- Multi-step workflow mapping (checkout, KYC, password reset).
- IDOR model: which IDs are tenant-scoped, which are global, which are predictable.
- Severity/confidence calibration for ambiguous findings.
- Greybox auth failure triage (CAPTCHA, 2FA, CSRF-on-login).

No / minimal thinking on:

- Rote payload injection from `payloads/*.txt` against discovered inputs.
- Running standard recon tools with stock flags.
- Nuclei overlay pass.
- Emitting JSON conforming to `schemas/finding.json`.

## Multimodal Hooks

- Playwright screenshots — captured per-entry; path stored at `evidence.playwright_screenshot_path`.
- Optional Playwright `.zip` trace for time-travel debugging of complex finding repros.
- Network HAR exports attachable to high-severity findings.
- Visual diff between low-priv and high-priv account views (IDOR evidence).

## Structured Output

Every output entry conforms to `schemas/finding.json`. DAST-specific fields: `affected.url`, `affected.http_method`, `affected.parameter`, `affected.payload`, `affected.http_status`, `affected.authenticated_as`, `evidence.playwright_screenshot_path`, `evidence.playwright_trace_path`, `evidence.har_path`.

## Workflow Index

| File | When |
|------|------|
| `workflows/blackbox_single_domain.md` | One domain, no creds |
| `workflows/greybox_authenticated.md`  | One domain, with creds |
| `workflows/multi_domain_parallel.md`  | ≥2 domains, one-shot |
| `workflows/continuous_scanning.md`    | Scheduled / CI recurring |

## Methodology Index

| File | Phase |
|------|-------|
| `methodology/recon.md`        | Phase 0 — surface discovery |
| `methodology/crawling.md`     | Phase 1 — Playwright BFS + auth |
| `methodology/vuln_testing.md` | Phase 2 — injection, authz, logic |
| `methodology/reporting.md`    | Phase 3 — output artifacts & gating |

## Payloads Index

| File | Content |
|------|---------|
| `payloads/xss_contexts.txt`       | HTML, attribute, JS, URL, WAF-bypass XSS |
| `payloads/sqli.txt`               | Auth-bypass, error, time, boolean, union, sqlmap flags |
| `payloads/ssrf_cloud_metadata.txt`| AWS/GCP/Azure/K8s metadata URLs, IP bypass |
| `payloads/path_traversal.txt`     | Unix/Windows traversal, CVE patterns, target files |
| `payloads/crlf_smuggling.txt`     | CRLF header injection, CL.TE/TE.CL smuggling |
| `payloads/jwt_attacks.txt`        | alg:none, key confusion, kid/jku, weak HMAC |
| `payloads/business_logic.txt`     | Price, workflow skip, race, IDOR, mass assignment |

## References Index

| File | Content |
|------|---------|
| `references/hackerone_attack_patterns.md`    | 6,894 HackerOne patterns across 157 categories (pointer — don't inline) |
| `references/bounty_patterns_2024_2026.md`    | Post-2023 bounty TTPs (TE.0 smuggling, HTTP/2 CONNECT scan, WAFFLED parser bypass, SVG/popover XSS, base64-SSRF, prototype pollution, cache deception) |
| `references/advanced_exploitation_techniques.md` | OS-tool deep dives (sqlmap, nuclei, jwt_tool, etc.) |
| `references/dast_methodology.md`             | Full long-form methodology |
| `references/playwright_security_patterns.md` | Playwright-specific security patterns |
| `references/vulnerability_testing.md`        | Exhaustive vuln-class test catalogue |
| `references/tool_configuration.md`           | Per-tool config templates |
| `references/api_testing.md`                  | API-specific DAST |
| `references/reporting_guide.md`              | Long-form report customization |

## Examples Index

| File | Scenario |
|------|----------|
| `examples/blackbox_basic.md`         | Single-domain blackbox tool-call blueprint |
| `examples/greybox_multi_domain.md`   | Authenticated multi-domain with sub-agents |
| `examples/continuous_setup.md`       | Setting up scheduled scans |
| `examples/github_actions_dast.yml`   | Drop-in CI workflow |

## Tools

| Name | Purpose | Install |
|------|---------|---------|
| Playwright MCP      | Browser automation, crawling, auth, evidence | MCP server in Claude config |
| nmap                | Port/service discovery | `apt install nmap` |
| subfinder           | Passive subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| whatweb             | Tech fingerprinting | `apt install whatweb` |
| ffuf                | Content discovery | `go install github.com/ffuf/ffuf/v2@latest` |
| nuclei              | CVE / misconfig / panel templates | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| sqlmap              | Automated SQLi | `apt install sqlmap` |
| nikto               | Web-server misconfig (optional) | `apt install nikto` |
| jwt_tool            | JWT attacks | `pip install jwt_tool` |
| interactsh-client   | OOB exfil for SSRF/blind RCE | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |

Helper scripts live under `scripts/` (entry points: `playwright_dast_scanner.py`, `dast_orchestrator.py`, `check_findings.py`).

## Last Validated

- Date: 2026-04
- Minimum versions: Playwright ≥ 1.45, nuclei ≥ 3.2, sqlmap ≥ 1.8, ffuf ≥ 2.1, Python ≥ 3.12.
- Requires Playwright MCP to be configured and reachable before greybox scans.
