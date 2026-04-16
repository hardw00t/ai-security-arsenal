# Phase 2: Vulnerability Testing

Drive tests from `crawl_summary.json`. Each sub-phase below can parallelize across endpoints; **within one endpoint**, run in the order listed because later tests depend on state established by earlier ones.

## Test ordering (per endpoint)

1. Authentication / session invariants (greybox only)
2. Injection class (XSS, SQLi, SSRF, path traversal, CRLF)
3. Authorization (IDOR, role escalation, tenant isolation)
4. Business logic (pricing, workflow skip, race)
5. Nuclei template pass (CVE/misconfig overlay)

## XSS

Feed each input field through `payloads/xss_contexts.txt`. For each payload:

1. Playwright navigate + fill + submit.
2. Dismiss dialogs automatically (`page.on('dialog', ...)`) and record fire.
3. Additionally inspect DOM for raw reflection (no-exec XSS is still reportable).
4. Re-test post-submit navigation pages (stored XSS).
5. Confirmation requires execution OR unambiguous unescaped reflection in a sink (innerHTML, src of script, href=javascript:).

## SQL Injection

1. Start with boolean/time payloads from `payloads/sqli.txt` (fast, low-noise).
2. If either returns a signal, hand off to sqlmap with the exact request:
   ```bash
   sqlmap -r request.txt --batch --level=3 --risk=2 --dbs
   ```
3. Do NOT run destructive flags (`--os-shell`, `--sql-shell`, `--file-write`) without explicit scope.

## SSRF

1. Test params listed in `payloads/ssrf_cloud_metadata.txt` → `COMMON_VULNERABLE_PARAMS`.
2. First probe with an **out-of-band** target (interactsh) — confirms egress without hitting cloud creds.
3. If OOB fires, then escalate to cloud metadata URLs.
4. Check all three providers (AWS/GCP/Azure) — some hosts are multi-cloud.
5. On IMDSv1 success, capture but **do not exfiltrate** credentials; include role name + partial ARN only.

## Path Traversal / LFI

1. Iterate `payloads/path_traversal.txt` against params with file-like names (`file=`, `path=`, `template=`, `page=`, `include=`, `download=`).
2. Confirm with a stable fingerprint (`/etc/passwd` → `root:x:0:0:`).
3. Escalate to log poisoning / RCE only under explicit scope.

## CSRF

For each state-changing form:

1. Capture legitimate request in Playwright.
2. Reissue from a fresh context (no cookies / cross-site).
3. If successful → CSRF. If blocked, check:
   - Token validation on replay (try omit / empty / cross-session token).
   - SameSite cookie attribute.
   - Origin/Referer header validation (spoof them).

## IDOR / Broken Authz (greybox)

Two-account pattern:

1. User A enumerates own object IDs (sequential, GUID, timestamp — see `payloads/business_logic.txt`).
2. User B attempts read/write on User A's IDs.
3. Same account, same method, swap `/users/<self>/...` → `/users/<other>/...`.
4. Report CRUD matrix: R / W / Delete across unauthorized objects.

## Business Logic

Requires **extended thinking** — see `payloads/business_logic.txt`. Don't automate blindly.

Mapping checkout, KYC, voucher, referral, or credit flows requires understanding *intent*:

- Diagram the happy path from crawl.
- For each state transition, ask: "What if I skip, replay, or re-order this?"
- Race conditions: Playwright `Promise.all([page.evaluate(fetch), ...×20])` or Turbo Intruder single-packet.

## Nuclei overlay

Run after endpoint enumeration completes:

```bash
nuclei -l endpoints.txt -t http/ -severity critical,high,medium \
       -jsonl -o nuclei-endpoints.jsonl -rate-limit 50
```

## False-positive filter

Before reporting, every High/Critical finding must have:

- Reproduction steps (≤ 10).
- Evidence artifact (request/response OR Playwright screenshot path).
- CWE + severity justification.
- One manual re-verification.

## Parallelism inside this phase

```
xss_scan      ──┐
sqli_probe    ──┤
ssrf_probe    ──┼─→ aggregate → nuclei overlay → report
csrf_probe    ──┤
path_trav     ──┘
```

Business-logic and IDOR are sequential with crawl+auth completion; don't start until `crawl_summary.json` is final.
