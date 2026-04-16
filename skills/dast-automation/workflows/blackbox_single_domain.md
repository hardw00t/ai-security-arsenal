# Workflow: Blackbox single-domain DAST

**Trigger:** "Scan https://target.com for vulnerabilities" / "blackbox DAST on <domain>".

**Duration:** 15–60 min depending on surface size.

**Precondition:** Written scope authorization.

## Step plan

```
┌────────────────────────────────┐
│ 1. Confirm scope w/ operator   │  (ask for out-of-scope paths)
├────────────────────────────────┤
│ 2. Phase 0 — Recon (parallel)  │  methodology/recon.md
│    nmap + whatweb + ffuf       │
│    + nuclei (root) + subfinder │
├────────────────────────────────┤
│ 3. Phase 1 — Crawl             │  methodology/crawling.md
│    Playwright MCP → BFS click  │
│    + form probe                │
├────────────────────────────────┤
│ 4. Phase 2 — Vuln testing      │  methodology/vuln_testing.md
│    XSS, SQLi, SSRF, traversal, │
│    CRLF, open redirect, CSRF   │
│    (can parallelize by class)  │
├────────────────────────────────┤
│ 5. Nuclei overlay on endpoints │
├────────────────────────────────┤
│ 6. Manual re-verify Crit/High  │
├────────────────────────────────┤
│ 7. Emit schemas/finding.json + │  methodology/reporting.md
│    output.html + output.md     │
└────────────────────────────────┘
```

## Commands you'll actually run

```bash
# Step 2 — parallel recon
mkdir -p results/target/{crawl,evidence,screenshots}
subfinder -d target.com -silent -o results/target/subs.txt &
nmap -sV -sC -T4 target.com -oN results/target/nmap.txt &
whatweb -a 3 https://target.com --log-json results/target/whatweb.json &
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
     -o results/target/ffuf.json -of json &
nuclei -u https://target.com -severity critical,high,medium \
       -jsonl -o results/target/nuclei-root.jsonl &
wait

# Step 3 — Playwright crawl (via MCP; pseudo-code, invoke via tool)
# playwright_mcp.launch(url=https://target.com, mode=blackbox, depth=3)

# Step 5 — nuclei over discovered endpoints
nuclei -l results/target/crawl/endpoints.txt \
       -severity critical,high,medium \
       -jsonl -o results/target/nuclei-endpoints.jsonl
```

## Decision gates

- **No endpoints discovered:** check for SPA blocking Playwright; fall back to `wget --spider` + `katana`.
- **WAF blocking:** reduce rate; switch to `--tamper` set when running sqlmap; do not bypass without authorization.
- **Rate-limit errors (429):** pause scan, coordinate with operator, do not auto-retry from new IPs.

## Output

`results/target.com/output.json` conforming to `schemas/finding.json`.

## Related

- Greybox auth: `workflows/greybox_authenticated.md`
- Many targets: `workflows/multi_domain_parallel.md`
- Scheduled re-runs: `workflows/continuous_scanning.md`
