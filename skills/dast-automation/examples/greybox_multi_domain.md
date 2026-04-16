# Example: Greybox scan, multiple domains

**User:** "Test app.corp.com, api.corp.com, admin.corp.com as admin@corp.com / <pw>."

## Tool-call blueprint

1. Confirm scope + tier of account; ask for second (low-priv) account for IDOR.
2. Spawn **3 sub-agents via the Task tool**, one per domain. Each executes `workflows/greybox_authenticated.md`.
3. Each sub-agent:
   - Runs Phase 0 recon (parallel inside itself).
   - Logs in via Playwright, persists `storageState.json` in its own directory.
   - Runs authed crawl and vuln tests.
   - Writes `results/<domain>/output.json`.
4. Parent agent waits on all sub-agents.
5. `Bash` → merge per-domain outputs into `results/aggregate.json`.
6. Re-verify all Critical/High across all domains.
7. Return executive summary + path to aggregate output.

## Concurrency

- Max 5 parallel sub-agents; here we use 3 (domain count).
- Each sub-agent caps at 5 req/s.
- Auth is **sequential** inside each sub-agent; crawl is parallel across sub-agents.

## Multi-account pattern

If the operator supplies both `admin@corp.com` and `user@corp.com`:

- Run two sub-agents per target (one per account).
- The IDOR comparator then diffs object-ID reachability between the two storage states.

## Secrets handling

- Read credentials from env (`DAST_USER`, `DAST_PASS`) — never inline in tool calls.
- Scrub logs: `grep -r "$DAST_PASS" results/` must return nothing before delivery.
