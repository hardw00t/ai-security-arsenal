# Example: Blackbox scan, one domain

**User:** "Scan https://example.com for vulnerabilities."

## Tool-call blueprint

1. Ask operator for scope confirmation and out-of-scope paths (if ambiguous).
2. `Bash` → parallel recon (see `workflows/blackbox_single_domain.md` step 2).
3. Playwright MCP → launch context, navigate, BFS-crawl, emit `crawl/endpoints.jsonl`.
4. For each injection class (XSS, SQLi, SSRF, path traversal, CRLF), iterate `payloads/*.txt` against discovered inputs.
5. `Bash` → `nuclei -l endpoints.txt ...` for CVE/misconfig overlay.
6. Manually re-verify Critical/High.
7. `Write` → `results/example.com/output.json` conforming to `schemas/finding.json`.

## Minimal state-tracking

```
results/example.com/
  crawl/endpoints.jsonl   # from Playwright
  crawl/forms.jsonl
  recon/nmap.txt
  recon/nuclei-root.jsonl
  output.json             # final
```

## Report back to operator

- Count by severity.
- Top 3 risks with one-line description each.
- Path to `output.html`.

Do **not** paste every finding inline; link to the structured output.
