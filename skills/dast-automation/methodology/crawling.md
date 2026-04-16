# Phase 1: Playwright-Driven Crawling

Use Playwright MCP to execute JavaScript, trigger SPA routes, and capture *all* network traffic — including requests that static crawlers miss (XHR, fetch, WebSocket, GraphQL, service-worker, beacon).

## Blackbox crawl flow

1. Launch isolated browser context per target.
2. Enable request interception; log every request to `network.ndjson`.
3. Navigate to the root URL; wait for `networkidle`.
4. Extract:
   - All `<a href>`, `<form action>`, `<script src>`
   - Inline JS regex-scanned for `/api/` / `fetch(` / `XMLHttpRequest` / GraphQL operation strings
   - Source maps (`*.map`) for routed SPA URLs
5. BFS-click through nav, menus, accordions, tabs up to depth 3.
6. Submit forms with benign markers (`asdf-probe-<uuid>`) to discover back-end handlers.
7. Diff network log against recon `paths[]` — capture endpoints that only appear at runtime.

## Greybox crawl flow (authenticated)

**Auth MUST complete before crawl.** Do not attempt to parallelize auth with crawl.

1. Navigate to login page.
2. Fill credentials via Playwright (detect reCAPTCHA / 2FA early — abort with guidance to operator).
3. Verify authenticated state (presence of logout link / user menu / session cookie).
4. Persist storage state (`context.storageState()`) to JSON for reuse across browser contexts.
5. **Then** run the blackbox crawl flow with the stored state attached to every new context.
6. Re-validate auth mid-crawl; detect session expiry and re-authenticate.
7. If multiple accounts were provided (low-priv + high-priv), crawl **each in its own context** to support IDOR/authz diff.

## What to capture

| Artifact | Purpose |
|----------|---------|
| `endpoints.jsonl` | Unique (method, URL, param schema) for fuzzing |
| `forms.jsonl` | Action + fields + CSRF-token names for CSRF/XSS tests |
| `graphql_ops.json` | Operation name + variables (feed to `graphql-cop`) |
| `websocket.jsonl` | WS URLs + first messages |
| `screenshots/` | Per-route screenshots for report evidence |
| `storageState.json` | Reusable auth state (greybox) |
| `api_spec.json` | Inferred OpenAPI skeleton (feed to nuclei `http/vulnerabilities/generic/`) |

## Scope & safety

- Honor `robots.txt` unless operator explicitly says otherwise.
- Exclude destructive routes (`/logout`, `/delete`, `/purge`, `/admin/reset`) from the click-BFS — annotate but don't trigger.
- Rate-limit via Playwright `await page.waitForTimeout(...)` or a request throttler; default ≤ 5 req/s.

## Handoff to vulnerability testing

Produce `crawl_summary.json`:

```json
{
  "target": "https://app.example.com",
  "mode": "greybox",
  "auth_user": "user@test.com",
  "endpoints_count": 412,
  "forms_count": 37,
  "graphql_count": 1,
  "output_dir": "results/app.example.com/crawl/"
}
```

`methodology/vuln_testing.md` consumes the `endpoints.jsonl` + `forms.jsonl` produced here.
