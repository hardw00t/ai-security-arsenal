# Bug Bounty Patterns 2024-2026 — dast-automation

## Overview

Post-2023 offensive web patterns from PortSwigger "Top 10 Web Hacking Techniques" 2024 & 2025,
Akamai / Sysdig WAF research, the WAFFLED (arXiv:2503.10846) study, and individual researcher
disclosures. Last validated: 2026-04. Emit findings via `../schemas/finding.json`. This file
complements — does not replace — `hackerone_attack_patterns.md`.

## Pattern Index

| #   | Pattern                                                       | Severity | Primary Source                        |
|-----|---------------------------------------------------------------|----------|---------------------------------------|
| P21 | TE.0 / 0.CL HTTP Request Smuggling                            | Critical | PortSwigger Top 10 2024 — "TE.0"      |
| P22 | HTTP/2 CONNECT-method internal port scanning                   | High     | PortSwigger Top 10 2025               |
| P23 | WAF Bypass via Parser Discrepancies (WAFFLED)                 | Critical | arXiv:2503.10846 (2025)               |
| P24 | SVG / Popover-Event WAF XSS Evasion                           | High     | Sysdig Research 2024                  |
| P25 | BreakingWAF — Base64-Encoded SSRF in Headers                  | High     | Akamai / BreakingWAF 2024-2025        |
| PA  | Prototype Pollution — DOMPurify Bypass                        | High     | PortSwigger Top 10 2024 · CVE-2024-45801 |
| PC  | Cache Deception via Path-Traversal (ChatGPT ATO)              | High     | PortSwigger Top 10 2024 — Harel       |

---

## Patterns

### P21. TE.0 / 0.CL HTTP Request Smuggling

- **CVE / Source:** PortSwigger "Top 10 Web Hacking Techniques 2024" — "Unveiling TE.0 HTTP Request Smuggling" (affected thousands of Google Cloud-hosted sites).
- **Summary:** Front-end parses `Transfer-Encoding`, back-end treats request as `Content-Length: 0` (or vice-versa), desync injects a secondary request into the next client's connection. Variants: `TE.0`, `0.CL`, `CL.0` — beyond the classic `CL.TE`/`TE.CL`.
- **Affected surface:** Any chain front-end ↔ back-end where parser differs: GCP LB → backend, Cloudfront → origin, nginx → uvicorn, K8s Ingress → pod.
- **Detection (automated):**
  - Use Burp's HTTP Request Smuggler (TE.0 and 0.CL modes) against every unique front-end/back-end pair.
  - Supplement with `smuggler.py` / `h2cSmuggler` for HTTP/2 downgrade cases.
  - Distinguish timeout-based oracle from differential-response oracle to avoid false positives.
- **Exploitation / PoC:**
  ```http
  POST / HTTP/1.1
  Host: target.tld
  Content-Length: 0
  Transfer-Encoding: chunked

  0

  SMUGGLED GET /admin HTTP/1.1
  X-Ignore: X
  ```
  (Do not run against unowned infra; use lab replicas.)
- **Indicators:** Mismatched request counts between front-end and origin logs; admin requests showing a prior-client IP.
- **Mitigation:** Normalize front-end ↔ back-end parser behavior; reject ambiguous `TE`+`CL` messages; use HTTP/2 end-to-end; disable HTTP/1.1 downgrade where possible.
- **Cross-refs:** CWE-444; related → P22.

### P22. HTTP/2 CONNECT Internal Port Scanning

- **CVE / Source:** PortSwigger "Top 10 2025" — "Playing with HTTP/2 CONNECT".
- **Summary:** HTTP/2 CONNECT method, reintroduced in many front-ends for WebSockets over H2, can target arbitrary `authority:port`, giving attackers an authenticated tunnel into internal services via the public edge.
- **Affected surface:** LBs / API gateways advertising ALPN `h2` with CONNECT enabled (HAProxy, nginx w/ experimental H2, Envoy defaults).
- **Detection (automated):**
  ```bash
  # nghttp2 client
  nghttp -v -m 1 https://target.tld --header=':method: CONNECT' --header=':authority: 127.0.0.1:6379'
  ```
  Iterate private ranges + common service ports (`22,80,443,6379,9200,11211,2375,5984`).
- **Exploitation / PoC:** Successful 200 frame + subsequent DATA frames = tunnel open; use to reach Redis / Consul / Docker socket.
- **Indicators:** Edge logs show CONNECT frames with `:authority:` set to private IP / loopback.
- **Mitigation:** Disable CONNECT at the edge unless explicitly needed; deny `:authority` to RFC1918 / loopback / metadata.
- **Cross-refs:** CWE-441; related → P15.

### P23. WAF Bypass via Parser Discrepancies (WAFFLED)

- **CVE / Source:** "WAFFLED" research — arXiv:2503.10846 (2025). 1207 bypasses across AWS WAF, Azure WAF, Cloud Armor, Cloudflare, ModSecurity.
- **Summary:** Content-type, boundary, and encoding edge cases produce different parser outputs in the WAF vs. the application. Example: multipart boundary with trailing whitespace, duplicate `Content-Type`, chunked-body with body-size mismatch — WAF sees a benign body; backend sees the real payload.
- **Affected surface:** All WAFs in inline-proxy deployment; especially effective against signature-first WAFs.
- **Detection (automated):**
  - Fuzz Content-Type variants: `application/json; charset=utf-7`, `multipart/form-data; boundary=--a`, `application/xml`, `text/plain` with JSON body.
  - Differential: submit the same malicious payload under 20 content-type variants; observe which pass WAF and which are blocked.
  - Replay known SQLi / XSS payloads under altered framing (HTTP pipelining, chunked framing with extra whitespace).
- **Exploitation / PoC:**
  ```http
  POST /api/item HTTP/1.1
  Host: target.tld
  Content-Type: application/json ; charset=utf-7
  Content-Length: 45

  {"q":"+ADw-script+AD4-alert(1)+ADw-/script+AD4-"}
  ```
- **Indicators:** WAF reports benign content-type; app WAF logs mismatch vs. app logs.
- **Mitigation:** Move to semantic / reverse-tokenizing WAFs (e.g., Coraza body inspection, ML-augmented parsers); strict Content-Type allow-list at origin; canonicalize encoding before WAF inspection.
- **Cross-refs:** CWE-436 (parser mismatch); related → P24, P25.

### P24. SVG / Popover-Event WAF XSS Evasion

- **CVE / Source:** Sysdig Research 2024 — AWS WAF bypass via HTML5 popover (`onbeforetoggle`) event and SVG internal tags.
- **Summary:** Legacy WAF XSS rules match `onerror`, `onload`, `alert(`, `<script>`, `javascript:`. New HTML5 event attributes (`onbeforetoggle`, `onbeforematch`, `ontoggle`) and SVG animate primitives bypass signatures while still executing in browsers.
- **Affected surface:** AWS WAF managed rules pre-2024 baseline; ModSecurity CRS < 4.0 without OWASP-CRS anomaly scoring; hand-rolled regex filters.
- **Detection (automated):**
  - Probe each parameter with the [modern XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) focusing on: `<details open ontoggle=>`, `<xmp popover ontoggle=>`, `<svg><animate attributeName=onbegin values=alert(1)>`.
  - Use `dalfox --custom-payload` with the 2024-2025 cheatsheet.
- **Exploitation / PoC:**
  ```html
  <div popover id=p ontoggle=alert(1)></div>
  <button popovertarget=p>x</button>

  <svg><set attributeName="onload" to="alert(1)"/></svg>
  ```
- **Indicators:** WAF block rate drops for these token classes; XSS verified in downstream proof.
- **Mitigation:** Upgrade managed WAF rules; defence-in-depth via CSP (`default-src 'self'; script-src 'self'`); output encoding at render.
- **Cross-refs:** CWE-79; related → P23.

### P25. BreakingWAF — Base64-Encoded SSRF in Headers

- **CVE / Source:** Akamai threat research; BreakingWAF tooling adopted across 2024-2025 red-team engagements.
- **Summary:** WAFs inspect only the decoded form of a small set of headers; hiding the SSRF URL base64-encoded inside `Referer`, `X-Forwarded-For`, or a custom header that the application decodes at the proxy layer bypasses the rule.
- **Affected surface:** Apps that Base64-decode headers server-side (tracking tokens, `Authorization: Basic`, SSO-state blobs) before making an egress HTTP call.
- **Detection (automated):**
  - Enumerate every header the application reflects or acts upon; test Base64 + URL-encoded + hex-encoded payloads.
  - Chain with an out-of-band callback host (Interactsh / Collaborator) to confirm SSRF.
- **Exploitation / PoC:**
  ```http
  GET /fetch HTTP/1.1
  Host: target.tld
  Referer: aHR0cDovLzE2OS4yNTQuMTY5LjI1NC9sYXRlc3QvbWV0YS1kYXRhLw==
  ```
- **Indicators:** Outbound request to `169.254.169.254` / internal IP originating from a request whose on-wire body looked benign.
- **Mitigation:** Decode headers before WAF inspection; enforce layered SSRF defence at egress.
- **Cross-refs:** CWE-918; related → P15, P23.

### PA. Prototype Pollution — DOMPurify Bypass (CVE-2024-45801)

- **CVE / Source:** PortSwigger "Top 10 2024"; CVE-2024-45801 (DOMPurify < 3.0.8).
- **Summary:** Polluting `Object.prototype` before DOMPurify initialization (via a cold-path config merge) lets attacker override internal allow-lists, enabling stored XSS through otherwise-sanitized input.
- **Affected surface:** Any SPA using DOMPurify < 3.0.8 with untrusted config merges; config loaders that recursively deep-merge JSON.
- **Detection (automated):**
  - Static: grep for `Object.assign(x, y)` / `lodash.merge` / `_.defaultsDeep` touching untrusted input.
  - Dynamic: fuzz `__proto__`, `constructor.prototype`, `__proto__[ALLOWED_TAGS]` into JSON inputs; re-render content through DOMPurify.
- **Exploitation / PoC:**
  ```js
  Object.prototype.ALLOWED_TAGS = ['script'];
  DOMPurify.sanitize('<script>alert(1)</script>'); // now passes
  ```
- **Indicators:** Post-sanitizer HTML contains tags that should be stripped; CSP violation reports for inline script.
- **Mitigation:** Upgrade DOMPurify ≥ 3.0.8; `Object.freeze(Object.prototype)`; safe merge (`structuredClone` + allow-list keys).
- **Cross-refs:** CWE-1321, CWE-79; related → SAST rule in `../../sast-orchestration/references/bounty_patterns_2024_2026.md`.

### PC. Cache Deception via Path-Traversal (ChatGPT Account Takeover)

- **CVE / Source:** PortSwigger "Top 10 2024" — Harel; chain demonstrated against ChatGPT.
- **Summary:** Wildcard cache rules (e.g., cache any `*.css`, `*.js`) combined with path-traversal paths (`/api/me/../me.css`) cache authenticated response bodies under an unauthenticated key; the next anonymous request retrieves a prior user's data.
- **Affected surface:** Any CDN / reverse-proxy with extension-based caching and a normalization mismatch between CDN and origin.
- **Detection (automated):**
  - Fetch `/api/me` vs `/api/me/a.css`, `/api/me;foo.css`, `/api/me/%2e%2e/me.css` and diff responses; look for any static-looking suffix yielding sensitive JSON.
  - Capture `Cache-Control` / `X-Cache` headers; note edge caching without `Vary: Authorization`.
- **Exploitation / PoC:**
  ```http
  GET /api/me/x.css HTTP/1.1
  Authorization: Bearer VICTIM
  ```
  Followed by anonymous:
  ```http
  GET /api/me/x.css HTTP/1.1
  ```
- **Indicators:** Edge cache HIT on authenticated endpoints; responses served to user A containing user B's data.
- **Mitigation:** Normalize path at edge identical to origin; cache only explicitly marked-public responses; require `Vary: Authorization, Cookie` for any cached 2xx.
- **Cross-refs:** CWE-525; related → P21, P23.

---

## Cross-skill links
- API: OAuth/JWT chains that cache-deception amplifies — `../../api-security/methodology/bounty_patterns_2024_2026.md`.
- Cloud: SSRF to metadata — `../../cloud-security/references/bounty_patterns_2024_2026.md` (P15).
- SAST: prototype-pollution / ORM leakage detection rules — `../../sast-orchestration/references/bounty_patterns_2024_2026.md`.
