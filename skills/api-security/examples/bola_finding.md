# Example: BOLA Finding Blueprint

A filled-in instance of `schemas/finding.json` for a BOLA exploit.

```json
{
  "id": "APISEC-2026-001",
  "title": "BOLA in GET /api/v1/users/{id} allows cross-user data read",
  "severity": "critical",
  "confidence": "confirmed",
  "cwe": "CWE-639",
  "owasp": "API1:2023",
  "owasp_api_id": "API1:2023",
  "cvss": 8.1,
  "endpoint": "/api/v1/users/{id}",
  "http_method": "GET",
  "api_type": "rest",
  "auth_context": "cross-user",
  "affected": {
    "service": "users-api",
    "version": "3.14.2"
  },
  "evidence": {
    "request": "GET /api/v1/users/456 HTTP/1.1\nHost: target.tld\nAuthorization: Bearer <userA_token>",
    "response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":456,\"email\":\"userb@example.com\",\"ssn\":\"XXX-XX-XXXX\"}"
  },
  "reproduction": [
    "Register userA (id=123) and userB (id=456).",
    "Authenticate as userA and capture bearer token.",
    "Send GET /api/v1/users/456 with userA token.",
    "Observe HTTP 200 with userB PII in body."
  ],
  "remediation": "Enforce object-level authorization: verify the authenticated principal is the owner of or explicitly permitted to read the target object. Prefer indirect references or ACL checks at the service layer, not just the gateway.",
  "references": [
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "https://cwe.mitre.org/data/definitions/639.html"
  ]
}
```
