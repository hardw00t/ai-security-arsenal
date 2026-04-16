# Example: GraphQL Mutation BOLA Finding Blueprint

```json
{
  "id": "APISEC-2026-003",
  "title": "GraphQL updateUser mutation allows role change on other users",
  "severity": "critical",
  "confidence": "confirmed",
  "cwe": "CWE-639",
  "owasp": "API1:2023",
  "owasp_api_id": "API1:2023",
  "cvss": 9.0,
  "endpoint": "/graphql",
  "http_method": "POST",
  "api_type": "graphql",
  "auth_context": "cross-user",
  "evidence": {
    "graphql_query": "mutation { updateUser(id: \"userB-uuid\", input: { role: \"admin\" }) { id role } }",
    "request": "POST /graphql HTTP/1.1\nHost: target.tld\nAuthorization: Bearer <userA_token>\nContent-Type: application/json\n\n{\"query\":\"mutation { updateUser(id: \\\"userB-uuid\\\", input: { role: \\\"admin\\\" }) { id role } }\"}",
    "response": "HTTP/1.1 200 OK\n\n{\"data\":{\"updateUser\":{\"id\":\"userB-uuid\",\"role\":\"admin\"}}}"
  },
  "reproduction": [
    "Authenticate as userA.",
    "Issue mutation { updateUser(id: \"<userB-id>\", input: { role: \"admin\" }) { id role } }.",
    "Observe successful update of another user's role."
  ],
  "remediation": "Enforce per-object authorization in resolvers. updateUser must verify the caller is either the target user or has administrative rights. Prefer centralizing checks with a GraphQL Shield / authorization directive rather than per-resolver ad-hoc code.",
  "references": [
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "https://cwe.mitre.org/data/definitions/639.html"
  ]
}
```
