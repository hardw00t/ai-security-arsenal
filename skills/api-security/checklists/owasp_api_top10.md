# OWASP API Security Top 10 2023 Testing Checklist

## Pre-Assessment Setup
- [ ] Identify all API endpoints (documentation, traffic analysis, JS extraction)
- [ ] Obtain authentication credentials for different roles
- [ ] Configure proxy for traffic interception
- [ ] Set up testing environment

---

## API1:2023 - Broken Object Level Authorization (BOLA)

### Testing Steps
- [ ] Identify endpoints with object references (IDs, UUIDs)
- [ ] Test horizontal access: User A accessing User B's resources
- [ ] Test vertical access: Regular user accessing admin resources
- [ ] Test ID enumeration (sequential, predictable patterns)
- [ ] Test with different ID formats (int, UUID, encoded)
- [ ] Test object references in:
  - [ ] URL path parameters (/users/{id})
  - [ ] Query parameters (?user_id=123)
  - [ ] Request body (POST/PUT data)
  - [ ] Headers (custom headers with IDs)

### Payloads
```
/users/1 → /users/2
/orders/{myOrderId} → /orders/{otherOrderId}
?id=123 → ?id=124
{"user_id": 1} → {"user_id": 2}
```

### Findings Template
```
Title: BOLA - [Endpoint]
Severity: Critical/High
Endpoint: [URL]
Method: [GET/POST/etc]
Description: [Details]
PoC: [Steps to reproduce]
Impact: [Data exposure, etc]
```

---

## API2:2023 - Broken Authentication

### Testing Steps
- [ ] Identify all authentication endpoints
- [ ] Test credential stuffing/brute force resistance
- [ ] Check for weak password policies
- [ ] Test password reset functionality
- [ ] Analyze authentication tokens (JWT, session)
- [ ] Test for authentication bypass:
  - [ ] Missing auth on endpoints
  - [ ] Token manipulation
  - [ ] Algorithm confusion (JWT)
  - [ ] Session fixation
- [ ] Check multi-factor authentication
- [ ] Test API key security

### JWT Testing
- [ ] Decode and analyze header/payload
- [ ] Test 'none' algorithm attack
- [ ] Test algorithm confusion (RS256→HS256)
- [ ] Brute force weak secrets (HS256)
- [ ] Test 'kid' parameter injection
- [ ] Test 'jku'/'x5u' header injection
- [ ] Check expiration handling
- [ ] Test signature verification

### OAuth Testing
- [ ] Check redirect_uri validation
- [ ] Test state parameter (CSRF)
- [ ] Check authorization code reuse
- [ ] Test scope manipulation
- [ ] Check PKCE implementation

---

## API3:2023 - Broken Object Property Level Authorization

### Testing Steps
- [ ] Identify API responses with sensitive fields
- [ ] Check for excessive data exposure:
  - [ ] Password hashes in responses
  - [ ] Internal IDs/tokens
  - [ ] PII unnecessarily exposed
- [ ] Test mass assignment:
  - [ ] Add admin fields to requests
  - [ ] Modify read-only properties
  - [ ] Change user roles via API

### Mass Assignment Payloads
```json
{"username": "test", "role": "admin"}
{"username": "test", "is_admin": true}
{"username": "test", "balance": 999999}
{"username": "test", "verified": true}
```

---

## API4:2023 - Unrestricted Resource Consumption

### Testing Steps
- [ ] Test rate limiting on:
  - [ ] Authentication endpoints
  - [ ] Password reset
  - [ ] Resource-intensive operations
- [ ] Check pagination limits
- [ ] Test for denial of service:
  - [ ] Large file uploads
  - [ ] Complex queries
  - [ ] Batch operations
- [ ] Test GraphQL complexity attacks
- [ ] Check for resource exhaustion

### Rate Limit Bypass Techniques
- [ ] Header manipulation (X-Forwarded-For)
- [ ] Case variation in URLs
- [ ] Parameter pollution
- [ ] HTTP method override

---

## API5:2023 - Broken Function Level Authorization (BFLA)

### Testing Steps
- [ ] Identify admin/privileged endpoints
- [ ] Test access with regular user tokens:
  - [ ] Admin panels
  - [ ] User management
  - [ ] Configuration endpoints
- [ ] Test HTTP method changes (GET→DELETE)
- [ ] Check debug/internal endpoints
- [ ] Test role manipulation

### Common Admin Endpoints
```
/api/admin
/api/admin/users
/api/config
/api/settings
/api/internal
/api/debug
/admin
/manage
```

---

## API6:2023 - Unrestricted Access to Sensitive Business Flows

### Testing Steps
- [ ] Identify business-critical flows
- [ ] Test for automation abuse:
  - [ ] Mass account creation
  - [ ] Bulk purchasing
  - [ ] Content scraping
- [ ] Check anti-automation controls
- [ ] Test referral/voucher abuse
- [ ] Check for race conditions

### Business Logic Tests
- [ ] Voucher/coupon reuse
- [ ] Price manipulation
- [ ] Quantity manipulation
- [ ] Workflow bypass (skip steps)
- [ ] Currency confusion

---

## API7:2023 - Server Side Request Forgery (SSRF)

### Testing Steps
- [ ] Identify URL fetch functionality
- [ ] Test internal network access:
  - [ ] localhost/127.0.0.1
  - [ ] Internal IPs (10.x, 172.x, 192.168.x)
- [ ] Test cloud metadata access:
  - [ ] AWS: 169.254.169.254
  - [ ] GCP: metadata.google.internal
  - [ ] Azure: 169.254.169.254
- [ ] Test protocol smuggling (gopher, file, dict)
- [ ] Test bypass techniques

### Vulnerable Parameters
```
url=
uri=
path=
dest=
redirect=
next=
target=
webhook=
callback=
```

---

## API8:2023 - Security Misconfiguration

### Testing Steps
- [ ] Check security headers:
  - [ ] CORS configuration
  - [ ] Content-Type
  - [ ] X-Content-Type-Options
  - [ ] Strict-Transport-Security
- [ ] Test for verbose errors
- [ ] Check API documentation exposure
- [ ] Test default credentials
- [ ] Check unnecessary HTTP methods
- [ ] Verify TLS configuration

### Debug/Info Endpoints
```
/debug
/trace
/actuator
/.env
/config
/phpinfo
/server-status
/.git/config
```

---

## API9:2023 - Improper Inventory Management

### Testing Steps
- [ ] Identify all API versions
- [ ] Test deprecated/old API versions
- [ ] Check for undocumented endpoints
- [ ] Test staging/dev environments
- [ ] Check API gateway configuration
- [ ] Review API documentation

### Discovery Techniques
```
/api/v1/ vs /api/v2/
/api-dev/
/api-staging/
/internal-api/
```

---

## API10:2023 - Unsafe Consumption of APIs

### Testing Steps
- [ ] Identify third-party API integrations
- [ ] Test input validation from external sources
- [ ] Check for SSRF via redirects
- [ ] Test error handling from external APIs
- [ ] Verify TLS for external connections

---

## Post-Assessment
- [ ] Document all findings with PoC
- [ ] Classify severity (CVSS scoring)
- [ ] Provide remediation guidance
- [ ] Generate executive summary
- [ ] Schedule retest for critical findings
