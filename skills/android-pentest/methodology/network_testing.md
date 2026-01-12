# Network Security Testing Methodology

Network security testing focuses on analyzing the application's communication with backend servers, including transport security, API security, and data validation.

---

## Transport Layer Security

### TLS Configuration Testing

```bash
# Test server TLS configuration with testssl.sh
testssl.sh api.target.com

# Test with nmap
nmap --script ssl-enum-ciphers -p 443 api.target.com

# Test with sslyze
sslyze --regular api.target.com
```

### Certificate Pinning Verification

```python
# 1. First, test with pinning intact
pid = frida_spawn("com.target.app")
# Try to intercept - should fail if pinning works

# 2. Then bypass pinning
frida_bypass_ssl(pid)
# Now intercept - should work

# If bypass works, document the finding
# If app still fails, pinning may be native or custom
```

### Network Security Config Analysis

```xml
<!-- Check res/xml/network_security_config.xml -->

<!-- Vulnerable: Allows cleartext -->
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">api.target.com</domain>
</domain-config>

<!-- Vulnerable: Trusts user certificates -->
<base-config>
    <trust-anchors>
        <certificates src="user"/>
        <certificates src="system"/>
    </trust-anchors>
</base-config>

<!-- Secure: Certificate pinning -->
<domain-config>
    <domain includeSubdomains="true">api.target.com</domain>
    <pin-set expiration="2025-01-01">
        <pin digest="SHA-256">base64EncodedPinHere=</pin>
    </pin-set>
</domain-config>
```

---

## Traffic Interception Setup

### Burp Suite Configuration

```python
# 1. Configure device proxy
setup_proxy("device-id", "192.168.1.100", 8080)

# 2. Install Burp CA certificate
install_ca_cert("device-id", "/path/to/burp-ca.der")

# 3. Bypass SSL pinning
pid = frida_spawn("com.target.app")
frida_bypass_ssl(pid)

# 4. Configure Burp:
# - Proxy listener on 192.168.1.100:8080 (all interfaces)
# - Enable invisible proxying
# - Add target to scope
```

### mitmproxy Configuration

```bash
# Start mitmproxy
mitmproxy -p 8080 --mode transparent

# Or with web interface
mitmweb -p 8080

# Install CA certificate on device
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
# Install via Settings > Security > Install certificate
```

### Packet Capture

```python
# Using MCP tool
capture_traffic_start("com.target.app")
# ... interact with app ...
capture_traffic_stop()

# Or via ADB
# adb shell "su -c 'tcpdump -i any -w /sdcard/capture.pcap'"
# adb pull /sdcard/capture.pcap
```

---

## API Security Testing

### Authentication Testing

```
# Test in Burp Suite:

1. Credential Bruteforce
   - Is rate limiting implemented?
   - Account lockout after failed attempts?

2. Token Analysis
   - JWT structure and claims
   - Token expiration
   - Token reuse after logout

3. Session Management
   - Session timeout
   - Concurrent session handling
   - Session fixation
```

### Authorization Testing (BOLA/IDOR)

```
# Test object-level authorization:

1. Enumerate IDs
   - Sequential IDs: /api/users/1, /api/users/2, etc.
   - UUIDs: Try to guess or enumerate

2. Access Control
   - Can user A access user B's resources?
   - Modify ID in request: /api/orders/123 → /api/orders/456

3. Privilege Escalation
   - Change role parameter
   - Access admin endpoints
```

### Input Validation Testing

```
# Injection Testing:

1. SQL Injection
   - ' OR '1'='1
   - 1; DROP TABLE users--
   - UNION SELECT attacks

2. NoSQL Injection
   - {"$ne": null}
   - {"$gt": ""}

3. Command Injection
   - ; id
   - | cat /etc/passwd
   - `whoami`

4. Path Traversal
   - ../../../etc/passwd
   - ..\..\..\..\windows\system32\config\sam
```

### Data Exposure Testing

```
# Check responses for:

1. Sensitive Data
   - Passwords in responses
   - API keys
   - Internal IPs
   - Debug information

2. Excessive Data
   - More fields than necessary
   - Internal IDs
   - User PII

3. Error Messages
   - Stack traces
   - SQL errors
   - Internal paths
```

---

## WebSocket Testing

### Monitoring WebSocket Traffic

```javascript
frida_run_script(pid, """
Java.perform(function() {
    // Hook OkHttp WebSocket
    var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');

    RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
        console.log('[WS SEND] ' + text);
        return this.send(text);
    };

    RealWebSocket.send.overload('okio.ByteString').implementation = function(bytes) {
        console.log('[WS SEND BINARY] ' + bytes.hex());
        return this.send(bytes);
    };

    // Hook message receive
    var WebSocketListener = Java.use('okhttp3.WebSocketListener');
    WebSocketListener.onMessage.overload('okhttp3.WebSocket', 'java.lang.String').implementation = function(ws, text) {
        console.log('[WS RECV] ' + text);
        return this.onMessage(ws, text);
    };
});
""")
```

### WebSocket Security Tests

```
1. Authentication
   - Is auth required for connection?
   - Token in headers vs. query string

2. Authorization
   - Can user subscribe to unauthorized channels?
   - Message-level authorization

3. Input Validation
   - Injection in message payload
   - Malformed messages

4. Rate Limiting
   - Message flooding
   - Connection limits
```

---

## Network-Level Attacks

### Man-in-the-Middle Testing

```bash
# With SSL pinning bypassed, test:

1. Request/Response Tampering
   - Modify prices in shopping apps
   - Change user IDs
   - Alter permissions

2. Replay Attacks
   - Capture and replay transactions
   - Duplicate requests

3. Downgrade Attacks
   - Force HTTP instead of HTTPS
   - Weak cipher selection
```

### DNS Testing

```bash
# Check for DNS leakage
adb shell "su -c 'cat /proc/net/dns'"

# Test DNS rebinding
# Configure DNS to resolve to internal IP after TTL
```

---

## Network Testing Checklist

### Transport Security
- [ ] TLS version (1.2 or 1.3 required)
- [ ] Cipher suites (no weak ciphers)
- [ ] Certificate validation
- [ ] Certificate pinning
- [ ] No cleartext traffic
- [ ] HSTS enabled

### API Security
- [ ] Authentication tested
- [ ] Authorization (BOLA/IDOR) tested
- [ ] Input validation tested
- [ ] Rate limiting verified
- [ ] Error handling reviewed
- [ ] Data exposure checked

### WebSocket Security
- [ ] Authentication required
- [ ] Authorization per channel
- [ ] Input validation
- [ ] Rate limiting

### Network Configuration
- [ ] Network security config reviewed
- [ ] No debug traffic
- [ ] No hardcoded endpoints
- [ ] Certificate storage secure

---

## Common Findings

| Finding | Severity | MASTG Reference |
|---------|----------|-----------------|
| No certificate pinning | Medium | MASTG-TEST-0021 |
| Cleartext traffic allowed | High | MASTG-TEST-0019 |
| Weak TLS configuration | Medium | MASTG-TEST-0020 |
| IDOR vulnerabilities | High | MASTG-TEST-0023 |
| Missing rate limiting | Medium | MASTG-TEST-0024 |
| Sensitive data in responses | High | MASTG-TEST-0025 |
| JWT not validated | Critical | MASTG-TEST-0026 |
