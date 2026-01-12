# Finding Template

Use this template to document individual vulnerabilities discovered during testing.

---

## [FINDING-XXX] [Descriptive Title]

### Metadata

| Field | Value |
|-------|-------|
| **Finding ID** | FINDING-XXX |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS Score** | X.X |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Status** | Open / Remediated / Accepted Risk |
| **Component** | [Affected component/file/function] |
| **MASTG Reference** | MASTG-TEST-XXXX |
| **CWE** | CWE-XXX ([CWE Name]) |
| **OWASP Mobile Top 10** | M1-M10 |

---

### Description

[Provide a clear, concise description of the vulnerability. Explain what the issue is and why it matters from a security perspective. This should be understandable by both technical and non-technical readers.]

---

### Technical Details

[Provide detailed technical information about the vulnerability, including:
- Exact location (file path, class name, method)
- Vulnerable code or configuration
- How the vulnerability was discovered
- Technical root cause]

**Affected Location:**
```
/data/data/com.target.app/[path]
```

**Vulnerable Code/Configuration:**
```java
// Example vulnerable code
public void storeCredentials(String password) {
    SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
    prefs.edit().putString("password", password).apply();  // Plaintext!
}
```

---

### Steps to Reproduce

1. [First step with exact commands/actions]
2. [Second step]
3. [Third step]
4. [Observe the vulnerability]

**Commands Used:**
```bash
# MCP tool
dump_shared_prefs("com.target.app")

# or ADB
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/auth.xml'"
```

**Frida Script (if applicable):**
```javascript
Java.perform(function() {
    // Hook code here
});
```

---

### Evidence

#### Screenshot 1: [Description]
[Insert screenshot or reference to evidence file]

#### Log Output
```
[Relevant log output or tool output]
```

#### Request/Response (if applicable)
```http
POST /api/login HTTP/1.1
Host: api.target.com
Content-Type: application/json

{"username": "test", "password": "test123"}
```

---

### Impact

[Describe the potential impact of this vulnerability if exploited. Consider:
- Confidentiality impact
- Integrity impact
- Availability impact
- Business impact
- Affected users/data]

**Potential Attack Scenarios:**

1. **Scenario 1**: An attacker with physical device access could...
2. **Scenario 2**: A malicious app on the same device could...
3. **Scenario 3**: Through ADB backup, an attacker could...

---

### Remediation

#### Recommended Fix

[Provide specific, actionable remediation steps]

1. [First remediation step]
2. [Second remediation step]
3. [Third remediation step]

#### Secure Code Example

```java
// Secure implementation
import androidx.security.crypto.EncryptedSharedPreferences;

public void storeCredentials(String token) {
    SharedPreferences prefs = EncryptedSharedPreferences.create(
        "auth_secure",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    );
    prefs.edit().putString("token", token).apply();
}
```

#### References

- [OWASP MASTG - Testing Local Storage](https://mas.owasp.org/MASTG/...)
- [Android Security Documentation](https://developer.android.com/security/...)
- [Relevant CVE if applicable]

---

### Timeline

| Date | Action |
|------|--------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Reported to client |
| YYYY-MM-DD | Remediation implemented |
| YYYY-MM-DD | Fix verified |

---

### Notes

[Any additional notes, considerations, or context that may be helpful]

---

## Severity Rating Guide

| Severity | CVSS Range | Description |
|----------|------------|-------------|
| Critical | 9.0 - 10.0 | Direct system compromise, widespread impact |
| High | 7.0 - 8.9 | Significant security impact, data exposure |
| Medium | 4.0 - 6.9 | Moderate impact, requires specific conditions |
| Low | 0.1 - 3.9 | Minor impact, limited exposure |
| Info | 0.0 | Best practice recommendation |
