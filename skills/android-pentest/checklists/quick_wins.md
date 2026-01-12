# Quick Wins Checklist

Fast vulnerability identification tests that often yield high-impact findings with minimal effort.

---

## 5-Minute Assessment

### 1. Check Debug Flag
```python
info = get_app_info("com.target.app")
# Look for: android:debuggable="true"
```
**Finding**: Debuggable application in production
**Severity**: Critical

### 2. Check Backup Flag
```python
info = get_app_info("com.target.app")
# Look for: android:allowBackup="true"
```
**Finding**: Backup enabled - data extractable
**Severity**: High

### 3. Dump SharedPreferences
```python
prefs = dump_shared_prefs("com.target.app")
# Search for: password, token, key, secret
```
**Finding**: Credentials stored in plaintext
**Severity**: Critical

### 4. Check Exported Components
```python
components = list_exported_components("com.target.app")
# Look for: exported=true without permission
```
**Finding**: Unprotected exported components
**Severity**: High

### 5. Test SSL Pinning
```python
pid = frida_spawn("com.target.app")
frida_bypass_ssl(pid)
# If bypass works = no pinning
```
**Finding**: No certificate pinning
**Severity**: Medium

---

## 15-Minute Deep Dive

### 6. Database Analysis
```python
databases = dump_databases("com.target.app")
# Check for: unencrypted DB, credentials, PII
```
**Finding**: Sensitive data in unencrypted database
**Severity**: High

### 7. Logcat Review
```python
logs = get_logcat("com.target.app")
# Search for: password, token, key, error
```
**Finding**: Sensitive data in logs
**Severity**: High

### 8. Root Detection Test
```python
pid = frida_spawn("com.target.app")
frida_bypass_root(pid)
# If app runs normally = bypass works
```
**Finding**: Root detection easily bypassed
**Severity**: Low (informational)

### 9. Content Provider Query
```python
# For each exported provider:
query_content_provider("content://com.target.app.provider/users")
query_content_provider("content://com.target.app.provider/users' OR '1'='1")
```
**Finding**: SQL injection in content provider
**Severity**: Critical

### 10. Deep Link Test
```python
launch_activity("com.target.app", ".DeepLinkActivity",
               data_uri="targetapp://test?url=javascript:alert(1)")
```
**Finding**: XSS/injection via deep link
**Severity**: High

---

## Common High-Value Targets

### Authentication Tokens
```python
# SharedPreferences
prefs = dump_shared_prefs("com.target.app")
# Look for: *token*, *session*, *auth*, *jwt*

# Runtime capture
frida_run_script(pid, "credential_hooks.js")
```

### API Keys
```bash
# Static analysis
grep -rniE "(api[_-]?key|apikey|client_secret)" jadx_output/
grep -rniE "AIza[0-9A-Za-z]{35}" jadx_output/  # Google API
grep -rniE "AKIA[0-9A-Z]{16}" jadx_output/     # AWS
```

### Hardcoded Credentials
```bash
grep -rniE "(password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']" jadx_output/
grep -rni "admin" jadx_output/ --include="*.java"
```

### Encryption Keys
```bash
grep -rni "SecretKeySpec" jadx_output/ -A3
grep -rniE "new byte\[\].*\{" jadx_output/
```

---

## Quick Win Summary Table

| Test | Time | Tool | Severity |
|------|------|------|----------|
| Debug flag | 30s | get_app_info | Critical |
| Backup flag | 30s | get_app_info | High |
| SharedPrefs dump | 1m | dump_shared_prefs | Critical |
| Exported components | 1m | list_exported_components | High |
| SSL pinning | 2m | frida_bypass_ssl | Medium |
| Database dump | 2m | dump_databases | High |
| Logcat review | 2m | get_logcat | High |
| Content provider | 3m | query_content_provider | Critical |
| Deep links | 3m | launch_activity | High |
| API keys (static) | 5m | grep | High |

---

## Automated Quick Scan

```python
# Run all quick wins in sequence
def quick_scan(package):
    findings = []

    # 1. App info
    info = get_app_info(package)
    if info.get('debuggable'):
        findings.append(('Critical', 'Debuggable flag enabled'))
    if info.get('allowBackup'):
        findings.append(('High', 'Backup enabled'))

    # 2. SharedPreferences
    prefs = dump_shared_prefs(package)
    # Analyze for sensitive data...

    # 3. Databases
    dbs = dump_databases(package)
    # Analyze for sensitive data...

    # 4. Exported components
    components = list_exported_components(package)
    for comp in components['activities']:
        if comp['exported'] and not comp['permission']:
            findings.append(('High', f'Unprotected activity: {comp["name"]}'))

    # 5. SSL pinning
    pid = frida_spawn(package)
    frida_bypass_ssl(pid)
    # If no error = no pinning

    return findings
```

---

## Priority Matrix

| Finding | Impact | Effort | Priority |
|---------|--------|--------|----------|
| Hardcoded credentials | Critical | Low | Immediate |
| SQL injection | Critical | Low | Immediate |
| Plaintext tokens | Critical | Low | Immediate |
| Debug flag | Critical | Minimal | Immediate |
| Unprotected components | High | Low | High |
| Missing encryption | High | Low | High |
| No SSL pinning | Medium | Low | Medium |
| Weak crypto | Medium | Medium | Medium |
