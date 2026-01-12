# Pre-Engagement Checklist

Verify all requirements before starting the Android penetration test.

---

## Scope Verification

### Application Details
- [ ] Package name confirmed: `________________`
- [ ] Version to test: `________________`
- [ ] Source: Google Play / APK provided / Enterprise
- [ ] Backend APIs in scope: Yes / No
- [ ] Third-party integrations in scope: Yes / No

### Testing Authorization
- [ ] Written authorization received
- [ ] Scope document signed
- [ ] Test account(s) provided
- [ ] Emergency contact established
- [ ] Legal review completed (if required)

### Excluded Items
- [ ] Production systems: ________________
- [ ] Specific APIs: ________________
- [ ] Third-party services: ________________
- [ ] Other exclusions: ________________

---

## Environment Setup

### Test Device
- [ ] Device type: Physical / Emulator
- [ ] Device model: `________________`
- [ ] Android version: `________________`
- [ ] Root access verified
- [ ] SELinux status: Permissive / Enforcing
- [ ] Device dedicated to testing (no personal data)

### Device Verification
```bash
# Verify ADB connection
adb devices
# Expected: device listed

# Verify root access
adb shell su -c "id"
# Expected: uid=0(root)

# Check Android version
adb shell getprop ro.build.version.release
```

### Frida Setup
- [ ] Frida server version: `________________`
- [ ] Frida tools version: `________________`
- [ ] Versions match

```bash
# Verify Frida
frida --version
frida-ps -U
# Expected: process list appears
```

### MCP Server
- [ ] Server installed and configured
- [ ] Tools accessible from Claude Code

```python
# Test MCP connectivity
get_app_info("com.android.settings")
# Expected: app info returned
```

---

## Tools Checklist

### Required Tools
- [ ] ADB (Android Debug Bridge)
- [ ] Frida + frida-tools
- [ ] apktool
- [ ] jadx / jadx-gui
- [ ] Burp Suite / mitmproxy
- [ ] SQLite browser (optional)

### Optional Tools
- [ ] Objection
- [ ] MobSF
- [ ] Ghidra (for native analysis)
- [ ] Android Studio (for emulator)

### Tool Verification
```bash
# ADB
adb version

# Frida
frida --version
frida-tools --version

# apktool
apktool --version

# jadx
jadx --version
```

---

## Network Setup

### Proxy Configuration
- [ ] Proxy tool: Burp Suite / mitmproxy / Other
- [ ] Proxy IP: `________________`
- [ ] Proxy port: `________________`
- [ ] CA certificate exported

### Certificate Installation
```bash
# Push CA certificate
adb push burp-ca.der /sdcard/

# For system-level (requires root)
# Convert and push to system store
```

### Proxy Verification
```python
# Configure device proxy
setup_proxy("device-id", "192.168.1.100", 8080)

# Verify traffic flows through proxy
# Expected: requests visible in Burp/mitmproxy
```

---

## Application Setup

### APK Acquisition
- [ ] APK obtained from: `________________`
- [ ] APK hash verified (if provided)
- [ ] APK size: `________________`

```bash
# Calculate APK hash
sha256sum app.apk
```

### Application Installation
```python
# Install APK
install_apk("/path/to/app.apk")

# Verify installation
get_app_info("com.target.app")
```

### Test Accounts
- [ ] Regular user account: `________________`
- [ ] Admin account (if applicable): `________________`
- [ ] Premium/paid account (if applicable): `________________`
- [ ] Account credentials stored securely

---

## Documentation Preparation

### Templates Ready
- [ ] Finding template
- [ ] Technical report template
- [ ] Executive summary template

### Evidence Collection
- [ ] Screenshot tool configured
- [ ] Screen recording ready
- [ ] Log collection scripts ready
- [ ] Evidence folder created

### Notes System
- [ ] Testing notes document created
- [ ] Finding tracker initialized
- [ ] Timeline logging ready

---

## Communication

### Client Contact
- [ ] Primary contact: `________________`
- [ ] Technical contact: `________________`
- [ ] Emergency contact: `________________`

### Reporting Schedule
- [ ] Daily updates: Yes / No
- [ ] Critical finding notification: Immediate / Daily / End of engagement
- [ ] Final report deadline: `________________`

---

## Pre-Test Verification Script

```python
def pre_test_verification(package, device_id=None):
    """Run before starting the penetration test"""
    checks = []

    # 1. Device connection
    try:
        # Test ADB
        result = run_adb(["devices"])
        if device_id in result or "device" in result:
            checks.append(("ADB Connection", "PASS"))
        else:
            checks.append(("ADB Connection", "FAIL"))
    except:
        checks.append(("ADB Connection", "FAIL"))

    # 2. Root access
    try:
        result = run_adb(["shell", "su", "-c", "id"])
        if "uid=0" in result:
            checks.append(("Root Access", "PASS"))
        else:
            checks.append(("Root Access", "FAIL"))
    except:
        checks.append(("Root Access", "FAIL"))

    # 3. Frida connection
    try:
        frida_ps_output = frida_ps()
        if len(frida_ps_output) > 0:
            checks.append(("Frida Connection", "PASS"))
        else:
            checks.append(("Frida Connection", "FAIL"))
    except:
        checks.append(("Frida Connection", "FAIL"))

    # 4. Target app installed
    try:
        info = get_app_info(package)
        if info:
            checks.append(("Target App Installed", "PASS"))
        else:
            checks.append(("Target App Installed", "FAIL"))
    except:
        checks.append(("Target App Installed", "FAIL"))

    # 5. MCP tools working
    try:
        components = list_exported_components(package)
        if components:
            checks.append(("MCP Tools", "PASS"))
        else:
            checks.append(("MCP Tools", "FAIL"))
    except:
        checks.append(("MCP Tools", "FAIL"))

    # Print results
    print("\n=== Pre-Test Verification ===")
    for check, status in checks:
        print(f"  {check}: {status}")

    all_pass = all(status == "PASS" for _, status in checks)
    print(f"\nReady to begin: {'YES' if all_pass else 'NO'}")

    return all_pass
```

---

## Final Confirmation

Before starting the test, confirm:

- [ ] All scope items verified
- [ ] Authorization documented
- [ ] Environment fully configured
- [ ] All tools working
- [ ] Backup of test device created
- [ ] Communication channels established
- [ ] Emergency procedures understood

**Ready to begin testing**: [ ] Yes [ ] No

**Test start date/time**: `________________`

**Tester name**: `________________`
