# Troubleshooting

Common failures during Android pentests and minimum-fix recipes.

## Frida

### "Failed to spawn: unable to find application"
Verify the exact package name.
```bash
adb shell pm list packages | grep <partial>
# or
list_installed_apps()  # MCP
```

### "Failed to attach: process not found"
App isn't running — use `frida_spawn(pkg)` instead of `frida_attach(pkg)`.

### "Script terminated with error" — class/method not found
Likely obfuscation (class names become `a`, `b`, `c`…).
```python
frida_enumerate_classes(pid, "*TargetClass*")
```
Cross-reference jadx decompile to locate the renamed class.

### Frida server crashes or version mismatch
```bash
frida --version  # client version
# Download matching frida-server from github.com/frida/frida/releases
adb push frida-server /data/local/tmp/ && adb shell "su -c chmod 755 /data/local/tmp/frida-server"
```

## SSL pinning

### Universal bypass does nothing
Custom pinner — decompile APK, search for `certificate`/`pin`/`ssl`/`trust`, then write a targeted hook. See `workflows/ssl_pinning_bypass.md` Method 2.

### App still fails after bypass
Multiple pinning layers:
1. Native SSL verification in `libssl.so` — use Method 3 (`SSL_CTX_set_custom_verify`).
2. Frida-detection: run `anti_tampering_bypass.js` first.
3. Try `objection -g <pkg> explore` → `android sslpinning disable`.
4. Consider embedding frida-gadget in the APK.

## Root detection

### App exits on launch with "rooted device"
```python
frida_run_script(pid, "root_bypass.js")
```
Additional layers:
- Enable Magisk Hide / Zygisk DenyList for the package.
- Native root checks → hook `fopen`, `access`, `stat` from libc.
- Frida-gadget embedded in the APK for persistent injection.

### App detects Frida itself
- Apply `anti_tampering_bypass.js` before other scripts.
- Rename the `frida-server` binary on device.
- Hook `pthread_create` to hide Frida threads.

## ADB

### "device unauthorized"
```bash
adb kill-server && adb start-server
# then accept the RSA key prompt on device
```

### "Permission denied" reading app data
```bash
adb root                         # userdebug builds only
adb shell su -c "cat /data/data/<pkg>/..."  # rooted production devices
```

## Data extraction

### SQLCipher-encrypted database
Capture the passphrase at open time:
```python
frida_hook_method(pid, "net.sqlcipher.database.SQLiteDatabase", "openOrCreateDatabase")
```
Or scan memory for `PRAGMA key` strings:
```python
frida_memory_search(pid, "PRAGMA key")
```

### Files exist but are zero bytes after pull
Scoped storage (Android 10+) — use `adb shell run-as <pkg> cat <path>` on debuggable builds, or `adb shell su -c cat` on rooted devices.
