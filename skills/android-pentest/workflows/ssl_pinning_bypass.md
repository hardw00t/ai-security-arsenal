# Workflow: SSL Pinning Bypass

Three progressive methods — try in order, escalate only on failure.

## Method 1 — Universal Frida bypass
Covers OkHttp, TrustManager, WebView, and Conscrypt pinning.
```python
pid = frida_spawn("com.target.app")
frida_bypass_ssl(pid)
```

## Method 2 — Custom app-specific pinner
Identify the pinner class with jadx (search: `certificate`, `pin`, `ssl`, `trust`), then:
```python
frida_run_script(pid, """
Java.perform(function() {
    var CustomPinner = Java.use('com.target.app.security.Pinner');
    CustomPinner.verify.implementation = function() {
        console.log('[+] Bypassed custom pinner');
        return true;
    };
});
""")
```

## Method 3 — Flutter / native SSL (BoringSSL)
```python
frida_run_script(pid, """
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_CTX_set_custom_verify"), {
    onEnter: function(args) {
        args[2] = new NativeCallback(function() { return 0; }, 'int', ['pointer', 'pointer']);
    }
});
""")
```

## Escalation checklist if traffic still fails
1. Confirm Burp CA installed into system store (not just user store on Android 7+).
2. Check `network_security_config.xml` for `cleartextTrafficPermitted=false` and custom trust anchors.
3. Try `objection -g com.target.app explore` → `android sslpinning disable`.
4. Embed frida-gadget into APK for persistent injection.
5. Hook `pthread_create` to evade Frida-thread detection (see anti_tampering_bypass.js).

## Verification
Drive a login through the proxy; confirm TLS handshake succeeds and request body appears in Burp.
