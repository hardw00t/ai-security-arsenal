# Cryptography Security Testing Methodology

Cryptography testing evaluates the application's implementation of cryptographic operations, including algorithm selection, key management, random number generation, and proper use of cryptographic APIs.

---

## Cryptographic Algorithm Analysis

### Static Analysis

```bash
# Search for weak algorithms
grep -rniE "(DES|RC4|RC2|MD5|SHA1)[^a-zA-Z]" jadx_output/ --include="*.java"

# ECB mode (insecure)
grep -rni "AES/ECB" jadx_output/
grep -rni "/ECB/" jadx_output/

# Check for proper modes
grep -rniE "(AES/GCM|AES/CBC)" jadx_output/

# Search for custom crypto implementations
grep -rniE "(XOR|ROT13|Caesar|custom.*encrypt)" jadx_output/
```

### Weak Algorithm Detection

| Algorithm | Status | Recommendation |
|-----------|--------|----------------|
| DES | Broken | Use AES-256 |
| 3DES | Deprecated | Use AES-256 |
| RC4 | Broken | Use AES-GCM |
| MD5 | Broken | Use SHA-256+ |
| SHA1 | Deprecated | Use SHA-256+ |
| AES-ECB | Insecure | Use AES-GCM or AES-CBC |
| RSA-1024 | Deprecated | Use RSA-2048+ |
| RSA PKCS#1 v1.5 | Vulnerable | Use OAEP |

---

## Runtime Crypto Monitoring

### Comprehensive Crypto Hooks

```javascript
frida_run_script(pid, """
Java.perform(function() {
    console.log('[*] Crypto Monitoring Active');

    function bytesToHex(bytes) {
        if (!bytes) return 'null';
        var hex = '';
        var len = Math.min(bytes.length, 32);
        for (var i = 0; i < len; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex + (bytes.length > 32 ? '...' : '');
    }

    // Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        console.log('[CRYPTO] Cipher.getInstance: ' + transformation);

        // Flag weak algorithms
        var t = transformation.toUpperCase();
        if (t.indexOf('DES') !== -1) console.log('  [!] WEAK: DES detected');
        if (t.indexOf('RC4') !== -1) console.log('  [!] WEAK: RC4 detected');
        if (t.indexOf('ECB') !== -1) console.log('  [!] WEAK: ECB mode');
        if (t.indexOf('PKCS1') !== -1) console.log('  [!] WARNING: PKCS1 padding');

        return this.getInstance(transformation);
    };

    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'WRAP/UNWRAP';
        console.log('[CRYPTO] Cipher.init');
        console.log('  Mode: ' + modeStr);
        console.log('  Algorithm: ' + key.getAlgorithm());

        var encoded = key.getEncoded();
        if (encoded) {
            console.log('  Key length: ' + encoded.length * 8 + ' bits');
            console.log('  Key (hex): ' + bytesToHex(encoded));
        }

        return this.init(mode, key);
    };

    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[CRYPTO] Cipher.doFinal');
        console.log('  Input: ' + bytesToHex(input));
        var output = this.doFinal(input);
        console.log('  Output: ' + bytesToHex(output));
        return output;
    };

    // SecretKeySpec - key material capture
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
        console.log('[CRYPTO] SecretKeySpec');
        console.log('  Algorithm: ' + algorithm);
        console.log('  Key length: ' + keyBytes.length * 8 + ' bits');
        console.log('  Key (hex): ' + bytesToHex(keyBytes));

        // Check for weak key length
        if (algorithm.toUpperCase().indexOf('AES') !== -1 && keyBytes.length < 16) {
            console.log('  [!] WEAK: AES key < 128 bits');
        }

        return this.$init(keyBytes, algorithm);
    };

    // IvParameterSpec - IV capture
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log('[CRYPTO] IvParameterSpec');
        console.log('  IV (hex): ' + bytesToHex(iv));
        console.log('  IV length: ' + iv.length + ' bytes');
        return this.$init(iv);
    };

    // MessageDigest - hash operations
    var MessageDigest = Java.use('java.security.MessageDigest');

    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        console.log('[CRYPTO] MessageDigest.getInstance: ' + algorithm);

        if (algorithm.toUpperCase() === 'MD5') console.log('  [!] WEAK: MD5');
        if (algorithm.toUpperCase() === 'SHA-1') console.log('  [!] WEAK: SHA-1');

        return this.getInstance(algorithm);
    };

    MessageDigest.digest.overload('[B').implementation = function(input) {
        console.log('[CRYPTO] MessageDigest.digest');
        console.log('  Input: ' + bytesToHex(input));
        var hash = this.digest(input);
        console.log('  Hash: ' + bytesToHex(hash));
        return hash;
    };

    // MAC operations
    var Mac = Java.use('javax.crypto.Mac');

    Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        console.log('[CRYPTO] Mac.getInstance: ' + algorithm);
        return this.getInstance(algorithm);
    };

    Mac.doFinal.overload('[B').implementation = function(input) {
        console.log('[CRYPTO] Mac.doFinal');
        console.log('  Input: ' + bytesToHex(input));
        var mac = this.doFinal(input);
        console.log('  MAC: ' + bytesToHex(mac));
        return mac;
    };
});
""")
```

---

## Key Management Testing

### Hardcoded Key Detection

```bash
# Search for hardcoded keys
grep -rni "SecretKeySpec" jadx_output/ -A5
grep -rniE "new byte\[.*\{.*\}" jadx_output/ --include="*.java"
grep -rniE "(AES_KEY|SECRET_KEY|ENCRYPTION_KEY)" jadx_output/

# Search for Base64 encoded keys
grep -rniE "\"[A-Za-z0-9+/]{16,}={0,2}\"" jadx_output/ --include="*.java"
```

### Key Derivation Analysis

```javascript
// Monitor key derivation
frida_run_script(pid, """
Java.perform(function() {
    // PBKDF2
    var SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');

    SecretKeyFactory.generateSecret.implementation = function(keySpec) {
        console.log('[CRYPTO] SecretKeyFactory.generateSecret');
        console.log('  KeySpec class: ' + keySpec.getClass().getName());

        // Check if PBEKeySpec
        if (keySpec.getClass().getName().indexOf('PBEKeySpec') !== -1) {
            var pbeSpec = Java.cast(keySpec, Java.use('javax.crypto.spec.PBEKeySpec'));
            var password = pbeSpec.getPassword();
            console.log('  Password: ' + Java.use('java.lang.String').$new(password));
            console.log('  Salt: ' + pbeSpec.getSalt());
            console.log('  Iterations: ' + pbeSpec.getIterationCount());
            console.log('  Key length: ' + pbeSpec.getKeyLength());

            if (pbeSpec.getIterationCount() < 10000) {
                console.log('  [!] WEAK: Low iteration count');
            }
        }

        return this.generateSecret(keySpec);
    };
});
""")
```

### Android Keystore Analysis

```javascript
// Monitor Keystore operations
frida_run_script(pid, """
Java.perform(function() {
    var KeyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');

    KeyGenParameterSpec.$init.overload('java.lang.String', 'int').implementation = function(alias, purposes) {
        console.log('[KEYSTORE] Key generation: ' + alias);

        var purposeStr = [];
        if (purposes & 1) purposeStr.push('ENCRYPT');
        if (purposes & 2) purposeStr.push('DECRYPT');
        if (purposes & 4) purposeStr.push('SIGN');
        if (purposes & 8) purposeStr.push('VERIFY');
        console.log('  Purposes: ' + purposeStr.join(', '));

        return this.$init(alias, purposes);
    };

    KeyGenParameterSpec.setUserAuthenticationRequired.implementation = function(required) {
        console.log('[KEYSTORE] setUserAuthenticationRequired: ' + required);
        if (!required) {
            console.log('  [!] WARNING: No user authentication required');
        }
        return this.setUserAuthenticationRequired(required);
    };

    KeyGenParameterSpec.setUserAuthenticationValidityDurationSeconds.implementation = function(seconds) {
        console.log('[KEYSTORE] Authentication validity: ' + seconds + 's');
        if (seconds > 300) {
            console.log('  [!] WARNING: Long authentication validity');
        }
        return this.setUserAuthenticationValidityDurationSeconds(seconds);
    };
});
""")
```

---

## Random Number Generation Testing

### Detect Insecure Random

```bash
# Search for java.util.Random (insecure)
grep -rni "java.util.Random" jadx_output/ --include="*.java"
grep -rni "new Random()" jadx_output/ --include="*.java"

# Should use SecureRandom instead
grep -rni "SecureRandom" jadx_output/ --include="*.java"
```

### Monitor Random Operations

```javascript
frida_run_script(pid, """
Java.perform(function() {
    // Insecure Random
    var Random = Java.use('java.util.Random');

    Random.$init.overload().implementation = function() {
        console.log('[!] INSECURE: java.util.Random used');
        console.log('  Stack: ' + Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
        return this.$init();
    };

    Random.$init.overload('long').implementation = function(seed) {
        console.log('[!] INSECURE: java.util.Random with seed: ' + seed);
        return this.$init(seed);
    };

    // Secure Random
    var SecureRandom = Java.use('java.security.SecureRandom');

    SecureRandom.$init.overload().implementation = function() {
        console.log('[CRYPTO] SecureRandom created');
        return this.$init();
    };

    SecureRandom.nextBytes.implementation = function(bytes) {
        console.log('[CRYPTO] SecureRandom.nextBytes: ' + bytes.length + ' bytes');
        return this.nextBytes(bytes);
    };
});
""")
```

---

## Certificate/TLS Testing

### Certificate Storage

```bash
# Search for embedded certificates
find jadx_output/ -name "*.cer" -o -name "*.crt" -o -name "*.pem" -o -name "*.p12" -o -name "*.bks"
find apktool_output/assets/ -name "*.cer" -o -name "*.crt" -o -name "*.pem"

# Search for certificate pinning
grep -rniE "(CertificatePinner|TrustManager|X509TrustManager)" jadx_output/
```

### TrustManager Analysis

```javascript
frida_run_script(pid, """
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

    // Find all TrustManager implementations
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf('TrustManager') !== -1) {
                console.log('[TLS] TrustManager implementation: ' + className);
            }
        },
        onComplete: function() {}
    });

    // Hook custom TrustManager implementations
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.implementation = function(km, tm, random) {
        console.log('[TLS] SSLContext.init');
        if (tm) {
            for (var i = 0; i < tm.length; i++) {
                console.log('  TrustManager[' + i + ']: ' + tm[i].getClass().getName());
            }
        }
        return this.init(km, tm, random);
    };
});
""")
```

---

## Cryptography Checklist

### Algorithm Selection
- [ ] No DES, 3DES, RC4
- [ ] No MD5, SHA-1 for security purposes
- [ ] AES with GCM or CBC mode (not ECB)
- [ ] RSA 2048+ bits with OAEP padding
- [ ] ECDSA with P-256 or higher

### Key Management
- [ ] No hardcoded keys
- [ ] Keys derived with PBKDF2 (10000+ iterations)
- [ ] Android Keystore for sensitive keys
- [ ] User authentication for key access
- [ ] Proper key validity periods

### Random Numbers
- [ ] SecureRandom used (not java.util.Random)
- [ ] No predictable seeds
- [ ] Proper entropy sources

### IV/Nonce Management
- [ ] Unique IV for each encryption
- [ ] IV not derived from predictable data
- [ ] Proper IV length for algorithm

### Certificate Handling
- [ ] Certificate validation enabled
- [ ] Certificate pinning implemented
- [ ] No trust-all TrustManagers
- [ ] Secure certificate storage

---

## Common Findings

| Finding | Severity | MASTG Reference |
|---------|----------|-----------------|
| Hardcoded encryption key | Critical | MASTG-TEST-0013 |
| Use of ECB mode | High | MASTG-TEST-0014 |
| Use of DES/3DES | High | MASTG-TEST-0014 |
| MD5 for password hashing | High | MASTG-TEST-0014 |
| java.util.Random for crypto | High | MASTG-TEST-0015 |
| Low PBKDF2 iterations | Medium | MASTG-TEST-0013 |
| Static IV | Medium | MASTG-TEST-0014 |
| Weak RSA key (< 2048 bits) | Medium | MASTG-TEST-0014 |
| No Keystore for secrets | Medium | MASTG-TEST-0013 |
