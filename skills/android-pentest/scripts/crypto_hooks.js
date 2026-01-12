/**
 * Cryptographic Operations Hook for Android
 *
 * Hooks and logs:
 * - AES/DES encryption/decryption
 * - RSA encryption/decryption
 * - HMAC operations
 * - Key generation
 * - SecretKeySpec creation
 * - MessageDigest (hashing)
 * - KeyStore operations
 *
 * Usage: frida -U -f <package> -l crypto_hooks.js --no-pause
 */

Java.perform(function() {
    console.log("[*] Cryptographic Operations Hook loaded");

    function bytesToHex(bytes) {
        if (!bytes) return "null";
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            if (b.length === 1) hex += "0";
            hex += b;
        }
        return hex;
    }

    function bytesToString(bytes) {
        if (!bytes) return "null";
        try {
            var result = "";
            for (var i = 0; i < bytes.length; i++) {
                result += String.fromCharCode(bytes[i] & 0xFF);
            }
            // Return printable string or hex if not printable
            if (/^[\x20-\x7E]*$/.test(result)) {
                return result;
            }
            return "[hex: " + bytesToHex(bytes) + "]";
        } catch (e) {
            return "[hex: " + bytesToHex(bytes) + "]";
        }
    }

    // ================== Cipher Hook ==================
    try {
        var Cipher = Java.use('javax.crypto.Cipher');

        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log("\n[Cipher.getInstance]");
            console.log("  Transformation: " + transformation);
            return this.getInstance(transformation);
        };

        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            var mode = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : "MODE_" + opmode;
            console.log("\n[Cipher.init]");
            console.log("  Mode: " + mode);
            console.log("  Algorithm: " + key.getAlgorithm());
            console.log("  Key: " + bytesToHex(key.getEncoded()));
            return this.init(opmode, key);
        };

        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
            var mode = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : "MODE_" + opmode;
            console.log("\n[Cipher.init with params]");
            console.log("  Mode: " + mode);
            console.log("  Algorithm: " + key.getAlgorithm());
            console.log("  Key: " + bytesToHex(key.getEncoded()));

            // Try to get IV if IvParameterSpec
            try {
                var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
                var ivSpec = Java.cast(params, IvParameterSpec);
                console.log("  IV: " + bytesToHex(ivSpec.getIV()));
            } catch (e) {}

            return this.init(opmode, key, params);
        };

        Cipher.doFinal.overload('[B').implementation = function(input) {
            var result = this.doFinal(input);
            console.log("\n[Cipher.doFinal]");
            console.log("  Input: " + bytesToString(input));
            console.log("  Output: " + bytesToString(result));
            return result;
        };

        console.log("[+] Cipher hooks installed");
    } catch (e) {
        console.log("[-] Cipher hooks failed: " + e);
    }

    // ================== SecretKeySpec Hook ==================
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
            console.log("\n[SecretKeySpec]");
            console.log("  Algorithm: " + algorithm);
            console.log("  Key: " + bytesToHex(key));
            console.log("  Key (string): " + bytesToString(key));
            return this.$init(key, algorithm);
        };

        SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function(key, offset, len, algorithm) {
            console.log("\n[SecretKeySpec]");
            console.log("  Algorithm: " + algorithm);
            console.log("  Key: " + bytesToHex(key));
            console.log("  Offset: " + offset + ", Length: " + len);
            return this.$init(key, offset, len, algorithm);
        };

        console.log("[+] SecretKeySpec hooks installed");
    } catch (e) {
        console.log("[-] SecretKeySpec hooks failed: " + e);
    }

    // ================== IvParameterSpec Hook ==================
    try {
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

        IvParameterSpec.$init.overload('[B').implementation = function(iv) {
            console.log("\n[IvParameterSpec]");
            console.log("  IV: " + bytesToHex(iv));
            return this.$init(iv);
        };

        console.log("[+] IvParameterSpec hooks installed");
    } catch (e) {
        console.log("[-] IvParameterSpec hooks failed: " + e);
    }

    // ================== MessageDigest Hook ==================
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');

        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("\n[MessageDigest.getInstance]");
            console.log("  Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        MessageDigest.update.overload('[B').implementation = function(input) {
            console.log("\n[MessageDigest.update]");
            console.log("  Input: " + bytesToString(input));
            return this.update(input);
        };

        MessageDigest.digest.overload().implementation = function() {
            var result = this.digest();
            console.log("\n[MessageDigest.digest]");
            console.log("  Hash: " + bytesToHex(result));
            return result;
        };

        MessageDigest.digest.overload('[B').implementation = function(input) {
            var result = this.digest(input);
            console.log("\n[MessageDigest.digest]");
            console.log("  Input: " + bytesToString(input));
            console.log("  Hash: " + bytesToHex(result));
            return result;
        };

        console.log("[+] MessageDigest hooks installed");
    } catch (e) {
        console.log("[-] MessageDigest hooks failed: " + e);
    }

    // ================== Mac (HMAC) Hook ==================
    try {
        var Mac = Java.use('javax.crypto.Mac');

        Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("\n[Mac.getInstance]");
            console.log("  Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        Mac.init.overload('java.security.Key').implementation = function(key) {
            console.log("\n[Mac.init]");
            console.log("  Key: " + bytesToHex(key.getEncoded()));
            return this.init(key);
        };

        Mac.doFinal.overload('[B').implementation = function(input) {
            var result = this.doFinal(input);
            console.log("\n[Mac.doFinal]");
            console.log("  Input: " + bytesToString(input));
            console.log("  HMAC: " + bytesToHex(result));
            return result;
        };

        console.log("[+] Mac (HMAC) hooks installed");
    } catch (e) {
        console.log("[-] Mac hooks failed: " + e);
    }

    // ================== KeyGenerator Hook ==================
    try {
        var KeyGenerator = Java.use('javax.crypto.KeyGenerator');

        KeyGenerator.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("\n[KeyGenerator.getInstance]");
            console.log("  Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        KeyGenerator.generateKey.implementation = function() {
            var key = this.generateKey();
            console.log("\n[KeyGenerator.generateKey]");
            console.log("  Generated Key: " + bytesToHex(key.getEncoded()));
            return key;
        };

        console.log("[+] KeyGenerator hooks installed");
    } catch (e) {
        console.log("[-] KeyGenerator hooks failed: " + e);
    }

    // ================== PBEKeySpec Hook (Password-Based Encryption) ==================
    try {
        var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec');

        PBEKeySpec.$init.overload('[C', '[B', 'int', 'int').implementation = function(password, salt, iterations, keyLength) {
            console.log("\n[PBEKeySpec]");
            console.log("  Password: " + Java.use('java.lang.String').$new(password));
            console.log("  Salt: " + bytesToHex(salt));
            console.log("  Iterations: " + iterations);
            console.log("  Key Length: " + keyLength);
            return this.$init(password, salt, iterations, keyLength);
        };

        console.log("[+] PBEKeySpec hooks installed");
    } catch (e) {
        console.log("[-] PBEKeySpec hooks failed: " + e);
    }

    // ================== RSA Hook ==================
    try {
        var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');

        KeyPairGenerator.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("\n[KeyPairGenerator.getInstance]");
            console.log("  Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        console.log("[+] KeyPairGenerator hooks installed");
    } catch (e) {
        console.log("[-] KeyPairGenerator hooks failed: " + e);
    }

    // ================== Base64 Hook ==================
    try {
        var Base64 = Java.use('android.util.Base64');

        Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
            var result = this.encodeToString(input, flags);
            console.log("\n[Base64.encodeToString]");
            console.log("  Input: " + bytesToString(input));
            console.log("  Output: " + result);
            return result;
        };

        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            var result = this.decode(str, flags);
            console.log("\n[Base64.decode]");
            console.log("  Input: " + str);
            console.log("  Output: " + bytesToString(result));
            return result;
        };

        console.log("[+] Base64 hooks installed");
    } catch (e) {
        console.log("[-] Base64 hooks failed: " + e);
    }

    console.log("[*] Cryptographic hooks complete - monitoring all crypto operations");
});
