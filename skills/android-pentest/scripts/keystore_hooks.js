/**
 * Android Keystore Operations Hook
 *
 * Monitors and logs:
 * - Key generation in Android Keystore
 * - Key retrieval operations
 * - Signing operations
 * - Encryption/Decryption with keystore keys
 * - Biometric authentication callbacks
 *
 * Usage: frida -U -f <package> -l keystore_hooks.js --no-pause
 */

Java.perform(function() {
    console.log("[*] Android Keystore Hook loaded");

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

    // ================== KeyStore Operations ==================
    try {
        var KeyStore = Java.use('java.security.KeyStore');

        KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
            console.log("\n[KeyStore.getInstance]");
            console.log("  Type: " + type);
            return this.getInstance(type);
        };

        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function(stream, password) {
            console.log("\n[KeyStore.load]");
            if (password) {
                console.log("  Password: " + Java.use('java.lang.String').$new(password));
            }
            return this.load(stream, password);
        };

        KeyStore.getKey.overload('java.lang.String', '[C').implementation = function(alias, password) {
            console.log("\n[KeyStore.getKey]");
            console.log("  Alias: " + alias);
            if (password) {
                console.log("  Password: " + Java.use('java.lang.String').$new(password));
            }
            var key = this.getKey(alias, password);
            if (key) {
                console.log("  Key Algorithm: " + key.getAlgorithm());
                console.log("  Key Format: " + key.getFormat());
                try {
                    console.log("  Key Encoded: " + bytesToHex(key.getEncoded()));
                } catch (e) {
                    console.log("  Key Encoded: <protected>");
                }
            }
            return key;
        };

        KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter').implementation = function(alias, protParam) {
            console.log("\n[KeyStore.getEntry]");
            console.log("  Alias: " + alias);
            var entry = this.getEntry(alias, protParam);
            if (entry) {
                console.log("  Entry Type: " + entry.getClass().getName());
            }
            return entry;
        };

        KeyStore.setEntry.overload('java.lang.String', 'java.security.KeyStore$Entry', 'java.security.KeyStore$ProtectionParameter').implementation = function(alias, entry, protParam) {
            console.log("\n[KeyStore.setEntry]");
            console.log("  Alias: " + alias);
            console.log("  Entry Type: " + entry.getClass().getName());
            return this.setEntry(alias, entry, protParam);
        };

        KeyStore.aliases.implementation = function() {
            var aliases = this.aliases();
            console.log("\n[KeyStore.aliases]");
            var aliasList = [];
            while (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();
                aliasList.push(alias);
            }
            console.log("  Aliases: " + aliasList.join(", "));
            // Return a new enumeration since we consumed the original
            return Java.use('java.util.Collections').enumeration(
                Java.use('java.util.Arrays').asList(aliasList)
            );
        };

        console.log("[+] KeyStore hooks installed");
    } catch (e) {
        console.log("[-] KeyStore hooks failed: " + e);
    }

    // ================== KeyGenerator (Android Keystore) ==================
    try {
        var KeyGenerator = Java.use('javax.crypto.KeyGenerator');

        KeyGenerator.init.overload('java.security.spec.AlgorithmParameterSpec').implementation = function(params) {
            console.log("\n[KeyGenerator.init]");
            console.log("  Params: " + params.getClass().getName());

            // Try to extract KeyGenParameterSpec details
            try {
                var KeyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec');
                var spec = Java.cast(params, KeyGenParameterSpec);
                console.log("  Keystore Alias: " + spec.getKeystoreAlias());
                console.log("  Key Size: " + spec.getKeySize());
                console.log("  Purposes: " + spec.getPurposes());
                console.log("  Block Modes: " + spec.getBlockModes());
                console.log("  Encryption Paddings: " + spec.getEncryptionPaddings());
                console.log("  User Auth Required: " + spec.isUserAuthenticationRequired());
                console.log("  Invalidated by Biometric: " + spec.isInvalidatedByBiometricEnrollment());
            } catch (e) {}

            return this.init(params);
        };

        console.log("[+] KeyGenerator hooks installed");
    } catch (e) {
        console.log("[-] KeyGenerator hooks failed: " + e);
    }

    // ================== KeyPairGenerator (Android Keystore) ==================
    try {
        var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');

        KeyPairGenerator.initialize.overload('java.security.spec.AlgorithmParameterSpec').implementation = function(params) {
            console.log("\n[KeyPairGenerator.initialize]");
            console.log("  Params: " + params.getClass().getName());

            try {
                var KeyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec');
                var spec = Java.cast(params, KeyGenParameterSpec);
                console.log("  Keystore Alias: " + spec.getKeystoreAlias());
                console.log("  Key Size: " + spec.getKeySize());
                console.log("  Purposes: " + spec.getPurposes());
            } catch (e) {}

            return this.initialize(params);
        };

        KeyPairGenerator.generateKeyPair.implementation = function() {
            console.log("\n[KeyPairGenerator.generateKeyPair]");
            var keyPair = this.generateKeyPair();
            console.log("  Public Key Algorithm: " + keyPair.getPublic().getAlgorithm());
            console.log("  Public Key Format: " + keyPair.getPublic().getFormat());
            console.log("  Public Key: " + bytesToHex(keyPair.getPublic().getEncoded()));
            return keyPair;
        };

        console.log("[+] KeyPairGenerator hooks installed");
    } catch (e) {
        console.log("[-] KeyPairGenerator hooks failed: " + e);
    }

    // ================== Signature Operations ==================
    try {
        var Signature = Java.use('java.security.Signature');

        Signature.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("\n[Signature.getInstance]");
            console.log("  Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        Signature.initSign.overload('java.security.PrivateKey').implementation = function(privateKey) {
            console.log("\n[Signature.initSign]");
            console.log("  Key Algorithm: " + privateKey.getAlgorithm());
            return this.initSign(privateKey);
        };

        Signature.initVerify.overload('java.security.PublicKey').implementation = function(publicKey) {
            console.log("\n[Signature.initVerify]");
            console.log("  Key Algorithm: " + publicKey.getAlgorithm());
            console.log("  Public Key: " + bytesToHex(publicKey.getEncoded()));
            return this.initVerify(publicKey);
        };

        Signature.update.overload('[B').implementation = function(data) {
            console.log("\n[Signature.update]");
            console.log("  Data: " + bytesToHex(data));
            return this.update(data);
        };

        Signature.sign.overload().implementation = function() {
            var sig = this.sign();
            console.log("\n[Signature.sign]");
            console.log("  Signature: " + bytesToHex(sig));
            return sig;
        };

        Signature.verify.overload('[B').implementation = function(signature) {
            var result = this.verify(signature);
            console.log("\n[Signature.verify]");
            console.log("  Signature: " + bytesToHex(signature));
            console.log("  Valid: " + result);
            return result;
        };

        console.log("[+] Signature hooks installed");
    } catch (e) {
        console.log("[-] Signature hooks failed: " + e);
    }

    // ================== BiometricPrompt Hooks ==================
    try {
        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');

        BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(cancel, executor, callback) {
            console.log("\n[BiometricPrompt.authenticate]");
            console.log("  Callback: " + callback.getClass().getName());
            return this.authenticate(cancel, executor, callback);
        };

        console.log("[+] BiometricPrompt hooks installed");
    } catch (e) {
        console.log("[-] BiometricPrompt hooks failed: " + e);
    }

    // ================== FingerprintManager Hooks (legacy) ==================
    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');

        FingerprintManager.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler').implementation = function(crypto, cancel, flags, callback, handler) {
            console.log("\n[FingerprintManager.authenticate]");
            if (crypto) {
                console.log("  CryptoObject: " + crypto.getClass().getName());
            }
            return this.authenticate(crypto, cancel, flags, callback, handler);
        };

        console.log("[+] FingerprintManager hooks installed");
    } catch (e) {
        console.log("[-] FingerprintManager hooks failed (probably not available)");
    }

    // ================== KeyInfo (get key properties) ==================
    try {
        var KeyInfo = Java.use('android.security.keystore.KeyInfo');

        // Hook methods that reveal key properties
        var keyInfoMethods = [
            'isInsideSecureHardware',
            'isUserAuthenticationRequired',
            'isUserAuthenticationRequirementEnforcedBySecureHardware',
            'getUserAuthenticationValidityDurationSeconds',
            'isInvalidatedByBiometricEnrollment'
        ];

        keyInfoMethods.forEach(function(methodName) {
            try {
                KeyInfo[methodName].implementation = function() {
                    var result = this[methodName]();
                    console.log("\n[KeyInfo." + methodName + "]");
                    console.log("  Result: " + result);
                    return result;
                };
            } catch (e) {}
        });

        console.log("[+] KeyInfo hooks installed");
    } catch (e) {
        console.log("[-] KeyInfo hooks failed: " + e);
    }

    console.log("[*] Android Keystore monitoring active");
});
