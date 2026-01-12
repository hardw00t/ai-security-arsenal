/**
 * Universal Root Detection Bypass for Android
 *
 * Bypasses common root detection methods:
 * - File existence checks (su, busybox, etc.)
 * - Package manager checks (Superuser, Magisk)
 * - Build tags and properties
 * - Native library checks
 * - Runtime.exec() based checks
 * - Common root detection libraries (RootBeer, etc.)
 *
 * Usage: frida -U -f <package> -l root_bypass.js --no-pause
 */

Java.perform(function() {
    console.log("[*] Root Detection Bypass loaded");

    // ================== File Class Hooks ==================
    var rootIndicatorFiles = [
        "/system/app/Superuser.apk",
        "/system/app/Superuser",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/su",
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99telekit",
        "/system/app/Kinguser.apk",
        "/data/adb/ksu",
        "/data/adb/ksud"
    ];

    try {
        var File = Java.use('java.io.File');

        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootIndicatorFiles.length; i++) {
                if (path.indexOf(rootIndicatorFiles[i]) !== -1) {
                    console.log("[+] File.exists() bypassed for: " + path);
                    return false;
                }
            }
            return this.exists.call(this);
        };

        File.canRead.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootIndicatorFiles.length; i++) {
                if (path.indexOf(rootIndicatorFiles[i]) !== -1) {
                    console.log("[+] File.canRead() bypassed for: " + path);
                    return false;
                }
            }
            return this.canRead.call(this);
        };

        File.canWrite.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("/system") !== -1 || path.indexOf("/data") !== -1) {
                console.log("[+] File.canWrite() bypassed for: " + path);
                return false;
            }
            return this.canWrite.call(this);
        };

        console.log("[+] File existence bypass installed");
    } catch (e) {
        console.log("[-] File bypass failed: " + e);
    }

    // ================== Runtime.exec() Hook ==================
    try {
        var Runtime = Java.use('java.lang.Runtime');

        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 ||
                cmd.indexOf("busybox") !== -1 || cmd.indexOf("magisk") !== -1) {
                console.log("[+] Runtime.exec() blocked: " + cmd);
                throw new Error("Command not found");
            }
            return this.exec(cmd);
        };

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            var cmd = cmdArray.join(" ");
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 ||
                cmd.indexOf("busybox") !== -1 || cmd.indexOf("magisk") !== -1) {
                console.log("[+] Runtime.exec() blocked: " + cmd);
                throw new Error("Command not found");
            }
            return this.exec(cmdArray);
        };

        console.log("[+] Runtime.exec() bypass installed");
    } catch (e) {
        console.log("[-] Runtime.exec() bypass failed: " + e);
    }

    // ================== ProcessBuilder Hook ==================
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

        ProcessBuilder.start.implementation = function() {
            var cmd = this.command().toString();
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                console.log("[+] ProcessBuilder.start() blocked: " + cmd);
                throw new Error("Command not found");
            }
            return this.start.call(this);
        };

        console.log("[+] ProcessBuilder bypass installed");
    } catch (e) {
        console.log("[-] ProcessBuilder bypass failed: " + e);
    }

    // ================== Package Manager Hook ==================
    var rootPackages = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclean.gp",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "me.weishu.kernelsu"
    ];

    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (packageName === rootPackages[i]) {
                    console.log("[+] PackageManager.getPackageInfo() bypassed for: " + packageName);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(packageName);
                }
            }
            return this.getPackageInfo(packageName, flags);
        };

        PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (packageName === rootPackages[i]) {
                    console.log("[+] PackageManager.getApplicationInfo() bypassed for: " + packageName);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(packageName);
                }
            }
            return this.getApplicationInfo(packageName, flags);
        };

        console.log("[+] PackageManager bypass installed");
    } catch (e) {
        console.log("[-] PackageManager bypass failed: " + e);
    }

    // ================== Build Properties Hook ==================
    try {
        var Build = Java.use('android.os.Build');

        Build.TAGS.value = "release-keys";
        Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace("test-keys", "release-keys");

        console.log("[+] Build properties modified");
    } catch (e) {
        console.log("[-] Build properties modification failed: " + e);
    }

    // ================== System Properties Hook ==================
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');

        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (key === "ro.build.tags" || key === "ro.build.selinux") {
                console.log("[+] SystemProperties.get() bypassed for: " + key);
                return "release-keys";
            }
            if (key === "ro.debuggable" || key === "service.adb.root") {
                console.log("[+] SystemProperties.get() bypassed for: " + key);
                return "0";
            }
            return this.get(key);
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (key === "ro.build.tags" || key === "ro.build.selinux") {
                console.log("[+] SystemProperties.get() bypassed for: " + key);
                return "release-keys";
            }
            if (key === "ro.debuggable" || key === "service.adb.root") {
                console.log("[+] SystemProperties.get() bypassed for: " + key);
                return "0";
            }
            return this.get(key, def);
        };

        console.log("[+] SystemProperties bypass installed");
    } catch (e) {
        console.log("[-] SystemProperties bypass failed: " + e);
    }

    // ================== RootBeer Library Bypass ==================
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');

        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() bypassed");
            return false;
        };

        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("[+] RootBeer.isRootedWithoutBusyBoxCheck() bypassed");
            return false;
        };

        RootBeer.detectRootManagementApps.implementation = function() {
            console.log("[+] RootBeer.detectRootManagementApps() bypassed");
            return false;
        };

        RootBeer.detectPotentiallyDangerousApps.implementation = function() {
            console.log("[+] RootBeer.detectPotentiallyDangerousApps() bypassed");
            return false;
        };

        RootBeer.detectTestKeys.implementation = function() {
            console.log("[+] RootBeer.detectTestKeys() bypassed");
            return false;
        };

        RootBeer.checkForBusyBoxBinary.implementation = function() {
            console.log("[+] RootBeer.checkForBusyBoxBinary() bypassed");
            return false;
        };

        RootBeer.checkForSuBinary.implementation = function() {
            console.log("[+] RootBeer.checkForSuBinary() bypassed");
            return false;
        };

        RootBeer.checkSuExists.implementation = function() {
            console.log("[+] RootBeer.checkSuExists() bypassed");
            return false;
        };

        RootBeer.checkForRWPaths.implementation = function() {
            console.log("[+] RootBeer.checkForRWPaths() bypassed");
            return false;
        };

        RootBeer.checkForDangerousProps.implementation = function() {
            console.log("[+] RootBeer.checkForDangerousProps() bypassed");
            return false;
        };

        RootBeer.checkForRootNative.implementation = function() {
            console.log("[+] RootBeer.checkForRootNative() bypassed");
            return false;
        };

        RootBeer.detectRootCloakingApps.implementation = function() {
            console.log("[+] RootBeer.detectRootCloakingApps() bypassed");
            return false;
        };

        RootBeer.checkForMagiskBinary.implementation = function() {
            console.log("[+] RootBeer.checkForMagiskBinary() bypassed");
            return false;
        };

        console.log("[+] RootBeer bypass installed");
    } catch (e) {
        console.log("[-] RootBeer library not found");
    }

    // ================== Native Library Check Bypass ==================
    try {
        var System = Java.use('java.lang.System');

        System.loadLibrary.implementation = function(libName) {
            console.log("[*] System.loadLibrary(): " + libName);
            return this.loadLibrary(libName);
        };

        console.log("[+] Native library monitoring installed");
    } catch (e) {
        console.log("[-] Native library monitoring failed: " + e);
    }

    console.log("[*] Root Detection Bypass complete - device appears non-rooted to app");
});
