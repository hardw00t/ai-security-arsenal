# Frida Code Snippets for Android Pentesting

Common Frida patterns and recipes for mobile security testing.

## Basic Operations

### List Loaded Classes
```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("com.target.app")) {
                console.log(className);
            }
        },
        onComplete: function() {}
    });
});
```

### List Methods of a Class
```javascript
Java.perform(function() {
    var targetClass = Java.use("com.target.app.ClassName");
    var methods = targetClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log(method.toString());
    });
});
```

### Hook Method with Arguments
```javascript
Java.perform(function() {
    var targetClass = Java.use("com.target.app.ClassName");

    targetClass.methodName.overload('java.lang.String', 'int').implementation = function(str, num) {
        console.log("methodName called");
        console.log("  arg1: " + str);
        console.log("  arg2: " + num);

        var result = this.methodName(str, num);
        console.log("  return: " + result);
        return result;
    };
});
```

### Modify Return Value
```javascript
Java.perform(function() {
    var targetClass = Java.use("com.target.app.SecurityCheck");

    targetClass.isSecure.implementation = function() {
        console.log("isSecure() called - returning true");
        return true;
    };
});
```

### Call Method on Existing Instance
```javascript
Java.perform(function() {
    Java.choose("com.target.app.ClassName", {
        onMatch: function(instance) {
            console.log("Found instance: " + instance);
            var result = instance.someMethod();
            console.log("Result: " + result);
        },
        onComplete: function() {}
    });
});
```

## String Operations

### Hook All String Operations
```javascript
Java.perform(function() {
    var StringBuilder = Java.use('java.lang.StringBuilder');

    StringBuilder.toString.implementation = function() {
        var result = this.toString();
        if (result.length > 0 && result.length < 500) {
            console.log("[StringBuilder] " + result);
        }
        return result;
    };
});
```

### Search Memory for Strings
```javascript
var pattern = "password";
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, pattern, {
        onMatch: function(address, size) {
            console.log("Found at: " + address);
            console.log(hexdump(address, { length: 64 }));
        },
        onComplete: function() {}
    });
});
```

## Network/HTTP Hooks

### Hook OkHttp Requests
```javascript
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');

    var RealCall = Java.use('okhttp3.RealCall');
    RealCall.execute.implementation = function() {
        var request = this.request();
        console.log("\n[OkHttp Request]");
        console.log("  URL: " + request.url().toString());
        console.log("  Method: " + request.method());
        console.log("  Headers: " + request.headers().toString());

        var response = this.execute();
        console.log("  Response Code: " + response.code());
        return response;
    };
});
```

### Hook URL Connections
```javascript
Java.perform(function() {
    var URL = Java.use('java.net.URL');

    URL.openConnection.overload().implementation = function() {
        console.log("[URL.openConnection] " + this.toString());
        return this.openConnection();
    };
});
```

### Log All HTTP Traffic
```javascript
Java.perform(function() {
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');

    HttpURLConnection.getInputStream.implementation = function() {
        console.log("\n[HTTP Request]");
        console.log("  URL: " + this.getURL().toString());
        console.log("  Method: " + this.getRequestMethod());
        console.log("  Response Code: " + this.getResponseCode());
        return this.getInputStream();
    };
});
```

## Database Hooks

### Hook SQLite Queries
```javascript
Java.perform(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        console.log("\n[SQLite rawQuery]");
        console.log("  SQL: " + sql);
        if (args) {
            console.log("  Args: " + args.join(", "));
        }
        return this.rawQuery(sql, args);
    };

    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log("\n[SQLite execSQL]");
        console.log("  SQL: " + sql);
        return this.execSQL(sql);
    };
});
```

### Hook SharedPreferences
```javascript
Java.perform(function() {
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');

    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log("[SharedPrefs GET] " + key + " = " + result);
        return result;
    };

    var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    Editor.putString.implementation = function(key, value) {
        console.log("[SharedPrefs PUT] " + key + " = " + value);
        return this.putString(key, value);
    };
});
```

## File Operations

### Hook File Access
```javascript
Java.perform(function() {
    var File = Java.use('java.io.File');

    File.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[File] " + path);
        return this.$init(path);
    };

    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log("[FileInputStream] " + file.getAbsolutePath());
        return this.$init(file);
    };

    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log("[FileOutputStream] " + file.getAbsolutePath());
        return this.$init(file);
    };
});
```

## WebView Hooks

### Monitor WebView Loading
```javascript
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log("[WebView.loadUrl] " + url);
        return this.loadUrl(url);
    };

    WebView.loadData.implementation = function(data, mimeType, encoding) {
        console.log("[WebView.loadData]");
        console.log("  Data: " + data.substring(0, 200));
        return this.loadData(data, mimeType, encoding);
    };

    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[WebView.addJavascriptInterface] " + name);
        console.log("  Object: " + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };
});
```

### Execute JavaScript in WebView
```javascript
Java.perform(function() {
    Java.choose('android.webkit.WebView', {
        onMatch: function(webview) {
            Java.scheduleOnMainThread(function() {
                webview.evaluateJavascript("document.cookie",
                    Java.use('android.webkit.ValueCallback').$new({
                        onReceiveValue: function(value) {
                            console.log("Cookies: " + value);
                        }
                    })
                );
            });
        },
        onComplete: function() {}
    });
});
```

## Intent Hooks

### Monitor Intents
```javascript
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');

    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log("\n[startActivity]");
        console.log("  Action: " + intent.getAction());
        console.log("  Component: " + intent.getComponent());
        console.log("  Data: " + intent.getDataString());
        console.log("  Extras: " + intent.getExtras());
        return this.startActivity(intent);
    };

    Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, requestCode) {
        console.log("\n[startActivityForResult]");
        console.log("  Action: " + intent.getAction());
        console.log("  RequestCode: " + requestCode);
        return this.startActivityForResult(intent, requestCode);
    };
});
```

## Clipboard Monitoring

```javascript
Java.perform(function() {
    var ClipboardManager = Java.use('android.content.ClipboardManager');

    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var text = clip.getItemAt(0).getText();
        console.log("[Clipboard SET] " + text);
        return this.setPrimaryClip(clip);
    };

    ClipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        if (clip && clip.getItemCount() > 0) {
            console.log("[Clipboard GET] " + clip.getItemAt(0).getText());
        }
        return clip;
    };
});
```

## Native Hooks

### Hook libc Functions
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
        console.log("[open] " + this.path);
    },
    onLeave: function(retval) {
        console.log("  fd: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "system"), {
    onEnter: function(args) {
        console.log("[system] " + Memory.readUtf8String(args[0]));
    }
});
```

### Hook Native Function in Library
```javascript
var targetLib = Module.findBaseAddress("libnative.so");
var targetFunc = targetLib.add(0x1234);  // Offset from IDA/Ghidra

Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("Native function called");
        console.log("  arg0: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("  return: " + retval);
    }
});
```

## Utility Functions

### Bytes to Hex
```javascript
function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}
```

### Get Stack Trace
```javascript
function getStackTrace() {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    return Log.getStackTraceString(Exception.$new());
}
```

### Run on Main Thread
```javascript
Java.scheduleOnMainThread(function() {
    // Code that must run on UI thread
});
```

## Quick Reference

```bash
# Spawn app with script
frida -U -f com.target.app -l script.js --no-pause

# Attach to running app
frida -U com.target.app -l script.js

# List running processes
frida-ps -U

# List installed apps
frida-ps -Uai

# Quick REPL exploration
frida -U com.target.app
# Then: Java.perform(function() { ... })
```
