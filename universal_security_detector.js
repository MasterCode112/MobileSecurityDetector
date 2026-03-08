/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║        UNIVERSAL SECURITY DETECTOR - Frida Script v2.0          ║
 * ║        Works on Android & iOS | Any Application                 ║
 * ║        Detects: SSL Pinning, Root/Jailbreak, Anti-Debug,        ║
 * ║        Emulator, Integrity, Biometric, Obfuscation & More       ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * USAGE:
 *   frida -U -f com.target.app -l universal_security_detector.js --no-pause
 *   frida -U --attach-name com.target.app -l universal_security_detector.js
 *   frida -H 127.0.0.1:27042 -f com.target.app -l universal_security_detector.js
 *
 * OUTPUT: JSON reports in console + optional file logging
 */

"use strict";

// ─── Configuration ────────────────────────────────────────────────────────────
const CONFIG = {
  verbose: true,          // Show detailed hook logs
  bypassMode: false,      // Auto-bypass detected checks (use carefully)
  logToFile: false,       // Log to /data/local/tmp/frida_security_report.json
  colorOutput: true,      // ANSI colors in terminal
  hookTimeout: 5000,      // ms to wait for hooks to settle
  platform: null,         // Auto-detected: 'android' | 'ios'
};

// ─── Color Helpers ─────────────────────────────────────────────────────────────
const C = {
  red:     s => CONFIG.colorOutput ? `\x1b[31m${s}\x1b[0m` : s,
  green:   s => CONFIG.colorOutput ? `\x1b[32m${s}\x1b[0m` : s,
  yellow:  s => CONFIG.colorOutput ? `\x1b[33m${s}\x1b[0m` : s,
  blue:    s => CONFIG.colorOutput ? `\x1b[34m${s}\x1b[0m` : s,
  magenta: s => CONFIG.colorOutput ? `\x1b[35m${s}\x1b[0m` : s,
  cyan:    s => CONFIG.colorOutput ? `\x1b[36m${s}\x1b[0m` : s,
  bold:    s => CONFIG.colorOutput ? `\x1b[1m${s}\x1b[0m` : s,
  dim:     s => CONFIG.colorOutput ? `\x1b[2m${s}\x1b[0m` : s,
};

// ─── Detection Report ──────────────────────────────────────────────────────────
const REPORT = {
  timestamp: new Date().toISOString(),
  platform: null,
  appInfo: {},
  checks: {
    ssl_pinning:          { detected: false, methods: [], severity: "CRITICAL", bypassed: false },
    root_jailbreak:       { detected: false, methods: [], severity: "HIGH",     bypassed: false },
    anti_debug:           { detected: false, methods: [], severity: "HIGH",     bypassed: false },
    emulator_detection:   { detected: false, methods: [], severity: "MEDIUM",   bypassed: false },
    integrity_check:      { detected: false, methods: [], severity: "HIGH",     bypassed: false },
    certificate_auth:     { detected: false, methods: [], severity: "CRITICAL", bypassed: false },
    biometric_auth:       { detected: false, methods: [], severity: "MEDIUM",   bypassed: false },
    obfuscation:          { detected: false, methods: [], severity: "LOW",      bypassed: false },
    hook_detection:       { detected: false, methods: [], severity: "HIGH",     bypassed: false },
    memory_integrity:     { detected: false, methods: [], severity: "HIGH",     bypassed: false },
    network_security:     { detected: false, methods: [], severity: "MEDIUM",   bypassed: false },
    crypto_operations:    { detected: false, methods: [], severity: "INFO",     bypassed: false },
    keystore_usage:       { detected: false, methods: [], severity: "INFO",     bypassed: false },
    screenshot_prevention:{ detected: false, methods: [], severity: "LOW",      bypassed: false },
    clipboard_protection: { detected: false, methods: [], severity: "LOW",      bypassed: false },
  },
  summary: {},
};

// ─── Logger ────────────────────────────────────────────────────────────────────
function log(category, message, level = "INFO") {
  const icons = { INFO: "ℹ", DETECT: "🔍", BYPASS: "✅", WARN: "⚠", ERROR: "❌", CRITICAL: "🚨" };
  const colors = { INFO: C.blue, DETECT: C.yellow, BYPASS: C.green, WARN: C.magenta, ERROR: C.red, CRITICAL: C.red };
  const colorFn = colors[level] || C.blue;
  const icon = icons[level] || "•";
  const ts = new Date().toTimeString().split(" ")[0];
  console.log(`${C.dim(`[${ts}]`)} ${icon} ${C.bold(colorFn(`[${category}]`))} ${message}`);
}

function detect(checkKey, method, details = "") {
  const check = REPORT.checks[checkKey];
  if (!check) return;
  check.detected = true;
  check.methods.push({ method, details, timestamp: new Date().toISOString() });
  log(checkKey.toUpperCase().replace(/_/g, " "), `${C.yellow(method)}${details ? " → " + details : ""}`, "DETECT");
}

// ─── Platform Detection ────────────────────────────────────────────────────────
function detectPlatform() {
  try {
    Java.available ? CONFIG.platform = "android" : null;
  } catch(e) {}
  try {
    if (ObjC.available) CONFIG.platform = "ios";
  } catch(e) {}
  REPORT.platform = CONFIG.platform;
  log("INIT", `Platform detected: ${C.cyan(CONFIG.platform || "unknown")}`, "INFO");
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ANDROID HOOKS
// ═══════════════════════════════════════════════════════════════════════════════
function hookAndroid() {
  if (!Java.available) return;

  Java.perform(() => {
    log("ANDROID", "Java runtime ready. Installing hooks...", "INFO");

    // ── App Info ────────────────────────────────────────────────────────────
    try {
      const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
      REPORT.appInfo = {
        packageName: context.getPackageName(),
        versionName: context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName.value,
        targetSdk: context.getApplicationInfo().targetSdkVersion.value,
        dataDir: context.getDataDir().getAbsolutePath(),
      };
      log("APP", `Package: ${C.cyan(REPORT.appInfo.packageName)} v${REPORT.appInfo.versionName}`, "INFO");
    } catch(e) { log("APP", "Could not fetch app info: " + e.message, "WARN"); }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. SSL PINNING
    // ─────────────────────────────────────────────────────────────────────────

    // OkHttp3 CertificatePinner
    hookSafe("okhttp3.CertificatePinner", "check", function(hostname, peerCertificates) {
      detect("ssl_pinning", "OkHttp3.CertificatePinner.check", `host=${hostname}`);
      if (CONFIG.bypassMode) { log("BYPASS", `OkHttp3 SSL pin bypassed for ${hostname}`, "BYPASS"); return; }
      return this.check(hostname, peerCertificates);
    }, 2);

    hookSafe("okhttp3.CertificatePinner", "check$okhttp", function(hostname, peerCertificates) {
      detect("ssl_pinning", "OkHttp3.CertificatePinner.check$okhttp", `host=${hostname}`);
      if (CONFIG.bypassMode) return;
      return this.check$okhttp(hostname, peerCertificates);
    }, 2);

    // OkHttp3 Builder
    hookSafe("okhttp3.OkHttpClient$Builder", "certificatePinner", function(pinner) {
      detect("ssl_pinning", "OkHttp3.Builder.certificatePinner", "CertificatePinner configured");
      return this.certificatePinner(pinner);
    }, 1);

    // TrustManager / X509
    hookSafe("javax.net.ssl.HttpsURLConnection", "setSSLSocketFactory", function(factory) {
      detect("ssl_pinning", "HttpsURLConnection.setSSLSocketFactory", "Custom SSLSocketFactory set");
      return this.setSSLSocketFactory(factory);
    }, 1);

    // TrustKit
    hookSafe("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", function(hostname, session) {
      detect("ssl_pinning", "TrustKit.OkHostnameVerifier.verify", `host=${hostname}`);
      if (CONFIG.bypassMode) return true;
      return this.verify(hostname, session);
    }, 2);

    // Retrofit / Network Security Config
    hookSafe("android.security.net.config.NetworkSecurityTrustManager", "checkPins", function(chain) {
      detect("ssl_pinning", "NetworkSecurityTrustManager.checkPins", "Network Security Config pin check");
      if (CONFIG.bypassMode) return;
      return this.checkPins(chain);
    }, 1);

    // Volley HurlStack
    hookSafe("com.android.volley.toolbox.HurlStack", "createConnection", function(url) {
      detect("ssl_pinning", "Volley.HurlStack.createConnection", `url=${url}`);
      return this.createConnection(url);
    }, 1);

    // WebViewClient SSL errors
    hookSafe("android.webkit.WebViewClient", "onReceivedSslError", function(view, handler, error) {
      detect("ssl_pinning", "WebViewClient.onReceivedSslError", `error=${error}`);
      if (CONFIG.bypassMode) { handler.proceed(); return; }
      return this.onReceivedSslError(view, handler, error);
    }, 3);

    // ─────────────────────────────────────────────────────────────────────────
    // 2. ROOT DETECTION
    // ─────────────────────────────────────────────────────────────────────────

    // File existence checks (su binary, Magisk, etc.)
    const File = Java.use("java.io.File");
    File.exists.implementation = function() {
      const path = this.getAbsolutePath();
      const rootPaths = [
        "/su", "/bin/su", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/data/data/com.noshufou.android.su", "/data/data/eu.chainfire.supersu",
        "/data/data/com.koushikdutta.superuser", "/data/data/com.thirdparty.superuser",
        "/system/etc/init.d/99SuperSUDaemon", "/dev/com.koushikdutta.superuser.daemon/",
        "/.magisk", "/sbin/.magisk", "/data/adb/magisk",
        "/system/xbin/busybox", "/system/bin/busybox",
        "/proc/self/maps", // checked for Magisk map entries
      ];
      if (rootPaths.some(p => path.includes(p))) {
        detect("root_jailbreak", "File.exists()", `Suspicious path: ${path}`);
        if (CONFIG.bypassMode) return false;
      }
      return this.exists();
    };

    // Runtime.exec (su command check)
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
      if (typeof cmd === "string" && (cmd.includes("su") || cmd.includes("which") || cmd.includes("id"))) {
        detect("root_jailbreak", "Runtime.exec()", `Command: ${cmd}`);
        detect("anti_debug", "Runtime.exec()", `Shell command: ${cmd}`);
        if (CONFIG.bypassMode) throw Java.use("java.io.IOException").$new("Permission denied");
      }
      return this.exec(cmd);
    };

    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
      const cmdStr = cmds ? cmds.join(" ") : "";
      if (cmdStr.includes("su") || cmdStr.includes("busybox") || cmdStr.includes("magisk")) {
        detect("root_jailbreak", "Runtime.exec(String[])", `Command: ${cmdStr}`);
        if (CONFIG.bypassMode) throw Java.use("java.io.IOException").$new("Permission denied");
      }
      return this.exec(cmds);
    };

    // System Properties check
    hookSafe("android.os.SystemProperties", "get", function(key) {
      const val = this.get(key);
      const suspiciousKeys = ["ro.debuggable", "ro.secure", "service.adb.root"];
      if (suspiciousKeys.includes(key)) {
        detect("root_jailbreak", "SystemProperties.get()", `key=${key} value=${val}`);
        if (CONFIG.bypassMode) {
          if (key === "ro.debuggable") return "0";
          if (key === "ro.secure") return "1";
          if (key === "service.adb.root") return "0";
        }
      }
      return val;
    }, 1);

    // ─────────────────────────────────────────────────────────────────────────
    // 3. ANTI-DEBUG
    // ─────────────────────────────────────────────────────────────────────────

    // Debug.isDebuggerConnected
    hookSafe("android.os.Debug", "isDebuggerConnected", function() {
      detect("anti_debug", "Debug.isDebuggerConnected()", "Debugger presence check");
      if (CONFIG.bypassMode) return false;
      return this.isDebuggerConnected();
    }, 0);

    // Debug.waitingForDebugger
    hookSafe("android.os.Debug", "waitingForDebugger", function() {
      detect("anti_debug", "Debug.waitingForDebugger()", "Waiting for debugger check");
      if (CONFIG.bypassMode) return false;
      return this.waitingForDebugger();
    }, 0);

    // ApplicationInfo.FLAG_DEBUGGABLE
    hookSafe("android.app.ApplicationInfo", "flags", null, 0, (field) => {
      // Field hook via getter
    });

    // ptrace-based via /proc/self/status
    const BufferedReader = Java.use("java.io.BufferedReader");
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const FileInputStream = Java.use("java.io.FileInputStream");

    FileInputStream.$init.overload("java.lang.String").implementation = function(path) {
      if (path === "/proc/self/status" || path === "/proc/self/maps" || path === "/proc/self/task") {
        detect("anti_debug", "FileInputStream(/proc/self/...)", `Tracerpid/maps check: ${path}`);
      }
      return this.$init(path);
    };

    // Timing-based anti-debug
    hookSafe("java.lang.System", "currentTimeMillis", function() {
      return this.currentTimeMillis();
    }, 0); // track if called rapidly (timing check detection - basic)

    // ─────────────────────────────────────────────────────────────────────────
    // 4. EMULATOR DETECTION
    // ─────────────────────────────────────────────────────────────────────────

    // Build properties commonly checked
    const Build = Java.use("android.os.Build");
    [
      { field: "FINGERPRINT", emulatorVals: ["generic", "unknown", "emulator", "sdk_gphone"] },
      { field: "MODEL",       emulatorVals: ["sdk", "Emulator", "Android SDK"] },
      { field: "MANUFACTURER",emulatorVals: ["Genymotion", "unknown", "Google"] },
      { field: "BRAND",       emulatorVals: ["generic", "generic_x86", "TTVM"] },
      { field: "DEVICE",      emulatorVals: ["generic", "vbox86p", "emulator"] },
      { field: "PRODUCT",     emulatorVals: ["sdk", "sdk_gphone", "emulator_armeabi"] },
      { field: "HARDWARE",    emulatorVals: ["goldfish", "ranchu", "vbox86"] },
    ].forEach(({ field }) => {
      try {
        const val = Build[field].value;
        if (val && (val.toLowerCase().includes("emulator") || val.toLowerCase().includes("generic") ||
            val.toLowerCase().includes("genymotion") || val.toLowerCase().includes("goldfish"))) {
          // Passive detection — note environment
          detect("emulator_detection", `Build.${field} read`, `value="${val}" (emulator indicator in env)`);
        }
      } catch(e) {}
    });

    // TelephonyManager checks
    hookSafe("android.telephony.TelephonyManager", "getDeviceId", function() {
      const id = this.getDeviceId();
      detect("emulator_detection", "TelephonyManager.getDeviceId()", `IMEI=${id}`);
      if (CONFIG.bypassMode) return "358239051111110";
      return id;
    }, 0);

    hookSafe("android.telephony.TelephonyManager", "getNetworkOperatorName", function() {
      const op = this.getNetworkOperatorName();
      detect("emulator_detection", "TelephonyManager.getNetworkOperatorName()", `operator=${op}`);
      if (CONFIG.bypassMode) return "T-Mobile";
      return op;
    }, 0);

    // ─────────────────────────────────────────────────────────────────────────
    // 5. INTEGRITY CHECKS (Signature / Package Verification)
    // ─────────────────────────────────────────────────────────────────────────

    const PackageManager = Java.use("android.content.pm.PackageManager");

    // Signature check
    hookSafe("android.content.pm.PackageManager", "getPackageInfo", function(packageName, flags) {
      if ((flags & 64) !== 0) { // GET_SIGNATURES = 64
        detect("integrity_check", "PackageManager.getPackageInfo(GET_SIGNATURES)", `pkg=${packageName}`);
      }
      return this.getPackageInfo(packageName, flags);
    }, 2);

    // Play Integrity API / SafetyNet
    hookSafe("com.google.android.gms.safetynet.SafetyNetClient", "attest", function(nonce, apiKey) {
      detect("integrity_check", "SafetyNet.attest()", "Google SafetyNet attestation");
      return this.attest(nonce, apiKey);
    }, 2);

    hookSafe("com.google.android.gms.integrity.IntegrityManager", "requestIntegrityToken", function(request) {
      detect("integrity_check", "Play Integrity API requestIntegrityToken()", "Play Integrity check");
      return this.requestIntegrityToken(request);
    }, 1);

    // Custom hash checks via MessageDigest
    hookSafe("java.security.MessageDigest", "digest", function() {
      const result = this.digest();
      detect("integrity_check", "MessageDigest.digest()", `algo=${this.getAlgorithm()} - possible APK hash check`);
      return result;
    }, 0);

    // ─────────────────────────────────────────────────────────────────────────
    // 6. CERTIFICATE / MUTUAL TLS
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("javax.net.ssl.SSLContext", "init", function(km, tm, sr) {
      if (km !== null) detect("certificate_auth", "SSLContext.init(KeyManager)", "Client certificate / mTLS configured");
      if (tm !== null) detect("certificate_auth", "SSLContext.init(TrustManager)", "Custom TrustManager - possible pinning");
      return this.init(km, tm, sr);
    }, 3);

    hookSafe("java.security.KeyStore", "load", function(stream, password) {
      detect("certificate_auth", "KeyStore.load()", "KeyStore loaded - checking certificates");
      return this.load(stream, password);
    }, 2);

    // ─────────────────────────────────────────────────────────────────────────
    // 7. BIOMETRIC / AUTHENTICATION
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("androidx.biometric.BiometricPrompt", "authenticate", function(cryptoObject) {
      detect("biometric_auth", "BiometricPrompt.authenticate(cryptoObject)", "Biometric auth with crypto");
      return this.authenticate(cryptoObject);
    }, 1);

    hookSafe("androidx.biometric.BiometricPrompt", "authenticate", function() {
      detect("biometric_auth", "BiometricPrompt.authenticate()", "Biometric auth without crypto");
      return this.authenticate();
    }, 0);

    hookSafe("android.hardware.fingerprint.FingerprintManager", "authenticate", function(crypto, cancel, flags, callback, handler) {
      detect("biometric_auth", "FingerprintManager.authenticate()", "Legacy fingerprint auth");
      return this.authenticate(crypto, cancel, flags, callback, handler);
    }, 5);

    // ─────────────────────────────────────────────────────────────────────────
    // 8. HOOK / FRIDA DETECTION
    // ─────────────────────────────────────────────────────────────────────────

    // Checks for Frida-related artifacts
    const fridaIndicators = [
      "frida", "gum-js-loop", "gmain", "linjector",
      "frida-gadget", "re.frida", "com.frida"
    ];

    // /proc/maps check for Frida
    const Scanner = Java.use("java.util.Scanner");
    try {
      const maps = Java.use("java.io.File").$new("/proc/self/maps");
      if (maps.exists()) {
        detect("hook_detection", "/proc/self/maps exists", "App may scan for Frida in memory maps");
      }
    } catch(e) {}

    // Class loader checks
    hookSafe("java.lang.ClassLoader", "loadClass", function(name) {
      const fridaClasses = ["com.saurik.substrate", "de.robv.android.xposed", "XposedBridge"];
      if (fridaClasses.some(c => name && name.includes(c))) {
        detect("hook_detection", "ClassLoader.loadClass()", `Loading suspicious class: ${name}`);
      }
      return this.loadClass(name);
    }, 1);

    // Xposed check
    hookSafe("android.app.ApplicationPackageManager", "getInstalledApplications", function(flags) {
      const apps = this.getInstalledApplications(flags);
      // Passive — just note that installed apps list is being scanned
      detect("hook_detection", "getInstalledApplications()", "Scanning installed apps (Xposed/Magisk detection?)");
      return apps;
    }, 1);

    // ─────────────────────────────────────────────────────────────────────────
    // 9. NETWORK SECURITY
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("java.net.URL", "openConnection", function() {
      const url = this.toString();
      if (url.startsWith("http://")) {
        detect("network_security", "URL.openConnection(http://)", `Cleartext HTTP: ${url}`);
      }
      return this.openConnection();
    }, 0);

    // Proxy detection
    hookSafe("java.net.Proxy", "$init", function(type, sa) {
      detect("network_security", "Proxy configured", `type=${type}`);
      return this.$init(type, sa);
    }, 2);

    // Check if app detects proxy
    hookSafe("java.lang.System", "getProperty", function(key) {
      const val = this.getProperty(key);
      if (key && (key.includes("proxy") || key.includes("http.proxy"))) {
        detect("network_security", "System.getProperty(proxy)", `Checking proxy: ${key}=${val}`);
      }
      return val;
    }, 1);

    // ─────────────────────────────────────────────────────────────────────────
    // 10. CRYPTO OPERATIONS
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("javax.crypto.Cipher", "getInstance", function(transformation) {
      detect("crypto_operations", "Cipher.getInstance()", `Algorithm: ${transformation}`);
      return this.getInstance(transformation);
    }, 1);

    hookSafe("javax.crypto.SecretKeyFactory", "getInstance", function(algorithm) {
      detect("crypto_operations", "SecretKeyFactory.getInstance()", `Algorithm: ${algorithm}`);
      return this.getInstance(algorithm);
    }, 1);

    // ─────────────────────────────────────────────────────────────────────────
    // 11. ANDROID KEYSTORE
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("android.security.keystore.KeyGenParameterSpec$Builder", "$init", function(alias, purposes) {
      detect("keystore_usage", "KeyGenParameterSpec.Builder()", `alias=${alias} purposes=${purposes}`);
      return this.$init(alias, purposes);
    }, 2);

    hookSafe("java.security.KeyPairGenerator", "getInstance", function(algorithm, provider) {
      if (provider && provider.toString().includes("AndroidKeyStore")) {
        detect("keystore_usage", "KeyPairGenerator (AndroidKeyStore)", `algo=${algorithm}`);
      }
      return this.getInstance(algorithm, provider);
    }, 2);

    // ─────────────────────────────────────────────────────────────────────────
    // 12. SCREENSHOT PREVENTION
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("android.view.Window", "setFlags", function(flags, mask) {
      const FLAG_SECURE = 8192; // 0x2000
      if ((flags & FLAG_SECURE) !== 0) {
        detect("screenshot_prevention", "Window.setFlags(FLAG_SECURE)", "Screenshot/screen recording blocked");
        if (CONFIG.bypassMode) {
          flags &= ~FLAG_SECURE;
          mask &= ~FLAG_SECURE;
        }
      }
      return this.setFlags(flags, mask);
    }, 2);

    hookSafe("android.view.Window", "addFlags", function(flags) {
      const FLAG_SECURE = 8192;
      if ((flags & FLAG_SECURE) !== 0) {
        detect("screenshot_prevention", "Window.addFlags(FLAG_SECURE)", "FLAG_SECURE added dynamically");
        if (CONFIG.bypassMode) flags &= ~FLAG_SECURE;
      }
      return this.addFlags(flags);
    }, 1);

    // ─────────────────────────────────────────────────────────────────────────
    // 13. CLIPBOARD PROTECTION
    // ─────────────────────────────────────────────────────────────────────────

    hookSafe("android.content.ClipboardManager", "setPrimaryClip", function(clip) {
      detect("clipboard_protection", "ClipboardManager.setPrimaryClip()", "App writing to clipboard");
      return this.setPrimaryClip(clip);
    }, 1);

    // ─────────────────────────────────────────────────────────────────────────
    // 14. OBFUSCATION DETECTION (passive analysis)
    // ─────────────────────────────────────────────────────────────────────────

    // Detect reflection-heavy code (obfuscation indicator)
    let reflectionCount = 0;
    hookSafe("java.lang.reflect.Method", "invoke", function(obj, args) {
      reflectionCount++;
      if (reflectionCount === 1) {
        detect("obfuscation", "Reflection.invoke() heavy usage", "Possible obfuscated code path");
      }
      return this.invoke(obj, args);
    }, 2);

    // DexClassLoader (dynamic code loading)
    hookSafe("dalvik.system.DexClassLoader", "$init", function(dexPath, optimizedDirectory, librarySearchPath, parent) {
      detect("obfuscation", "DexClassLoader.$init()", `Loading: ${dexPath}`);
      return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    }, 4);

    hookSafe("dalvik.system.InMemoryDexClassLoader", "$init", function(buffer, parent) {
      detect("obfuscation", "InMemoryDexClassLoader", "Loading DEX from memory - advanced obfuscation");
      return this.$init(buffer, parent);
    }, 2);

    // ─────────────────────────────────────────────────────────────────────────
    // 15. MEMORY INTEGRITY (Native)
    // ─────────────────────────────────────────────────────────────────────────

    // Hook native functions via Interceptor
    hookNativeIfExists("open", (args) => {
      const path = args[0].readUtf8String();
      if (path && (path.includes("/proc/self") || path.includes("/proc/net"))) {
        detect("memory_integrity", "native open()", `Proc read: ${path}`);
      }
    });

    hookNativeIfExists("ptrace", (args) => {
      detect("anti_debug", "native ptrace()", `request=${args[0].toInt32()}`);
      if (CONFIG.bypassMode) return ptr(0); // Return success
    });

    hookNativeIfExists("kill", (args) => {
      const sig = args[1].toInt32();
      if (sig === 0) detect("anti_debug", "native kill(pid, 0)", "Self-debugging check via kill(0)");
    });

    log("ANDROID", `${C.green("✓")} All Android hooks installed successfully`, "INFO");
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  iOS HOOKS
// ═══════════════════════════════════════════════════════════════════════════════
function hookIOS() {
  if (!ObjC.available) return;
  log("iOS", "ObjC runtime ready. Installing hooks...", "INFO");

  // ── SSL Pinning (iOS) ────────────────────────────────────────────────────
  hookObjC("NSURLSession", "dataTaskWithRequest:completionHandler:", function(self, sel, request, completionHandler) {
    detect("ssl_pinning", "NSURLSession.dataTaskWithRequest", `url=${request.URL().absoluteString()}`);
    return self.dataTaskWithRequest_completionHandler_(request, completionHandler);
  });

  hookObjC("NSURLConnection", "sendAsynchronousRequest:queue:completionHandler:", function(self, sel, request, queue, completionHandler) {
    detect("ssl_pinning", "NSURLConnection.sendAsynchronousRequest", "Legacy NSURLConnection");
    return self.sendAsynchronousRequest_queue_completionHandler_(request, queue, completionHandler);
  });

  // TrustKit iOS
  hookObjC("TKNSURLSessionTaskDelegate", "URLSession:task:didReceiveChallenge:completionHandler:", function(self, sel, session, task, challenge, completionHandler) {
    detect("ssl_pinning", "TrustKit.URLSession:task:didReceiveChallenge", "TrustKit SSL validation");
    return self.URLSession_task_didReceiveChallenge_completionHandler_(session, task, challenge, completionHandler);
  });

  // ── Jailbreak Detection (iOS) ────────────────────────────────────────────
  hookObjC("NSFileManager", "fileExistsAtPath:", function(self, sel, path) {
    const pathStr = path.toString();
    const jbPaths = [
      "/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
      "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/",
      "/private/var/stash", "/var/lib/cydia", "/Applications/Sileo.app",
      "/.bootstrapped_electra", "/usr/lib/libjailbreak.dylib"
    ];
    if (jbPaths.some(p => pathStr === p || pathStr.startsWith(p))) {
      detect("root_jailbreak", "NSFileManager.fileExistsAtPath", `Path: ${pathStr}`);
      if (CONFIG.bypassMode) return false;
    }
    return self.fileExistsAtPath_(path);
  });

  hookObjC("UIApplication", "canOpenURL:", function(self, sel, url) {
    const urlStr = url.absoluteString ? url.absoluteString().toString() : url.toString();
    if (urlStr.includes("cydia://")) {
      detect("root_jailbreak", "UIApplication.canOpenURL(cydia://)", "Cydia URL scheme check");
      if (CONFIG.bypassMode) return false;
    }
    return self.canOpenURL_(url);
  });

  // ── Anti-Debug (iOS) ─────────────────────────────────────────────────────
  // sysctl-based debugger check (native)
  hookNativeIfExists("sysctl", (args) => {
    detect("anti_debug", "native sysctl()", "Possible debugger presence check via sysctl");
  });

  hookNativeIfExists("ptrace", (args) => {
    const request = args[0].toInt32();
    if (request === 31) { // PT_DENY_ATTACH
      detect("anti_debug", "native ptrace(PT_DENY_ATTACH)", "Anti-debug protection active");
      if (CONFIG.bypassMode) return ptr(0);
    }
  });

  // ── Biometric (iOS) ──────────────────────────────────────────────────────
  hookObjC("LAContext", "evaluatePolicy:localizedReason:reply:", function(self, sel, policy, reason, reply) {
    detect("biometric_auth", "LAContext.evaluatePolicy", `policy=${policy} reason=${reason}`);
    return self.evaluatePolicy_localizedReason_reply_(policy, reason, reply);
  });

  hookObjC("LAContext", "canEvaluatePolicy:error:", function(self, sel, policy, error) {
    detect("biometric_auth", "LAContext.canEvaluatePolicy", "Biometric availability check");
    return self.canEvaluatePolicy_error_(policy, error);
  });

  // ── Screenshot Prevention (iOS) ──────────────────────────────────────────
  hookObjC("UIScreen", "isCaptured", function(self, sel) {
    detect("screenshot_prevention", "UIScreen.isCaptured", "Screen capture detection");
    if (CONFIG.bypassMode) return false;
    return self.isCaptured();
  });

  // ── Crypto (iOS) ─────────────────────────────────────────────────────────
  hookNativeIfExists("CCCrypt", (args) => {
    const op = args[0].toInt32(); // 0=encrypt, 1=decrypt
    const alg = args[1].toInt32();
    detect("crypto_operations", "CCCrypt()", `op=${op === 0 ? "encrypt" : "decrypt"} alg=${alg}`);
  });

  hookNativeIfExists("SecItemAdd", (args) => {
    detect("keystore_usage", "SecItemAdd()", "Keychain item added");
  });

  hookNativeIfExists("SecItemCopyMatching", (args) => {
    detect("keystore_usage", "SecItemCopyMatching()", "Keychain item read");
  });

  log("iOS", `${C.green("✓")} All iOS hooks installed successfully`, "INFO");
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function hookSafe(className, methodName, impl, argCount, extra) {
  try {
    const clazz = Java.use(className);
    if (!clazz) return;

    // Try overload with argCount first
    try {
      const overloads = clazz[methodName].overloads;
      if (overloads && overloads.length > 0) {
        overloads.forEach(overload => {
          if (impl) overload.implementation = impl;
        });
      } else {
        if (impl) clazz[methodName].implementation = impl;
      }
    } catch(e2) {
      if (impl) clazz[methodName].implementation = impl;
    }
    if (CONFIG.verbose) log("HOOK", `${C.dim(className)}.${C.cyan(methodName)}`, "INFO");
  } catch(e) {
    if (CONFIG.verbose) log("HOOK", `${C.dim("Skip:")} ${className}.${methodName} (${e.message.split("\n")[0]})`, "WARN");
  }
}

function hookObjC(className, methodName, impl) {
  try {
    const cls = ObjC.classes[className];
    if (!cls) return;
    const method = cls[`- ${methodName}`] || cls[`+ ${methodName}`];
    if (!method) return;
    Interceptor.attach(method.implementation, {
      onEnter: function(args) {
        const self = new ObjC.Object(args[0]);
        if (impl) impl(self, args[1], ...Array.from({length: 10}, (_, i) => new ObjC.Object(args[i + 2])));
      }
    });
    if (CONFIG.verbose) log("HOOK", `[ObjC] ${C.dim(className)}.${C.cyan(methodName)}`, "INFO");
  } catch(e) {
    if (CONFIG.verbose) log("HOOK", `${C.dim("Skip:")} ${className}.${methodName} (${e.message})`, "WARN");
  }
}

function hookNativeIfExists(fnName, onEnterCb) {
  try {
    const addr = Module.findExportByName(null, fnName);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function(args) {
        if (onEnterCb) onEnterCb(args);
      }
    });
    if (CONFIG.verbose) log("HOOK", `[native] ${C.cyan(fnName)} @ ${addr}`, "INFO");
  } catch(e) {
    if (CONFIG.verbose) log("HOOK", `${C.dim("Skip native:")} ${fnName}`, "WARN");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════
function generateReport() {
  const detected = Object.entries(REPORT.checks).filter(([,v]) => v.detected);
  const total = Object.keys(REPORT.checks).length;
  const score = Math.round((detected.length / total) * 100);

  REPORT.summary = {
    totalChecks: total,
    detectedChecks: detected.length,
    securityScore: score,
    riskLevel: score > 70 ? "HIGH" : score > 40 ? "MEDIUM" : score > 10 ? "LOW" : "MINIMAL",
    criticalIssues: detected.filter(([,v]) => v.severity === "CRITICAL").length,
    highIssues:     detected.filter(([,v]) => v.severity === "HIGH").length,
    mediumIssues:   detected.filter(([,v]) => v.severity === "MEDIUM").length,
    lowIssues:      detected.filter(([,v]) => v.severity === "LOW").length,
  };

  const divider = "═".repeat(65);
  console.log(`\n${C.cyan(divider)}`);
  console.log(C.bold(C.cyan(`  🛡  UNIVERSAL SECURITY ANALYSIS REPORT`)));
  console.log(C.cyan(divider));
  console.log(`  ${C.bold("App:")}      ${REPORT.appInfo.packageName || "Unknown"}`);
  console.log(`  ${C.bold("Platform:")} ${REPORT.platform}`);
  console.log(`  ${C.bold("Time:")}     ${REPORT.timestamp}`);
  console.log(C.cyan("─".repeat(65)));

  detected.forEach(([key, check]) => {
    const sev = check.severity;
    const sevColor = sev === "CRITICAL" ? C.red : sev === "HIGH" ? C.yellow : sev === "MEDIUM" ? C.magenta : C.blue;
    console.log(`\n  ${sevColor(`[${sev}]`)} ${C.bold(key.toUpperCase().replace(/_/g, " "))}`);
    check.methods.forEach(m => {
      console.log(`    ${C.dim("→")} ${m.method}${m.details ? C.dim(" • " + m.details) : ""}`);
    });
  });

  if (detected.length === 0) {
    console.log(`\n  ${C.green("✓ No security checks detected during this session")}`);
    console.log(`  ${C.dim("(Try interacting with the app to trigger more checks)")}`);
  }

  console.log(`\n${C.cyan("─".repeat(65))}`);
  console.log(`  ${C.bold("Security Checks Detected:")} ${C.yellow(detected.length)} / ${total}`);
  console.log(`  ${C.bold("Risk Level:")} ${REPORT.summary.riskLevel === "HIGH" ? C.red("HIGH") : REPORT.summary.riskLevel === "MEDIUM" ? C.yellow("MEDIUM") : C.green(REPORT.summary.riskLevel)}`);
  console.log(`  ${C.bold("Critical:")} ${C.red(REPORT.summary.criticalIssues)}  ${C.bold("High:")} ${C.yellow(REPORT.summary.highIssues)}  ${C.bold("Medium:")} ${C.magenta(REPORT.summary.mediumIssues)}  ${C.bold("Low:")} ${C.blue(REPORT.summary.lowIssues)}`);
  console.log(C.cyan(divider));
  console.log(`\n  ${C.dim("Full JSON report:")} send(JSON.stringify(REPORT))`);
  console.log(`  ${C.dim("Tip: Interact with the app (login, make requests) to trigger more checks")}`);
  console.log();

  if (CONFIG.logToFile) {
    try {
      const f = new File("/data/local/tmp/frida_security_report.json", "w");
      f.write(JSON.stringify(REPORT, null, 2));
      f.flush();
      f.close();
      log("REPORT", "Saved to /data/local/tmp/frida_security_report.json", "INFO");
    } catch(e) { log("REPORT", "Could not write file: " + e.message, "WARN"); }
  }

  // Send report via Frida RPC
  send({ type: "security_report", data: REPORT });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RPC EXPORTS (for Python controller)
// ═══════════════════════════════════════════════════════════════════════════════
rpc.exports = {
  getReport: () => REPORT,
  getDetected: () => Object.entries(REPORT.checks).filter(([,v]) => v.detected).map(([k,v]) => ({check: k, ...v})),
  enableBypass: () => { CONFIG.bypassMode = true; log("CONFIG", "Bypass mode ENABLED", "BYPASS"); },
  disableBypass: () => { CONFIG.bypassMode = false; log("CONFIG", "Bypass mode DISABLED", "INFO"); },
  setVerbose: (v) => { CONFIG.verbose = v; },
  generateReport: () => generateReport(),
};

// ═══════════════════════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════
(function main() {
  console.log(C.cyan(`
╔══════════════════════════════════════════════════════════════════╗
║     UNIVERSAL SECURITY DETECTOR  v2.0  — Frida Script           ║
║     Detecting: SSL Pinning | Root | Anti-Debug | Emulator       ║
║     Integrity | Biometric | Hooks | Memory | Crypto & More      ║
╚══════════════════════════════════════════════════════════════════╝`));

  detectPlatform();

  if (CONFIG.platform === "android") {
    hookAndroid();
  } else if (CONFIG.platform === "ios") {
    hookIOS();
  } else {
    log("INIT", "Unknown platform — trying both runtimes", "WARN");
    try { hookAndroid(); } catch(e) {}
    try { hookIOS(); } catch(e) {}
  }

  // Auto-generate report after a delay
  setTimeout(() => {
    generateReport();
    log("REPORT", `${C.dim("Monitoring active. Interact with the app to detect more checks...")}`, "INFO");
  }, CONFIG.hookTimeout);

  // Refresh report every 30 seconds
  setInterval(() => {
    const detected = Object.values(REPORT.checks).filter(v => v.detected).length;
    if (detected > 0) generateReport();
  }, 30000);
})();
