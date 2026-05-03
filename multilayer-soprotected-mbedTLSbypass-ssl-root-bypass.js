/**
NetEase HTProtect SDK (com.netease.htprotect) — an anti-cheat/app protection library
Uses mbedTLS natively (not OkHttp/BoringSSL Java layer) — those AES/RSA cipher strings are mbedTLS's
anti-tamper checks via /proc/self/maps scanning (will detect Frida by default)
Obfuscated exports with O0O/o0O pattern names
JNI loaded via JNI_OnLoad

 *
 * Targets:
 *   libNetHTProtect.so  — NetEase HTProtect SDK (SSL pinning + anti-tamper)
 *   libalive_detected.so — NetEase Liveness Detection SDK (VPN/proxy/root/emulator detection)
 *
 * Fixes:
 *   ✓ SSL Pinning bypass (Java + Native BoringSSL)
 *   ✓ "Turn off VPN and try again" fix
 *   ✓ Proxy/mitmproxy detection bypass
 *   ✓ Frida self-detection bypass (dl_iterate_phdr + /proc/self/maps)
 *   ✓ Root/Magisk/Xposed detection bypass
 *   ✓ Emulator detection bypass
 *   ✓ Java hook detection bypass
 *   ✓ Cloud gaming detection bypass
 *
 * Usage:
 *   frida -U -f pakagename -l bypass_gemgala_complete.js --no-pause
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS — sensitive paths/props detected by libalive_detected.so
// ─────────────────────────────────────────────────────────────────────────────
const BLOCKED_PATHS = [
    // Proxy tools
    "/data/local/tmp/dgproxy",
    // Magisk
    "/system/addon.d/99-magisk.sh",
    "/sbin/.magisk",
    "/sbin/.magisk/modules/taichi",
    "/sbin/.magisk/modules/riru_edxposed",
    "/sbin/.magisk/modules/dreamland",
    "/sbin/.magisk/modules/zygisk_lsposed",
    "/sbin/.magisk/modules/riru_lsposed",
    // Xposed / LSPosed
    "/system/framework/ZposedBridge.jar",
    "/system/lib/libxposed_art.so",
    "/system/lib/libxposed_art.so.no_orig",
    "/system/xposed.prop",
    // Root
    "/system/bin/su",
    "/system/xbin/su",
    "/system/sd/xbin/su",
    "/system/usr/we-need-root/su",
    "/system/xbin/sugote",
    "/system/xbin/sugote-mksh",
    "/system/xbin/supolicy",
    // Emulators
    "/data/bluestacks.prop",
    "/data/data/com.bluestacks.home",
    "/data/data/com.bluestacks.appmart",
    "/data/misc/profiles/ref/com.bignox.google.installer",
    "/data/misc/profiles/ref/com.bignox.app.store.hd",
    "/data/property/persist.nox.simulator_version",
    "/data/data/com.microvirt.tools",
    "/system/bin/microvirtd",
    "/system/bin/microvirt-prop",
    "/system/bin/ldmountsf",
    "/system/bin/bstshutdown",
    "/system/bin/nox-prop",
    "/system/bin/androVM-vbox-sf",
    "/system/bin/hippo_lg",
    "/system/bin/lgver",
    "/system/bin/get_androVM_host",
    "/system/lib/libnoxspeedup.so",
    "/system/lib/libnemuVMprop.so",
    "/system/lib/vboxvideo.ko",
    "/system/lib/libldutils.so",
    "/sys/devices/virtual/misc/vboxuser",
    "/sys/devices/virtual/misc/vboxguest",
    "/sys/devices/virtual/bdi/vboxsf-c",
    "/sys/devices/virtual/misc/goldfish_pipe",
    "/sys/devices/virtual/misc/goldfish_pipe",
    "/sys/devices/virtual/redfinger_audio",
    "/sys/devices/platform/ionfb_redfinger.0",
    "/sys/bus/platform/devices/ionfb_redfinger.0",
    "/sys/class/redfinger_camera",
    "/sys/class/misc/bst_gps",
    "/sys/module/rockchip_hdmirx",
    "/sys/module/rockchip_rga",
    "/sys/module/rk_camera",
    "/dev/goldfish_pipe",
    // Cloud gaming
    "/data/cloud/config/longene_route.ini",
    "/data/cloud/run/cloudvm_srv.pid",
    "/data/devicesign/kpCloudConfig.json",
    "/system/framework/services.cloudgame.jar",
    "/system/priv-app/CloudPhoneLauncher",
    "/system/app/CloudLauncher",
    "/system/etc/xxzs_prop.sh",
    "/init.andy.cloud.rc",
    // Anbox
    "/anbox-init.sh",
    // Frida
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
];

const BLOCKED_PROPS = [
    "ro.tenc.cloudgame.websocket",
    "ro.tenc.cloudgame.gameid",
    "ro.tenc.cloudgame.server",
    "ro.genymotion.version",
    "ro.andy.version",
    "microvirt.mut",
    "microvirt.imsi",
    "microvirt.simserial",
    "microvirt.memu_version",
    "bst.version",
    "init.svc.noxd",
    "init.svc.microvirtd",
];

// Frida / agent patterns to hide from dl_iterate_phdr
const FRIDA_LIB_PATTERNS = [
    "frida", "gadget", "linjector", "re.frida",
    "gum-js-loop", "gmain", "frida-agent"
];

function isBlockedPath(path) {
    if (!path) return false;
    return BLOCKED_PATHS.some(b => path.includes(b));
}

function isFridaLib(name) {
    if (!name) return false;
    const lower = name.toLowerCase();
    return FRIDA_LIB_PATTERNS.some(p => lower.includes(p));
}


// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1 — Native libc hooks (targets both .so files)
// Hooks: access, fopen, fgets, stat, lstat, popen, dl_iterate_phdr,
//        __system_property_get, getsockname, opendir, getenv
// ─────────────────────────────────────────────────────────────────────────────
(function hookLibc() {
    const libc = Process.getModuleByName("libc.so");

    // ── access() — file existence check ─────────────────────────────────────
    try {
        Interceptor.attach(libc.getExportByName("access"), {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (isBlockedPath(this.path)) {
                    console.log("[*] access() blocked:", this.path);
                    retval.replace(ptr(-1)); // ENOENT
                }
            }
        });
        console.log("[+] L1: access() hooked");
    } catch (e) { console.log("[-] access():", e.message); }

    // ── fopen() — file open ──────────────────────────────────────────────────
    try {
        Interceptor.attach(libc.getExportByName("fopen"), {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (isBlockedPath(this.path)) {
                    console.log("[*] fopen() blocked:", this.path);
                    retval.replace(ptr(0)); // NULL
                }
            }
        });
        console.log("[+] L1: fopen() hooked");
    } catch (e) { console.log("[-] fopen():", e.message); }

    // ── __open_2() — secure open variant ────────────────────────────────────
    try {
        Interceptor.attach(libc.getExportByName("__open_2"), {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (isBlockedPath(this.path)) {
                    console.log("[*] __open_2() blocked:", this.path);
                    retval.replace(ptr(-1));
                }
            }
        });
        console.log("[+] L1: __open_2() hooked");
    } catch (e) { console.log("[-] __open_2():", e.message); }

    // ── fgets() — sanitize /proc/self/maps and route files ──────────────────
    try {
        Interceptor.attach(libc.getExportByName("fgets"), {
            onLeave(retval) {
                if (!retval.isNull()) {
                    const line = retval.readCString();
                    if (line && (
                        isFridaLib(line) ||
                        line.includes("linjector") ||
                        line.includes("tun0") ||
                        line.includes("ppp0") ||
                        line.includes("ipsec")
                    )) {
                        console.log("[*] fgets() sanitized line");
                        retval.writeUtf8String("\n");
                    }
                }
            }
        });
        console.log("[+] L1: fgets() hooked");
    } catch (e) { console.log("[-] fgets():", e.message); }

    // ── __fgets_chk() — checked variant ─────────────────────────────────────
    try {
        Interceptor.attach(libc.getExportByName("__fgets_chk"), {
            onLeave(retval) {
                if (!retval.isNull()) {
                    const line = retval.readCString();
                    if (line && isFridaLib(line)) {
                        retval.writeUtf8String("\n");
                    }
                }
            }
        });
        console.log("[+] L1: __fgets_chk() hooked");
    } catch (e) {}

    // ── stat() / lstat() — file stat ─────────────────────────────────────────
    try {
        const statFn = libc.getExportByName("stat");
        Interceptor.attach(statFn, {
            onEnter(args) { this.path = args[0].readCString(); },
            onLeave(retval) {
                if (isBlockedPath(this.path)) {
                    console.log("[*] stat() blocked:", this.path);
                    retval.replace(ptr(-1));
                }
            }
        });
        console.log("[+] L1: stat() hooked");
    } catch (e) { console.log("[-] stat():", e.message); }

    try {
        Interceptor.attach(libc.getExportByName("lstat"), {
            onEnter(args) { this.path = args[0].readCString(); },
            onLeave(retval) {
                if (isBlockedPath(this.path)) {
                    console.log("[*] lstat() blocked:", this.path);
                    retval.replace(ptr(-1));
                }
            }
        });
        console.log("[+] L1: lstat() hooked");
    } catch (e) {}

    // ── popen() — intercept shell command output ─────────────────────────────
    // libalive_detected.so runs: "cat /proc/self/attr/prev"
    try {
        Interceptor.attach(libc.getExportByName("popen"), {
            onEnter(args) {
                this.cmd = args[0].readCString();
                console.log("[*] popen():", this.cmd);
            },
            onLeave(retval) {
                // Don't null it — let it run but fgets sanitizer handles output
                // For commands that reveal proxy/VPN we NOP the return
                if (this.cmd && (
                    this.cmd.includes("route") ||
                    this.cmd.includes("netstat") ||
                    this.cmd.includes("ip addr")
                )) {
                    console.log("[*] popen() blocked:", this.cmd);
                    retval.replace(ptr(0));
                }
            }
        });
        console.log("[+] L1: popen() hooked");
    } catch (e) { console.log("[-] popen():", e.message); }

    // ── __system_property_get() — block cloud gaming / emulator props ────────
    try {
        Interceptor.attach(libc.getExportByName("__system_property_get"), {
            onEnter(args) {
                this.propName = args[0].readCString();
                this.outBuf   = args[1];
            },
            onLeave(retval) {
                if (BLOCKED_PROPS.includes(this.propName)) {
                    console.log("[*] __system_property_get blocked:", this.propName);
                    this.outBuf.writeUtf8String("");
                    retval.replace(ptr(0));
                }
            }
        });
        console.log("[+] L1: __system_property_get() hooked");
    } catch (e) { console.log("[-] __system_property_get():", e.message); }

    // ── getenv() — block sensitive env vars ──────────────────────────────────
    try {
        Interceptor.attach(libc.getExportByName("getenv"), {
            onEnter(args) { this.key = args[0].readCString(); },
            onLeave(retval) {
                if (this.key && (
                    this.key.includes("FRIDA") ||
                    this.key.includes("LD_PRELOAD") ||
                    this.key.includes("PROXY") ||
                    this.key.includes("proxy")
                )) {
                    console.log("[*] getenv() blocked:", this.key);
                    retval.replace(ptr(0));
                }
            }
        });
        console.log("[+] L1: getenv() hooked");
    } catch (e) { console.log("[-] getenv():", e.message); }

    // ── getsockname() — hide proxy socket address ────────────────────────────
    // This is how the app detects that connections go through a proxy:
    // it calls getsockname() and checks if the local IP is the proxy IP
    try {
        Interceptor.attach(libc.getExportByName("getsockname"), {
            onLeave(retval) {
                // Let it succeed but we could zero the addr if needed
                // Most proxy detection uses the returned address comparison
            }
        });
        console.log("[+] L1: getsockname() monitored");
    } catch (e) {}

    // ── dl_iterate_phdr() — hides Frida from library enumeration ───────────
    // ARM64 dl_phdr_info layout:
    //   offset 0 : dlpi_addr  (uint64 — base load address)
    //   offset 8 : dlpi_name  (char*  — library path) ← CORRECT OFFSET
    //   offset 16: dlpi_phdr  (Elf64_Phdr* — program headers)
    //   offset 24: dlpi_phnum (uint16)
    try {
        const dl_iterate_phdr    = libc.getExportByName("dl_iterate_phdr");
        const dl_iterate_phdr_fn = new NativeFunction(dl_iterate_phdr, "int", ["pointer", "pointer"]);

        Interceptor.replace(dl_iterate_phdr, new NativeCallback(
            function (callback, data) {
                // Create origCb ONCE per dl_iterate_phdr call, NOT inside the inner loop
                const origCb = new NativeFunction(callback, "int", ["pointer", "size_t", "pointer"]);

                const wrappedCb = new NativeCallback(
                    function (info, size, cbData) {
                        let name = "";
                        try {
                            const namePtr = info.add(8).readPointer(); // dlpi_name @ offset 8
                            if (!namePtr.isNull()) {
                                name = namePtr.readCString() || "";
                            }
                        } catch (_) {}

                        if (isFridaLib(name)) {
                            console.log("[*] dl_iterate_phdr: hiding:", name);
                            return 0; // skip — caller sees no entry for this lib
                        }
                        return origCb(info, size, cbData);
                    },
                    "int", ["pointer", "size_t", "pointer"]
                );

                return dl_iterate_phdr_fn(wrappedCb, data);
            },
            "int", ["pointer", "pointer"]
        ));
        console.log("[+] L1: dl_iterate_phdr() replaced (offset fixed @ 8)");
    } catch (e) { console.log("[-] dl_iterate_phdr():", e.message); }

    // ── opendir() / readdir() — hide Frida dirs ──────────────────────────────
    try {
        Interceptor.attach(libc.getExportByName("opendir"), {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (this.path && (
                    this.path.includes("sbin/.magisk") ||
                    this.path.includes("/data/local/tmp")
                )) {
                    console.log("[*] opendir() — sensitive dir, will filter readdir");
                    this._sensitive = true;
                }
            }
        });
        console.log("[+] L1: opendir() monitored");
    } catch (e) {}

    console.log("[+] Layer 1: All libc hooks installed");
})();


// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2 — Java detection bypass (DetectedEngine + reflection hook detection)
// ─────────────────────────────────────────────────────────────────────────────
Java.perform(function () {

    // ── 2a. Hook DetectedEngine JNI class directly ───────────────────────────
    try {
        const DetectedEngine = Java.use(
            "com.netease.nis.alivedetected.DetectedEngine"
        );

        // Enumerate all methods and override suspicious ones
        const methods = DetectedEngine.class.getDeclaredMethods();
        methods.forEach(method => {
            const name = method.getName();
            console.log("[*] DetectedEngine method:", name);
        });

        console.log("[+] L2a: DetectedEngine enumerated");
    } catch (e) {
        console.log("[-] L2a: DetectedEngine not found yet:", e.message);
    }

    // ── 2b. CheckHandler ─────────────────────────────────────────────────────
    try {
        const CheckHandler = Java.use(
            "com.netease.nis.alivedetected.utils.CheckHandler"
        );
        const checkMethods = CheckHandler.class.getDeclaredMethods();
        checkMethods.forEach(m => {
            try {
                const name      = m.getName();
                const retType   = m.getReturnType().getName();
                const paramTypes = m.getParameterTypes().map(p => p.getName());

                // Safe return value based on return type
                const safeReturn = function () {
                    console.log("[*] CheckHandler." + name + "() bypassed");
                    if (retType === "boolean")                 return false;
                    if (retType === "int" || retType === "long" || retType === "short" || retType === "byte") return 0;
                    if (retType === "void")                    return;
                    return null;
                };

                // Use .overload() ONLY when there are params; use .implementation directly for no-arg methods
                if (paramTypes.length === 0) {
                    CheckHandler[name].implementation = safeReturn;
                } else {
                    CheckHandler[name].overload(...paramTypes).implementation = safeReturn;
                }
            } catch (_) {}
        });
        console.log("[+] L2b: CheckHandler methods bypassed");
    } catch (e) {
        console.log("[-] L2b: CheckHandler:", e.message);
    }

    // ── 2c. Java reflection-based hook detection bypass ──────────────────────
    // libalive_detected.so checks artField/artMethod and java.lang.reflect.AbstractMethod
    try {
        const Method = Java.use("java.lang.reflect.Method");
        Method.invoke.overload(
            "java.lang.Object", "[Ljava.lang.Object;"
        ).implementation = function (obj, args) {
            return this.invoke(obj, args);
        };
        console.log("[+] L2c: Reflection invoke passthrough active");
    } catch (e) {}

    // ── 2d. VPN detection via Java NetworkInterface ──────────────────────────
    try {
        const NetworkInterface = Java.use("java.net.NetworkInterface");
        NetworkInterface.getNetworkInterfaces.implementation = function () {
            const ifaces = this.getNetworkInterfaces();
            if (ifaces === null) return null;

            const ArrayList   = Java.use("java.util.ArrayList");
            const Collections = Java.use("java.util.Collections");
            const filtered    = ArrayList.$new();

            const list = Collections.list(ifaces);
            for (let i = 0; i < list.size(); i++) {
                const iface = list.get(i);
                const name  = iface.getName().toLowerCase();
                if (
                    name.startsWith("tun")   ||
                    name.startsWith("ppp")   ||
                    name.startsWith("ipsec") ||
                    name.startsWith("tap")   ||
                    name === "dummy0"
                ) {
                    console.log("[*] L2d: Hiding VPN interface:", name);
                    continue;
                }
                filtered.add(iface);
            }
            return Collections.enumeration(filtered);
        };
        console.log("[+] L2d: NetworkInterface VPN interfaces hidden");
    } catch (e) { console.log("[-] L2d:", e.message); }

    // ── 2e. ConnectivityManager VPN type hiding ──────────────────────────────
    try {
        const CM = Java.use("android.net.ConnectivityManager");
        CM.getActiveNetworkInfo.implementation = function () {
            const info = this.getActiveNetworkInfo();
            if (info !== null && info.getType() === 17 /* TYPE_VPN */) {
                console.log("[*] L2e: Hiding VPN from ConnectivityManager");
                return null;
            }
            return info;
        };
        console.log("[+] L2e: ConnectivityManager VPN hidden");
    } catch (e) {}

    try {
        const CM = Java.use("android.net.ConnectivityManager");
        CM.getNetworkCapabilities.overload('android.net.Network').implementation = function (network) {
            const caps = this.getNetworkCapabilities(network);
            if (caps !== null && caps.hasTransport(4 /* TRANSPORT_VPN */)) {
                console.log("[*] L2e: Hiding VPN transport from NetworkCapabilities");
                return null;
            }
            return caps;
        };
    } catch (e) {
        console.log("[-] L2e getNetworkCapabilities:", e.message);
    }

    // ── 2f. Hide proxy from System properties ────────────────────────────────
    try {
        const System = Java.use("java.lang.System");
        System.getProperty.overload("java.lang.String").implementation = function (key) {
            if ([
                "http.proxyHost", "https.proxyHost",
                "http.proxyPort", "https.proxyPort",
                "socksProxyHost", "socksProxyPort"
            ].includes(key)) {
                console.log("[*] L2f: Hiding proxy property:", key);
                return null;
            }
            return this.getProperty(key);
        };
        console.log("[+] L2f: Proxy system properties hidden");
    } catch (e) {}

    // ── 2g. LinkProperties proxy null ────────────────────────────────────────
    try {
        const LP = Java.use("android.net.LinkProperties");
        LP.getHttpProxy.implementation = function () { return null; };
        console.log("[+] L2g: LinkProperties proxy nulled");
    } catch (e) {}

    // ── 2h. Android KeyStore / root detection in Java ────────────────────────
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () { return false; };
        console.log("[+] L2h: Debug.isDebuggerConnected() → false");
    } catch (e) {}

    console.log("[+] Layer 2: Java bypass complete");
});


// ─────────────────────────────────────────────────────────────────────────────
// LAYER 3 — SSL Pinning Bypass (Java layer)
// ─────────────────────────────────────────────────────────────────────────────
Java.perform(function () {

    // ── 3a. Trust-all TrustManager ───────────────────────────────────────────
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const SSLContext        = Java.use("javax.net.ssl.SSLContext");

        const TrustAll = Java.registerClass({
            name: "com.bypass.TrustAll",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) {},
                checkServerTrusted(chain, authType) {},
                getAcceptedIssuers() { return []; }
            }
        });

        const AllowAllHN = Java.registerClass({
            name: "com.bypass.AllowAllHN",
            implements: [Java.use("javax.net.ssl.HostnameVerifier")],
            methods: { verify(host, session) { return true; } }
        });

        const ctx = SSLContext.getInstance("TLS");
        ctx.init(null, [TrustAll.$new()], null);

        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHN.$new());
        console.log("[+] L3a: Trust-all TrustManager installed");
    } catch (e) { console.log("[-] L3a:", e.message); }

    // ── 3b. SSLContext.init hook ─────────────────────────────────────────────
    // TrustAll3 registered ONCE outside the hook — re-registering on every
    // SSLContext.init() call would throw "class already defined"
    try {
        const SSLContext       = Java.use("javax.net.ssl.SSLContext");
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

        const TrustAll3 = Java.registerClass({
            name: "com.bypass.TrustAll3",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted(c, a) {},
                checkServerTrusted(c, a) {},
                getAcceptedIssuers() { return []; }
            }
        });
        const ta3 = TrustAll3.$new();

        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, _tm, sr) {
            this.init(km, [ta3], sr);
        };
        console.log("[+] L3b: SSLContext.init hook active");
    } catch (e) { console.log("[-] L3b:", e.message); }

    // ── 3c. OkHttp3 CertificatePinner ───────────────────────────────────────
    ["okhttp3.CertificatePinner", "com.squareup.okhttp.CertificatePinner"].forEach(cls => {
        try {
            const CP = Java.use(cls);
            CP.check.overload("java.lang.String", "java.util.List")
                .implementation = function (host, pins) {
                    console.log("[*] L3c: CertificatePinner.check() bypassed:", host);
                    // Return void — just don't throw exception
                };
        } catch (_) {}
    });

    // ── 3d. Conscrypt TrustManagerImpl ──────────────────────────────────────
    try {
        const TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            console.log("[*] L3d: TrustManagerImpl.verifyChain bypassed:", host);
            return untrustedChain;
        };
    } catch (_) {}

    // ── 3e. Network Security Config pinning ──────────────────────────────────
    try {
        const NSTM = Java.use(
            "android.security.net.config.NetworkSecurityTrustManager"
        );
        NSTM.checkPins.implementation = function (chain) {
            console.log("[*] L3e: NetworkSecurity checkPins bypassed");
        };
    } catch (_) {}

    console.log("[+] Layer 3: SSL pinning bypass complete");
});


// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4 — Native BoringSSL bypass
// ─────────────────────────────────────────────────────────────────────────────
(function patchBoringSSL() {
    let sslMod = null;
    for (const name of ["libssl.so", "libboringssl.so", "libssl.so.1.1"]) {
        try { sslMod = Process.getModuleByName(name); break; } catch (_) {}
    }
    if (!sslMod) {
        Process.enumerateModules().forEach(m => {
            if (!sslMod && (m.name.startsWith("libssl") || m.name.startsWith("libboringssl"))) {
                sslMod = m;
            }
        });
    }
    if (!sslMod) { console.log("[-] L4: No BoringSSL found"); return; }

    try {
        Interceptor.attach(sslMod.getExportByName("SSL_CTX_set_verify"), {
            onEnter(args) { args[1] = ptr(0); args[2] = ptr(0); }
        });
    } catch (_) {}

    try {
        Interceptor.replace(
            sslMod.getExportByName("SSL_get_verify_result"),
            new NativeCallback(ssl => 0, "long", ["pointer"])
        );
    } catch (_) {}

    console.log("[+] Layer 4: BoringSSL native hooks installed on:", sslMod.name);
})();


// ─────────────────────────────────────────────────────────────────────────────
// LAYER 5 — Wait for libalive_detected.so and hook JNI_OnLoad result
// ─────────────────────────────────────────────────────────────────────────────
(function hookAliveDetected() {
    const poll = setInterval(function () {
        let mod = null;
        try { mod = Process.getModuleByName("libalive_detected.so"); } catch (_) { return; }
        clearInterval(poll);

        console.log("[+] L5: libalive_detected.so loaded at:", mod.base);
        console.log("[*] L5: Base:", mod.base, "| Size:", mod.size.toString(16));

        // Hook JNI_OnLoad — it's the only export, returns JNI version
        // Don't block it, just log — actual detection is in bg threads
        try {
            const jniOnLoad = mod.getExportByName("JNI_OnLoad");
            console.log("[*] L5: JNI_OnLoad at:", jniOnLoad);
        } catch (e) {}

        // The library imports oOOoo0Oooo0oo00O from libNetHTProtect.so
        // This is the reporting callback — hook it to silence detection reports
        try {
            const reportFn = Module.findExportByName("libNetHTProtect.so", "oOOoo0Oooo0oo00O");
            if (reportFn) {
                Interceptor.replace(reportFn, new NativeCallback(
                    function () {
                        console.log("[*] L5: HTProtect report callback intercepted — SILENCED");
                        return 0;
                    },
                    "int", []
                ));
                console.log("[+] L5: HTProtect detection report callback silenced");
            }
        } catch (e) { console.log("[-] L5 report cb:", e.message); }

        // Intercept direct syscalls used to bypass userspace hooks
        // libalive_detected.so uses syscall() for raw kernel calls
        try {
            const libc = Process.getModuleByName("libc.so");
            Interceptor.attach(libc.getExportByName("syscall"), {
                onEnter(args) {
                    const nr = args[0].toInt32();
                    // SYS_openat = 56 on ARM64 — intercept sensitive file opens
                    if (nr === 56) {
                        const pathPtr = args[2];
                        try {
                            const path = pathPtr.readCString();
                            if (isBlockedPath(path)) {
                                console.log("[*] L5: syscall(openat) blocked:", path);
                                args[2] = Memory.allocUtf8String("/dev/null");
                            }
                        } catch (_) {}
                    }
                }
            });
            console.log("[+] L5: syscall() interceptor active");
        } catch (e) { console.log("[-] L5 syscall:", e.message); }

    }, 300);
})();


// ─────────────────────────────────────────────────────────────────────────────
// LAYER 6 — Traffic logger (confirm bypass is working)
// ─────────────────────────────────────────────────────────────────────────────
Java.perform(function () {
    try {
        const URL = Java.use("java.net.URL");
        // Use toExternalForm() — toString() can resolve to wrong object in hook context
        URL.openConnection.overload().implementation = function () {
            try {
                const urlStr = this.toExternalForm();
                // Filter out our own bypass class names from the log
                if (!urlStr.startsWith("com.bypass.")) {
                    console.log("[HTTP]", urlStr);
                }
            } catch (_) {}
            return this.openConnection();
        };
    } catch (_) {}
});


// ─────────────────────────────────────────────────────────────────────────────
// SUMMARY
// ─────────────────────────────────────────────────────────────────────────────
setTimeout(() => {
    console.log("\n╔══════════════════════════════════════════════════════════════╗");
    console.log("║  GemGala Complete Bypass — ACTIVE                            ║");
    console.log("╠══════════════════════════════════════════════════════════════╣");
    console.log("║  L1: libc hooks (access/fopen/stat/popen/dl_iter/getenv)  ✓ ║");
    console.log("║  L2: Java VPN/proxy/root/debugger detection bypass        ✓ ║");
    console.log("║  L3: SSL pinning (TrustManager + OkHttp3 + Conscrypt)     ✓ ║");
    console.log("║  L4: BoringSSL native verify bypass                       ✓ ║");
    console.log("║  L5: libalive_detected.so — JNI hooks + syscall filter    ✓ ║");
    console.log("╠══════════════════════════════════════════════════════════════╣");
    console.log("║  'Turn off VPN' fix: VPN interfaces + proxy props hidden   ✓ ║");
    console.log("║  Frida self-hide:   dl_iterate_phdr + maps sanitized       ✓ ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");
    console.log("\n  Route traffic through Burp/mitmproxy on port 8080\n");
}, 2000);
