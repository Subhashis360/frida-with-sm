// Resolve required linker symbols dynamically
let linkerModule = Process.findModuleByName("linker64");
let dlopenPtr = null;
let ctorPtr = null;

linkerModule.enumerateSymbols().forEach(sym => {
    if (sym.name.includes("do_dlopen")) {
        dlopenPtr = sym.address;
    } else if (sym.name.includes("call_constructor")) {
        ctorPtr = sym.address;
    }
});

let flutterHandled = false;

// Hook do_dlopen to detect when libflutter.so is being loaded
if (dlopenPtr !== null) {
    Interceptor.attach(dlopenPtr, {
        onEnter(args) {
            try {
                let libPath = args[0].readCString();

                if (libPath && libPath.includes("libflutter.so")) {

                    // Hook constructor call only once
                    if (ctorPtr !== null) {
                        Interceptor.attach(ctorPtr, {
                            onEnter() {
                                if (!flutterHandled) {
                                    flutterHandled = true;

                                    let flutterMod = Process.findModuleByName("libflutter.so");
                                    if (flutterMod) {
                                        console.log("[+] libflutter.so base:", flutterMod.base);

                                        // Offset where session_verify_cert_chain is located
                                        let target = flutterMod.base.add(0x7dc720);
                                        bypassCertCheck(target);
                                    }
                                }
                            }
                        });
                    }
                }
            } catch (err) {
                console.log("[-] Error while reading library path:", err);
            }
        }
    });
}

// Replace return value of certificate verification function
function bypassCertCheck(funcAddr) {
    Interceptor.attach(funcAddr, {
        onLeave(retval) {
            retval.replace(ptr("0x1"));
            console.log("[+] Certificate check bypassed, return value forced to 1");
        }
    });
}
