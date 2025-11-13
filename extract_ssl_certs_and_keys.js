setTimeout(function() {
    Java.perform(function () {
        var keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');

        /* following function hooks to a Keystore.load(InputStream stream, char[] password) */
        keyStoreLoadStream.implementation = function(stream, charArray) {

            /* sometimes this happen, I have no idea why, tho... */
            if (stream == null) {
                /* just to avoid interfering with app's flow */
                this.load(stream, charArray);
                return;
            }

            /* just to notice the client we've hooked a KeyStore.load */
            send({event: '+found'});

            /* read the buffer stream to a variable */
            var hexString = readStreamToHex (stream);

            /* send KeyStore type to client shell */
            send({event: '+type', certType: this.getType()});

            /* send KeyStore password to client shell */
            send({event: '+pass', password: charArray});

            /* send the string representation to client shell */
            send({event: '+write', cert: hexString});

            /* call the original implementation of 'load' */
            this.load(stream, charArray);

            /* no need to return anything */
        }
    });
},0);

/* following function reads an InputStream and returns an ASCII char representation of it */
function readStreamToHex (stream) {
    var data = [];
    var byteRead = stream.read();
    while (byteRead != -1)
    {
        data.push( ('0' + (byteRead & 0xFF).toString(16)).slice(-2) );
                /* <---------------- binary to hex ---------------> */
        byteRead = stream.read();
    }
    stream.close();
    return data.join('');
}



// setTimeout(function () {
// Java.perform(function () {

//     console.log("[+] Universal Certificate & Key Extractor Loaded");

//     // === Base64 Helper ===
//     function b64(arr) {
//         return Java.use("android.util.Base64")
//             .encodeToString(arr, 0);
//     }

//     // ======================================================
//     // 1️⃣ Dump ALL X509 Certificates (Java Layer)
//     // ======================================================
//     try {
//         var X509 = Java.use("java.security.cert.X509Certificate");
//         X509.getEncoded.implementation = function () {
//             var enc = this.getEncoded();
//             console.log("\n=== [X509] Certificate Found ===");
//             console.log(
//                 "-----BEGIN CERTIFICATE-----\n" +
//                 b64(enc) +
//                 "\n-----END CERTIFICATE-----"
//             );
//             return enc;
//         };
//         console.log("[+] Hooked X509Certificate.getEncoded");
//     } catch (e) {}

//     // ======================================================
//     // 2️⃣ Dump from TrustManager (Pinned Certs)
//     // ======================================================
//     try {
//         var TM = Java.use("javax.net.ssl.X509TrustManager");
//         TM.checkServerTrusted.implementation = function (chain, authType) {
//             console.log("\n=== [TRUSTMANAGER] Certificate Chain ===");

//             for (var i = 0; i < chain.length; i++) {
//                 var enc = chain[i].getEncoded();
//                 console.log(
//                     "-----BEGIN CERTIFICATE-----\n" +
//                     b64(enc) +
//                     "\n-----END CERTIFICATE-----"
//                 );
//             }
//             return this.checkServerTrusted(chain, authType);
//         };
//         console.log("[+] Hooked X509TrustManager.checkServerTrusted");
//     } catch (e) {}


//     // ======================================================
//     // 3️⃣ Dump OkHttp CertificatePinner Pins
//     // ======================================================
//     try {
//         var CP = Java.use("okhttp3.CertificatePinner");
//         CP.check.overload("java.lang.String", "java.util.List")
//             .implementation = function (host, certList) {

//                 console.log("\n=== [OKHTTP PINNING] Host: " + host + " ===");

//                 certList.forEach(function (c) {
//                     console.log(String(c));
//                 });
//                 return;
//             };
//         console.log("[+] Hooked OkHttp CertificatePinner");
//     } catch (e) {}


//     // ======================================================
//     // 4️⃣ Extract certificates + private keys from KeyStore (BKS / PKCS12)
//     // ======================================================
//     try {
//         var KeyStore = Java.use("java.security.KeyStore");

//         KeyStore.load.overload(
//             "java.io.InputStream",
//             "[C"
//         ).implementation = function (stream, pw) {

//             console.log("\n=== [KEYSTORE] KeyStore Loaded ===");

//             var pass = "";
//             if (pw) {
//                 for (var i = 0; i < pw.length; i++) pass += pw[i];
//                 console.log("[+] KeyStore Password: " + pass);
//             }

//             // Try reading the raw keystore bytes
//             try {
//                 var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
//                 var baos = ByteArrayOutputStream.$new();
//                 var buffer = Java.array('byte', new Array(4096));
//                 var len;

//                 while ((len = stream.read(buffer)) !== -1) {
//                     baos.write(buffer, 0, len);
//                 }

//                 var raw = baos.toByteArray();
//                 console.log("[+] Raw KeyStore Data Base64:");
//                 console.log(b64(raw));

//                 console.log("\n=== If this is PKCS12, extract using OpenSSL ===\n" +
//                     "echo '" + b64(raw) + "' | base64 -d > client.p12\n" +
//                     "openssl pkcs12 -in client.p12 -nodes");

//             } catch (e) {
//                 console.log("[-] Failed extracting KeyStore bytes: " + e);
//             }

//             return this.load(stream, pw);
//         };

//         console.log("[+] Hooked KeyStore.load");
//     } catch (e) {}


// }); // Java.perform end


// // ==========================================================
// // 5️⃣ NATIVE LAYER (OpenSSL) — Extract runtime TLS certs
// // ==========================================================
// try {
//     var ssl = Module.findExportByName(null, "SSL_get_peer_certificate");
//     if (ssl) {
//         Interceptor.attach(ssl, {
//             onLeave: function (retval) {
//                 if (!retval.isNull()) {
//                     console.log("\n=== [OPENSSL] Peer Certificate Pointer: " + retval + " ===");
//                 }
//             }
//         });
//         console.log("[+] Hooked SSL_get_peer_certificate");
//     }

//     var i2d = Module.findExportByName(null, "i2d_X509");
//     if (i2d) {
//         Interceptor.attach(i2d, {
//             onLeave: function (retval) {
//                 console.log("[OPENSSL] X509 Certificate Serialized (DER)");
//             }
//         });
//         console.log("[+] Hooked i2d_X509");
//     }
// } catch (e) {}

// }, 0);
