Java.perform(function () {
    console.log("\n" + "=".repeat(80));
    console.log("🌐 UNIVERSAL NETWORK TRAFFIC CAPTURE");
    console.log("🚀 Capturing HTTP/HTTPS/WebSocket traffic");
    console.log("=".repeat(80) + "\n");

    // ==================== SSL PINNING BYPASS ====================

    try {
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

        const TrustAll = Java.registerClass({
            name: 'com.frida.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });

        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
            const trustAll = TrustAll.$new();
            this.init(km, Java.array('Ljavax.net.ssl.X509TrustManager;', [trustAll]), sr);
        };
    } catch (e) { }

    try {
        const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        HostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
            return true;
        };
    } catch (e) { }

    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () { };
    } catch (e) { }

    // ==================== HELPER FUNCTIONS ====================

    function getHost(url) {
        try {
            const match = url.match(/^(?:https?|wss?):\/\/([^\/]+)/);
            return match ? match[1] : "unknown";
        } catch (e) {
            return "unknown";
        }
    }

    function getPath(url) {
        try {
            const match = url.match(/^(?:https?|wss?):\/\/[^\/]+(\/.*)?$/);
            return match ? (match[1] || '/') : url;
        } catch (e) {
            return url;
        }
    }

    function formatRequest(method, url, headers, body) {
        console.log("\n" + "=".repeat(80));
        console.log(`${method} ${getPath(url)} HTTP/1.1`);
        console.log(`Host: ${getHost(url)}`);

        if (headers && headers.trim().length > 0) {
            console.log(headers.trim());
        }

        if (body && body.trim().length > 0) {
            console.log("");
            console.log(body);
        }
        console.log("-".repeat(40));
    }

    function formatResponse(code, message, headers, body) {
        if (code) {
            console.log(`HTTP/1.1 ${code} ${message || ''}`);

            if (headers) {
                console.log(headers.trim());
            }

            if (body) {
                console.log("");
                try {
                    const json = JSON.parse(body);
                    console.log(JSON.stringify(json, null, 2));
                } catch (e) {
                    console.log(body);
                }
            }

            console.log("=".repeat(80));
        }
    }

    function bytesToString(bytes) {
        try {
            const String = Java.use("java.lang.String");
            return String.$new(bytes, "UTF-8");
        } catch (e) {
            return `[Binary: ${bytes.length} bytes]`;
        }
    }

    // ==================== OKHTTP3 INTERCEPTOR ====================

    try {
        const Interceptor = Java.use("okhttp3.Interceptor");
        const ResponseBody = Java.use("okhttp3.ResponseBody");

        const LoggingInterceptor = Java.registerClass({
            name: 'com.frida.LogInterceptor',
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    let request = null;
                    let url = "";
                    let method = "";
                    let headersStr = "";
                    let requestBody = null;

                    try {
                        request = chain.request();
                        url = request.url().toString();
                        method = request.method();

                        const headers = request.headers();
                        const headerCount = headers.size();
                        const seenHeaders = {};

                        if (headerCount > 0) {
                            for (let i = 0; i < headerCount; i++) {
                                const name = headers.name(i);
                                const value = headers.value(i);
                                const lowerName = name.toLowerCase();

                                if (lowerName === 'host') {
                                    if (seenHeaders[lowerName]) continue;
                                }

                                headersStr += `${name}: ${value}\n`;
                                seenHeaders[lowerName] = true;
                            }
                        }

                        const body = request.body();
                        if (body) {
                            try {
                                const Buffer = Java.use("okio.Buffer");
                                const buffer = Buffer.$new();
                                body.writeTo(buffer);
                                const bodyBytes = buffer.readByteArray();
                                const String = Java.use("java.lang.String");
                                requestBody = String.$new(bodyBytes, "UTF-8");
                            } catch (e) { }
                        }
                    } catch (e) {
                        console.log(`[!] Request error: ${e}`);
                    }

                    let response = null;
                    try {
                        response = chain.proceed(request);
                    } catch (e) {
                        console.log(`[!] Proceed error: ${e}`);
                        if (request) {
                            try {
                                return chain.proceed(request);
                            } catch (e2) {
                                throw e;
                            }
                        }
                        throw e;
                    }

                    if (!response) {
                        console.log(`[!] Response is null, returning original`);
                        return response;
                    }

                    let responseCode = 0;
                    let responseMessage = "";
                    let respHeadersStr = "";
                    let responseBodyStr = null;
                    let newResponse = response;

                    try {
                        responseCode = response.code();
                        responseMessage = response.message();

                        const respHeaders = response.headers();
                        for (let i = 0; i < respHeaders.size(); i++) {
                            respHeadersStr += `${respHeaders.name(i)}: ${respHeaders.value(i)}\n`;
                        }

                        const respBody = response.body();
                        if (respBody) {
                            try {
                                const contentType = respBody.contentType();
                                const bodySource = respBody.source();

                                const Long = Java.use("java.lang.Long");
                                bodySource.request(Long.MAX_VALUE.value);

                                const originalBuffer = bodySource.buffer();

                                const contentEncoding = respHeaders.get("content-encoding");
                                const isGzipped = contentEncoding && contentEncoding.toLowerCase().includes("gzip");

                                if (isGzipped) {
                                    try {
                                        const GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
                                        const ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                                        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

                                        const compressedBytes = originalBuffer.snapshot().toByteArray();
                                        const bais = ByteArrayInputStream.$new(compressedBytes);
                                        const gzis = GZIPInputStream.$new(bais);
                                        const baos = ByteArrayOutputStream.$new();

                                        const bufferArray = Java.array('byte', new Array(1024).fill(0));
                                        let len = gzis.read(bufferArray);
                                        while (len !== -1) {
                                            baos.write(bufferArray, 0, len);
                                            len = gzis.read(bufferArray);
                                        }

                                        const decompressedBytes = baos.toByteArray();
                                        const String = Java.use("java.lang.String");
                                        responseBodyStr = String.$new(decompressedBytes, "UTF-8");

                                        gzis.close();
                                        baos.close();
                                    } catch (e) {
                                        console.log(`[!] Gzip error: ${e}`);
                                    }
                                } else {
                                    const byteString = originalBuffer.snapshot();
                                    const charset = Java.use("java.nio.charset.Charset");
                                    const utf8 = charset.forName("UTF-8");
                                    responseBodyStr = byteString.string(utf8);
                                }

                                const newBody = ResponseBody.create(contentType, originalBuffer.snapshot().toByteArray());
                                newResponse = response.newBuilder().body(newBody).build();
                            } catch (e) {
                                console.log(`[!] Body error: ${e}`);
                                newResponse = response;
                            }
                        }
                    } catch (e) {
                        console.log(`[!] Response error: ${e}`);
                        newResponse = response;
                    }

                    formatRequest(method, url, headersStr, requestBody);
                    formatResponse(responseCode, responseMessage, respHeadersStr, responseBodyStr);

                    return newResponse;
                }
            }
        });

        const OkHttpClient$Builder = Java.use("okhttp3.OkHttpClient$Builder");

        OkHttpClient$Builder.build.implementation = function () {
            try {
                this.addInterceptor(LoggingInterceptor.$new());
            } catch (e) {
                console.log(`[!] Failed to add interceptor: ${e}`);
            }
            return this.build();
        };

        console.log("[✅] OkHttp Interceptor installed");
    } catch (e) {
        console.log(`[⚠️] OkHttp Interceptor: ${e.message}`);
    }

    // ==================== OKHTTP NEWCALL FALLBACK ====================

    try {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");

        OkHttpClient.newCall.implementation = function (request) {
            const url = request.url().toString();
            const method = request.method();

            const session = {
                url: url,
                method: method,
                headers: "",
                requestBody: null,
                responseCode: null,
                responseMessage: null,
                responseHeaders: null,
                responseBody: null
            };

            const headers = request.headers();
            let headersStr = "";
            for (let i = 0; i < headers.size(); i++) {
                headersStr += `${headers.name(i)}: ${headers.value(i)}\n`;
            }
            session.headers = headersStr;

            const body = request.body();
            if (body) {
                try {
                    const Buffer = Java.use("okio.Buffer");
                    const buffer = Buffer.$new();
                    body.writeTo(buffer);
                    session.requestBody = buffer.readUtf8();
                } catch (e) { }
            }

            const call = this.newCall(request);

            const CallClass = Java.use("okhttp3.Call");

            try {
                const originalExecute = call.execute;
                if (originalExecute) {
                    call.execute = function () {
                        const response = originalExecute.call(this);

                        session.responseCode = response.code();
                        session.responseMessage = response.message();

                        const respHeaders = response.headers();
                        let respHeadersStr = "";
                        for (let i = 0; i < respHeaders.size(); i++) {
                            respHeadersStr += `${respHeaders.name(i)}: ${respHeaders.value(i)}\n`;
                        }
                        session.responseHeaders = respHeadersStr;

                        try {
                            const respBody = response.body();
                            if (respBody) {
                                const bodySource = respBody.source();
                                bodySource.request(9223372036854775807);
                                const bufferSnapshot = bodySource.buffer().clone();
                                const charset = Java.use("java.nio.charset.Charset");
                                const utf8 = charset.forName("UTF-8");
                                session.responseBody = bufferSnapshot.readString(utf8);
                            }
                        } catch (e) { }

                        formatRequest(session.method, session.url, session.headers, session.requestBody);
                        formatResponse(session.responseCode, session.responseMessage,
                            session.responseHeaders, session.responseBody);

                        return response;
                    };
                }
            } catch (e) { }

            const originalEnqueue = call.enqueue;
            if (originalEnqueue) {
                call.enqueue = function (callback) {
                    const Callback = Java.use("okhttp3.Callback");

                    const WrappedCallback = Java.registerClass({
                        name: 'com.frida.Callback' + Date.now(),
                        implements: [Callback],
                        methods: {
                            onFailure: function (c, e) {
                                callback.onFailure(c, e);
                            },
                            onResponse: function (c, response) {
                                session.responseCode = response.code();
                                session.responseMessage = response.message();

                                const respHeaders = response.headers();
                                let respHeadersStr = "";
                                for (let i = 0; i < respHeaders.size(); i++) {
                                    respHeadersStr += `${respHeaders.name(i)}: ${respHeaders.value(i)}\n`;
                                }
                                session.responseHeaders = respHeadersStr;

                                try {
                                    const respBody = response.body();
                                    if (respBody) {
                                        const bodySource = respBody.source();
                                        bodySource.request(9223372036854775807);
                                        const bufferSnapshot = bodySource.buffer().clone();
                                        const charset = Java.use("java.nio.charset.Charset");
                                        const utf8 = charset.forName("UTF-8");
                                        session.responseBody = bufferSnapshot.readString(utf8);
                                    }
                                } catch (e) { }

                                formatRequest(session.method, session.url, session.headers, session.requestBody);
                                formatResponse(session.responseCode, session.responseMessage,
                                    session.responseHeaders, session.responseBody);

                                callback.onResponse(c, response);
                            }
                        }
                    });

                    return originalEnqueue.call(this, WrappedCallback.$new());
                };
            }

            return call;
        };

        console.log("[✅] OkHttp newCall installed");
    } catch (e) {
        console.log(`[⚠️] OkHttp newCall: ${e.message}`);
    }

    // ==================== HTTPURLCONNECTION CAPTURE ====================

    try {
        const URL = Java.use("java.net.URL");

        URL.openConnection.overload().implementation = function () {
            const conn = this.openConnection();
            const url = this.toString();

            if (url.startsWith('http://') || url.startsWith('https://')) {
                try {
                    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
                    const httpConn = Java.cast(conn, HttpURLConnection);

                    const session = {
                        url: url,
                        method: "GET",
                        headers: "",
                        requestBody: null,
                        responseCode: null,
                        responseMessage: null,
                        responseHeaders: null,
                        responseBody: null
                    };

                    const originalGetOutputStream = httpConn.getOutputStream;
                    httpConn.getOutputStream = function () {
                        session.method = this.getRequestMethod();

                        const OutputStream = Java.use("java.io.OutputStream");
                        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                        const original = originalGetOutputStream.call(this);

                        const Wrapper = Java.registerClass({
                            name: 'com.frida.OutStream' + Date.now(),
                            superClass: OutputStream,
                            methods: {
                                write: [{
                                    returnType: 'void',
                                    argumentTypes: ['int'],
                                    implementation: function (b) {
                                        if (!this.buffer) {
                                            this.buffer = ByteArrayOutputStream.$new();
                                        }
                                        this.buffer.write(b);
                                        this.original.write(b);
                                    }
                                }, {
                                    returnType: 'void',
                                    argumentTypes: ['[B', 'int', 'int'],
                                    implementation: function (b, off, len) {
                                        if (!this.buffer) {
                                            this.buffer = ByteArrayOutputStream.$new();
                                        }
                                        this.buffer.write(b, off, len);
                                        this.original.write(b, off, len);
                                    }
                                }],
                                close: function () {
                                    if (this.buffer) {
                                        const bytes = this.buffer.toByteArray();
                                        session.requestBody = bytesToString(bytes);
                                    }
                                    this.original.close();
                                }
                            }
                        });

                        const wrapped = Wrapper.$new();
                        wrapped.original = original;
                        wrapped.buffer = null;
                        return wrapped;
                    };

                    const originalGetInputStream = httpConn.getInputStream;
                    httpConn.getInputStream = function () {
                        session.method = this.getRequestMethod();

                        try {
                            const props = this.getRequestProperties();
                            if (props) {
                                const iter = props.keySet().iterator();
                                let headersStr = "";
                                while (iter.hasNext()) {
                                    const key = iter.next();
                                    headersStr += `${key}: ${props.get(key)}\n`;
                                }
                                session.headers = headersStr;
                            }
                        } catch (e) { }

                        formatRequest(session.method, session.url, session.headers, session.requestBody);

                        const original = originalGetInputStream.call(this);

                        session.responseCode = this.getResponseCode();
                        session.responseMessage = this.getResponseMessage();

                        try {
                            const fields = this.getHeaderFields();
                            if (fields) {
                                const iter = fields.keySet().iterator();
                                let headersStr = "";
                                while (iter.hasNext()) {
                                    const key = iter.next();
                                    if (key) {
                                        headersStr += `${key}: ${fields.get(key)}\n`;
                                    }
                                }
                                session.responseHeaders = headersStr;
                            }
                        } catch (e) { }

                        const InputStream = Java.use("java.io.InputStream");
                        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

                        const Wrapper = Java.registerClass({
                            name: 'com.frida.InStream' + Date.now(),
                            superClass: InputStream,
                            methods: {
                                read: [{
                                    returnType: 'int',
                                    argumentTypes: [],
                                    implementation: function () {
                                        if (!this.buffer) {
                                            this.buffer = ByteArrayOutputStream.$new();
                                        }
                                        const b = this.original.read();
                                        if (b !== -1) {
                                            this.buffer.write(b);
                                        }
                                        return b;
                                    }
                                }, {
                                    returnType: 'int',
                                    argumentTypes: ['[B', 'int', 'int'],
                                    implementation: function (b, off, len) {
                                        if (!this.buffer) {
                                            this.buffer = ByteArrayOutputStream.$new();
                                        }
                                        const count = this.original.read(b, off, len);
                                        if (count > 0) {
                                            this.buffer.write(b, off, count);
                                        }
                                        return count;
                                    }
                                }],
                                close: function () {
                                    if (this.buffer) {
                                        const bytes = this.buffer.toByteArray();
                                        session.responseBody = bytesToString(bytes);
                                    }

                                    formatResponse(session.responseCode, session.responseMessage,
                                        session.responseHeaders, session.responseBody);

                                    this.original.close();
                                }
                            }
                        });

                        const wrapped = Wrapper.$new();
                        wrapped.original = original;
                        wrapped.buffer = null;
                        return wrapped;
                    };
                } catch (e) { }
            }

            return conn;
        };

        console.log("[✅] HttpURLConnection installed");
    } catch (e) {
        console.log(`[⚠️] HttpURLConnection: ${e.message}`);
    }

    // ==================== WEBSOCKET CAPTURE ====================

    try {
        const RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");

        RealWebSocket.connect.implementation = function (client) {
            const request = this.request.value;
            console.log(`\n[🔌] WebSocket Connect: ${request.url()}`);
            return this.connect(client);
        };

        RealWebSocket.send.overload('java.lang.String').implementation = function (text) {
            console.log(`\n[🔌] WebSocket Send (${text.length} chars):`);
            console.log(text.substring(0, 1000));
            return this.send(text);
        };

        console.log("[✅] WebSocket installed");
    } catch (e) {
        console.log(`[⚠️] WebSocket: ${e.message}`);
    }

    // ==================== WEBVIEW CAPTURE ====================

    try {
        const WebViewClient = Java.use("android.webkit.WebViewClient");

        WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function (view, req) {
            const url = req.getUrl().toString();

            if (url.startsWith('http://') || url.startsWith('https://')) {
                console.log(`\n[🌍] WebView: ${req.getMethod()} ${url}`);
            }

            return this.shouldInterceptRequest(view, req);
        };

        console.log("[✅] WebView installed");
    } catch (e) {
        console.log(`[⚠️] WebView: ${e.message}`);
    }

    console.log("\n" + "=".repeat(80));
    console.log("✅ READY - Monitoring all network traffic");
    console.log("=".repeat(80) + "\n");
});
