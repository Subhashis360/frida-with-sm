console.log("====================== SM THE KING ======================");

var algorithm = null;
var data = null;

Java.perform(function () {
    var MessageDigest = Java.use('java.security.MessageDigest');

    MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
        algorithm = algo;
        return this.getInstance(algo);
    };

    var updateMethod = MessageDigest.update.overload('[B');
    updateMethod.implementation = function (dataBytes) {
        if (dataBytes && dataBytes.hasOwnProperty('length')) {
            data = byte_to_string(dataBytes);
            if (containsPrintableASCII(data)) {
                updateMethod.call(this, dataBytes);
            } else {
                data = null;
            }
        }
    };

    var digestMethod = MessageDigest.digest.overload();
    digestMethod.implementation = function () {
        var hashValue = digestMethod.call(this);
        if (algorithm !== null && data !== null ) {
            var strHash = bytesToHexString(hashValue);
            if (strHash && strHash.length > 0) {
                send("[+] Algorithm: " + algorithm + " || Plaintext: {" + data + "} || Hashvalue: {" + strHash + "}");
                send("========================================");
            } else {
                console.log("Error: Invalid hash value encountered.");
            }
            algorithm = null;
            data = null;
        }
        return hashValue;
    };
});

function byte_to_string(byte_array){
    var StringClass = Java.use('java.lang.String');
    return StringClass.$new(byte_array).toString();
}

function bytesToHexString(byteArray){
    var result = [];
    for (var i = 0; i < byteArray.length; ++i) {
        result.push(('0' + (byteArray[i] & 0xFF).toString(16)).slice(-2));
    }
    return result.join('');
}

function containsPrintableASCII(str) {
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        // Check if the character is outside the printable ASCII range
        if (code < 32 || code > 126) {
            return false; // Non-printable ASCII character found
        }
    }
    return true; // Contains only printable ASCII characters
}
