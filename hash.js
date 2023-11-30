// console.log("====================== SM THE KING ======================");

// var algorithm = null;
// var data = null;

// Java.perform(function () {
//     var MessageDigest = Java.use('java.security.MessageDigest');

//     MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
//         algorithm = algo;
//         // console.log("[+] MessageDigest getInstance called with algorithm: ", algo);
//         return this.getInstance(algo);
//     };

//     var updateMethod = MessageDigest.update.overload('[B');
//     updateMethod.implementation = function (dataBytes) {
//         data = byte_to_string(dataBytes);
//         // console.log("[+] MessageDigest update called with data: ", data);
//         updateMethod.call(this, dataBytes);
//     };

//     var digestMethod = MessageDigest.digest.overload();
//     digestMethod.implementation = function () {
//         var hashValue = digestMethod.call(this);
//         if (algorithm !== null && data !== null) {
//             var strHash = bytesToHexString(hashValue);
//             // console.log("[+] Algorithm: ", algorithm);
//             // console.log("[+] Plaintext: ", data);
//             // console.log("[+] Hashvalue: ", strHash);
//             // console.log("========================================");
//             // send("[+] Algorithm: ", algorithm);
//             // send("[+] Plaintext: ", data);
//             // send("[+] Hashvalue: ", strHash);
//             send("[+] Algorithm: " + algorithm + " || Plaintext: " + data + " || Hashvalue: " + strHash);
//             send("========================================");
//             algorithm = null;
//             data = null;
//         }
//         return hashValue;
//     };
// });

// function byte_to_string(byte_array){
//     var StringClass = Java.use('java.lang.String');
//     return StringClass.$new(byte_array).toString();
// }

// function bytesToHexString(byteArray){
//     var result = [];
//     for (var i = 0; i < byteArray.length; ++i) {
//         result.push(('0' + (byteArray[i] & 0xFF).toString(16)).slice(-2));
//     }
//     return result.join('');
// }


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
            updateMethod.call(this, dataBytes);
        } else {
            // console.error("Invalid dataBytes object:", dataBytes);
        }
    };

    var digestMethod = MessageDigest.digest.overload();
    digestMethod.implementation = function () {
        var hashValue = digestMethod.call(this);
        if (algorithm !== null && data !== null ) {
            var strHash = bytesToHexString(hashValue);
            // send("[+] Algorithm: ", algorithm);
            // send("[+] Plaintext: ", data);
            // send("[+] Hashvalue: ", strHash);
            console.log("[+] Algorithm: " + algorithm + " || Plaintext: " + data + " || Hashvalue: " + strHash);
            send("========================================");
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




function byte_to_base64(byte_array){
    var Base64Class = Java.use('java.util.Base64');
    var encodedBytes = Base64Class.getEncoder().encode(byte_array);
    return byte_to_string(encodedBytes);
}

function base64_to_byte(base64_string){
    var Base64Class = Java.use('java.util.Base64');
    var decodedBytes = Base64Class.getDecoder().decode(base64_string);
    return decodedBytes;
}
