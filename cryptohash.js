console.log("====================== SM THE KING ======================");
var algorithm = null; 
var data = null;
function send_log(string, value) {
    // console.log("[+] "+string+" : "+value);
    send("[+] " + string + " : " + value);
}

function byte_to_string(byte_array) {
    var StringClass = Java.use('java.lang.String');
    return StringClass.$new(byte_array).toString();
}

function containsPrintableASCII(str) {
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code < 32 || code > 126) {
            return false;
        }
    }
    return true;
}

function bytesToHexString(byteArray) {
    var result = [];
    for (var i = 0; i < byteArray.length; ++i) {
        result.push(('0' + (byteArray[i] & 0xFF).toString(16)).slice(-2));
    }
    return result.join('');
}

Java.perform(function () {
    var base64 = Java.use('java.util.Base64');
    var cipher = Java.use('javax.crypto.Cipher');
    var ivParameter = Java.use('javax.crypto.spec.IvParameterSpec');
    var MessageDigest = Java.use('java.security.MessageDigest');

    cipher.init.overload('int', 'java.security.Key').implementation = function(opmode,key){
        send_log("Key",base64.getEncoder().encodeToString(key.getEncoded()));
        send_log("Opmode String",this.getOpmodeString(opmode));
        send_log("Algorithm",this.getAlgorithm());
        this.init.overload('int', 'java.security.Key').call(this,opmode,key);
    }
    
    cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function(opmode,certificate){
        send_log("Certificate",base64.getEncoder().encodeToString(certificate.getEncoded()));
        send_log("Opmode String",this.getOpmodeString(opmode));
        send_log("Algorithm",this.getAlgorithm());

        this.init.overload('int', 'java.security.cert.Certificate').call(this,opmode,certificate)
    }
    
    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function(opmode,key,algorithmParameter){
        send_log("Key",base64.getEncoder().encodeToString(key.getEncoded()));
        send_log("Opmode String",this.getOpmodeString(opmode));
        send_log("Algorithm",this.getAlgorithm());

        this.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').call(this,opmode,key,algorithmParameter);
    }


    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode,key,algorithmParameter){
        send_log("Key",base64.getEncoder().encodeToString(key.getEncoded()));
        send_log("Opmode String",this.getOpmodeString(opmode));
        send_log("Algorithm",this.getAlgorithm());
        this.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').call(this,opmode,key,algorithmParameter);
    }

    cipher.doFinal.overload('[B').implementation = function(input){
        var input_base64 = base64.getEncoder().encodeToString(input);
        var input_string = byte_to_string(input);
        var output = this.doFinal.overload('[B').call(this,input);
        var output_base64 = base64.getEncoder().encodeToString(output);
        send_log("Input Base64",input_base64);
        send_log("Input String",input_string);
        send_log("Output Base64",output_base64);
        send_log("======================","======================");
        return output;
    }

    cipher.doFinal.overload('[B', 'int').implementation = function(input,input2){
        var input_base64 = base64.getEncoder().encodeToString(input);
        var input_string = byte_to_string(input);
        var output = this.doFinal.overload('[B', 'int').call(this,input,input2);
        var output_base64 = base64.getEncoder().encodeToString(output);
        send_log("Input Base64",input_base64);
        send_log("Input String",input_string);
        send_log("Output Base64",output_base64);
        send_log("======================","======================");
        return output;
    }

    cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input,input2,input3){
        var input_base64 = base64.getEncoder().encodeToString(input);
        var input_string = byte_to_string(input);
        var output = this.doFinal.overload('[B', 'int', 'int').call(this,input,input2,input3);
        var output_base64 = base64.getEncoder().encodeToString(output);
        send_log("Input Base64",input_base64);
        send_log("Input String",input_string);
        send_log("Output Base64",output_base64);
        send_log("======================","======================");
        return output;
    }

    cipher.doFinal.overload('[B', 'int', 'int', '[B').implementation = function(input,input2,input3,input4){
        var input_base64 = base64.getEncoder().encodeToString(input);
        var input_string = byte_to_string(input);
        var output = this.doFinal.overload('[B', 'int', 'int', '[B').call(this,input,input2,input3,input4);
        var output_base64 = base64.getEncoder().encodeToString(output);
        send_log("Input Base64",input_base64);
        send_log("Input String",input_string);
        send_log("Output Base64",output_base64);
        send_log("======================","======================");
        return output;
    }

    cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = function(input,input2,input3,input4,input5){
        var input_base64 = base64.getEncoder().encodeToString(input);
        var input_string = byte_to_string(input);
        var output = this.doFinal.overload('[B', 'int', 'int', '[B', 'int').call(this,input,input2,input3,input4,input5);
        var output_base64 = base64.getEncoder().encodeToString(output);
        send_log("Input Base64",input_base64);
        send_log("Input String",input_string);
        send_log("Output Base64",output_base64);
        send_log("====================== SM THE","KING ======================");
        return output;
    }

    ivParameter.$init.overload('[B').implementation = function (ivKey) {
        send_log("Iv ", base64.getEncoder().encodeToString(ivKey));
        this.$init.overload('[B').call(this, ivKey);
    }



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
        if (algorithm !== null && data !== null) {
            var strHash = bytesToHexString(hashValue);
            if (strHash && strHash.length > 0) {
                send("[+] Hash Algorithm: " + algorithm + " || Plaintext: {" + data + "} || Hashvalue: {" + strHash + "}");
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

console.log('Script Injected successfully');
console.log("====================== SM THE KING ======================");
