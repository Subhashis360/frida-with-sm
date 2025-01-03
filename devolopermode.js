function bypass_developerMode_check() {
    try {
        var settingSecure = Java.use('android.provider.Settings$Secure');
        var settingGlobal = Java.use('android.provider.Settings$Global');

        // Hook Secure.getInt methods
        settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
            //console.log("[+] Secure.getInt(" + name + ", " + flag + ") Bypassed");
            return 0;
        }
        settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            //console.log("[+] Secure.getInt(" + name + ") Bypassed");
            return 0;
        }

        // Hook Global.getInt methods
        settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
            //console.log("[+] Global.getInt(" + name + ", " + flag + ") Bypassed");
            return 0;
        }
        settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            //console.log("[+] Global.getInt(" + name + ") Bypassed");
            return 0;
        }
    } catch (error) {
        //console.error("Error in bypass_developerMode_check:", error);
    }
}

Java.perform(function() {
    bypass_developerMode_check();
});
