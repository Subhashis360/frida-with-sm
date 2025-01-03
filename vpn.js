setTimeout(function() {
    Java.perform(function() {
        
        var TYPE_VPN = 0x00000011;
        var TRANSPORT_VPN = 0x00000004;
        var interface_list = ['tun', 'tun0', 'utun0', 'utun1', 'utun2', 'utun3', 'utun4', 'ppp0', 'ppp', 'pptp'];

        var connectivityManager = Java.use('android.net.ConnectivityManager');
        connectivityManager.getNetworkInfo.overload('int').implementation = function(netType) {
            if (netType === TYPE_VPN) {
                //console.log("[*] Bypassing VPN detection check for getNetworkInfo(TYPE_VPN)");
                return null;
            } else {
                return this.getNetworkInfo(netType);
            }
        };

        var networkCapabilities = Java.use('android.net.NetworkCapabilities');
        networkCapabilities.hasTransport.overload('int').implementation = function(transportType) {
            if (transportType === TRANSPORT_VPN) {
                //console.log("[*] Bypassing VPN detection check for hasTransport(TRANSPORT_VPN)");
                return false;
            } else {
                return this.hasTransport(transportType);
            }
        };

        var networkInterface = Java.use('java.net.NetworkInterface');
        networkInterface.getByName.overload('java.lang.String').implementation = function(name) {
            if (interface_list.includes(name)) {
                //console.log(`[*] Bypassing VPN detection check for getByName(${name})`);
                return null;
            } else {
                return this.getByName(name);
            }
        };

        networkInterface.getDisplayName.overload().implementation = function() {
            var ret = this.getDisplayName();
            if (interface_list.includes(ret)) {
                //console.log("[*] Bypassing VPN detection check for getDisplayName()");
                return 'ZDUABIDBWA';
            } else {
                return ret;
            }
        };

        networkInterface.getName.overload().implementation = function() {
            var ret = this.getName();
            if (interface_list.includes(ret)) {
                //console.log("[*] Bypassing VPN detection check for getName()");
                return 'ZDUABIDBWA';
            } else {
                return ret;
            }
        };

    });
}, 0);
