var do_dlopen = null;
var call_constructor = null;
var so_library = "libflutter.so"
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(symbol){
    if(symbol.name.indexOf("do_dlopen") >= 0){
        do_dlopen = symbol.address;
    } else if (symbol.name.indexOf("call_constructor") >= 0){
        call_constructor = symbol.address;
    }
})

var lib_loaded = 0;
Interceptor.attach(do_dlopen, function(){
    var library_path = this.context.x0.readCString();
    if(library_path.indexOf(so_library) >= 0){
        Interceptor.attach(call_constructor, function(){
            if(lib_loaded == 0){
                var native_mod = Process.findModuleByName(so_library);
                // console.log(library is loaded at ${native_mod.base});
                ssl_bypass(native_mod.base)
            }
            lib_loaded = 1;
        })
    }
})


function ssl_bypass(base){
// 0x3e0f74 find and chnage the offset
Interceptor.attach(base.add(0x3e0f74), {
    onLeave: function(retval) {
        console.log("BYPASSING SSL")
        retval.replace(0x1);
    }
})


}
