"""
DataProbe Frida Hook Script
Injected into target process to hook SSL_write/SSL_read for plaintext capture.
Usage: python frida_hook.py <target_process_name>
"""
import sys, json, time, os, struct

def main():
    if len(sys.argv) < 2:
        print('{"status":"error","message":"missing target"}', flush=True)
        return

    target = sys.argv[1]

    try:
        import frida
    except ImportError:
        print('{"status":"error","message":"frida not installed"}', flush=True)
        return

    session = None
    try:
        session = frida.attach(target)

        script_code = """
        var ssl_modules = [
            "libssl-3.dll", "libssl-1_1.dll", "libssl-1_1-x64.dll",
            "ssleay32.dll", "libssl-1_0_0.dll"
        ];

        function try_hook_ssl_write() {
            for (var i = 0; i < ssl_modules.length; i++) {
                var addr = Module.findExportByName(ssl_modules[i], "SSL_write");
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 65536) {
                                var data = args[1].readByteArray(len);
                                send(JSON.stringify({type:"ssl_write",len:len,data:Array.from(data)}));
                            }
                        }
                    });
                    console.log("[DP] SSL_write hooked in " + ssl_modules[i]);
                    return true;
                }
            }
            return false;
        }

        function try_hook_ssl_read() {
            for (var i = 0; i < ssl_modules.length; i++) {
                var addr = Module.findExportByName(ssl_modules[i], "SSL_read");
                if (addr) {
                    Interceptor.attach(addr, {
                        onLeave: function(retval) {
                            var len = retval.toInt32();
                            if (len > 0 && len < 65536) {
                                send(JSON.stringify({type:"ssl_read",len:len}));
                            }
                        }
                    });
                    console.log("[DP] SSL_read hooked in " + ssl_modules[i]);
                    return true;
                }
            }
            return false;
        }

        var wrote = try_hook_ssl_write();
        var read = try_hook_ssl_read();
        if (!wrote && !read) {
            console.log("[DP] No SSL library found");
        }
        """;

        script = session.create_script(script_code)
        script.on('message', lambda msg, data: print(json.dumps(msg), flush=True))
        script.load()

        print('{"status":"attached","target":"%s"}' % target, flush=True)

        # Keep alive
        while True:
            time.sleep(1)

    except frida.ProcessNotFoundError:
        print('{"status":"error","message":"process not found"}', flush=True)
    except Exception as e:
        print('{"status":"error","message":"%s"}' % str(e), flush=True)
    finally:
        if session:
            session.detach()

if __name__ == "__main__":
    main()
