// spy.js - The Injected Agent

console.log("[*] PrivacyLens Spy Injected via Frida");

// 1. Hook File Access (CreateFileW is used for opening/creating files)
var createFileAddr = Module.findExportByName("kernel32.dll", "CreateFileW");

if (createFileAddr) {
    Interceptor.attach(createFileAddr, {
        onEnter: function(args) {
            // Windows API 'CreateFileW' takes the filename as the first argument (args[0])
            // It is a wide string (UTF-16), so we must read it as Utf16.
            try {
                var filename = Memory.readUtf16String(args[0]);
                
                // Filter out noise (DLLs, pipes, system files) to keep logs clean
                if (filename && filename.indexOf("C:\\") !== -1 && filename.indexOf(".dll") === -1) {
                    send({
                        type: "file_access",
                        action: "OPEN/CREATE",
                        path: filename
                    });
                }
            } catch (e) {
                // Ignore memory read errors (common in system processes)
            }
        }
    });
} else {
    console.log("[!] Error: Could not find CreateFileW in kernel32.dll");
}

// 2. Hook Network Send (Winsock send)
var sendAddr = Module.findExportByName("ws2_32.dll", "send");

if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            // args[1] is the buffer containing the data being sent
            // args[2] is the length of the data
            this.bufPtr = args[1];
            this.bufLen = args[2].toInt32();
        },
        onLeave: function(retval) {
            // We read the data here to ensure the buffer was valid
            if (this.bufLen > 0) {
                // Read a small chunk (first 64 bytes) to identify the protocol
                var data = Memory.readByteArray(this.bufPtr, Math.min(this.bufLen, 64));
                
                send({
                    type: "network_upload",
                    size: this.bufLen,
                    // We send the raw bytes to Python for analysis
                    payload: data 
                });
            }
        }
    });
}