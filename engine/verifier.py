import sys
import math
from collections import Counter


class PrivacyVerifier:
    def __init__(self, target_path, spy_script_path="hooks/spy.js"):
        self.target_path = target_path
        self.spy_script_path = spy_script_path
        self.session = None
        self.script = None

    def calculate_entropy(self, data):
        """
        Calculates Shannon Entropy to detect encrypted/compressed data.
        High Entropy (> 7.5) = Likely Encryption or Image/Zip.
        Low Entropy (< 4.0) = Likely Text/JSON.
        """
        if not data:
            return 0
        entropy = 0
        length = len(data)

        # Fast frequency count (O(N) complexity)
        counts = Counter(data)

        for count in counts.values():
            p_x = count / length
            entropy += -p_x * math.log(p_x, 2)

        return entropy

    def on_message(self, message, data):
        """
        Callback: Triggered when JavaScript sends data back to Python.
        """
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type")

            if msg_type == "file_access":
                print(f"[FILESYSTEM] Accessed: {payload['path']}")

            elif msg_type == "network_upload":
                # Only calculate entropy if we have raw binary data (data variable)
                entropy = 0
                if data:
                    entropy = self.calculate_entropy(data)

                print(
                    f"[NETWORK] Uploading {payload['size']} bytes | Entropy: {entropy:.2f}"
                )

        elif message["type"] == "error":
            print(f"[FRIDA ERROR] {message['description']}")

    def start(self):
        import frida   # LAZY IMPORT HERE
        
        print(f"[*] Spawning {self.target_path}...")

        # 1. Spawn the process (start it in a suspended state)
        device = frida.get_local_device()
        pid = device.spawn([self.target_path])

        # 2. Attach Frida to the suspended process
        self.session = device.attach(pid)

        # 3. Inject our Spy JavaScript
        with open(self.spy_script_path, "r") as f:
            js_code = f.read()

        self.script = self.session.create_script(js_code)
        self.script.on("message", self.on_message)
        self.script.load()

        # 4. Resume the process (let it run)
        device.resume(pid)
        print(f"[*] Attached! PID: {pid}. Press Ctrl+C to stop.")

        # Keep the script running to listen for messages
        sys.stdin.read()


# --- TEST BLOCK ---
if __name__ == "__main__":
    # We use Notepad again because it's safe and installed on every Windows PC
    target = r"C:\Windows\System32\notepad.exe"

    verifier = PrivacyVerifier(target)
    try:
        verifier.start()
    except KeyboardInterrupt:
        print("\nStopping...")
    except Exception as e:
        print(f"Error: {e}")
