import psutil
import subprocess
import time
import threading

class PrivacyVerifier:
    def __init__(self, target_path):
        self.target_path = target_path
        self.process = None
        self.logs = []
        self._stop_event = threading.Event()

    def start(self):
        try:
            self.process = subprocess.Popen([self.target_path])
            pid = self.process.pid
            
            try:
                proc_monitor = psutil.Process(pid)
            except psutil.NoSuchProcess:
                print("[!] Verifier: Process terminated immediately upon launch.")
                return

            while not self._stop_event.is_set():
                if self.process.poll() is not None:
                    break 
                
                try:
                    # Watch Files
                    for file in proc_monitor.open_files():
                        path = file.path
                        if not any(x in path.lower() for x in ['.dll', 'windows\\fonts', '.nls']):
                            finding = f"DYNAMIC_FILE_{path}"
                            if finding not in self.logs:
                                self.logs.append(finding)

                    # Watch Network
                    for conn in proc_monitor.connections(kind='inet'):
                        if conn.raddr:
                            ip = f"{conn.raddr.ip}:{conn.raddr.port}"
                            finding = f"DYNAMIC_NET_{ip}"
                            if finding not in self.logs:
                                self.logs.append(finding)
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break 
                
                time.sleep(1) 
                
        except Exception as e:
            print(f"[!] Verifier Error: {e}")

    def stop_and_collect(self):
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except:
                pass
        return self.logs