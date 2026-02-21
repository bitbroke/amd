import pefile
import re


class Detective:
    def __init__(self, target_path):
        self.target_path = target_path
        # The standard API watchlist we had before
        self.api_watchlist = {
            "Networking": ["socket", "connect", "send", "InternetOpen", "HttpSend"],
            "Filesystem": ["ReadFile", "CreateFile", "WriteFile", "FindFirstFile"],
            "Registry": ["RegOpenKey", "RegGetValue"],
        }

        # NEW: High-fidelity Regex patterns for hidden strings
        self.regex_patterns = {
            "URL": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
            "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Base64": r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        }

    def investigate(self):
        print(f"[*] Scanning: {self.target_path}")
        results = []

        # 1. Standard API Scan
        results.extend(self._scan_apis())

        # 2. NEW: Deep String Scan (The "Hidden Tunnel" Scan)
        results.extend(self._scan_strings())

        return results

    def _scan_apis(self):
        findings = []
        try:
            pe = pefile.PE(self.target_path)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        if func.name:
                            name = func.name.decode("utf-8")
                            for cat, keys in self.api_watchlist.items():
                                if any(k.lower() in name.lower() for k in keys):
                                    findings.append(f"API_{name}")
            return findings
        except Exception:
            return []

    def _scan_strings(self):
        findings = []
        try:
            with open(self.target_path, "rb") as f:
                # Read the whole file and treat as text, ignoring non-ASCII junk
                content = f.read().decode("ascii", "ignore")

                for label, pattern in self.regex_patterns.items():
                    matches = re.findall(pattern, content)
                    for match in set(matches):  # use set to avoid duplicates
                        print(f"    [!] Found {label}: {match}")
                        findings.append(f"STR_{label}_{match}")
            return findings
        except Exception as e:
            print(f"String scan error: {e}")
            return []
