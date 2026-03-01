import pefile
import re
import os
import math
import pandas as pd

class Detective:
    def __init__(self, target_path):
        self.target_path = target_path
        self.api_watchlist = {
            "Networking": ["socket", "connect", "send", "InternetOpen", "HttpSend"],
            "Filesystem": ["ReadFile", "CreateFile", "WriteFile", "FindFirstFile"],
            "Registry": ["RegOpenKey", "RegGetValue"]
        }
        
        self.regex_patterns = {
            "URL": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
            "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Base64": r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        }

    def investigate(self):
        print(f"[*] Scanning: {self.target_path}")
        results = []
        results.extend(self._scan_apis())
        results.extend(self._scan_strings())
        return results

    def _scan_apis(self):
        findings = []
        try:
            pe = pefile.PE(self.target_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        if func.name:
                            name = func.name.decode('utf-8')
                            for cat, keys in self.api_watchlist.items():
                                if any(k.lower() in name.lower() for k in keys):
                                    findings.append(f"API_{name}")
            return findings
        except: 
            return []

    def _scan_strings(self):
        findings = []
        try:
            with open(self.target_path, "rb") as f:
                content = f.read().decode('ascii', 'ignore')
                for label, pattern in self.regex_patterns.items():
                    matches = re.findall(pattern, content)
                    for match in set(matches): 
                        print(f"    [!] Found {label}: {match}")
                        findings.append(f"STR_{label}_{match}")
            return findings
        except Exception as e:
            print(f"String scan error: {e}")
            return []

    # --- ML FEATURE EXTRACTION (Stolen from GitHub Repo) ---
    def _calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_ml_features(self):
        try:
            pe = pefile.PE(self.target_path)

            features = {
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'Characteristics': pe.FILE_HEADER.Characteristics,
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'DirectoryEntryExport': 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
                'ImageDirectoryEntryExport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
                'DirectoryEntryImportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
                'SectionMaxChar': len(pe.sections),  
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'SectionMinEntropy': None,  
                'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'SectionMinVirtualsize': None  
            }

            entropies = []
            for section in pe.sections:
                entropy = self._calculate_entropy(section.get_data())
                entropies.append(entropy)

            if entropies:
                features['SectionMinEntropy'] = min(entropies)

            features['SectionMinVirtualsize'] = min(section.Misc_VirtualSize for section in pe.sections)

            # Return exactly what their model expects: a Pandas DataFrame
            return pd.DataFrame([features])
            
        except Exception as e:
            print(f"[!] ML Feature Extraction Error: {e}")
            return None