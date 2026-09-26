"""Candidate registry for optional Secure Lab integrations.
Package mappings are intentionally blank until verified against Kali's live repository.
"""
from __future__ import annotations
import json
from pathlib import Path

CANDIDATES = [
("CryptoLyzer","Network & crypto"),("JS-Recon","Web & API"),("ADscan","Active Directory"),("Kingfisher","Secrets discovery"),("mithril","Firmware & IoT"),("MemProcFS","Forensics"),("Garak","AI security"),("MobSF","Mobile"),("Radamsa","Fuzzing"),("Atomic Red Team","Detection validation"),
("VULTURE","Firmware & IoT"),("moria","Firmware & IoT"),("GGFWPi","Firmware & IoT"),("expliot-framework","Firmware & IoT"),("urh","Firmware & IoT"),
("PacketSnitch","Network"),("Setezor","Network"),("L0p4Map","Active Directory"),("godap","Active Directory"),("ldapx","Active Directory"),
("cloud-audit","Cloud"),("BucketLoot","Cloud"),("auditai","Cloud"),("binsuid","Cloud"),("Noir","Cloud"),
("Dissect","Forensics"),("Kanvas","Forensics"),("LogGraphic","Forensics"),("pdfalyzer","Forensics"),("IntelOwl","Threat intelligence"),
("ShadowMap","Recon"),("Screamer","Recon"),("nmapautomatorNG","Recon"),("zscan","Recon"),("OpenDoor","Recon"),
("gobypass403","Web & API"),("403Bypasser","Web & API"),("BypassFuzzer","Web & API"),
("maigret","OSINT"),("linkook","OSINT"),("Favihunter","OSINT"),("Harpoon","OSINT"),
("kittysploit","Framework"),("Hayduk","Framework"),("Intframework","Framework"),
("PenPeeper","Reporting"),("SERPICO","Reporting"),("writehat","Reporting"),
("TRON","Experimental / restricted"),("OSRipper","Experimental / restricted"),("Ravage-Framework","Experimental / restricted"),("Koi","Experimental / restricted"),("Freeze","Experimental / restricted"),("PCILeech","Experimental / restricted"),("AngryOxide","Experimental / restricted")]

def registry():
    return [{"id": n.lower().replace(" ","-").replace("_","-"), "name": n, "category": c,
             "kali_status": "Unverified", "apt_package": None,
             "maintenance": "Unverified", "install_method": "Needs source verification",
             "notes": "Package mapping and upstream maintenance have not yet been verified."}
            for n,c in CANDIDATES]

def load(path: Path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(registry(), indent=2), encoding="utf-8")
    data=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data,list): raise ValueError("Tool registry must be a JSON list")
    return data
