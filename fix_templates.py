"""One-time script to fix template extends and URL references after copying."""
import os
import re

BASE = r"c:\mega project\CyberSuite\templates"

# (folder, {old: new} replacements)
FIXES = {
    "crypto": {
        "url_for('file.": "url_for('crypto.",
        'url_for("file.': 'url_for("crypto.',
    },
    "threat": {
        "url_for('scan_url_route')": "url_for('phishing.scan_url')",
        "url_for('scan_ip_route')":  "url_for('phishing.scan_ip')",
        "url_for('scan_file_route')":"url_for('phishing.scan_file')",
        "url_for('scan_hash_route')":"url_for('phishing.scan_hash')",
        "url_for('scan_history')":   "url_for('phishing.history')",
        "url_for('logout')":         "url_for('auth.logout')",
        "url_for('login')":          "url_for('auth.login')",
        "url_for('register')":       "url_for('auth.register')",
        "url_for('admin_panel')":    "url_for('admin')",
        "url_for('profile')":        "url_for('profile')",
    },
    "scanner": {
        "url_for('dashboard')":   "url_for('scanner.dashboard')",
        "url_for('history')":     "url_for('scanner.history')",
        "url_for('logout')":      "url_for('auth.logout')",
        "url_for('login')":       "url_for('auth.login')",
        "url_for('register')":    "url_for('auth.register')",
        "url_for('admin_panel')": "url_for('admin')",
        "url_for('export_scan,":  "url_for('scanner.export_scan,",
        "url_for('export_scan'":  "url_for('scanner.export_scan'",
        "/scan'":                 "/portscan/scan'",
        "action=\"/scan\"":       'action="/portscan/scan"',
        "fetch('/scan'":          "fetch('/portscan/scan'",
        "fetch(\"/scan\"":        'fetch("/portscan/scan"',
    },
}

for folder, replacements in FIXES.items():
    folder_path = os.path.join(BASE, folder)
    for fname in os.listdir(folder_path):
        if not fname.endswith(".html"):
            continue
        fpath = os.path.join(folder_path, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        for old, new in replacements.items():
            content = content.replace(old, new)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Fixed: {folder}/{fname}")

print("Done!")
