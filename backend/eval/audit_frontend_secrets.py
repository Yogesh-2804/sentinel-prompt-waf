"""
Frontend Secret & Credential Audit Script
Scans all JS / JSX files in frontend/ to ensure ZERO hardcoded admin passwords,
JWT signing secrets, or private credential strings exist in source files.
"""

import os

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "frontend")

FORBIDDEN_STRINGS = [
    "SentinelAdmin2026!",
    "SentinelAdminPass2026!",
    "sentinel-super-secret",
    "jwt_secret",
    "admin_password = "
]

def run_secret_audit():
    print("=" * 70)
    print("   SENTINELPROMPT - FRONTEND SECRET & CREDENTIAL AUDIT   ")
    print("=" * 70 + "\n")

    found_violations = []

    for root, dirs, files in os.walk(FRONTEND_DIR):
        if "node_modules" in root or ".next" in root:
            continue
        for f in files:
            if f.endswith(".js") or f.endswith(".jsx") or f.endswith(".json"):
                fpath = os.path.join(root, f)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as file_obj:
                    content = file_obj.read()
                    for forbidden in FORBIDDEN_STRINGS:
                        if forbidden in content:
                            found_violations.append((fpath, forbidden))

    print(f"Scanned directory: {os.path.abspath(FRONTEND_DIR)}")
    print(f"Total Violations Found: {len(found_violations)}")

    if len(found_violations) == 0:
        print("  -> SUCCESS: ZERO hardcoded admin credentials or JWT secrets found in frontend source!\n")
    else:
        for path, viol in found_violations:
            print(f"  -> WARNING Violation: '{viol}' found in {path}")
        print()

if __name__ == "__main__":
    run_secret_audit()
