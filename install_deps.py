"""
install_deps.py — SIEMSecure Pro v3.0
Run this ONCE before launching the app:
    python install_deps.py

Installs all required packages and prints a checklist of what worked.
"""

import subprocess
import sys
import os

PACKAGES = [
    ("streamlit",      "streamlit>=1.32.0"),
    ("pandas",         "pandas>=2.0.0"),
    ("plotly",         "plotly>=5.18.0"),
    ("paramiko",       "paramiko>=3.0.0"),
    ("dotenv",         "python-dotenv>=1.0.0"),
    ("pyotp",          "pyotp>=2.9.0"),
    ("qrcode",         "qrcode[pil]>=7.4.2"),
    ("sklearn",        "scikit-learn>=1.3.0"),
    ("numpy",          "numpy>=1.24.0"),
    ("bcrypt",         "bcrypt>=4.0.0"),
    ("PIL",            "Pillow>=10.0.0"),
]

def pip(pkg_spec):
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg_spec, "-q"],
        capture_output=True, text=True
    )
    return result.returncode == 0

def check(module):
    try:
        __import__(module)
        return True
    except ImportError:
        return False

print("\n" + "="*60)
print("  SIEMSecure Pro — Dependency Installer")
print("="*60)

results = []
for module, pkg_spec in PACKAGES:
    already = check(module)
    if already:
        results.append((pkg_spec, "✅ already installed"))
    else:
        print(f"  Installing {pkg_spec}...", end=" ", flush=True)
        ok = pip(pkg_spec)
        if ok:
            results.append((pkg_spec, "✅ installed"))
            print("done")
        else:
            results.append((pkg_spec, "❌ FAILED"))
            print("FAILED")

print("\n" + "-"*60)
print("  Results:")
for pkg, status in results:
    print(f"  {status}  {pkg}")

# Check .env file
print("\n" + "-"*60)
print("  Environment check:")
env_path = ".env"
if os.path.exists(env_path):
    print("  ✅  .env file found")
    from dotenv import load_dotenv
    load_dotenv()
    keys = {
        "SMTP_USER":         os.getenv("SMTP_USER"),
        "SMTP_PASSWORD":     os.getenv("SMTP_PASSWORD"),
        "ALERT_RECIPIENT":   os.getenv("ALERT_RECIPIENT"),
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY"),
    }
    for k, v in keys.items():
        status = "✅" if v else "⚠️  NOT SET"
        masked = ("*" * (len(v)-4) + v[-4:]) if v and len(v) > 4 else v
        print(f"  {status}  {k} = {masked or 'not configured'}")
else:
    print("  ⚠️   .env file NOT found — copy .env.example to .env and fill in credentials")

# Check core modules
print("\n" + "-"*60)
print("  Core module check:")
modules = [
    ("core/notification_engine.py", "core.notification_engine"),
    ("core/ip_enrichment.py",       "core.ip_enrichment"),
    ("core/risk_engine.py",         "core.risk_engine"),
    ("core/totp_manager.py",        "core.totp_manager"),
    ("core/syslog_collector.py",    "core.syslog_collector"),
    ("core/windows_event_collector.py", "core.windows_event_collector"),
]
sys.path.insert(0, os.path.abspath("."))
for path, mod in modules:
    file_ok = os.path.exists(path)
    try:
        __import__(mod)
        import_ok = True
    except Exception as e:
        import_ok = False
    icon = "✅" if file_ok and import_ok else ("⚠️  file missing" if not file_ok else f"❌ import error")
    print(f"  {icon}  {path}")

print("\n" + "="*60)
print("  Done! Launch with:  streamlit run app_advanced.py")
print("="*60 + "\n")