import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from main import SIEMFramework

print("=" * 60)
print("TESTING ALERT SEVERITY")
print("=" * 60)

# Run test mode
siem = SIEMFramework(test_mode=True)
siem.run_analysis()

print("\n--- Generated Alerts ---")
if siem.alerts:
    for i, alert in enumerate(siem.alerts, 1):
        print(f"\nAlert {i}:")
        print(f"  ID: {alert.get('alert_id')}")
        print(f"  Severity: {alert.get('severity')}")
        print(f"  Rule: {alert.get('rule')}")
        print(f"  User: {alert.get('username')}")
        print(f"  IP: {alert.get('ip_address')}")
else:
    print("❌ No alerts generated")

print("\n" + "=" * 60)