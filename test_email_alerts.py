import os
import json
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("EMAIL ALERTS DEBUG")
print("=" * 60)

# Check .env
print("\n--- Checking .env variables ---")
smtp_user = os.getenv("SMTP_USER")
smtp_pass = os.getenv("SMTP_PASSWORD")
alert_recipient = os.getenv("ALERT_RECIPIENT")

print(f"SMTP_USER: {smtp_user}")
print(f"SMTP_PASSWORD: {'*' * 10 if smtp_pass else 'NOT SET'}")
print(f"ALERT_RECIPIENT: {alert_recipient}")

# Check notification config file
print("\n--- Checking notification_config.json ---")
try:
    with open("notification_config.json") as f:
        config = json.load(f)
    print(f"Config found: {config}")
except FileNotFoundError:
    print("❌ notification_config.json NOT FOUND")
except Exception as e:
    print(f"Error reading config: {e}")

# Check if NotificationEngine works
print("\n--- Testing NotificationEngine ---")
try:
    from core.notification_engine import NotificationEngine
    print("✓ NotificationEngine imported")
    
    notifier = NotificationEngine()
    print("✓ NotificationEngine initialized")
    
    # Test sending
    ok, msg = notifier.send_test_email()
    print(f"Test email result: {ok}")
    print(f"Message: {msg}")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)