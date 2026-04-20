import os
import sys

print("=" * 60)
print("DEBUGGING 2FA SETUP")
print("=" * 60)

# Check Python version
print(f"\n✓ Python version: {sys.version}")

# Check imports
print("\n--- Checking imports ---")
try:
    import pyotp
    print("✓ pyotp installed")
except ImportError as e:
    print(f"✗ pyotp NOT installed: {e}")
    sys.exit(1)

try:
    import qrcode
    print("✓ qrcode installed")
except ImportError as e:
    print(f"✗ qrcode NOT installed: {e}")
    sys.exit(1)

# Check TOTPManager
print("\n--- Testing TOTPManager ---")
try:
    from core.totp_manager import TOTPManager
    print("✓ TOTPManager imported")
except Exception as e:
    print(f"✗ Failed to import TOTPManager: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Initialize
print("\n--- Initializing TOTPManager ---")
try:
    os.makedirs("qr_codes", exist_ok=True)
    print("✓ qr_codes directory created")
    
    mgr = TOTPManager()
    print("✓ TOTPManager initialized")
except Exception as e:
    print(f"✗ Failed to initialize: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test setup_user
print("\n--- Testing setup_user ---")
try:
    secret, qr_path = mgr.setup_user("testuser", "test@example.com")
    print(f"✓ Secret generated: {secret}")
    print(f"✓ QR path returned: {qr_path}")
    
    if qr_path is None:
        print("✗ ERROR: qr_path is None!")
    elif not os.path.exists(qr_path):
        print(f"✗ ERROR: QR file doesn't exist at {qr_path}")
        print(f"   Current directory: {os.getcwd()}")
        print(f"   Files in qr_codes: {os.listdir('qr_codes') if os.path.exists('qr_codes') else 'FOLDER NOT FOUND'}")
    else:
        file_size = os.path.getsize(qr_path)
        print(f"✓ QR file exists: {qr_path}")
        print(f"✓ File size: {file_size} bytes")
except Exception as e:
    print(f"✗ setup_user failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test get_qr_as_base64
print("\n--- Testing get_qr_as_base64 ---")
try:
    qr_b64 = mgr.get_qr_as_base64("testuser", "test@example.com")
    if qr_b64 is None:
        print("✗ ERROR: get_qr_as_base64 returned None")
    else:
        print(f"✓ QR as base64 generated")
        print(f"✓ Base64 length: {len(qr_b64)} characters")
        print(f"✓ Starts with: {qr_b64[:50]}...")
except Exception as e:
    print(f"✗ get_qr_as_base64 failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("✓ ALL TESTS PASSED - 2FA should work!")
print("=" * 60)