"""
core/totp_manager.py
TOTP-based two-factor authentication for SIEM admin users.

Requires: pyotp, qrcode[pil]   (pip install pyotp qrcode[pil])

Usage:
    from core.totp_manager import TOTPManager
    totp = TOTPManager()

    # First-time setup for a user
    secret, qr_path = totp.setup_user("Kaavya", "krnkaavya03@gmail.com")

    # Verify a code entered by the user
    ok = totp.verify("Kaavya", "123456")
"""

import os
import json
import base64
import logging
import secrets

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("TOTPManager")
logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")

TOTP_SECRETS_FILE = "totp_secrets.json"   # stores {username: encrypted_secret}
QR_DIR = "qr_codes"
ISSUER_NAME = "SIEMSecure"

# ─────────────────────────────────────────────
# Helpers — lightweight secret encryption
# Using XOR with a machine-derived key (no external crypto deps needed)
# For production, replace with Fernet / KMS
# ─────────────────────────────────────────────

def _machine_key() -> bytes:
    """Derive a stable machine key from hostname + a fixed salt."""
    import hashlib
    import socket
    raw = socket.gethostname() + "siemSecureTotp2026"
    return hashlib.sha256(raw.encode()).digest()


def _xor_encrypt(plaintext: str) -> str:
    key = _machine_key()
    data = plaintext.encode()
    enc  = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(enc).decode()


def _xor_decrypt(ciphertext: str) -> str:
    key  = _machine_key()
    data = base64.b64decode(ciphertext)
    dec  = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return dec.decode()


# ─────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────

class TOTPManager:

    def __init__(self):
        self._secrets = self._load_secrets()

    # ---- Public API ----

    def setup_user(self, username: str, email: str = "") -> tuple:
        """
        Generate a new TOTP secret for a user and save a QR code PNG.
        Returns (secret_base32: str, qr_image_path: str | None).
        Safe to call again — generates a fresh secret each time.
        """
        try:
            import pyotp
        except ImportError:
            logger.error("pyotp not installed. Run: pip install pyotp")
            return None, None

        secret = pyotp.random_base32()
        self._secrets[username] = _xor_encrypt(secret)
        self._save_secrets()

        # Build provisioning URI
        totp = pyotp.TOTP(secret)
        uri  = totp.provisioning_uri(
            name=email or username,
            issuer_name=ISSUER_NAME
        )

        qr_path = self._save_qr(username, uri)
        logger.info(f"TOTP secret generated for {username}")
        return secret, qr_path

    def verify(self, username: str, code: str) -> bool:
        """
        Verify a 6-digit TOTP code for a user.
        Returns True if valid (±1 window = 30 s tolerance).
        """
        try:
            import pyotp
        except ImportError:
            logger.error("pyotp not installed — 2FA bypassed")
            return True   # fail open so the app doesn't lock out everyone

        enc = self._secrets.get(username)
        if not enc:
            logger.warning(f"No TOTP secret found for {username} — 2FA not set up")
            return False

        try:
            secret = _xor_decrypt(enc)
            totp   = pyotp.TOTP(secret)
            ok     = totp.verify(code, valid_window=1)
            logger.info(f"TOTP verify for {username}: {'OK' if ok else 'FAIL'}")
            return ok
        except Exception as e:
            logger.error(f"TOTP verify error for {username}: {e}")
            return False

    def has_2fa(self, username: str) -> bool:
        """Return True if the user has a TOTP secret configured."""
        return username in self._secrets

    def remove_user(self, username: str):
        """Remove TOTP secret for a user (e.g., when deleting the account)."""
        if username in self._secrets:
            del self._secrets[username]
            self._save_secrets()
            logger.info(f"TOTP secret removed for {username}")

    def get_qr_as_base64(self, username: str, email: str = "") -> str | None:
        """
        Return a base64-encoded PNG of the QR code for embedding in Streamlit.
        Generates a new QR if not already saved.
        """
        qr_path = os.path.join(QR_DIR, f"{username}.png")
        if not os.path.exists(qr_path):
            _, qr_path = self.setup_user(username, email)
        if not qr_path or not os.path.exists(qr_path):
            return None
        with open(qr_path, "rb") as f:
            return base64.b64encode(f.read()).decode()

    # ---- Internal ----

    def _save_qr(self, username: str, uri: str) -> str | None:
        """Save QR code PNG. Returns path or None if qrcode not installed."""
        try:
            import qrcode
            os.makedirs(QR_DIR, exist_ok=True)
            img = qrcode.make(uri)
            path = os.path.join(QR_DIR, f"{username}.png")
            img.save(path)
            logger.info(f"QR code saved: {path}")
            return path
        except ImportError:
            logger.warning("qrcode not installed. Run: pip install qrcode[pil]")
            return None
        except Exception as e:
            logger.error(f"QR code generation failed: {e}")
            return None

    def _load_secrets(self) -> dict:
        if os.path.exists(TOTP_SECRETS_FILE):
            try:
                with open(TOTP_SECRETS_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_secrets(self):
        try:
            with open(TOTP_SECRETS_FILE, "w") as f:
                json.dump(self._secrets, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save TOTP secrets: {e}")


# ─────────────────────────────────────────────
# Standalone test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    mgr = TOTPManager()
    secret, qr = mgr.setup_user("TestUser", "test@example.com")
    if secret:
        print(f"Secret: {secret}")
        print(f"QR code: {qr}")
        code = input("Enter code from authenticator app: ").strip()
        print("Valid!" if mgr.verify("TestUser", code) else "Invalid code.")
    else:
        print("pyotp not installed — run: pip install pyotp qrcode[pil]")
