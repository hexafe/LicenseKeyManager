import base64
import binascii
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class LicenseKeyManager:
    """A class to manage license generation and validation."""

    MAX_LICENSE_KEY_LENGTH = 8192

    @staticmethod
    def generate_rsa_key_pair():
        """Generate an RSA public-private key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        return private_key, private_key.public_key()

    @staticmethod
    def generate_hardware_id():
        """Generate a hardware ID based on the network adapter MAC address."""
        return ":".join(hex(i)[2:].zfill(2) for i in uuid.getnode().to_bytes(6, "big"))

    @staticmethod
    def _get_expiration_date_str(days_to_expire: int) -> str:
        expiration_date = datetime.now() + timedelta(days=days_to_expire)
        expiration_date = expiration_date.replace(hour=23, minute=59, second=59)
        return expiration_date.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _encode_license_container(payload: dict, signature: bytes) -> str:
        container = {
            "payload": payload,
            "signature": base64.b64encode(signature).decode("utf-8"),
        }
        raw = json.dumps(container, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("utf-8")

    @staticmethod
    def _decode_license_container(license_key: str) -> Optional[tuple]:
        """Decode and validate outer/base schema of a license key."""
        if not isinstance(license_key, str) or len(license_key) > LicenseKeyManager.MAX_LICENSE_KEY_LENGTH:
            return None

        try:
            decoded = base64.b64decode(license_key.encode("utf-8"), validate=True)
            container = json.loads(decoded.decode("utf-8"))
        except (ValueError, json.JSONDecodeError, binascii.Error, UnicodeDecodeError):
            return None

        if not isinstance(container, dict):
            return None

        payload = container.get("payload")
        signature_b64 = container.get("signature")

        if not isinstance(payload, dict) or not isinstance(signature_b64, str):
            return None

        hardware_id = payload.get("hardware_id")
        expiration_date = payload.get("expiration_date")
        if not isinstance(hardware_id, str) or not isinstance(expiration_date, str):
            return None

        try:
            signature = base64.b64decode(signature_b64.encode("utf-8"), validate=True)
        except (ValueError, binascii.Error):
            return None

        payload_data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return payload, payload_data, signature

    @staticmethod
    def generate_license_key(hardware_id, days_to_expire, private_key, private_key_password=None):
        """Generate a signed license key for a hardware ID."""
        private_key_obj = serialization.load_pem_private_key(
            private_key,
            password=private_key_password,
            backend=default_backend(),
        )

        payload = {
            "hardware_id": hardware_id,
            "expiration_date": LicenseKeyManager._get_expiration_date_str(days_to_expire),
        }
        payload_data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = LicenseKeyManager.sign_data(payload_data, private_key_obj)
        return LicenseKeyManager._encode_license_container(payload, signature)

    @staticmethod
    def validate_license_key(license_key, hardware_id, public_key):
        """Validate a license key. Returns False for any malformed/tampered input."""
        decoded = LicenseKeyManager._decode_license_container(license_key)
        if decoded is None:
            return False

        payload, payload_data, signature = decoded

        if not LicenseKeyManager.verify_signature(payload_data, signature, public_key):
            return False

        try:
            expiration_date = datetime.strptime(payload["expiration_date"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False

        return datetime.now() <= expiration_date and payload["hardware_id"] == hardware_id

    @staticmethod
    def sign_data(data, private_key):
        """Sign data using the private key."""
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    @staticmethod
    def verify_signature(data, signature, public_key):
        """Verify the signature of data using the public key."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    @staticmethod
    def write_license_key_file(encrypted_key):
        """Write the license key to a license key file."""
        with open("license.key", "w", encoding="utf-8") as file:
            file.write(encrypted_key)

    @staticmethod
    def read_license_key_file():
        """Read the license key from the license key file."""
        try:
            with open("license.key", "r", encoding="utf-8") as file:
                return file.read().strip()
        except FileNotFoundError:
            return None

    @staticmethod
    def write_private_key_file(private_key_pem):
        """Write the private key with restrictive permissions."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open("private.key", flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(private_key_pem)
        finally:
            try:
                os.chmod("private.key", 0o600)
            except FileNotFoundError:
                pass

    @staticmethod
    def read_private_key_file():
        """Read the private key from a file."""
        try:
            with open("private.key", "rb") as file:
                return file.read()
        except FileNotFoundError:
            return None

    @staticmethod
    def write_public_key_file(public_key_pem):
        """Write the public key to a file."""
        with open("public.key", "wb") as file:
            file.write(public_key_pem)

    @staticmethod
    def read_public_key_file():
        """Read the public key from a file."""
        try:
            with open("public.key", "rb") as file:
                return serialization.load_pem_public_key(file.read(), backend=default_backend())
        except (FileNotFoundError, ValueError, TypeError):
            return None

    @staticmethod
    def generate_keys_and_write_to_files(private_key_password: Optional[bytes] = None):
        """Generate RSA key pair and write them to files.

        Args:
            private_key_password: Optional bytes password for private key PEM encryption.
        """
        private_key, public_key = LicenseKeyManager.generate_rsa_key_pair()

        encryption_algorithm = (
            serialization.BestAvailableEncryption(private_key_password)
            if private_key_password
            else serialization.NoEncryption()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm,
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        LicenseKeyManager.write_private_key_file(private_key_pem)
        LicenseKeyManager.write_public_key_file(public_key_pem)

    @staticmethod
    def get_verified_expiration_date_from_license_key(license_key, public_key):
        """Return expiration date only if signature verifies; otherwise None."""
        decoded = LicenseKeyManager._decode_license_container(license_key)
        if decoded is None:
            return None

        payload, payload_data, signature = decoded
        if not LicenseKeyManager.verify_signature(payload_data, signature, public_key):
            return None

        try:
            datetime.strptime(payload["expiration_date"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

        return payload["expiration_date"]

    @staticmethod
    def get_expiration_date_from_license_key(license_key):
        """Backward-compatible parser for expiration date, returns None when malformed."""
        decoded = LicenseKeyManager._decode_license_container(license_key)
        if decoded is None:
            return None
        payload, _, _ = decoded
        return payload.get("expiration_date")

    @staticmethod
    def is_license_valid_for_current_machine():
        """Canonical client-runtime license gate."""
        license_key = LicenseKeyManager.read_license_key_file()
        public_key = LicenseKeyManager.read_public_key_file()
        if not license_key or public_key is None:
            return False

        hardware_id = LicenseKeyManager.generate_hardware_id()
        return LicenseKeyManager.validate_license_key(license_key, hardware_id, public_key)
