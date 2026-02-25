import base64
import binascii
import json
import os
import platform
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class LicenseKeyManager:
    """A class to manage license generation and validation."""

    MAX_LICENSE_KEY_LENGTH = 8192
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    UTC_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

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
    def _read_text_file(path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8") as file:
                return file.read().strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    @staticmethod
    def _build_hardware_id(seed: str) -> str:
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _get_windows_machine_guid() -> Optional[str]:
        try:
            output = subprocess.check_output(
                [
                    "reg",
                    "query",
                    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                    "/v",
                    "MachineGuid",
                ],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return None

        match = re.search(r"MachineGuid\s+REG_\w+\s+(.+)", output)
        return match.group(1).strip() if match else None

    @staticmethod
    def _get_macos_platform_uuid() -> Optional[str]:
        try:
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return None

        match = re.search(r'"IOPlatformUUID" = "([^"]+)"', output)
        return match.group(1).strip() if match else None

    @staticmethod
    def generate_hardware_id():
        """Generate a stable hardware ID from machine identifiers (not network adapters)."""
        system = platform.system().lower()

        if system == "linux":
            for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                machine_id = LicenseKeyManager._read_text_file(path)
                if machine_id:
                    return LicenseKeyManager._build_hardware_id(f"linux:{machine_id}")
        elif system == "windows":
            machine_guid = LicenseKeyManager._get_windows_machine_guid()
            if machine_guid:
                return LicenseKeyManager._build_hardware_id(f"windows:{machine_guid}")
        elif system == "darwin":
            platform_uuid = LicenseKeyManager._get_macos_platform_uuid()
            if platform_uuid:
                return LicenseKeyManager._build_hardware_id(f"darwin:{platform_uuid}")

        fallback_seed = f"{platform.system()}|{platform.node()}|{uuid.getnode()}"
        return LicenseKeyManager._build_hardware_id(f"fallback:{fallback_seed}")

    @staticmethod
    def _get_expiration_date_str(days_to_expire: int) -> str:
        expiration_date = datetime.now(timezone.utc) + timedelta(days=days_to_expire)
        expiration_date = expiration_date.replace(hour=23, minute=59, second=59, microsecond=0)
        return expiration_date.strftime(LicenseKeyManager.UTC_DATE_FORMAT)

    @staticmethod
    def _parse_expiration_date(expiration_date_str: str) -> Optional[datetime]:
        for fmt, tz in (
            (LicenseKeyManager.UTC_DATE_FORMAT, timezone.utc),
            (LicenseKeyManager.DATE_FORMAT, None),
        ):
            try:
                parsed = datetime.strptime(expiration_date_str, fmt)
                return parsed.replace(tzinfo=tz) if tz else parsed
            except ValueError:
                continue
        return None

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

        expiration_date = LicenseKeyManager._parse_expiration_date(payload["expiration_date"])
        if expiration_date is None:
            return False

        now = datetime.now(expiration_date.tzinfo) if expiration_date.tzinfo else datetime.now()
        return now <= expiration_date and payload["hardware_id"] == hardware_id

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
        except (FileNotFoundError, PermissionError, OSError):
            return None

    @staticmethod
    def write_private_key_file(private_key_pem):
        """Write the private key with restrictive permissions."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open("private.key", flags, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(private_key_pem)

    @staticmethod
    def read_private_key_file():
        """Read the private key from a file."""
        try:
            with open("private.key", "rb") as file:
                return file.read()
        except (FileNotFoundError, PermissionError, OSError):
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
        except (FileNotFoundError, PermissionError, OSError, ValueError, TypeError):
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

        if LicenseKeyManager._parse_expiration_date(payload["expiration_date"]) is None:
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
