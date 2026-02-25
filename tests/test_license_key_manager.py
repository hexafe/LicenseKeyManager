import base64
import json
import os
import platform

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from LicenseKeyManager import LicenseKeyManager


def _generate_keys(password=None):
    private_key, public_key = LicenseKeyManager.generate_rsa_key_pair()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        ),
    )
    return private_pem, public_key


def test_valid_license_passes():
    hardware_id = "aa:bb:cc:dd:ee:ff"
    private_pem, public_key = _generate_keys()
    license_key = LicenseKeyManager.generate_license_key(hardware_id, 7, private_pem)
    assert LicenseKeyManager.validate_license_key(license_key, hardware_id, public_key)


def test_generate_license_key_rejects_non_int_days_to_expire():
    hardware_id = "aa:bb:cc:dd:ee:ff"
    private_pem, _ = _generate_keys()

    with pytest.raises(ValueError, match="days_to_expire must be an int"):
        LicenseKeyManager.generate_license_key(hardware_id, "7", private_pem)

    with pytest.raises(ValueError, match="days_to_expire must be an int"):
        LicenseKeyManager.generate_license_key(hardware_id, 7.5, private_pem)


def test_generate_license_key_rejects_negative_days_to_expire():
    hardware_id = "aa:bb:cc:dd:ee:ff"
    private_pem, _ = _generate_keys()

    with pytest.raises(ValueError, match="days_to_expire must be greater than or equal to 0"):
        LicenseKeyManager.generate_license_key(hardware_id, -1, private_pem)


def test_generate_license_key_rejects_excessive_days_to_expire():
    hardware_id = "aa:bb:cc:dd:ee:ff"
    private_pem, _ = _generate_keys()

    with pytest.raises(
        ValueError,
        match=f"days_to_expire must be less than or equal to {LicenseKeyManager.MAX_DAYS_TO_EXPIRE}",
    ):
        LicenseKeyManager.generate_license_key(
            hardware_id,
            LicenseKeyManager.MAX_DAYS_TO_EXPIRE + 1,
            private_pem,
        )


def test_expired_license_fails():
    hardware_id = "aa:bb:cc:dd:ee:ff"
    private_pem, public_key = _generate_keys()

    private_key_obj = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend(),
    )
    payload = {
        "hardware_id": hardware_id,
        "expiration_date": "2000-01-01T00:00:00Z",
    }
    payload_data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = LicenseKeyManager.sign_data(payload_data, private_key_obj)
    license_key = LicenseKeyManager._encode_license_container(payload, signature)

    assert not LicenseKeyManager.validate_license_key(license_key, hardware_id, public_key)


def test_wrong_hardware_fails():
    private_pem, public_key = _generate_keys()
    license_key = LicenseKeyManager.generate_license_key("aa:bb:cc:dd:ee:ff", 7, private_pem)
    assert not LicenseKeyManager.validate_license_key(license_key, "11:22:33:44:55:66", public_key)


def test_tampered_bytes_fail():
    hardware_id = "aa:bb:cc:dd:ee:ff"
    private_pem, public_key = _generate_keys()
    license_key = LicenseKeyManager.generate_license_key(hardware_id, 7, private_pem)

    decoded = base64.b64decode(license_key)
    container = json.loads(decoded.decode("utf-8"))
    container["payload"]["hardware_id"] = "00:00:00:00:00:00"
    tampered = base64.b64encode(json.dumps(container).encode("utf-8")).decode("utf-8")

    assert not LicenseKeyManager.validate_license_key(tampered, hardware_id, public_key)


def test_invalid_base64_fails_gracefully():
    _, public_key = _generate_keys()
    assert LicenseKeyManager.validate_license_key("not@@base64", "aa:bb:cc:dd:ee:ff", public_key) is False


def test_missing_files_fail_gracefully(tmp_path):
    original = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert LicenseKeyManager.read_license_key_file() is None
        assert LicenseKeyManager.read_public_key_file() is None
        assert LicenseKeyManager.is_license_valid_for_current_machine() is False
    finally:
        os.chdir(original)



def test_readers_return_none_on_permission_error(monkeypatch):
    def _raise_permission_error(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("builtins.open", _raise_permission_error)

    assert LicenseKeyManager.read_license_key_file() is None
    assert LicenseKeyManager.read_private_key_file() is None
    assert LicenseKeyManager.read_public_key_file() is None


def test_is_license_valid_returns_false_on_unreadable_files(monkeypatch):
    def _raise_permission_error(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("builtins.open", _raise_permission_error)

    assert LicenseKeyManager.is_license_valid_for_current_machine() is False


def test_end_to_end_issuer_to_client_flow(tmp_path):
    original = os.getcwd()
    os.chdir(tmp_path)
    try:
        issuer_hardware_id = "aa:bb:cc:dd:ee:ff"
        client_hardware_id = issuer_hardware_id

        LicenseKeyManager.generate_keys_and_write_to_files(private_key_password=b"secret-pass")
        private_pem = LicenseKeyManager.read_private_key_file()
        public_key = LicenseKeyManager.read_public_key_file()
        assert private_pem is not None
        assert public_key is not None

        license_key = LicenseKeyManager.generate_license_key(
            issuer_hardware_id,
            7,
            private_pem,
            private_key_password=b"secret-pass",
        )
        LicenseKeyManager.write_license_key_file(license_key)

        original_generate_hardware_id = LicenseKeyManager.generate_hardware_id
        LicenseKeyManager.generate_hardware_id = staticmethod(lambda: client_hardware_id)
        try:
            assert LicenseKeyManager.is_license_valid_for_current_machine() is True
        finally:
            LicenseKeyManager.generate_hardware_id = original_generate_hardware_id
    finally:
        os.chdir(original)


def test_overly_large_license_key_fails_gracefully():
    _, public_key = _generate_keys()
    assert (
        LicenseKeyManager.validate_license_key(
            "A" * (LicenseKeyManager.MAX_LICENSE_KEY_LENGTH + 1),
            "aa:bb:cc:dd:ee:ff",
            public_key,
        )
        is False
    )


def test_invalid_public_key_file_returns_none(tmp_path):
    original = os.getcwd()
    os.chdir(tmp_path)
    try:
        with open("public.key", "wb") as file:
            file.write(b"not-a-valid-public-key")

        assert LicenseKeyManager.read_public_key_file() is None
    finally:
        os.chdir(original)


def test_generate_hardware_id_uses_machine_id(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        LicenseKeyManager,
        "_read_text_file",
        staticmethod(lambda path: "fixed-machine-id" if path == "/etc/machine-id" else None),
    )

    first = LicenseKeyManager.generate_hardware_id()
    second = LicenseKeyManager.generate_hardware_id()

    assert first == second
    assert len(first) == 32
    assert ":" not in first


def test_generate_hardware_id_fallback_is_stable(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "node", lambda: "host-1")
    monkeypatch.setattr(LicenseKeyManager, "_read_text_file", staticmethod(lambda _: None))
    monkeypatch.setattr("uuid.getnode", lambda: 123456789)

    first = LicenseKeyManager.generate_hardware_id()
    second = LicenseKeyManager.generate_hardware_id()

    assert first == second
    assert len(first) == 32
    assert ":" not in first


def test_write_private_key_file_does_not_use_chmod(monkeypatch, tmp_path):
    original = os.getcwd()
    os.chdir(tmp_path)
    chmod_calls = []

    def _fail_chmod(*args, **kwargs):
        chmod_calls.append((args, kwargs))
        raise AssertionError("os.chmod should not be called")

    monkeypatch.setattr(os, "chmod", _fail_chmod)

    try:
        LicenseKeyManager.write_private_key_file(b"private-key-bytes")
    finally:
        os.chdir(original)

    assert chmod_calls == []
    assert (tmp_path / "private.key").read_bytes() == b"private-key-bytes"
