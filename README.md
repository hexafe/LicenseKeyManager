# LicenseKeyManager

Simple offline license generation and validation based on a stable machine fingerprint.

## Security model

- **Issuer side (admin/backoffice only):** holds `private.key`, generates licenses.
- **Client runtime (shipped app):** holds only `public.key`, validates `license.key`.

> Never ship `private.key` with your client artifacts.

## Issuer flow (trusted environment)

```python
from LicenseKeyManager import LicenseKeyManager

# 1) Generate key pair once (optionally encrypt private.key)
LicenseKeyManager.generate_keys_and_write_to_files(private_key_password=b"strong-passphrase")

# 2) Create a license for a specific hardware ID
private_key_pem = LicenseKeyManager.read_private_key_file()
hardware_id = LicenseKeyManager.generate_hardware_id()  # collected from target machine
license_key = LicenseKeyManager.generate_license_key(
    hardware_id,
    days_to_expire=30,
    private_key=private_key_pem,
    private_key_password=b"strong-passphrase",
)

# 3) Deliver only license.key + public.key to client
LicenseKeyManager.write_license_key_file(license_key)
```

## Client runtime flow (shipped app)

Bundle:
- `public.key`
- `license.key`

At startup:

```python
from LicenseKeyManager import LicenseKeyManager

if not LicenseKeyManager.is_license_valid_for_current_machine():
    raise SystemExit("License validation failed")

# launch protected features
```

## License format

License key is base64(JSON) with this structure:

```json
{
  "payload": {
    "hardware_id": "2aef6f5d43e948b4864d5e2c410af947",
    "expiration_date": "2026-12-31T23:59:59Z"
  },
  "signature": "<base64-signature>"
}
```

Runtime validation performs strict decode and schema checks and returns `False` for malformed input.

`generate_hardware_id()` now uses OS machine identifiers (`/etc/machine-id`, Windows `MachineGuid`, macOS `IOPlatformUUID`) and hashes them, avoiding NIC/MAC churn from switching Wi-Fi/Ethernet/docks.

## Verified expiration helper

Use verified expiration read when needed:

```python
public_key = LicenseKeyManager.read_public_key_file()
exp = LicenseKeyManager.get_verified_expiration_date_from_license_key(license_key, public_key)
```

Returns `None` if malformed or signature-invalid.
