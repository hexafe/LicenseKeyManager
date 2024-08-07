# LicenseKeyManager
Simple class for local offline license keys generation and validation based on hardware id

Example usage:

```python
from datetime import datetime, timedelta
from LicenseKeyManager import LicenseKeyManager

def main():
    """
    Main function to demonstrate license key generation, writing, reading, and validation.
    """
    # Generate the hardware ID
    hardware_id = LicenseKeyManager.generate_hardware_id()
    
    # Generate and save public and private keys
    LicenseKeyManager.generate_keys_and_write_to_files()
    
    private_key = LicenseKeyManager.read_private_key_file()
    public_key = LicenseKeyManager.read_public_key_file()
    
    if private_key is None or public_key is None:
        print("Failed to read keys.")
        return

    # Generate the license key and expiration date
    days_to_expire = 7
    license_key = LicenseKeyManager.generate_license_key(hardware_id, days_to_expire, private_key)
    expiration_date = LicenseKeyManager.get_expiration_date_from_license_key(license_key)
    print("Generated License Key:", license_key)
    print("Expiration Date:", expiration_date)

    # Write the license key to a file
    LicenseKeyManager.write_license_key_file(license_key)
    print("License Key written to file.")

    # Load the license key from the file
    stored_license_key = LicenseKeyManager.read_license_key_file()
    print("License Key read from file.")

    # Validate the license key
    if stored_license_key and public_key:
        if LicenseKeyManager.validate_license_key(stored_license_key, hardware_id, public_key):
            print("License Key is Valid!")
        else:
            print("Invalid License Key or No License Key Found!")
    else:
        print("No License Key or Public Key Found!")

if __name__ == "__main__":
    main()
