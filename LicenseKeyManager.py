import uuid
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class LicenseKeyManager:
    """
    A class to manage license generation and validation
    """

    @staticmethod
    def generate_rsa_key_pair():
        """
        Generate an RSA public-private key pair.
        
        Returns:
            tuple: (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_hardware_id():
        """
        Generate a hardware ID based on the MAC address of the network adapter.
        
        Returns:
            str: The generated hardware ID.
        """
        mac = ':'.join(hex(i)[2:].zfill(2) for i in uuid.getnode().to_bytes(6, 'big'))
        return mac

    @staticmethod
    def generate_license_key(hardware_id, days_to_expire, private_key):
        """
        Generate a license key.

        Args:
            hardware_id (str): The hardware ID.
            days_to_expire (int): Number of days until the license key expires.
            private_key (bytes): The private key used for signing.

        Returns:
            str: The generated license key.
        """
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        expiration_date = (datetime.now() + timedelta(days=days_to_expire)).strftime("%Y-%m-%d %H:%M:%S")
        license_data = f"{hardware_id}{expiration_date}".encode()
        signature = LicenseKeyManager.sign_data(license_data, private_key)
        license_key = base64.b64encode(license_data + signature).decode()
        return license_key

    @staticmethod
    def validate_license_key(license_key, hardware_id, public_key):
        """
        Validate a license key.
        
        Args:
            license_key (str): The license key to validate.
            hardware_id (str): The hardware ID to match against.
            public_key (bytes): The public key used for signature verification.
        
        Returns:
            bool: True if the license key is valid, False otherwise.
        """
        license_data, signature = base64.b64decode(license_key.encode())[:-256], base64.b64decode(license_key.encode())[-256:]
        if not LicenseKeyManager.verify_signature(license_data, signature, public_key):
            return False

        expiration_date_str = license_data[17:].decode()
        expiration_date = datetime.strptime(expiration_date_str, "%Y-%m-%d %H:%M:%S")
        current_date = datetime.now()

        stored_hardware_id = license_data[:17].decode()

        return current_date <= expiration_date and stored_hardware_id == hardware_id

    @staticmethod
    def sign_data(data, private_key):
        """
        Sign data using the private key.
        
        Args:
            data (bytes): The data to sign.
            private_key (bytes): The private key used for signing.
        
        Returns:
            bytes: The signature.
        """
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(data, signature, public_key):
        """
        Verify the signature of data using the public key.
        
        Args:
            data (bytes): The data whose signature needs to be verified.
            signature (bytes): The signature to verify.
            public_key (bytes): The public key used for verification.
        
        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print("Signature verification failed:", e)
            return False

    @staticmethod
    def write_license_key_file(encrypted_key):
        """
        Write the encrypted license key to a license key file.
        
        Args:
            encrypted_key (str): The encrypted license key.
        """
        with open("license.key", "w") as file:
            file.write(encrypted_key)

    @staticmethod
    def read_license_key_file():
        """
        Read the encrypted license key from the license key file.
        
        Returns:
            str: The encrypted license key.
        """
        try:
            with open("license.key", "r") as file:
                encrypted_key = file.read().strip()
            return encrypted_key
        except FileNotFoundError:
            return None

    @staticmethod
    def write_private_key_file(private_key_pem):
        """
        Write the private key to a file.
        
        Args:
            private_key_pem (bytes): The private key to write.
        """
        with open("private.key", "wb") as file:
            file.write(private_key_pem)

    @staticmethod
    def read_private_key_file():
        """
        Read the private key from a file.
        
        Returns:
            bytes: The private key.
        """
        try:
            with open("private.key", "rb") as file:
                private_key_pem = file.read()
            return private_key_pem
        except FileNotFoundError:
            return None
        
    @staticmethod
    def write_public_key_file(public_key_pem):
        """
        Write the public key to a file.
        
        Args:
            public_key_pem (bytes): The public key to write.
        """
        with open("public.key", "wb") as file:
            file.write(public_key_pem)    
    
    @staticmethod
    def read_public_key_file():
        """
        Read the public key from a file.
        
        Returns:
            bytes: The public key.
        """
        try:
            with open("public.key", "rb") as file:
                public_key_pem = file.read()
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            return public_key
        except FileNotFoundError:
            return None

    @staticmethod
    def generate_keys_and_write_to_files():
        """
        Generate RSA public-private key pair and write them to files.
        """
        private_key, public_key = LicenseKeyManager.generate_rsa_key_pair()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        LicenseKeyManager.write_private_key_file(private_key_pem)
        LicenseKeyManager.write_public_key_file(public_key_pem)

        @staticmethod
    def get_expiration_date_from_license_key(license_key):
        """
        Extract the expiration date from the license key.

        Args:
            license_key (str): The license key.

        Returns:
            str: The expiration date in '%Y-%m-%d %H:%M:%S' format.
        """
        decoded_license_key = base64.b64decode(license_key.encode())
        expiration_date_str = decoded_license_key[17:36].decode()
        return expiration_date_str
