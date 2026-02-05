import base64
import os
import json
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordVault:
    def __init__(self):
        self.salt_file = 'vault.salt'
        self.db_file = 'vault.json'
        self.key = None
        self.fernet = None

    def _get_or_create_salt(self):
        """
        Loads the salt from file or creates a new one if it doesn't exist.
        The salt ensures that the same password generates a unique key.
        """
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt

    def derive_key(self, master_password):
        """
        Derives a cryptographic key from the master password using PBKDF2.
        This transforms a human-readable password into a 32-byte secure key.
        """
        salt = self._get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.key = key
        self.fernet = Fernet(key)

    def save_password(self, service, password):
        """Encrypts (Ciphers) and stores a password."""
        if not self.fernet:
            print("❌ Vault locked.")
            return

        # Load existing data
        data = {}
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                data = {}

        # Encrypt the password
        encrypted_pwd = self.fernet.encrypt(password.encode()).decode()
        data[service] = encrypted_pwd

        # Write back to file
        with open(self.db_file, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"✔ Password for '{service}' saved successfully.")

    def get_password(self, service):
        """Retrieves and Decrypts (Deciphers) a password."""
        if not self.fernet:
            print("❌ Vault locked.")
            return

        if not os.path.exists(self.db_file):
            print("No passwords stored yet.")
            return

        with open(self.db_file, 'r') as f:
            data = json.load(f)

        if service in data:
            encrypted_pwd = data[service]
            try:
                # Decrypt the password
                decrypted_pwd = self.fernet.decrypt(encrypted_pwd.encode()).decode()
                print(f"🔓 Service: {service} | Password: {decrypted_pwd}")
            except Exception:
                print("❌ Error: Could not decrypt. Wrong Master Password?")
        else:
            print(f"❌ Service '{service}' not found.")

# --- CLI Interface ---
def main():
    print("=== 🔒 Simple Python Password Vault ===")
    vault = PasswordVault()
    
    # 1. User Authentication (Deriving the Key)
    master = input("Enter Master Password to Unlock/Create Vault: ")
    vault.derive_key(master)
    print("🔑 Key Derived. Vault Unlocked.\n")

    while True:
        print("\n1. Save a Password")
        print("2. Retrieve a Password")
        print("3. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            service = input("Service Name (e.g., Gmail): ")
            pwd = input("Password to store: ")
            vault.save_password(service, pwd)
        elif choice == '2':
            service = input("Service Name: ")
            vault.get_password(service)
        elif choice == '3':
            print("Exiting and locking vault.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()