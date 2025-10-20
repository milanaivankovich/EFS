import sys
import os
import hashlib
import random
import base64
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QMessageBox)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, NameAttribute, CertificateBuilder, random_serial_number
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding  # Corrected import
from secureFileSystem import SecureFileSystem
import secrets

USERS_FILE = "users.txt"
USERS_DIR = "users"
SALT_SIZE = 16  # Veličina soli za PBKDF2

HASH_FUNCTIONS = [hashlib.sha256, hashlib.sha512, hashlib.blake2b]

def hash_password(password: str) -> str:
    hash_function = random.choice(HASH_FUNCTIONS)  # Nasumično biranje hash funkcije
    return hash_function(password.encode()).hexdigest()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_private_key(private_key_pem: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Encrypt the private key
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add padding
    padder = padding.PKCS7(128).padder()  # Use the correctly imported padding module
    padded_data = padder.update(private_key_pem) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return salt + iv + encrypted data
    return salt + iv + encrypted_data

class RegisterPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Registration")
        self.setGeometry(100, 100, 400, 250)

        main_layout = QVBoxLayout()

        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_entry)
        main_layout.addLayout(username_layout)

        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_entry)
        main_layout.addLayout(password_layout)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self.register)
        main_layout.addWidget(register_button)

        self.setLayout(main_layout)

    def register(self):
        username = self.username_entry.text().strip()
        password = self.password_entry.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "All fields are required.!")
            return

        user_dir = os.path.join(USERS_DIR, username)
        if os.path.exists(user_dir):
            QMessageBox.warning(self, "Error", "Username already exists!")
            return

        os.makedirs(user_dir, exist_ok=True)

        private_key, public_key = self.generate_key_pair()
        encrypted_private_key = encrypt_private_key(private_key, password)
        private_key_path = os.path.join(user_dir, f"private_key_{username}.pem")
        public_key_path = os.path.join(user_dir, f"public_key_{username}.pem")

        with open(private_key_path, "wb") as priv_file:
            priv_file.write(encrypted_private_key)
        with open(public_key_path, "wb") as pub_file:
            pub_file.write(public_key)

        cert = self.generate_certificate(username, private_key)
        cert_path = os.path.join(user_dir, f"certificate_{username}.pem")
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert)

        hashed_password = hash_password(password)
        with open(USERS_FILE, "a") as file:
            file.write(f"{username} | {hashed_password} | {cert_path} | {public_key_path} | {private_key_path}\n")

        QMessageBox.information(self, "Success", "Registration successful!")
        self.open_secure_file_system(username, password)

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def generate_certificate(self, username, private_pem):
        private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
        subject = issuer = Name([
            NameAttribute(NameOID.COMMON_NAME, username)
        ])

        cert = CertificateBuilder()
        cert = cert.subject_name(subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(private_key.public_key())
        cert = cert.serial_number(random_serial_number())
        cert = cert.not_valid_before(datetime.utcnow())
        cert = cert.not_valid_after(datetime.utcnow() + timedelta(days=365))
        cert = cert.sign(private_key, hashes.SHA256(), default_backend())

        return cert.public_bytes(serialization.Encoding.PEM)

    def open_secure_file_system(self, username, password):
        self.secure_fs_window = SecureFileSystem(username, password)
        self.secure_fs_window.show()
        self.close()

def main():
    if not os.path.exists(USERS_DIR):
        os.makedirs(USERS_DIR)

    app = QApplication(sys.argv)
    window = RegisterPage()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()