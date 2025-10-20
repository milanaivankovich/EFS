import sys
import os
import hashlib
import base64
import random
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from datetime import datetime, timezone
from secureFileSystem import SecureFileSystem

USERS_FILE = "users.txt"
CRL_DIR = "crl"  # Folder sa opozvanim sertifikatima
HASH_FUNCTIONS = [hashlib.sha256, hashlib.sha512, hashlib.blake2b]
AUDIT_LOG_FILE = "audit_log.txt"  # File to store audit logs


class LoginPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Login")
        self.setGeometry(100, 100, 400, 250)

        main_layout = QVBoxLayout()

        # Korisničko ime
        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        main_layout.addWidget(self.username_label)
        main_layout.addWidget(self.username_entry)

        # Lozinka
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(self.password_label)
        main_layout.addWidget(self.password_entry)

        # Digitalni sertifikat (putanja se unosi ručno)
        self.cert_label = QLabel("Path of certificate:")
        self.cert_path_entry = QLineEdit()
        main_layout.addWidget(self.cert_label)
        main_layout.addWidget(self.cert_path_entry)

        # Dugme za prijavu
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        main_layout.addWidget(self.login_button)

        self.setLayout(main_layout)

    def login(self):
        username = self.username_entry.text().strip()
        password = self.password_entry.text().strip()
        cert_path = self.cert_path_entry.text().strip()

        if not username or not password or not cert_path:
            QMessageBox.warning(self, "Error", "Missing fields!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: Missing fields")
            return

        user_data = self.get_user_data(username)
        if not user_data:
            QMessageBox.warning(self, "Erorr", "User does not exist!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: User does not exist")
            return

        stored_hashed_password, stored_cert_path, public_key_path, encrypted_private_key_path = user_data

        # Provjera lozinke
        valid_password = any(hash_func(password.encode()).hexdigest() == stored_hashed_password for hash_func in HASH_FUNCTIONS)
        if not valid_password:
            QMessageBox.warning(self, "Error", "Invalid password!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: Invalid password")
            return

        # Provjera sertifikata
        if cert_path != stored_cert_path:
            QMessageBox.warning(self, "Error", "Invalid certificate path!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: Invalid certificate path")
            return

        if not self.validate_certificate(cert_path):
            QMessageBox.warning(self, "Error", "Expired or invalid certificate!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: Expired or invalid certificate")
            return

        # Provjera da li je sertifikat opozvan
        if os.path.exists(CRL_DIR) and os.path.basename(cert_path) in os.listdir(CRL_DIR):
            QMessageBox.warning(self, "Error", " Revoked certificate!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: Revoked certificate")
            return

        # Dešifrovanje privatnog ključa
        decrypted_private_key = self.decrypt_private_key(encrypted_private_key_path, password)
        if decrypted_private_key is None:
            QMessageBox.warning(self, "Error", "Private key decryption failed!")
            self.log_audit(username, "LOGIN_ATTEMPT", "FAILED: Private key decryption failed")
            return

        QMessageBox.information(self, "SUCCESS", "Successful login to the system!")
        self.log_audit(username, "LOGIN_ATTEMPT", "SUCCESS")

        self.open_secure_file_system(username,password)

    def get_user_data(self, username):
        if not os.path.exists(USERS_FILE):
            return None

        with open(USERS_FILE, "r") as file:
            for line in file:
                parts = line.strip().split(" | ")
                if len(parts) < 5:
                    print(f"Invalid format  users.txt: {line.strip()}")
                    continue
                if parts[0] == username:
                    return parts[1], parts[2], parts[3], parts[4]
        return None

    def decrypt_private_key(self, encrypted_private_key_path, password):
        try:
            with open(encrypted_private_key_path, "rb") as file:
                encrypted_data = file.read()
                salt, iv, encrypted_key = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
                key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_pem = decryptor.update(encrypted_key) + decryptor.finalize()
                return decrypted_pem.strip()
        except Exception as e:
            print(f"Error decrypting private key: {e}")
            return None

    def validate_certificate(self, cert_path):
        try:
            with open(cert_path, "rb") as cert_file:
                cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
                now = datetime.now(timezone.utc)
                return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except Exception as e:
            print(f"Certificate validation error: {e}")
            return False

    def open_secure_file_system(self, username,password):
        self.secure_fs_window = SecureFileSystem(username,password)
        self.secure_fs_window.show()
        self.close()

    def log_audit(self, username, action, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] User: {username}, Action: {action}, Details: {details}\n"
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(log_entry)


def main():
    app = QApplication(sys.argv)
    window = LoginPage()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()