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
from register import RegisterPage
from login import LoginPage

USERS_FILE = "users.txt"
CRL_DIR = "crl"  # Folder sa opozvanim sertifikatima
HASH_FUNCTIONS = [hashlib.sha256, hashlib.sha512, hashlib.blake2b]

class MainPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Welcome - Encrypted File System")
        self.setGeometry(100, 100, 500, 200)

        main_layout = QVBoxLayout()

        self.welcome_label = QLabel("Welcome to the Encrypted File System")
        main_layout.addWidget(self.welcome_label)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.open_login_page)
        main_layout.addWidget(self.login_button)

        self.register_button = QPushButton("Registration")
        self.register_button.clicked.connect(self.open_register_page)
        main_layout.addWidget(self.register_button)

        self.setLayout(main_layout)

    def open_login_page(self):
        self.login_window = LoginPage()
        self.login_window.show()
        self.close()

    def open_register_page(self):
        self.register_window = RegisterPage()
        self.register_window.show()
        self.close()

def main():
    app = QApplication(sys.argv)
    window = MainPage()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
