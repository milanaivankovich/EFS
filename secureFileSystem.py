import sys
import os
import hashlib
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton,
    QMessageBox, QInputDialog, QLineEdit, QFileDialog
)
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

USERS_DIR = "users"
SHARED_DIR = os.path.join(USERS_DIR, "shared")
PUBLIC_KEYS_DIR = os.path.join(USERS_DIR, "public_keys")
AUDIT_LOG_FILE = "audit_log.txt"
PRIVATE_KEYS_DIR = "private_keys"
CERTIFICATES_DIR = "certificates"

class SecureFileSystem(QWidget):
    def __init__(self, username, password):
        super().__init__()
        self.username = username
        self.password = password if isinstance(password, bytes) else password.encode()
        self.user_home = os.path.join(USERS_DIR, username)
        self.shared_dir = SHARED_DIR
        self.public_keys_dir = PUBLIC_KEYS_DIR
        self.private_key_path = os.path.join(self.user_home, f"private_key_{username}.pem")
        self.public_key_path = os.path.join(self.user_home, f"public_key_{username}.pem")
        self.signed_public_key_path = os.path.join(self.public_keys_dir, f"public_key_{username}.pem")

        # Ensure directories exist and are writable
        for directory in [self.user_home, SHARED_DIR, PUBLIC_KEYS_DIR, PRIVATE_KEYS_DIR, CERTIFICATES_DIR]:
            try:
                os.makedirs(directory, exist_ok=True)
                test_file = os.path.join(directory, ".write_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
            except Exception as e:
                self.log_audit("ERROR", f"Failed to create or write to directory {directory}: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to create or write to directory {directory}: {str(e)}")
                raise RuntimeError(f"Directory setup failed: {str(e)}")

        # Generate key pair and publish signed public key for new users
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            self.generate_key_pair()
        # Ensure signed public key exists and is valid
        try:
            self.publish_signed_public_key()
        except Exception as e:
            self.log_audit("ERROR", f"Failed to initialize signed public key for {self.username}: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to initialize signed public key: {str(e)}")
            raise

        self.init_ui()

    def generate_key_pair(self):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Serialize and save private key (encrypted with password)
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(self.password)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            padded_data = padder.update(private_key_pem) + padder.finalize()
            encrypted_private_key = encryptor.update(padded_data) + encryptor.finalize()

            with open(self.private_key_path, "wb") as f:
                f.write(salt + iv + encrypted_private_key)

            # Serialize public key
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.public_key_path, "wb") as f:
                f.write(public_key_pem)

            # Sign the public key
            signature = private_key.sign(
                public_key_pem,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Save to PUBLIC_KEYS_DIR
            os.makedirs(self.public_keys_dir, exist_ok=True)
            with open(self.signed_public_key_path, "wb") as f:
                f.write(public_key_pem)
            with open(self.signed_public_key_path + ".sig", "wb") as sig_file:
                sig_file.write(base64.b64encode(signature))

            # Verify file creation
            if not os.path.exists(self.signed_public_key_path) or not os.path.exists(self.signed_public_key_path + ".sig"):
                raise RuntimeError("Failed to create signed public key files")

            self.log_audit("KEY", f"Generated and signed public key for {self.username}")
        except Exception as e:
            self.log_audit("ERROR", f"Failed to generate key pair for {self.username}: {str(e)}")
            raise

    def init_ui(self):
        self.setWindowTitle(f"Secure File System - {self.username}")
        self.setGeometry(200, 100, 600, 400)

        layout = QVBoxLayout()

        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabel("User Files")
        layout.addWidget(self.file_tree)

        self.load_directory_structure()

        upload_button = QPushButton("Upload File")
        upload_button.clicked.connect(self.upload_file)
        layout.addWidget(upload_button)

        download_button = QPushButton("Download File")
        download_button.clicked.connect(self.download_file)
        layout.addWidget(download_button)

        delete_button = QPushButton("Delete File/Folder")
        delete_button.clicked.connect(self.delete_item)
        layout.addWidget(delete_button)

        share_button = QPushButton("Share File")
        share_button.clicked.connect(self.share_file)
        layout.addWidget(share_button)

        publish_key_button = QPushButton("Publish Signed Public Key")
        publish_key_button.clicked.connect(self.publish_signed_public_key)
        layout.addWidget(publish_key_button)

        self.setLayout(layout)

    def load_directory_structure(self):
        self.file_tree.clear()
        root_item = QTreeWidgetItem([self.username])
        self.file_tree.addTopLevelItem(root_item)

        for item in os.listdir(self.user_home):
            item_lower = item.lower()
            if not (item_lower.endswith(('.key', '.hash', '.sig', '.meta', '.pem', '.cert', '.crt', '.cer'))):
                item_path = os.path.join(self.user_home, item)
                item_widget = QTreeWidgetItem([item])
                root_item.addChild(item_widget)
                if os.path.isdir(item_path):
                    self.populate_tree(item_path, item_widget)

        shared_item = QTreeWidgetItem(["Shared Directory"])
        self.file_tree.addTopLevelItem(shared_item)
        self.populate_tree(self.shared_dir, shared_item)

    def populate_tree(self, directory, tree_item):
        for item in os.listdir(directory):
            item_lower = item.lower()
            if not (item_lower.endswith(('.key', '.hash', '.sig', '.meta', '.pem', '.cert', '.crt', '.cer'))):
                item_path = os.path.join(directory, item)
                item_widget = QTreeWidgetItem([item])
                tree_item.addChild(item_widget)
                if os.path.isdir(item_path):
                    self.populate_tree(item_path, item_widget)

    def upload_file(self):
        file_path, ok = QInputDialog.getText(self, "Upload File",
                                             "Enter the full path of the file to upload:")
        if not ok or not file_path:
            return
        if not os.path.isfile(file_path):
            QMessageBox.warning(self, "Error", "Invalid file path.")
            return

        file_name = os.path.basename(file_path)
        destination_path = os.path.join(self.user_home, file_name)

        signature = self.sign_file(file_path)
        if not signature:
            QMessageBox.warning(self, "Error", "Failed to create digital signature!")
            return

        encryption_algorithm = self.select_encryption_algorithm()
        key = self.derive_key_from_password(self.password)
        if encryption_algorithm == "TripleDES":
            key = key[:24]
            iv = os.urandom(8)
        else:
            iv = os.urandom(16)

        encrypted_file_path = destination_path + ".enc"
        self.encrypt_file(file_path, encrypted_file_path, key, iv, encryption_algorithm)

        with open(destination_path + ".meta", "wb") as meta_file:
            meta_file.write(f"Original path: {file_path}\n".encode())
            meta_file.write(f"EFS path: {destination_path}\n".encode())
            meta_file.write(f"Encryption algorithm: {encryption_algorithm}\n".encode())
            meta_file.write(f"IV: {iv.hex()}\n".encode())
            meta_file.write(b"-----BEGIN SIGNATURE-----\n")
            meta_file.write(base64.b64encode(signature) + b"\n")
            meta_file.write(b"-----END SIGNATURE-----\n")

        os.rename(encrypted_file_path, destination_path)

        self.log_audit("UPLOAD", f"Uploaded file: {file_name}")
        QMessageBox.information(self, "Success", "File uploaded successfully!")
        self.load_directory_structure()

    def encrypt_file(self, input_path, output_path, key, iv, algorithm):
        try:
            with open(input_path, "rb") as f:
                plaintext = f.read()

            if algorithm == "AES-256-CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            elif algorithm == "ChaCha20":
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext)
            elif algorithm == "TripleDES":
                from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
                cipher = Cipher(decrepit_algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(64).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            else:
                raise ValueError("Unsupported encryption algorithm")

            with open(output_path, "wb") as f:
                f.write(iv + ciphertext)
        except Exception as e:
            self.log_audit("ERROR", f"Encryption failed for {input_path}: {str(e)}")
            raise

    def publish_signed_public_key(self):
        # Ensure PUBLIC_KEYS_DIR exists and is writable
        try:
            os.makedirs(self.public_keys_dir, exist_ok=True)
            test_file = os.path.join(self.public_keys_dir, ".write_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            self.log_audit("ERROR", f"Failed to ensure {self.public_keys_dir} is writable: {str(e)}")
            raise RuntimeError(f"Cannot write to public keys directory: {str(e)}")

        # Check if signed public key and signature exist and are valid
        if os.path.exists(self.signed_public_key_path) and os.path.exists(self.signed_public_key_path + ".sig"):
            try:
                with open(self.signed_public_key_path, "rb") as f:
                    stored_public_key_pem = f.read()
                with open(self.signed_public_key_path + ".sig", "rb") as sig_file:
                    stored_signature = base64.b64decode(sig_file.read())

                # Load public key from stored PEM
                public_key = serialization.load_pem_public_key(
                    stored_public_key_pem,
                    backend=default_backend()
                )

                # Verify the signature
                public_key.verify(
                    stored_signature,
                    stored_public_key_pem,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                # Compare with user's public key
                with open(self.public_key_path, "rb") as f:
                    user_public_key_pem = f.read()
                if stored_public_key_pem == user_public_key_pem:
                    self.log_audit("KEY", f"Verified existing signed public key for {self.username}")
                    return  # No need to re-publish
                else:
                    self.log_audit("KEY", f"Stored public key does not match user's key for {self.username}")

            except Exception as e:
                self.log_audit("ERROR", f"Failed to verify existing signed public key for {self.username}: {str(e)}")
                # Remove invalid files and regenerate
                if os.path.exists(self.signed_public_key_path):
                    os.remove(self.signed_public_key_path)
                if os.path.exists(self.signed_public_key_path + ".sig"):
                    os.remove(self.signed_public_key_path + ".sig")

        # Generate key pair if missing
        if not os.path.exists(self.public_key_path) or not os.path.exists(self.private_key_path):
            self.log_audit("KEY", f"Regenerating key pair for {self.username}")
            self.generate_key_pair()

        # Publish the signed public key
        try:
            with open(self.public_key_path, "rb") as f:
                public_key_pem = f.read()

            signature = self.sign_file(self.public_key_path)
            if not signature:
                self.log_audit("ERROR", f"Failed to sign public key for {self.username}")
                raise RuntimeError("Failed to sign public key")

            with open(self.signed_public_key_path, "wb") as f:
                f.write(public_key_pem)
            with open(self.signed_public_key_path + ".sig", "wb") as sig_file:
                sig_file.write(base64.b64encode(signature))

            # Verify write operation
            if not os.path.exists(self.signed_public_key_path) or not os.path.exists(self.signed_public_key_path + ".sig"):
                self.log_audit("ERROR", f"Failed to write signed public key files for {self.username}")
                raise RuntimeError("Signed public key files not created")

            # Verify the newly written signature
            with open(self.signed_public_key_path, "rb") as f:
                stored_public_key_pem = f.read()
            with open(self.signed_public_key_path + ".sig", "rb") as sig_file:
                stored_signature = base64.b64decode(sig_file.read())
            public_key = serialization.load_pem_public_key(stored_public_key_pem, backend=default_backend())
            public_key.verify(
                stored_signature,
                stored_public_key_pem,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            self.log_audit("KEY", f"Published signed public key for {self.username}")
            QMessageBox.information(self, "Success", "Signed public key published successfully!")
        except Exception as e:
            self.log_audit("ERROR", f"Failed to publish signed public key for {self.username}: {str(e)}")
            raise

    def share_file(self):
        selected_item = self.file_tree.currentItem()
        if not selected_item or selected_item.text(0) in [self.username, "Shared Directory"]:
            QMessageBox.warning(self, "Error", "Please select a file to share.")
            return

        file_name = selected_item.text(0)
        source_path = os.path.join(self.user_home, file_name)

        if not os.path.isfile(source_path):
            QMessageBox.warning(self, "Error", "Invalid file selection.")
            return

        if not self.verify_file_integrity(source_path):
            QMessageBox.warning(self, "Error", "File integrity compromised. Cannot share file.")
            return

        # Ask for the recipient's username
        recipient, ok = QInputDialog.getText(self, "Share File", "Enter the recipient's username:")
        if not ok or not recipient:
            return

        recipient_public_key_path = os.path.join(self.public_keys_dir, f"public_key_{recipient}.pem")
        recipient_signature_path = recipient_public_key_path + ".sig"
        if not os.path.exists(recipient_public_key_path) or not os.path.exists(recipient_signature_path):
            QMessageBox.warning(self, "Error",
                                f"Recipient {recipient}'s signed public key not found in public keys directory.")
            return

        # Load and verify recipient's public key
        try:
            with open(recipient_public_key_path, "rb") as key_file:
                recipient_public_key_pem = key_file.read()
            with open(recipient_signature_path, "rb") as sig_file:
                recipient_signature = base64.b64decode(sig_file.read())

            recipient_public_key = serialization.load_pem_public_key(
                recipient_public_key_pem,
                backend=default_backend()
            )

            recipient_public_key.verify(
                recipient_signature,
                recipient_public_key_pem,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            self.log_audit("ERROR", f"Recipient {recipient}'s public key verification failed: {str(e)}")
            QMessageBox.warning(self, "Error", f"Recipient's public key signature verification failed: {str(e)}")
            return

        # Ensure sender's signed public key is published
        try:
            self.publish_signed_public_key()
        except Exception as e:
            self.log_audit("ERROR", f"Failed to publish sender's signed public key for {self.username}: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to publish sender's signed public key: {str(e)}")
            return

        # Verify sender's signed public key
        try:
            if not os.path.exists(self.signed_public_key_path) or not os.path.exists(self.signed_public_key_path + ".sig"):
                self.log_audit("ERROR", f"Sender's signed public key files missing for {self.username}")
                raise FileNotFoundError(f"Sender's signed public key not found at {self.signed_public_key_path}")
            with open(self.signed_public_key_path, "rb") as key_file:
                sender_public_key_pem = key_file.read()
            with open(self.signed_public_key_path + ".sig", "rb") as sig_file:
                sender_signature = base64.b64decode(sig_file.read())
            sender_public_key = serialization.load_pem_public_key(sender_public_key_pem, backend=default_backend())
            sender_public_key.verify(
                sender_signature,
                sender_public_key_pem,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            self.log_audit("ERROR", f"Sender's public key verification failed for {self.username}: {str(e)}")
            QMessageBox.warning(self, "Error", f"Sender's public key verification failed: {str(e)}")
            return

        # Proceed with file sharing
        try:
            with open(source_path + ".meta", "rb") as meta_file:
                meta_data = meta_file.readlines()
                algorithm = None
                iv_hex = None
                for line in meta_data:
                    if line.startswith(b"Encryption algorithm:"):
                        algorithm = line.split(b": ")[1].strip().decode()
                    elif line.startswith(b"IV:"):
                        iv_hex = line.split(b": ")[1].strip().decode()

            iv = bytes.fromhex(iv_hex)
            key = self.derive_key_from_password(self.password)
            if algorithm == "TripleDES":
                key = key[:24]

            temp_plaintext_path = source_path + ".temp"
            self.decrypt_file(source_path, temp_plaintext_path, key, iv, algorithm)

            symmetric_key = os.urandom(32)  # 256-bit key for AES
            iv = os.urandom(16)
            encrypted_file_path = source_path + ".shared.enc"
            self.encrypt_file(temp_plaintext_path, encrypted_file_path, symmetric_key, iv, "AES-256-CBC")

            encrypted_symmetric_key = recipient_public_key.encrypt(
                symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            signature = self.sign_file(encrypted_file_path)
            if not signature:
                os.remove(encrypted_file_path)
                os.remove(temp_plaintext_path)
                self.log_audit("ERROR", f"Failed to sign shared file {file_name} for {self.username}")
                raise RuntimeError("Failed to sign the shared file")

            # Replace dots in original filename to avoid parsing issues
            safe_file_name = file_name.replace('.', '_')
            destination_path = os.path.join(self.shared_dir, f"{safe_file_name}_{self.username}_to_{recipient}.enc")
            os.rename(encrypted_file_path, destination_path)

            with open(destination_path + ".meta", "wb") as meta_file:
                meta_file.write(f"Original file: {file_name}\n".encode())
                meta_file.write(f"Recipient: {recipient}\n".encode())
                meta_file.write(f"IV: {iv.hex()}\n".encode())
                meta_file.write(f"Encrypted symmetric key: {base64.b64encode(encrypted_symmetric_key).decode()}\n".encode())
                meta_file.write(b"-----BEGIN SIGNATURE-----\n")
                meta_file.write(base64.b64encode(signature) + b"\n")
                meta_file.write(b"-----END SIGNATURE-----\n")

            if os.path.exists(temp_plaintext_path):
                os.remove(temp_plaintext_path)

            self.log_audit("SHARE", f"Shared file: {file_name} with {recipient}")
            QMessageBox.information(self, "Success", "File shared successfully!")
            self.load_directory_structure()
        except Exception as e:
            self.log_audit("ERROR", f"Failed to share file {file_name} with {recipient}: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to share file: {str(e)}")
            if os.path.exists(temp_plaintext_path):
                os.remove(temp_plaintext_path)
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)

    def download_file(self):
        selected_item = self.file_tree.currentItem()
        if not selected_item or selected_item.text(0) in [self.username, "Shared Directory"]:
            QMessageBox.warning(self, "Error", "Please select a file to download.")
            return

        file_name = selected_item.text(0)
        encrypted_file_path = os.path.join(
            self.user_home if selected_item.parent().text(0) == self.username else self.shared_dir,
            file_name)

        if not os.path.isfile(encrypted_file_path):
            QMessageBox.warning(self, "Error", "Invalid file selection.")
            return

        # Check if it's a shared file
        is_shared = selected_item.parent().text(0) == "Shared Directory"
        if is_shared:
            meta_file = encrypted_file_path + ".meta"
            if not os.path.exists(meta_file):
                QMessageBox.warning(self, "Error", "Metadata missing for shared file.")
                return

            try:
                with open(meta_file, "rb") as f:
                    lines = f.readlines()
                    recipient = None
                    iv_hex = None
                    encrypted_key_b64 = None
                    signature = None
                    in_signature = False
                    signature_lines = []

                    for line in lines:
                        if line.startswith(b"Recipient:"):
                            recipient = line.split(b": ")[1].strip().decode()
                        elif line.startswith(b"IV:"):
                            iv_hex = line.split(b": ")[1].strip().decode()
                        elif line.startswith(b"Encrypted symmetric key:"):
                            encrypted_key_b64 = line.split(b": ")[1].strip().decode()
                        elif line.startswith(b"-----BEGIN SIGNATURE-----"):
                            in_signature = True
                        elif line.startswith(b"-----END SIGNATURE-----"):
                            in_signature = False
                        elif in_signature:
                            signature_lines.append(line.strip())

                    signature = base64.b64decode(b"".join(signature_lines)) if signature_lines else None

                if recipient != self.username:
                    self.log_audit("ERROR", f"User {self.username} is not the intended recipient of {file_name}")
                    QMessageBox.warning(self, "Error", "You are not the intended recipient of this file.")
                    return

                # Extract sender from filename
                try:
                    # Split by '_to_' to separate <original>_<sender> from <recipient>.enc
                    parts = file_name.rsplit('_to_', 1)
                    if len(parts) != 2:
                        raise ValueError(f"Invalid shared file name format: {file_name}")
                    recipient_part = parts[1]  # Should be <recipient>.enc
                    original_and_sender = parts[0]  # Should be <original>_<sender>
                    # Split original_and_sender from the right to get sender
                    sender_parts = original_and_sender.rsplit('_', 1)
                    if len(sender_parts) < 2:
                        raise ValueError(f"Cannot extract sender from {original_and_sender}")
                    sender = sender_parts[-1]
                    self.log_audit("DEBUG", f"Parsed file {file_name}: sender={sender}, recipient={recipient_part}")
                except Exception as e:
                    self.log_audit("ERROR", f"Failed to parse sender from filename {file_name}: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Invalid shared file name format: {str(e)}")
                    return

                sender_public_key_path = os.path.join(self.public_keys_dir, f"public_key_{sender}.pem")
                sender_signature_path = sender_public_key_path + ".sig"
                if not os.path.exists(sender_public_key_path):
                    self.log_audit("ERROR", f"Sender's public key not found at {sender_public_key_path}")
                    QMessageBox.warning(self, "Error", f"Sender's public key not found at {sender_public_key_path}")
                    return
                if not os.path.exists(sender_signature_path):
                    self.log_audit("ERROR", f"Sender's signature not found at {sender_signature_path}")
                    QMessageBox.warning(self, "Error", f"Sender's signature not found at {sender_signature_path}")
                    return

                with open(sender_public_key_path, "rb") as key_file:
                    sender_public_key_pem = key_file.read()
                with open(sender_signature_path, "rb") as sig_file:
                    sender_signature = base64.b64decode(sig_file.read())

                sender_public_key = serialization.load_pem_public_key(
                    sender_public_key_pem,
                    backend=default_backend()
                )

                try:
                    sender_public_key.verify(
                        sender_signature,
                        sender_public_key_pem,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception as e:
                    self.log_audit("ERROR", f"Sender's public key verification failed for {sender}: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Sender's public key signature verification failed: {str(e)}")
                    return

                with open(encrypted_file_path, "rb") as f:
                    file_data = f.read()

                try:
                    sender_public_key.verify(
                        signature,
                        file_data,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception as e:
                    self.log_audit("ERROR", f"File signature verification failed for {file_name}: {str(e)}")
                    QMessageBox.warning(self, "Error", f"File signature verification failed: {str(e)}")
                    return

                # Decrypt symmetric key with private key
                with open(self.private_key_path, "rb") as key_file:
                    encrypted_data = key_file.read()
                salt = encrypted_data[:16]
                iv_key = encrypted_data[16:32]
                encrypted_key = encrypted_data[32:]
                key = self.derive_key_from_password(self.password)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv_key), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_key) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                private_key_pem = unpadder.update(decrypted_data) + unpadder.finalize()
                private_key = serialization.load_pem_private_key(private_key_pem, password=None,
                                                                backend=default_backend())

                symmetric_key = private_key.decrypt(
                    base64.b64decode(encrypted_key_b64),
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                iv = bytes.fromhex(iv_hex)
                # Use original filename from metadata
                with open(meta_file, "rb") as f:
                    for line in f:
                        if line.startswith(b"Original file:"):
                            original_file_name = line.split(b": ")[1].strip().decode()
                            break
                    else:
                        original_file_name = file_name.split('_to_')[0]
                dest_path, _ = QFileDialog.getSaveFileName(self, "Save File", original_file_name)
                if not dest_path:
                    return

                self.decrypt_file(encrypted_file_path, dest_path, symmetric_key, iv, "AES-256-CBC")
            except Exception as e:
                self.log_audit("ERROR", f"Failed to download shared file {file_name}: {str(e)}")
                QMessageBox.warning(self, "Error", f"Failed to download shared file: {str(e)}")
                return
        else:
            try:
                if not self.verify_file_integrity(encrypted_file_path):
                    self.log_audit("ERROR", f"File integrity compromised for {file_name}")
                    QMessageBox.warning(self, "Error", "File integrity compromised. Cannot download.")
                    return

                dest_path, _ = QFileDialog.getSaveFileName(self, "Save File", file_name)
                if not dest_path:
                    return

                with open(encrypted_file_path + ".meta", "rb") as meta_file:
                    meta_data = meta_file.readlines()
                    algorithm = None
                    iv_hex = None
                    for line in meta_data:
                        if line.startswith(b"Encryption algorithm:"):
                            algorithm = line.split(b": ")[1].strip().decode()
                        elif line.startswith(b"IV:"):
                            iv_hex = line.split(b": ")[1].strip().decode()

                    iv = bytes.fromhex(iv_hex)
                key = self.derive_key_from_password(self.password)
                if algorithm == "TripleDES":
                    key = key[:24]
                self.decrypt_file(encrypted_file_path, dest_path, key, iv, algorithm)
            except Exception as e:
                self.log_audit("ERROR", f"Failed to download file {file_name}: {str(e)}")
                QMessageBox.warning(self, "Error", f"Failed to download file: {str(e)}")
                return

        self.log_audit("DOWNLOAD", f"Downloaded file: {file_name}")
        QMessageBox.information(self, "Success", "File downloaded successfully!")
        self.load_directory_structure()

    def decrypt_file(self, input_path, output_path, key, iv, algorithm):
        try:
            with open(input_path, "rb") as f:
                ciphertext = f.read()[len(iv):]

            if algorithm == "AES-256-CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
            elif algorithm == "ChaCha20":
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                unpadded_data = decryptor.update(ciphertext)
            elif algorithm == "TripleDES":
                from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
                cipher = Cipher(decrepit_algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(64).unpadder()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
            else:
                raise ValueError("Unsupported encryption algorithm")

            with open(output_path, "wb") as f:
                f.write(unpadded_data)
        except Exception as e:
            self.log_audit("ERROR", f"Decryption failed for {input_path}: {str(e)}")
            raise

    def verify_file_integrity(self, file_path):
        meta_file = file_path + ".meta"
        if not os.path.isfile(meta_file):
            self.log_audit("ERROR", f"Metadata file missing for {file_path}")
            return False

        try:
            with open(meta_file, "rb") as f:
                lines = f.readlines()
                signature = None
                in_signature = False
                signature_lines = []

                for line in lines:
                    if line.startswith(b"-----BEGIN SIGNATURE-----"):
                        in_signature = True
                    elif line.startswith(b"-----END SIGNATURE-----"):
                        in_signature = False
                    elif in_signature:
                        signature_lines.append(line.strip())

                if signature_lines:
                    signature = base64.b64decode(b"".join(signature_lines))

                if not signature:
                    self.log_audit("ERROR", f"No signature found in metadata for {file_path}")
                    return False

            encryption_algorithm = None
            iv_hex = None
            for line in lines:
                if line.startswith(b"Encryption algorithm:"):
                    encryption_algorithm = line.split(b": ")[1].strip().decode()
                elif line.startswith(b"IV:"):
                    iv_hex = line.split(b": ")[1].strip().decode()

            if not encryption_algorithm or not iv_hex:
                self.log_audit("ERROR", f"Missing encryption algorithm or IV in metadata for {file_path}")
                return False

            iv = bytes.fromhex(iv_hex)
            key = self.derive_key_from_password(self.password)
            if encryption_algorithm == "TripleDES":
                key = key[:24]

            temp_file = file_path + ".temp"
            self.decrypt_file(file_path, temp_file, key, iv, encryption_algorithm)

            verification_result = self.verify_signature(temp_file, signature)

            if os.path.exists(temp_file):
                os.remove(temp_file)

            return verification_result
        except Exception as e:
            self.log_audit("ERROR", f"Integrity verification failed for {file_path}: {str(e)}")
            return False

    def verify_signature(self, file_path, signature):
        public_key_path = os.path.join(self.public_keys_dir, f"public_key_{self.username}.pem")
        signature_path = public_key_path + ".sig"

        if not os.path.exists(public_key_path) or not os.path.exists(signature_path):
            self.log_audit("ERROR", f"Signed public key or signature not found at {public_key_path}")
            raise FileNotFoundError(f"Signed public key not found at {public_key_path}")

        try:
            with open(public_key_path, "rb") as key_file:
                public_key_pem = key_file.read()
            with open(signature_path, "rb") as sig_file:
                public_key_signature = base64.b64decode(sig_file.read())

            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )

            public_key.verify(
                public_key_signature,
                public_key_pem,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            with open(file_path, "rb") as f:
                file_data = f.read()

            public_key.verify(
                signature,
                file_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            self.log_audit("ERROR", f"Signature verification failed for {file_path}: {str(e)}")
            return False

    def delete_item(self):
        selected_item = self.file_tree.currentItem()
        if not selected_item or selected_item.text(0) in [self.username, "Shared Directory"]:
            QMessageBox.warning(self, "Error", "Please select a file or folder to delete.")
            return

        item_name = selected_item.text(0)
        item_path = os.path.join(
            self.user_home if selected_item.parent().text(0) == self.username else self.shared_dir,
            item_name
        )

        reply = QMessageBox.question(
            self, 'Confirm Delete',
            f"Are you sure you want to delete '{item_name}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.No:
            return

        try:
            if os.path.isdir(item_path):
                for root, dirs, files in os.walk(item_path, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(item_path)
            else:
                files_to_delete = [item_path]
                extensions = ['.hash', '.meta', '.sig', '.key']
                for ext in extensions:
                    if os.path.exists(item_path + ext):
                        files_to_delete.append(item_path + ext)

                for file_to_delete in files_to_delete:
                    if os.path.exists(file_to_delete):
                        os.remove(file_to_delete)

            self.log_audit("DELETE", f"Deleted: {item_name}")
            QMessageBox.information(self, "Success", "Item deleted successfully!")
            self.load_directory_structure()
        except Exception as e:
            self.log_audit("ERROR", f"Failed to delete item {item_name}: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to delete item: {str(e)}")

    def calculate_file_hash(self, file_path):
        hash_algorithm = self.select_hashing_algorithm()
        hasher = hashlib.new(hash_algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return f"{hash_algorithm}:{hasher.hexdigest()}"

    def derive_key_from_password(self, password):
        try:
            with open(self.private_key_path, "rb") as key_file:
                salt = key_file.read(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(password if isinstance(password, bytes) else password.encode())
        except Exception as e:
            self.log_audit("ERROR", f"Failed to derive key for {self.username}: {str(e)}")
            raise

    def sign_file(self, file_path):
        if not os.path.exists(self.private_key_path):
            self.log_audit("ERROR", f"Private key not found for {self.username} at {self.private_key_path}")
            QMessageBox.warning(self, "Error", "Private key not found. Please contact administrator.")
            raise FileNotFoundError("Private key not found")

        try:
            with open(self.private_key_path, "rb") as key_file:
                encrypted_data = key_file.read()

            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            encrypted_key = encrypted_data[32:]

            key = self.derive_key_from_password(self.password)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_key) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            private_key_pem = unpadder.update(decrypted_data) + unpadder.finalize()

            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )

            with open(file_path, "rb") as f:
                file_data = f.read()

            signature = private_key.sign(
                file_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.log_audit("SIGN", f"Signed file {file_path} for {self.username}")
            return signature
        except Exception as e:
            self.log_audit("ERROR", f"Failed to sign file {file_path} for {self.username}: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to sign file: {str(e)}")
            return None

    def log_audit(self, action, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] User: {self.username}, Action: {action}, Details: {details}\n"
        try:
            with open(AUDIT_LOG_FILE, "a") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write to audit log: {str(e)}")

    def select_encryption_algorithm(self):
        import random
        algorithms = ["AES-256-CBC", "ChaCha20", "TripleDES"]
        return random.choice(algorithms)

    def select_hashing_algorithm(self):
        import random
        algorithms = ["sha256", "sha3_256", "blake2b"]
        return random.choice(algorithms)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureFileSystem("testuser", "testpassword")
    window.show()
    sys.exit(app.exec_())