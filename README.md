# 🔐 Encrypted File System (EFS)
This application is a secure authentication and file-management system built using digital certificates, encryption, and access-control mechanisms.
The project is developed in Python, using the PyQt5 GUI framework and the cryptography library.
The system includes a complete PKI infrastructure with certificate generation, validation, and revocation.
# ⚙️ Features
## 🧾 Registration (register.py)
- Creates a new user and stores data in users.txt
- Generates a public/private key pair and a digital certificate
- Encrypts the private key using AES symmetric encryption
- Hashes the password using multiple hash functions (SHA-256, SHA-512, BLAKE2b)
## 🔑 Login (login.py)
### Authenticates a user based on:
- username
- password (hash verification)
- path to their digital certificate
### Performs validation checks:
- certificate validity (expiration date)
- certificate revocation status (CRL check)
- successful decryption of the private key
### Logs all actions to audit_log.txt
## 🗂️ Secure File System (secureFileSystem.py)
Allows file operations after a successful login:
- reading, writing, and deleting files
- secure encryption and decryption of file contents
  
All data is accessible only to the authenticated user

## 💾 Database Layer (database.py)
Handles reading and writing of user data from users.txt
Designed to be easily extendable to a future SQLite implementation

## 🧠 Security Mechanisms

| Mechanism	 | Description |
|------------|------|
| **Password Hashing** | 	Passwords are stored as hashes using SHA-256, SHA-512, and BLAKE2b
| **AES Encryption** |	Private keys are encrypted using AES (CBC mode)
| **Digital Certificates** |	User authentication is based on X.509 certificates
| **CRL (Certificate Revocation List)** |	Revoked certificates are stored in the crl/ directory
| **Audit Logging** |	All actions (login attempts, errors, successful operations) are recorded in audit_log.txt
| **PKI Infrastructure** |	Includes certificate creation, signing, validation, and revocation using a custom Certification Authority (CA)




