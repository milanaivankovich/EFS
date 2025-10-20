import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

USERS_FILE = "users.txt"


# Hesiranje lozinke
def hash_password(password):
    salt = os.urandom(16)  # Generisanje slučajnog salta
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    password_hash = kdf.derive(password.encode())
    return base64.b64encode(salt + password_hash).decode()  # Kodiranje u base64 radi lakšeg čuvanja


# Provjera lozinke
def verify_password(stored_password, provided_password):
    decoded_data = base64.b64decode(stored_password.encode())
    salt = decoded_data[:16]
    stored_hash = decoded_data[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(provided_password.encode(), stored_hash)
        return True
    except Exception:
        return False


# Registracija korisnika
def register_user(username, password, cert_path):
    password_hash = hash_password(password)
    with open(USERS_FILE, "a") as file:
        file.write(f"{username}|{password_hash}|{cert_path}\n")
    print("Registracija uspješna!")


# Prijava korisnika
def login_user(username, password, cert_path):
    if not os.path.exists(USERS_FILE):
        print("Nema registrovanih korisnika.")
        return False

    with open(USERS_FILE, "r") as file:
        for line in file:
            stored_username, stored_password, stored_cert_path = line.strip().split("|")
            if stored_username == username and verify_password(stored_password,
                                                               password) and stored_cert_path == cert_path:
                print("Prijava uspješna!")
                return True
    print("Neispravni podaci za prijavu.")
    return False


# Testiranje registra i prijave
if __name__ == "__main__":
    print("\nTestiranje registra i prijave:")
    register_user("test_user", "secure_password", "/path/to/certificate.pem")
    login_successful = login_user("test_user", "secure_password", "/path/to/certificate.pem")
    print("Prijava status:", login_successful)
