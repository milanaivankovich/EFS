from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
import base64
import os

# Paths
encrypted_file_path = "users/shared/racuni.txt_masa3_to_lola5.enc"
meta_file_path = encrypted_file_path + ".meta"
private_key_path = "users/lola5/private_key_lola5.pem"
output_path = "decrypted_test.txt"

# Read meta data
with open(meta_file_path, "rb") as f:
    lines = f.readlines()
    iv_hex = [l.split(b": ")[1].strip().decode() for l in lines if l.startswith(b"IV:")][0]
    encrypted_key_b64 = [l.split(b": ")[1].strip().decode() for l in lines if l.startswith(b"Encrypted symmetric key:")][0]

iv = bytes.fromhex(iv_hex)
encrypted_symmetric_key = base64.b64decode(encrypted_key_b64)
print(f"IV: {iv.hex()}")
print(f"Encrypted symmetric key length: {len(encrypted_symmetric_key)}")

# Load and decrypt private key
with open(private_key_path, "rb") as f:
    data = f.read()
salt = data[:16]
iv_key = data[16:32]
encrypted_key = data[32:]
print(f"Private key file size: {len(data)} bytes")
print(f"Salt: {salt.hex()}")
print(f"IV for private key: {iv_key.hex()}")

password = b"testpassword"  # Replace with the correct password if different
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
key = kdf.derive(password)
print(f"Derived key: {key.hex()}")

cipher = Cipher(algorithms.AES(key), modes.CBC(iv_key), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_data = decryptor.update(encrypted_key) + decryptor.finalize()
print(f"Decrypted data length: {len(decrypted_data)}")
print(f"Decrypted data (hex): {decrypted_data.hex()}")

unpadder = padding.PKCS7(128).unpadder()
try:
    private_key_pem = unpadder.update(decrypted_data) + unpadder.finalize()
    print("Private key decrypted successfully")
except ValueError as e:
    print(f"Unpadding error: {e}")
    print(f"Last 16 bytes (padding?): {decrypted_data[-16:].hex()}")
    exit(1)

private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

# Decrypt symmetric key
symmetric_key = private_key.decrypt(
    encrypted_symmetric_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print(f"Symmetric key: {symmetric_key.hex()}")

# Decrypt file
with open(encrypted_file_path, "rb") as f:
    ciphertext = f.read()[16:]  # Skip IV prepended to file
cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(plaintext) + unpadder.finalize()

with open(output_path, "wb") as f:
    f.write(decrypted_data)

print("Decryption complete. Check", output_path)