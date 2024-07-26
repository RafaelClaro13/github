from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import getpass

def generate_key_iv_from_password(password, salt, iterations=10000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=iterations,
        length=32,  # 32 bytes for a 256-bit key
        backend=default_backend()
    )
    key_iv = kdf.derive(password.encode('utf-8'))
    key = key_iv[:16]  # 16 bytes for the key
    iv = key_iv[16:]   # 16 bytes for the IV
    return key, iv

def aes_encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

def aes_decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return decrypted_text.decode('utf-8')

# Get password from user (using getpass for secure input)
password = getpass.getpass("Enter your password: ")

# Generate a random salt (should be stored securely if you need to regenerate the key/IV)
salt = get_random_bytes(16)

# Generate key and IV using PBKDF2
key, iv = generate_key_iv_from_password(password, salt)

# Example usage with ECB Mode
plaintext = "Hello, Miragaia!"
print("Original text:", plaintext)

# ECB Mode
encrypted_ecb = aes_encrypt_ecb(plaintext.encode('utf-8'), key)
decrypted_ecb = aes_decrypt_ecb(encrypted_ecb, key)
print("\nECB Mode:")
print("Encrypted text:", encrypted_ecb)
print("Decrypted text:", decrypted_ecb)
