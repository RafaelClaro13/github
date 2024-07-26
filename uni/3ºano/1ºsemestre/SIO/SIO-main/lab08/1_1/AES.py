from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def aes_encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

def aes_decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return decrypted_text.decode('utf-8')

def aes_encrypt_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

def aes_decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return decrypted_text.decode('utf-8')

# Example usage:
key = get_random_bytes(16)  # 16-byte key
iv = get_random_bytes(16)   # 16-byte initialization vector

plaintext = "Hello, Miragaia!"
print("Original text:", plaintext)

# ECB Mode
encrypted_ecb = aes_encrypt_ecb(plaintext.encode('utf-8'), key)
decrypted_ecb = aes_decrypt_ecb(encrypted_ecb, key)
print("\nECB Mode:")
print("Encrypted text:", encrypted_ecb)
print("Decrypted text:", decrypted_ecb)

# CBC Mode
encrypted_cbc = aes_encrypt_cbc(plaintext.encode('utf-8'), key, iv)
decrypted_cbc = aes_decrypt_cbc(encrypted_cbc, key, iv)
print("\nCBC Mode:")
print("Encrypted text:", encrypted_cbc)
print("Decrypted text:", decrypted_cbc)
