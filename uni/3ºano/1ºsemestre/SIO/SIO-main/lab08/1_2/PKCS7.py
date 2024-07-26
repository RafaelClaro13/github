from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def add_padding(plaintext, block_size):
    pad_length = block_size - (len(plaintext) % block_size)
    padded_text = plaintext + bytes([pad_length] * pad_length)
    return padded_text

def remove_padding(padded_text):
    pad_length = padded_text[-1]
    if pad_length < 1 or pad_length > len(padded_text):
        raise ValueError("Invalid padding")
    return padded_text[:-pad_length]

def aes_encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(add_padding(plaintext, AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

def aes_decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = remove_padding(cipher.decrypt(b64decode(ciphertext)))
    return decrypted_text.decode('utf-8')

def aes_encrypt_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(add_padding(plaintext, AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

def aes_decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = remove_padding(cipher.decrypt(b64decode(ciphertext)))
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
