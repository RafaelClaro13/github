from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import getpass
import base64

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

def encrypt_file(input_file, output_file, password, mode='ECB'):
    # Generate a random salt (should be stored securely if you need to regenerate the key/IV)
    salt = get_random_bytes(16)

    # Generate key and IV using PBKDF2
    key, iv = generate_key_iv_from_password(password, salt)

    # Initialize the AES cipher based on the chosen mode
    if mode.upper() == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode.upper() == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Invalid mode. Supported modes: ECB, CBC")

    # Read the contents of the input file
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    # Encrypt the contents
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Save salt and encrypted data to the output file
    with open(output_file, 'wb') as file:
        file.write(base64.b64encode(salt) + b'\n')
        file.write(base64.b64encode(ciphertext))


# Example usage:
input_file_name = input("Enter the name of the file to encrypt: ")
output_file_name = input("Enter the name of the file to store the cryptogram: ")
encryption_mode = input("Enter the mode of the encryption algorithm (ECB or CBC): ")
password = getpass.getpass("Enter your password: ")

encrypt_file(input_file_name, output_file_name, password, encryption_mode)
