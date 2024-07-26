from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def read_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def write_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)

def encrypt_file(original_filename, public_key_filename, encrypted_filename):
    original_data = read_file(original_filename)

    # Load public key
    with open(public_key_filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Determine block size based on key size
    key_size = public_key.key_size // 8
    block_size = key_size - 11

    # Perform encryption in blocks
    encrypted_blocks = []
    for i in range(0, len(original_data), block_size):
        block = original_data[i:i + block_size]
        encrypted_block = public_key.encrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_blocks.append(encrypted_block)

    # Concatenate encrypted blocks
    encrypted_data = b''.join(encrypted_blocks)

    # Save the encrypted data to a file
    write_file(encrypted_filename, encrypted_data)

    print(f"File '{original_filename}' encrypted successfully and saved as '{encrypted_filename}'.")

if __name__ == "__main__":
    original_filename = input("Enter the name of the original file to encrypt: ")
    public_key_filename = input("Enter the name of the file with the public key: ")
    encrypted_filename = input("Enter the name for the encrypted file: ")

    encrypt_file(original_filename, public_key_filename, encrypted_filename)