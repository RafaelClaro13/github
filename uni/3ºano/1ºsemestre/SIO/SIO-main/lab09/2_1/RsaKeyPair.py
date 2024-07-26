from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair(key_length):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_length,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key

def save_key_to_file(key, filename, key_type):
    with open(filename, 'wb') as key_file:
        if key_type == 'private':
            key_file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        elif key_type == 'public':
            key_file.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        else:
            raise ValueError("Invalid key type. Use 'private' or 'public'.")

def main():
    key_length = int(input("Enter the key length (1024, 2048, 3072, or 4096): "))
    private_key_filename = input("Enter the private key filename (e.g., private_key.pem): ")
    public_key_filename = input("Enter the public key filename (e.g., public_key.pem): ")

    private_key, public_key = generate_rsa_key_pair(key_length)

    save_key_to_file(private_key, private_key_filename, 'private')
    save_key_to_file(public_key, public_key_filename, 'public')

    print("RSA key pair generated and saved successfully.")

if __name__ == "__main__":
    main()
