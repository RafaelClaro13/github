import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

def verify_signature(signature_path, certificate_path, content_path):
    # Load the digital signature
    with open(signature_path, 'rb') as signature_file:
        signature = signature_file.read()

    # Load the public key certificate
    with open(certificate_path, 'rb') as certificate_file:
        certificate_data = certificate_file.read()
        certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
        public_key = certificate.public_key()

    # Load the signed contents
    with open(content_path, 'rb') as content_file:
        content = content_file.read()

    # Verify the signature
    try:
        public_key.verify(
            signature,
            content,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        print("Signature is valid.")
        print("Signer's identity (subject):", certificate.subject)
    except Exception as e:
        print("Signature verification failed:", e)

# Example usage:
signature_file_path = 'digital_signature.bin'
certificate_file_path = 'public_key_certificate.pem'
signed_content_file_path = 'signed_content.txt'

verify_signature(signature_file_path, certificate_file_path, signed_content_file_path)
