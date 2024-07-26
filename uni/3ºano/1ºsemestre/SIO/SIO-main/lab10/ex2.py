import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def load_certificates(directory):
    certificates = {}
    for entry in os.scandir(directory):
        if entry.is_file() and entry.name.endswith('.pem'):
            cert_path = entry.path
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                
                # Verify certificate validity
                current_time = datetime.utcnow()
                not_valid_before = cert.not_valid_before
                not_valid_after = cert.not_valid_after
                
                if not_valid_before <= current_time <= not_valid_after:
                    print(f"Certificate {entry.name} is valid.")
                else:
                    print(f"Certificate {entry.name} is not valid.")
                
                # Extract and store subject information
                subject_dict = dict((name.oid, name.value) for name in cert.subject)
                subject_str = "/".join([f"{oid}={value}" for oid, value in subject_dict.items()])
                certificates[subject_str] = cert_data

    return certificates

if __name__ == "__main__":
    # Replace 'your_certificate_directory' with the actual path to your directory containing certificates
    certificate_directory = "/etc/ssl/certs"

    loaded_certificates = load_certificates(certificate_directory)
    # You now have a dictionary containing certificates and their subjects

