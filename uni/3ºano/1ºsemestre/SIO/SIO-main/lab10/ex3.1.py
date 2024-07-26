import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def load_system_trusted_certificates(directory):
    trusted_certificates = {}
    for entry in os.scandir(directory):
        if entry.is_file() and entry.name.endswith('.pem'):
            cert_path = entry.path
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                # Check if the certificate is still valid
                current_time = datetime.utcnow()
                not_valid_before = cert.not_valid_before
                not_valid_after = cert.not_valid_after

                if not_valid_before <= current_time <= not_valid_after:
                    subject_dict = dict((name.oid, name.value) for name in cert.subject)
                    subject_str = "/".join([f"{oid}={value}" for oid, value in subject_dict.items()])
                    trusted_certificates[subject_str] = cert_data

    return trusted_certificates

if __name__ == "__main__":
    # Replace '/etc/ssl/certs' with the actual path to the directory containing system-trusted certificates
    system_trusted_directory = '/etc/ssl/certs'

    trusted_certificates = load_system_trusted_certificates(system_trusted_directory)
    print(trusted_certificates)
    # You now have a dictionary containing trusted certificates and their subjects
