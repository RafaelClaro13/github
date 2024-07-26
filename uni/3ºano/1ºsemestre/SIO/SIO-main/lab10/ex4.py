from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def build_certification_path(user_certificate, intermediate_roots, trusted_roots):
    certification_path = [user_certificate]

    current_cert = user_certificate
    while not is_self_signed(current_cert):
        issuer_subject = get_issuer_subject(current_cert)

        # Check if the issuer is in the user-specified intermediate roots
        if issuer_subject in intermediate_roots:
            issuer_certificate = x509.load_pem_x509_certificate(
                intermediate_roots[issuer_subject], default_backend())
            certification_path.append(issuer_certificate)
            current_cert = issuer_certificate
        # Check if the issuer is in the trusted roots
        elif issuer_subject in trusted_roots:
            issuer_certificate = x509.load_pem_x509_certificate(
                trusted_roots[issuer_subject], default_backend())
            certification_path.append(issuer_certificate)
            current_cert = issuer_certificate
        else:
            # The issuer is not found, and the chain cannot be completed
            print("Error: The issuer certificate is not found in intermediate or trusted roots.")
            return None

    return certification_path

def is_self_signed(cert):
    return cert.subject == cert.issuer

def get_issuer_subject(cert):
    return "/".join([f"{name.oid}={name.value}" for name in cert.issuer])

if __name__ == "__main__":
    # Replace 'user_certificate.pem' with the actual path to the user-provided certificate
    user_certificate_path = 'user_certificate.pem'

    # Replace 'intermediate_roots' and 'trusted_roots' with your dictionaries of intermediate and trusted root certificates
    intermediate_roots = {}
    trusted_roots = {}

    user_certificate_data = open(user_certificate_path, 'rb').read()
    user_certificate = x509.load_pem_x509_certificate(user_certificate_data, default_backend())

    certification_path = build_certification_path(user_certificate, intermediate_roots, trusted_roots)

    if certification_path:
        print("Certification Path:")
        for cert in certification_path:
            print(f"Subject: {get_issuer_subject(cert)}")
            print(f"Issuer: {get_issuer_subject(cert)}")
            print("-----")
