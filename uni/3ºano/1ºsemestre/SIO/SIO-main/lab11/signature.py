import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

lib = 'libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
slot = slots[0]

# Open a session
session = pkcs11.openSession(slot)

# Find the private key for CITIZEN AUTHENTICATION
private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                   (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

# Sign the text
text_to_sign = b'text to sign'
mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
signature = bytes(session.sign(private_key, text_to_sign, mechanism))

# Save the digital signature to a file
signature_file_path = 'digital_signature.bin'
with open(signature_file_path, 'wb') as signature_file:
    signature_file.write(signature)
print(f"Digital signature saved to: {signature_file_path}")

# Retrieve and save the public key certificate
certificate_objects = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                                           (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])

# Get the first certificate
certificate = x509.load_der_x509_certificate(bytes(session.getAttributeValue(certificate_objects[0], [PyKCS11.CKA_VALUE])[0]),
                                              default_backend())

# Save the public key certificate to a file
certificate_file_path = 'public_key_certificate.pem'
with open(certificate_file_path, 'wb') as certificate_file:
    certificate_file.write(certificate.public_bytes(serialization.Encoding.PEM))
print(f"Public key certificate saved to: {certificate_file_path}")

# Close the session
session.closeSession()
