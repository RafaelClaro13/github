# Requirements
```
pip install pycryptodome
```

# How to run

# 1.1
```
python3 AES.py
```

# 1.2
```
python3 PKCS7.py
```

# 1.3
```
python3 PBKDF2.py
```

# 1.4
```
python3 FileEncryption.py
```

- **Questions:**
    - #1 Can you determine the structure of the text from the cryptogram?
        - No, the structure of the original text cannot be determined from the encrypted ciphertext. Modern encryption algorithms are designed to be secure and provide confidentiality. The encrypted data should appear random and indistinguishable from random noise.

    - #2 Can you compare the lengths of the text and the cryptogram? 
        - In general, the length of the ciphertext (cryptogram) will be longer than the original plaintext due to the padding added during encryption. The exact increase in length depends on the encryption algorithm and mode used. For example, in AES with block cipher modes like ECB or CBC, the ciphertext length is a multiple of the block size (16 bytes for AES).

# 1.5
```
python3 FileDecryption.py
```
- **Questions:**
    - #1 Is padding visible in the decrypted text?
        - No, the padding is automatically removed during the decryption process. The unpad function is used to remove the padding, and it ensures that only the original data is returned.

    - #2 What happens if the cryptogram is truncated?
        - If the cryptogram is truncated, the decryption process will fail, and an error will occur. This is because the ciphertext must be intact for successful decryption.
    
    - #3 What happens if the cryptogram lacks some bytes in the beginning?
        - If the cryptogram lacks some bytes in the beginning, the decryption process will likely produce incorrect results or fail. The integrity of the ciphertext is crucial for proper decryption, and any modification or loss of data may result in decryption errors.