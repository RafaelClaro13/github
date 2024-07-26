# Requirements
```
pip install pycryptodome
```

# How to run

```
python3 RsaKeyPair.py
```

- **Questions:**
    - 2.1
        - #1 What do you think of using 4096 bit keys by default in relation to speed?
            - Using 4096-bit keys provides a higher level of security compared to smaller key sizes like 1024 or 2048 bits. The larger the key size, the more computationally difficult it becomes for an attacker to perform a brute-force attack and factorize the key. However, larger key sizes come at a cost in terms of computational resources. Key generation, encryption, and decryption operations with larger keys generally take more time and computational power. The specific impact on speed depends on the application and the acceptable trade-off between security and performance. In the context of the provided code, allowing the user to specify the key length is a good approach. Users can choose a key size based on their security requirements and the performance characteristics of their system.

        - #2 How does the actual key size vary with the number of bits?
            - The key size specified in the code refers to the modulus size of the RSA key pair. The actual key size in bits is the size of the modulus. The modulus size is the most critical factor in determining the security strength of the RSA algorithm.

            - For example:

                - For a key length of 1024, the modulus size is 1024 bits.
                - For a key length of 2048, the modulus size is 2048 bits.
                - And so on.

            - The formula for the actual key size (in bits) is generally:

                - Actual Key Size=Modulus Size=Key LengthActual Key Size=Modulus Size=Key Length

            - So, the key size directly corresponds to the security strength of the RSA key pair. Larger key sizes provide more security but may require more computational resources for key generation, encryption, and decryption.

    - 2.4.2 
        - #1 What combination of encryption technologies allow to efficiently send the file to the recipient, with the guarantee that only that person can decrypt the file?
            - The combination of encryption technologies that allows for efficient sending of a file to the recipient, with the guarantee that only that person can decrypt the file, is called Hybrid Encryption. This method combines two ciphers: a symmetric cipher (like AES128) to encrypt the file with a random key, and an asymmetric cipher (like RSA) to encrypt the key used in the previous step 4.


        - #2 With this method, what is sent to the destination?
            - Only the encrypted file (Hybrid_encrypted_file) is sent to the destination.

        - #3 Should we always send the public key?
            - No, the public key only needs to be sent once to the recipient. Afterward, the recipient can use their private key to decrypt files encrypted with the corresponding public key.
