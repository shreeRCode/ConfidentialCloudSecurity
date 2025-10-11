#Sample AES Implementation

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate a 128-bit key
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)

# Generate a 12-byte IV (Nonce)
nonce = os.urandom(12)

# Data to encrypt
plaintext = b"Your message here"

# Encrypt
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

# Decrypt
decrypted_text = aesgcm.decrypt(nonce, ciphertext, None)

print("Original:", plaintext)
print("Decrypted:", decrypted_text)
