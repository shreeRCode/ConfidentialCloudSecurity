import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class CryptoEngine:
    def __init__(self, master_key: bytes):
        if not isinstance(master_key, bytes) or len(master_key) < 32:
            raise ValueError("Master key must be at least 32 random bytes.")
        self._master_key = master_key

    def _derive_key(self, salt: bytes, key_length: int) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=b"adaptive-encryption-framework",
        )
        return hkdf.derive(self._master_key)

    def encrypt(self, plaintext: bytes, algorithm: str) -> bytes:
        salt = os.urandom(16)
        nonce = os.urandom(12)

        if algorithm == "AES-256-GCM":
            key = self._derive_key(salt, 32)
            aead = AESGCM(key)
        elif algorithm == "AES-128-GCM":
            key = self._derive_key(salt, 16)
            aead = AESGCM(key)
        elif algorithm == "ChaCha20-Poly1305":
            key = self._derive_key(salt, 32)
            aead = ChaCha20Poly1305(key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        ciphertext = aead.encrypt(nonce, plaintext, None)
        return salt + nonce + ciphertext

    def decrypt(self, ciphertext: bytes, algorithm: str) -> bytes:
        salt = ciphertext[:16]
        nonce = ciphertext[16:28]
        encrypted_data = ciphertext[28:]

        if algorithm == "AES-256-GCM":
            key = self._derive_key(salt, 32)
            aead = AESGCM(key)
        elif algorithm == "AES-128-GCM":
            key = self._derive_key(salt, 16)
            aead = AESGCM(key)
        elif algorithm == "ChaCha20-Poly1305":
            key = self._derive_key(salt, 32)
            aead = ChaCha20Poly1305(key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        try:
            return aead.decrypt(nonce, encrypted_data, None)
        except InvalidTag:
            print(f"Decryption failed for {algorithm}! The data may be corrupt or tampered with.")
            raise
