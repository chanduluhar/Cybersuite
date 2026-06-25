from Crypto.Cipher import ChaCha20_Poly1305
import os

class ChaChaCipher:
    def __init__(self, key):
        self.key = key # Must be 32 bytes

    def encrypt(self, data: bytes):
        cipher = ChaCha20_Poly1305.new(key=self.key)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return {
            'ciphertext': ciphertext,
            'iv': cipher.nonce,
            'tag': tag
        }

    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
