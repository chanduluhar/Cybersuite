from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
import os

class DESCipher:
    def __init__(self, key, mode='CBC'):
        # DES key must be 8 bytes
        self.key = key[:8].ljust(8, b'\0')
        self.mode = DES.MODE_CBC if mode.upper() == 'CBC' else DES.MODE_ECB

    def encrypt(self, data: bytes):
        iv = os.urandom(8)
        if self.mode == DES.MODE_ECB:
            cipher = DES.new(self.key, self.mode)
            return {'ciphertext': cipher.encrypt(pad(data, 8)), 'iv': b''}
        cipher = DES.new(self.key, self.mode, iv=iv)
        return {'ciphertext': cipher.encrypt(pad(data, 8)), 'iv': iv}

    def decrypt(self, ciphertext, iv):
        if self.mode == DES.MODE_ECB:
            cipher = DES.new(self.key, self.mode)
        else:
            cipher = DES.new(self.key, self.mode, iv=iv)
        return unpad(cipher.decrypt(ciphertext), 8)

class TripleDESCipher:
    def __init__(self, key, mode='CBC'):
        # DES3 key must be 16 or 24 bytes
        if len(key) < 16:
            self.key = key.ljust(16, b'\0')
        elif len(key) < 24:
            self.key = key[:16]
        else:
            self.key = key[:24]
        self.mode = DES3.MODE_CBC if mode.upper() == 'CBC' else DES3.MODE_ECB

    def encrypt(self, data: bytes):
        iv = os.urandom(8)
        cipher = DES3.new(self.key, self.mode, iv=iv) if self.mode != DES3.MODE_ECB else DES3.new(self.key, self.mode)
        ciphertext = cipher.encrypt(pad(data, 8))
        return {'ciphertext': ciphertext, 'iv': iv if self.mode != DES3.MODE_ECB else b''}

    def decrypt(self, ciphertext, iv):
        cipher = DES3.new(self.key, self.mode, iv=iv) if self.mode != DES3.MODE_ECB else DES3.new(self.key, self.mode)
        return unpad(cipher.decrypt(ciphertext), 8)
