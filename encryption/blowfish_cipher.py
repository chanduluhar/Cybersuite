from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import os

# Note: Twofish is often implemented via 'cryptography' or custom wrappers as it's not in PyCryptodome by default.
# I will use Blowfish here and a placeholder/wrapper if Twofish is strictly needed from another lib.
# For simplicity in this demo, I'll stick to robust Blowfish.

class BlowfishCipher:
    def __init__(self, key, mode='CBC'):
        self.key = key
        self.mode = Blowfish.MODE_CBC if mode.upper() == 'CBC' else Blowfish.MODE_ECB

    def encrypt(self, data: bytes):
        iv = os.urandom(8)
        if self.mode == Blowfish.MODE_ECB:
            cipher = Blowfish.new(self.key, self.mode)
            iv = b''
        else:
            cipher = Blowfish.new(self.key, self.mode, iv=iv)
        ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
        return {'ciphertext': ciphertext, 'iv': iv}

    def decrypt(self, ciphertext: bytes, iv: bytes):
        if self.mode == Blowfish.MODE_ECB:
            cipher = Blowfish.new(self.key, self.mode)
        else:
            cipher = Blowfish.new(self.key, self.mode, iv=iv)
        return unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
