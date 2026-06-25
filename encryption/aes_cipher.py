import base64
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    MODES = {
        'ECB': AES.MODE_ECB,
        'CBC': AES.MODE_CBC,
        'CFB': AES.MODE_CFB,
        'OFB': AES.MODE_OFB,
        'CTR': AES.MODE_CTR,
        'GCM': AES.MODE_GCM
    }

    def __init__(self, key, mode='CBC'):
        self.key = key
        self.mode_str = mode.upper()
        self.mode = self.MODES.get(self.mode_str, AES.MODE_CBC)

    def encrypt(self, data: bytes):
        iv = os.urandom(16)
        tag = None
        
        if self.mode == AES.MODE_ECB:
            cipher = AES.new(self.key, self.mode)
            ciphertext = cipher.encrypt(pad(data, AES.block_size))
            iv = b''
        elif self.mode == AES.MODE_CTR:
            iv = os.urandom(8) # nonce
            cipher = AES.new(self.key, self.mode, nonce=iv)
            ciphertext = cipher.encrypt(data)
        elif self.mode == AES.MODE_GCM:
            cipher = AES.new(self.key, self.mode)
            iv = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
        else: # CBC, CFB, OFB
            cipher = AES.new(self.key, self.mode, iv=iv)
            ciphertext = cipher.encrypt(pad(data, AES.block_size))
            
        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'tag': tag
        }

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes = None):
        if self.mode == AES.MODE_ECB:
            cipher = AES.new(self.key, self.mode)
            return unpad(cipher.decrypt(ciphertext), AES.block_size)
        elif self.mode == AES.MODE_CTR:
            cipher = AES.new(self.key, self.mode, nonce=iv)
            return cipher.decrypt(ciphertext)
        elif self.mode == AES.MODE_GCM:
            cipher = AES.new(self.key, self.mode, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag)
        else:
            cipher = AES.new(self.key, self.mode, iv=iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size)
