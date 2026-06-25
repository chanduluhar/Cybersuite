import hashlib
from Crypto.Protocol.KDF import PBKDF2, scrypt
from argon2 import PasswordHasher

class HashFunctions:
    @staticmethod
    def hash_data(data: bytes, algorithm='SHA256'):
        algo = algorithm.upper()
        if algo == 'MD5':
            return hashlib.md5(data).hexdigest()
        elif algo == 'SHA1':
            return hashlib.sha1(data).hexdigest()
        elif algo == 'SHA256':
            return hashlib.sha256(data).hexdigest()
        elif algo == 'SHA512':
            return hashlib.sha512(data).hexdigest()
        elif algo == 'BLAKE2B':
            return hashlib.blake2b(data).hexdigest()
        return hashlib.sha256(data).hexdigest()

class KeyDerivation:
    @staticmethod
    def derive_pbkdf2(password: str, salt: bytes, length=32):
        return PBKDF2(password, salt, dkLen=length, count=100000)

    @staticmethod
    def derive_scrypt(password: str, salt: bytes, length=32):
        return scrypt(password, salt, key_len=length, N=2**14, r=8, p=1)

    @staticmethod
    def derive_argon2(password: str):
        ph = PasswordHasher()
        return ph.hash(password)

    @staticmethod
    def verify_argon2(hash_str: str, password: str):
        ph = PasswordHasher()
        try:
            return ph.verify(hash_str, password)
        except:
            return False
