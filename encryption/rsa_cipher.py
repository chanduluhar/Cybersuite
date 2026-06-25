from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class RSACipher:
    @staticmethod
    def generate_key_pair(bits=2048):
        key = RSA.generate(bits)
        return key.export_key(), key.publickey().export_key()

    def __init__(self, private_key_pem):
        self.key = RSA.import_key(private_key_pem)
        self.cipher = PKCS1_OAEP.new(self.key)

    def encrypt(self, data: bytes, public_key_pem):
        pub_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(data)

    def decrypt(self, ciphertext: bytes):
        return self.cipher.decrypt(ciphertext)

class ECCSymmetric:
    # ECC is typically for signatures/key exchange (ECDSA/ECDH). 
    # For "encryption", we usually use ECDH to derive a symmetric key.
    @staticmethod
    def generate_key_pair(curve='P-256'):
        key = ECC.generate(curve=curve)
        return key.export_key(format='PEM'), key.public_key().export_key(format='PEM')

    @staticmethod
    def sign(data: bytes, private_key_pem):
        key = ECC.import_key(private_key_pem)
        h = SHA256.new(data)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(h)

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key_pem):
        key = ECC.import_key(public_key_pem)
        h = SHA256.new(data)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False
