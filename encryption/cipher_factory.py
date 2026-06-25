from encryption.aes_cipher import AESCipher
from encryption.des_cipher import DESCipher, TripleDESCipher
from encryption.chacha20_cipher import ChaChaCipher
from encryption.blowfish_cipher import BlowfishCipher

class CipherFactory:
    @staticmethod
    def get_cipher(algorithm, key, mode='CBC'):
        algo = algorithm.upper()
        if algo == 'AES':
            return AESCipher(key, mode)
        elif algo == 'DES':
            return DESCipher(key, mode)
        elif algo == '3DES' or algo == 'TRIPLEDES':
            return TripleDESCipher(key, mode)
        elif algo == 'CHACHA20':
            return ChaChaCipher(key)
        elif algo == 'BLOWFISH':
            return BlowfishCipher(key, mode)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
