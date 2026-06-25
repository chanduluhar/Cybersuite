import os
import secrets
import base64
from encryption.cipher_factory import CipherFactory
from encryption.key_derivation import KeyDerivation, HashFunctions
from models.file import FileMetadata
from models.audit_log import AuditLog
from extensions import db
from flask import current_app

class FileHandler:
    @staticmethod
    def generate_decryption_key():
        # URL-safe key that can be copied by user and reused for decryption.
        return secrets.token_urlsafe(24)

    @staticmethod
    def _hash_decryption_key(decryption_key: str, key_salt: str):
        data = f"{key_salt}:{decryption_key}".encode('utf-8')
        return HashFunctions.hash_data(data)

    @staticmethod
    def _derive_encryption_key(user, file_salt: str, key_size: int, decryption_key: str = None):
        # Use only the decryption_key + file_salt so that any user with the
        # correct decryption key can decrypt (cross-user sharing support).
        # NOTE: `user` param kept for API compatibility but is not used.
        base_secret = decryption_key or ''
        return KeyDerivation.derive_pbkdf2(base_secret, file_salt.encode(), length=key_size // 8)

    @staticmethod
    def encrypt_and_save(file_storage, user, algorithm, mode, key_size):
        # 1. Generate per-file salt and one-time decryption key
        file_salt = secrets.token_hex(16)
        decryption_key = FileHandler.generate_decryption_key()
        decryption_key_salt = secrets.token_hex(16)
        decryption_key_hash = FileHandler._hash_decryption_key(decryption_key, decryption_key_salt)
        password_key = FileHandler._derive_encryption_key(
            user,
            file_salt,
            key_size,
            decryption_key=decryption_key
        )
        
        # 2. Setup Cipher
        cipher = CipherFactory.get_cipher(algorithm, password_key, mode)
        
        # 3. Read file and Encrypt
        file_data = file_storage.read()
        file_hash = HashFunctions.hash_data(file_data)
        
        encryption_result = cipher.encrypt(file_data)
        ciphertext = encryption_result['ciphertext']
        iv = base64.b64encode(encryption_result['iv']).decode('utf-8')
        raw_tag = encryption_result.get('tag')
        tag = base64.b64encode(raw_tag).decode('utf-8') if raw_tag else None
        
        # 4. Save Encrypted File
        encrypted_filename = secrets.token_hex(16) + ".enc"
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(filepath, 'wb') as f:
            f.write(ciphertext)
            
        # Preserve user-facing filename for download while stripping unsafe path/control chars.
        original_filename = os.path.basename(file_storage.filename or "uploaded_file")
        original_filename = original_filename.replace('\x00', '').replace('\r', '').replace('\n', '').strip()
        if not original_filename:
            original_filename = "uploaded_file"

        # 5. Store Metadata
        metadata = FileMetadata(
            user_id=user.id,
            original_filename=original_filename,
            encrypted_filename=encrypted_filename,
            file_size=len(file_data),
            encryption_algorithm=algorithm,
            cipher_mode=mode,
            key_size=key_size,
            iv_nonce=iv,
            salt=file_salt,
            tag=tag,
            decryption_key_salt=decryption_key_salt,
            decryption_key_hash=decryption_key_hash,
            stored_decryption_key=decryption_key,
            file_hash=file_hash
        )
        db.session.add(metadata)
        db.session.flush()

        audit_log = AuditLog(
            user_id=user.id,
            action='ENCRYPT',
            file_id=metadata.id,
            algorithm_used=algorithm,
        )
        db.session.add(audit_log)

        db.session.commit()
        
        return metadata, decryption_key

    @staticmethod
    def decrypt_ciphertext(ciphertext, file_metadata, user, decryption_key=None, log_action=True):
        normalized_key = (decryption_key or '').strip()
        if file_metadata.decryption_key_hash:
            if not normalized_key:
                raise ValueError('Decryption key is required for this file.')

            expected_hash = FileHandler._hash_decryption_key(
                normalized_key,
                file_metadata.decryption_key_salt or ''
            )
            if not secrets.compare_digest(expected_hash, file_metadata.decryption_key_hash):
                raise ValueError('Invalid decryption key.')

        # Re-derive key (new files require decryption key; legacy files continue to work)
        password_key = FileHandler._derive_encryption_key(
            user,
            file_metadata.salt,
            file_metadata.key_size,
            decryption_key=normalized_key if file_metadata.decryption_key_hash else None
        )
        
        cipher = CipherFactory.get_cipher(file_metadata.encryption_algorithm, password_key, file_metadata.cipher_mode)
        
        iv = base64.b64decode(file_metadata.iv_nonce)
        tag = base64.b64decode(file_metadata.tag) if file_metadata.tag else None

        if tag is not None:
            decrypted = cipher.decrypt(ciphertext, iv, tag)
        else:
            decrypted = cipher.decrypt(ciphertext, iv)
            
        if log_action:
            audit_log = AuditLog(
                user_id=user.id,
                action='DECRYPT',
                file_id=file_metadata.id,
                algorithm_used=file_metadata.encryption_algorithm,
            )
            db.session.add(audit_log)
            db.session.commit()
        
        return decrypted

    @staticmethod
    def decrypt_and_get(file_metadata, user, decryption_key=None, log_action=True):
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_metadata.encrypted_filename)
        
        with open(filepath, 'rb') as f:
            ciphertext = f.read()

        return FileHandler.decrypt_ciphertext(ciphertext, file_metadata, user, decryption_key=decryption_key, log_action=log_action)
