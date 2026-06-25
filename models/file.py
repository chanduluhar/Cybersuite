from datetime import datetime
from extensions import db


class FileMetadata(db.Model):
    __tablename__ = 'files'

    id                   = db.Column(db.Integer, primary_key=True)
    user_id              = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_filename    = db.Column(db.String(255), nullable=False)
    encrypted_filename   = db.Column(db.String(255), unique=True, nullable=False)
    file_size            = db.Column(db.Integer)

    # Encryption Parameters
    encryption_algorithm = db.Column(db.String(50), nullable=False)
    cipher_mode          = db.Column(db.String(20))
    key_size             = db.Column(db.Integer)
    iv_nonce             = db.Column(db.Text)
    salt                 = db.Column(db.String(64))
    tag                  = db.Column(db.String(64))
    decryption_key_salt  = db.Column(db.String(64))
    decryption_key_hash  = db.Column(db.String(128))
    stored_decryption_key = db.Column(db.String(255))

    # Integrity
    hash_algorithm       = db.Column(db.String(20), default='SHA256')
    file_hash            = db.Column(db.String(128))

    is_encrypted         = db.Column(db.Boolean, default=True)
    created_at           = db.Column(db.DateTime, default=datetime.utcnow)
    last_downloaded      = db.Column(db.DateTime)

    def __repr__(self):
        return f'<File {self.original_filename}>'
