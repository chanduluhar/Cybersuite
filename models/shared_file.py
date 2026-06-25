import uuid
from datetime import datetime
from extensions import db


class SharedFile(db.Model):
    __tablename__ = 'shared_files'

    id                 = db.Column(db.Integer, primary_key=True)
    file_id            = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    shared_by          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_with_email  = db.Column(db.String(120), nullable=False)
    access_token       = db.Column(db.String(64), unique=True, default=lambda: str(uuid.uuid4()))
    expires_at         = db.Column(db.DateTime)
    is_one_time        = db.Column(db.Boolean, default=True)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)

    def is_valid(self):
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True
