import hashlib
from datetime import datetime
from extensions import db


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action             = db.Column(db.String(50), nullable=False)
    file_id            = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    algorithm_used     = db.Column(db.String(50))
    ip_address         = db.Column(db.String(45))
    timestamp          = db.Column(db.DateTime, default=datetime.utcnow)
    previous_log_hash  = db.Column(db.String(64))
    current_log_hash   = db.Column(db.String(64))

    def generate_hash(self):
        data = f"{self.user_id}{self.action}{self.file_id}{self.timestamp}{self.previous_log_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

    def __repr__(self):
        return f'<AuditLog {self.action} by User {self.user_id}>'
