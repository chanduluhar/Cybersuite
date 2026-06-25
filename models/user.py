from datetime import datetime
from flask_login import UserMixin
from extensions import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """Unified user model for all three sub-apps."""
    __tablename__ = 'users'

    id           = db.Column(db.Integer, primary_key=True)
    clerk_user_id = db.Column(db.String(128), unique=True, nullable=True, index=True)
    username     = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email        = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # Cryptograpy: per-user key derivation salt
    master_salt  = db.Column(db.String(64), nullable=True)

    # Role fields (both systems unified)
    role         = db.Column(db.String(20), default='user')  # 'user' | 'admin'
    is_admin     = db.Column(db.Boolean, default=False)

    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_login   = db.Column(db.DateTime)

    # Relationships
    files        = db.relationship('FileMetadata', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs   = db.relationship('AuditLog', backref='user', lazy='dynamic')
    scans        = db.relationship('Scan', backref='user', lazy=True)
    port_scans   = db.relationship('ScanHistory', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'
