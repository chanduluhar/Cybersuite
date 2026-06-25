from datetime import datetime
from extensions import db


class Scan(db.Model):
    """Threat scanner results (URL / IP / file / hash) — from phishing-detecor."""
    __tablename__ = 'scans'

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    scan_type   = db.Column(db.String(20), nullable=False)   # 'url', 'ip', 'file', 'hash'
    input_value = db.Column(db.Text, nullable=False)
    result      = db.Column(db.String(20), nullable=False)   # 'safe', 'phishing', 'unknown'
    risk_score  = db.Column(db.Float, default=0.0)
    details     = db.Column(db.JSON, nullable=True)
    scanned_at  = db.Column(db.DateTime, default=datetime.utcnow)


class SystemLog(db.Model):
    __tablename__ = 'system_logs'

    id         = db.Column(db.Integer, primary_key=True)
    level      = db.Column(db.String(20), nullable=False)
    message    = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
