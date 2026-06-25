from datetime import datetime
from extensions import db


class ScanHistory(db.Model):
    """Port scan history — migrated from portscanner (was MySQL, now SQLite)."""
    __tablename__ = 'scan_history'

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address  = db.Column(db.String(255), nullable=False)
    scan_result = db.Column(db.Text)           # JSON string of full scan result
    scan_date   = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ScanHistory {self.ip_address} @ {self.scan_date}>'
