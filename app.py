import os
from flask import Flask, render_template
from dotenv import load_dotenv
from config import Config
from extensions import db, login_manager, bcrypt, csrf, limiter
from sqlalchemy import inspect, text

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))


def ensure_schema_compatibility(app):
    """Runtime migration for any schema differences."""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            if 'users' in tables:
                existing_users = {col['name'] for col in inspector.get_columns('users')}
                if 'clerk_user_id' not in existing_users:
                    db.session.execute(text("ALTER TABLE users ADD COLUMN clerk_user_id VARCHAR(128)"))
                    db.session.commit()
            if 'files' in tables:
                existing = {col['name'] for col in inspector.get_columns('files')}
                stmts = []
                for col in ['decryption_key_salt', 'decryption_key_hash', 'stored_decryption_key']:
                    if col not in existing:
                        stmts.append(f"ALTER TABLE files ADD COLUMN {col} VARCHAR(255)")
                for stmt in stmts:
                    db.session.execute(text(stmt))
                if stmts:
                    db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Schema compat check failed: %s", exc)


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload/export folders exist
    for folder in [app.config['UPLOAD_FOLDER'], app.config['EXPORTS_FOLDER']]:
        os.makedirs(folder, exist_ok=True)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    # Rate limiter disabled on request
    # limiter.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # Register all models (so SQLAlchemy creates tables)
    from models import user, file, shared_file, audit_log, scan, scan_history  # noqa: F401

    # Register blueprints
    from blueprints.auth.routes import auth_bp
    from blueprints.crypto.routes import crypto_bp
    from blueprints.phishing.routes import phishing_bp
    from blueprints.scanner.routes import scanner_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(crypto_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(scanner_bp)

    # Main routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/dashboard')
    def dashboard():
        from flask_login import current_user
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for('auth.login'))
        from models.scan import Scan
        from models.scan_history import ScanHistory
        from models.file import FileMetadata

        recent_threat_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.scanned_at.desc()).limit(5).all()
        recent_port_scans   = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.scan_date.desc()).limit(5).all()
        recent_files        = FileMetadata.query.filter_by(user_id=current_user.id).order_by(FileMetadata.created_at.desc()).limit(5).all()
        threat_count  = Scan.query.filter_by(user_id=current_user.id).count()
        port_count    = ScanHistory.query.filter_by(user_id=current_user.id).count()
        file_count    = FileMetadata.query.filter_by(user_id=current_user.id).count()

        return render_template('dashboard.html',
                               recent_threat_scans=recent_threat_scans,
                               recent_port_scans=recent_port_scans,
                               recent_files=recent_files,
                               threat_count=threat_count,
                               port_count=port_count,
                               file_count=file_count)

    @app.route('/admin')
    def admin():
        from flask_login import current_user
        from flask import redirect, url_for
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('dashboard'))
        from models.user import User as UserModel
        from models.scan import Scan
        from models.scan_history import ScanHistory
        users       = UserModel.query.order_by(UserModel.created_at.desc()).all()
        total_scans = Scan.query.count() + ScanHistory.query.count()
        return render_template('admin.html', users=users, total_scans=total_scans)

    @app.route('/profile')
    def profile():
        from flask_login import current_user
        from flask import redirect, url_for
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        return render_template('profile.html')

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    # Create all tables
    with app.app_context():
        db.create_all()
        ensure_schema_compatibility(app)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
