import os
from datetime import timedelta


def _is_vercel_runtime():
    return os.environ.get('VERCEL') == '1'


def _database_uri(base_dir):
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        if database_url.startswith('postgres://'):
            return database_url.replace('postgres://', 'postgresql://', 1)
        return database_url

    if _is_vercel_runtime():
        return 'sqlite:////tmp/cybersuite.db'

    return f'sqlite:///{os.path.join(base_dir, "cybersuite.db")}'


def _storage_root(base_dir):
    return '/tmp' if _is_vercel_runtime() else base_dir


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cybersuite-secret-key-default-12345'

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    STORAGE_ROOT = _storage_root(BASE_DIR)
    SQLALCHEMY_DATABASE_URI = _database_uri(BASE_DIR)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(STORAGE_ROOT, 'uploads')
    EXPORTS_FOLDER = os.path.join(STORAGE_ROOT, 'exports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = _is_vercel_runtime()

    VIRUSTOTAL_API_KEY   = os.environ.get('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY    = os.environ.get('ABUSEIPDB_API_KEY', '')
    URLSCAN_API_KEY      = os.environ.get('URLSCAN_API_KEY', '')
    GSB_API_KEY          = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    ISMALICIOUS_API_KEY  = os.environ.get('ISMALICIOUS_API_KEY', '')
    ISMALICIOUS_API_URL  = os.environ.get('ISMALICIOUS_API_URL', 'https://api.ismalicious.com/v1/check')
