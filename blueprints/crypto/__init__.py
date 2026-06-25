from flask import Blueprint

crypto_bp = Blueprint('crypto', __name__, url_prefix='/crypto')

from blueprints.crypto.routes import *  # noqa: F401, F403
