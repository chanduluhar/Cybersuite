from flask import Blueprint

auth_bp = Blueprint('auth', __name__, url_prefix='')

from blueprints.auth.routes import *  # noqa: F401, F403, E402
