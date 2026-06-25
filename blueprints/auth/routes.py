import base64
import json
import os
import re
import secrets
import time
from urllib.parse import urljoin, urlparse

import jwt
import requests
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from jwt import InvalidTokenError
from sqlalchemy import func

from extensions import bcrypt, db
from models.user import User


auth_bp = Blueprint('auth', __name__)

CLERK_PUBLISHABLE_KEY = os.getenv('CLERK_PUBLISHABLE_KEY', '').strip()
CLERK_SECRET_KEY = os.getenv('CLERK_SECRET_KEY', '').strip()
CLERK_AUTH_ENABLED = bool(CLERK_PUBLISHABLE_KEY and CLERK_SECRET_KEY)
CLERK_JWKS_TTL_SECONDS = 60 * 60
CLERK_HTTP_TIMEOUT_SECONDS = 4
_CLERK_JWKS_CACHE = {}


def clerk_template_context():
    if not CLERK_AUTH_ENABLED:
        return {}
    return {
        'clerk_auth_enabled': True,
        'clerk_publishable_key': CLERK_PUBLISHABLE_KEY,
        'clerk_js_url': _clerk_js_url(),
    }


def _is_safe_redirect_url(target):
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def _safe_next_page(next_page):
    return next_page if _is_safe_redirect_url(next_page) else ''


def _auth_template_context(next_page='', block_clerk_auto_login=False):
    context = {
        'next_page': _safe_next_page(next_page or ''),
        'block_clerk_auto_login': bool(block_clerk_auto_login),
    }
    context.update(clerk_template_context())
    return context


def _build_unique_username(name_hint):
    cleaned = re.sub(r'[^a-zA-Z0-9_.-]+', '', (name_hint or '').strip().lower())
    base = (cleaned or 'user')[:40]
    candidate = base
    suffix = 1
    while User.query.filter(func.lower(User.username) == candidate.lower()).first():
        suffix_text = f'_{suffix}'
        candidate = f"{base[:50 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    return candidate


def _clerk_frontend_api():
    if not CLERK_PUBLISHABLE_KEY or not CLERK_PUBLISHABLE_KEY.startswith(('pk_test_', 'pk_live_')):
        return None
    try:
        b64 = CLERK_PUBLISHABLE_KEY.split('_', 2)[-1].strip()
        padded_b64 = b64 + ('=' * (-len(b64) % 4))
        decoded = base64.urlsafe_b64decode(padded_b64).decode('utf-8', errors='ignore').strip().rstrip('$')
        if decoded and '.' in decoded:
            return f'https://{decoded}'
    except Exception:
        return None
    return None


def _clerk_js_url():
    frontend_api = _clerk_frontend_api()
    if frontend_api:
        return f'{frontend_api}/npm/@clerk/clerk-js@5/dist/clerk.browser.js'
    return 'https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js'


def _get_unverified_jwt_claims(session_token):
    try:
        claims = jwt.decode(
            session_token,
            options={
                'verify_signature': False,
                'verify_exp': False,
                'verify_nbf': False,
                'verify_iat': False,
                'verify_aud': False,
                'verify_iss': False,
            },
        )
        return claims if isinstance(claims, dict) else None
    except InvalidTokenError:
        return None


def _fetch_clerk_jwks(issuer, force_refresh=False):
    if not issuer:
        return None

    issuer = issuer.rstrip('/')
    if not issuer.startswith('https://'):
        return None

    now = time.time()
    cached = _CLERK_JWKS_CACHE.get(issuer, {})
    cached_keys = cached.get('keys')
    cached_at = cached.get('fetched_at', 0)

    if not force_refresh and cached_keys and (now - cached_at) < CLERK_JWKS_TTL_SECONDS:
        return cached_keys

    jwks_url = f'{issuer}/.well-known/jwks.json'
    try:
        response = requests.get(jwks_url, timeout=CLERK_HTTP_TIMEOUT_SECONDS)
    except requests.RequestException as req_err:
        current_app.logger.error(f'Clerk JWKS fetch failed: {req_err}')
        return None

    if response.status_code >= 400:
        current_app.logger.warning(f'Clerk JWKS fetch status {response.status_code}')
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    keys = payload.get('keys') if isinstance(payload, dict) else None
    if not isinstance(keys, list) or not keys:
        return None

    _CLERK_JWKS_CACHE[issuer] = {
        'keys': keys,
        'fetched_at': now,
    }
    return keys


def _find_user_id_in_payload(payload):
    if isinstance(payload, dict):
        for key in ('user_id', 'userId', 'sub'):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in payload.values():
            nested = _find_user_id_in_payload(value)
            if nested:
                return nested
    elif isinstance(payload, list):
        for item in payload:
            nested = _find_user_id_in_payload(item)
            if nested:
                return nested
    return None


def _verify_clerk_session_token_via_api(session_token):
    if not CLERK_SECRET_KEY:
        return None

    verify_url = 'https://api.clerk.com/v1/client/sessions/verify'
    headers = {'Authorization': f'Bearer {CLERK_SECRET_KEY}'}

    response = None
    try:
        response = requests.post(
            verify_url,
            headers=headers,
            json={'token': session_token},
            timeout=CLERK_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as req_err:
        current_app.logger.error(f'Clerk verify API POST failed: {req_err}')

    if response is None or response.status_code >= 400:
        try:
            response = requests.get(
                verify_url,
                headers=headers,
                params={'token': session_token},
                timeout=CLERK_HTTP_TIMEOUT_SECONDS,
            )
        except requests.RequestException as req_err:
            current_app.logger.error(f'Clerk verify API GET failed: {req_err}')
            return None

    if response.status_code >= 400:
        current_app.logger.warning(f'Clerk verify API returned status {response.status_code}')
        return None

    claims = _get_unverified_jwt_claims(session_token) or {}
    if claims.get('sub'):
        return claims

    try:
        response_payload = response.json()
    except ValueError:
        response_payload = None

    user_id = _find_user_id_in_payload(response_payload)
    if not user_id:
        return None

    claims['sub'] = user_id
    return claims


def _verify_clerk_session_token(session_token):
    claims = _get_unverified_jwt_claims(session_token)
    if isinstance(claims, dict) and (claims.get('sub') or '').strip():
        return claims

    try:
        unverified_header = jwt.get_unverified_header(session_token)
    except InvalidTokenError:
        return _verify_clerk_session_token_via_api(session_token)

    if (unverified_header or {}).get('alg') != 'RS256':
        current_app.logger.warning('Unsupported Clerk token algorithm')
        return _verify_clerk_session_token_via_api(session_token)

    kid = (unverified_header or {}).get('kid')
    if not kid:
        return _verify_clerk_session_token_via_api(session_token)

    unverified_claims = _get_unverified_jwt_claims(session_token)
    if not unverified_claims:
        return _verify_clerk_session_token_via_api(session_token)

    issuer = (unverified_claims.get('iss') or '').strip()
    if not issuer:
        current_app.logger.warning('Clerk token missing issuer claim')
        return _verify_clerk_session_token_via_api(session_token)

    jwks_keys = _fetch_clerk_jwks(issuer, force_refresh=False)
    if not jwks_keys:
        return _verify_clerk_session_token_via_api(session_token)

    jwk = next((item for item in jwks_keys if item.get('kid') == kid), None)
    if jwk is None:
        jwks_keys = _fetch_clerk_jwks(issuer, force_refresh=True)
        if not jwks_keys:
            return _verify_clerk_session_token_via_api(session_token)
        jwk = next((item for item in jwks_keys if item.get('kid') == kid), None)

    if jwk is None:
        current_app.logger.warning('No matching Clerk JWKS key found for token')
        return _verify_clerk_session_token_via_api(session_token)

    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            session_token,
            key=public_key,
            algorithms=['RS256'],
            issuer=issuer,
            options={'verify_aud': False, 'require': ['exp', 'iat', 'sub']},
            leeway=60,
        )
        return claims if isinstance(claims, dict) else None
    except InvalidTokenError as token_err:
        current_app.logger.warning(f'Clerk token signature/claim validation failed: {token_err}')
        return _verify_clerk_session_token_via_api(session_token)


def _fetch_clerk_user_profile(clerk_user_id):
    if not CLERK_SECRET_KEY or not clerk_user_id:
        return None

    headers = {'Authorization': f'Bearer {CLERK_SECRET_KEY}'}
    try:
        response = requests.get(
            f'https://api.clerk.com/v1/users/{clerk_user_id}',
            headers=headers,
            timeout=CLERK_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as req_err:
        current_app.logger.error(f'Clerk user lookup failed: {req_err}')
        return None

    if response.status_code >= 400:
        current_app.logger.warning(f'Clerk user lookup status {response.status_code}')
        return None

    try:
        user_data = response.json()
    except ValueError:
        return None

    primary_email_id = user_data.get('primary_email_address_id')
    email_addresses = user_data.get('email_addresses') or []

    email = ''
    for email_item in email_addresses:
        if email_item.get('id') == primary_email_id:
            email = (email_item.get('email_address') or '').strip().lower()
            break
    if not email and email_addresses:
        email = (email_addresses[0].get('email_address') or '').strip().lower()

    username_hint = (
        user_data.get('username')
        or ' '.join(
            part for part in [
                (user_data.get('first_name') or '').strip(),
                (user_data.get('last_name') or '').strip(),
            ] if part
        )
        or (email.split('@')[0] if email else '')
    )

    if not email:
        return None

    return {
        'email': email,
        'username_hint': username_hint,
    }


@auth_bp.route('/auth/clerk', methods=['POST'])
def clerk_auth():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if not CLERK_AUTH_ENABLED:
        flash('Clerk authentication is not configured on this server.', 'warning')
        return redirect(url_for('auth.login'))

    next_page = (request.form.get('next') or request.args.get('next', type=str) or '').strip()
    clerk_token = (request.form.get('clerk_token') or '').strip()

    if not clerk_token:
        flash('Clerk token was not provided.', 'danger')
        return redirect(url_for('auth.login'))

    token_payload = _verify_clerk_session_token(clerk_token)
    if not token_payload:
        flash('Invalid Clerk session token. Please sign in again.', 'danger')
        return redirect(url_for('auth.login'))

    clerk_user_id = (token_payload.get('sub') or '').strip()
    if not clerk_user_id:
        flash('Clerk token does not include a valid user.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(clerk_user_id=clerk_user_id).first()
    if not user:
        clerk_profile = _fetch_clerk_user_profile(clerk_user_id)
        if not clerk_profile:
            current_app.logger.warning(
                f'Clerk profile lookup failed for user_id={clerk_user_id}; '
                'falling back to synthetic local profile.'
            )
            synthetic_email = f'{clerk_user_id}@clerk.local'
            clerk_profile = {
                'email': synthetic_email.lower(),
                'username_hint': f'clerk_{clerk_user_id[:32]}',
            }

        email = (clerk_profile['email'] or '').strip().lower()
        user = User.query.filter(func.lower(User.email) == email).first()
        if user and not user.clerk_user_id:
            user.clerk_user_id = clerk_user_id
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
    created = False

    if not user:
        generated_username = _build_unique_username(clerk_profile.get('username_hint', 'user'))
        random_password = os.urandom(32).hex()
        hashed_password = bcrypt.generate_password_hash(random_password).decode('utf-8')
        is_first = User.query.count() == 0
        user = User(
            clerk_user_id=clerk_user_id,
            username=generated_username,
            email=email,
            password_hash=hashed_password,
            master_salt=secrets.token_hex(16),
            role='admin' if is_first else 'user',
            is_admin=is_first,
        )
        db.session.add(user)
        try:
            db.session.commit()
            created = True
        except Exception as db_err:
            db.session.rollback()
            current_app.logger.error(f'Clerk user creation failed: {db_err}')
            flash('Unable to create your account right now. Please try again.', 'danger')
            return redirect(url_for('auth.login'))

    login_user(user)
    flash('Account created via Clerk and signed in.' if created else 'Signed in with Clerk.', 'success')

    safe_next_page = _safe_next_page(next_page)
    if safe_next_page:
        return redirect(safe_next_page)
    return redirect(url_for('dashboard'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    next_page = request.args.get('next', type=str) or ''

    if request.method == 'POST':
        next_page = _safe_next_page((request.form.get('next') or request.args.get('next', type=str) or '').strip())
        flash('Password registration is disabled. Please continue with Clerk.', 'info')
        if next_page:
            return redirect(url_for('auth.register', next=next_page))
        return redirect(url_for('auth.register'))

    return render_template('register.html', **_auth_template_context(next_page))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    block_clerk_auto_login = bool(session.pop('block_clerk_auto_login', False))
    next_page = request.args.get('next', type=str) or ''

    if request.method == 'POST':
        next_page = _safe_next_page((request.form.get('next') or request.args.get('next', type=str) or '').strip())
        flash('Password login is disabled. Please continue with Clerk.', 'info')
        if next_page:
            return redirect(url_for('auth.login', next=next_page))
        return redirect(url_for('auth.login'))

    return render_template('login.html', **_auth_template_context(next_page, block_clerk_auto_login))


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session['block_clerk_auto_login'] = True
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
