from datetime import datetime, timedelta
import re

import jwt
from flask import current_app, jsonify, request

from app import db
from app.auth import bp
from app.logging_utils import bind_identity, business_log_aspect
from app.models import User
from app.services.auth_throttle import AuthThrottleError, enforce_email_code_send_limits
from app.services.captcha import generate_captcha, verify_captcha
from app.services.notification_sender import NotificationProviderError, send_auth_code_email
from app.services.verification_codes import (
    VerificationCodeRateLimitError,
    create_email_code,
    mask_email,
    verify_email_code,
)

DEFAULT_TENANT_ID = 1
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _clean_geo(value: str | None, max_len: int = 64):
    text = (value or '').strip()
    return text[:max_len] if text else None


def _resolve_geo_from_request():
    city = (
        request.headers.get('X-Geo-City')
        or request.headers.get('CF-IPCity')
        or request.headers.get('X-AppEngine-City')
    )
    province = (
        request.headers.get('X-Geo-Region')
        or request.headers.get('CF-Region')
        or request.headers.get('X-AppEngine-Region')
    )
    return _clean_geo(province), _clean_geo(city)


def _normalize_email(value: str | None) -> str:
    return (value or '').strip().lower()


def _is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value))


def _resolve_client_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        first_ip = forwarded_for.split(',')[0].strip()
        if first_ip:
            return first_ip[:64]
    real_ip = (request.headers.get('X-Real-IP') or '').strip()
    if real_ip:
        return real_ip[:64]
    return (request.remote_addr or 'unknown')[:64]


@bp.route('/captcha', methods=['GET'])
@business_log_aspect('auth.captcha', tags=['auth', 'business', 'aop'])
def captcha():
    return jsonify(generate_captcha()), 200


@bp.route('/email-code', methods=['POST'])
@business_log_aspect('auth.email_code', tags=['auth', 'business', 'aop'])
def send_email_code():
    data = request.get_json() or {}
    email = _normalize_email(data.get('email'))
    purpose = (data.get('purpose') or '').strip().lower()
    captcha_id = (data.get('captcha_id') or '').strip()
    captcha_code = (data.get('captcha_code') or '').strip()
    client_ip = _resolve_client_ip()

    if not email or not purpose:
        return jsonify({'error': 'email and purpose are required'}), 400

    if purpose not in {'register', 'reset_password'}:
        return jsonify({'error': 'purpose is invalid'}), 400

    if not _is_valid_email(email):
        return jsonify({'error': 'email format is invalid'}), 400

    if current_app.config.get('AUTH_CODE_REQUIRE_CAPTCHA', True):
        if not captcha_id or not captcha_code:
            return jsonify({'error': 'captcha is required before sending email code'}), 400
        if not verify_captcha(captcha_id, captcha_code):
            return jsonify({'error': 'captcha is invalid or expired'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if purpose == 'register' and existing_user:
        return jsonify({'error': 'email already exists'}), 400
    if purpose == 'reset_password' and not existing_user:
        return jsonify({'error': 'email does not exist'}), 400

    try:
        enforce_email_code_send_limits(email, client_ip)
        result = create_email_code(email, purpose)
        send_auth_code_email(email, result['code'], purpose, int(result['expires_in']))
    except AuthThrottleError as exc:
        payload = {'error': str(exc)}
        if exc.retry_after:
            payload['retry_after'] = exc.retry_after
        return jsonify(payload), 429
    except VerificationCodeRateLimitError as exc:
        return jsonify({'error': f'please retry after {exc.retry_after} seconds', 'retry_after': exc.retry_after}), 429
    except NotificationProviderError as exc:
        current_app.logger.error('Failed to send email code: %s', exc)
        return jsonify({'error': 'email sending is not configured correctly'}), 500
    except Exception as exc:
        current_app.logger.exception('Unexpected email code error: %s', exc)
        return jsonify({'error': 'failed to send email code'}), 500

    return jsonify({
        'message': 'email code sent',
        'masked_email': mask_email(email),
        'expires_in': result['expires_in'],
        'resend_seconds': result['resend_seconds'],
    }), 200


@bp.route('/register', methods=['POST'])
@business_log_aspect('auth.register', tags=['auth', 'business', 'aop'])
def register():
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    email = _normalize_email(data.get('email'))
    password = data.get('password')
    email_code = (data.get('email_code') or '').strip()
    age = data.get('age')

    if not username or not email or not password or not email_code or age in (None, ''):
        return jsonify({'error': 'username, email, password, age and email_code are required'}), 400

    if not _is_valid_email(email):
        return jsonify({'error': 'email format is invalid'}), 400

    try:
        age = int(age)
    except (TypeError, ValueError):
        return jsonify({'error': 'age must be integer'}), 400

    if age < 1 or age > 120:
        return jsonify({'error': 'age must be between 1 and 120'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username already exists'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'email already exists'}), 400

    if not verify_email_code(email, 'register', email_code):
        return jsonify({'error': 'email verification code is invalid or expired'}), 400

    tenant_id = int(current_app.config.get('DEFAULT_TENANT_ID', DEFAULT_TENANT_ID) or DEFAULT_TENANT_ID)
    user = User(username=username, name=username, email=email, age=age, tenant_id=tenant_id)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()
    bind_identity(user, auth_state='authenticated')

    return jsonify({'message': 'register success', 'user': user.to_dict()}), 201


@bp.route('/login', methods=['POST'])
@business_log_aspect('auth.login', tags=['auth', 'business', 'aop'])
def login():
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    password = data.get('password')
    captcha_id = data.get('captcha_id') or ''
    captcha_code = data.get('captcha_code') or ''

    if not username or not password or not captcha_id or not captcha_code:
        return jsonify({'error': 'username, password and captcha are required'}), 400

    if not verify_captcha(captcha_id, captcha_code):
        return jsonify({'error': 'captcha is invalid or expired'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'username or password invalid'}), 401

    province, city = _resolve_geo_from_request()
    changed = False
    if province and province != (user.province or '').strip():
        user.province = province
        changed = True
    if city and city != (user.city or '').strip():
        user.city = city
        changed = True
    if changed:
        db.session.commit()

    expires_delta = timedelta(seconds=current_app.config.get('JWT_EXPIRES_IN', 7200))
    tenant_id = int(user.tenant_id or current_app.config.get('DEFAULT_TENANT_ID', DEFAULT_TENANT_ID) or DEFAULT_TENANT_ID)
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'is_admin': user.is_admin(),
        'is_super_admin': bool(user.is_super_admin),
        'tenant_id': tenant_id,
        'exp': datetime.utcnow() + expires_delta,
    }
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256'),
    )
    bind_identity(user, auth_state='authenticated')

    return jsonify({'message': 'login success', 'token': token, 'user': user.to_dict()}), 200


@bp.route('/password-reset', methods=['POST'])
@business_log_aspect('auth.password_reset', tags=['auth', 'business', 'aop'])
def password_reset():
    data = request.get_json() or {}

    email = _normalize_email(data.get('email'))
    email_code = (data.get('email_code') or '').strip()
    password = data.get('password')

    if not email or not email_code or not password:
        return jsonify({'error': 'email, email_code and password are required'}), 400

    if not _is_valid_email(email):
        return jsonify({'error': 'email format is invalid'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'email does not exist'}), 404

    if not verify_email_code(email, 'reset_password', email_code):
        return jsonify({'error': 'email verification code is invalid or expired'}), 400

    user.set_password(password)
    db.session.commit()

    return jsonify({'message': 'password reset success'}), 200


@bp.route('/logout', methods=['POST'])
@business_log_aspect('auth.logout', tags=['auth', 'business', 'aop'])
def logout():
    return jsonify({'message': 'logout success'}), 200


@bp.route('/check', methods=['GET'])
def check_auth():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'is_authenticated': False}), 401

    token = auth_header.split(' ', 1)[1].strip()
    if not token:
        return jsonify({'is_authenticated': False}), 401

    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=[current_app.config.get('JWT_ALGORITHM', 'HS256')],
        )
    except Exception:
        return jsonify({'is_authenticated': False}), 401

    user_id = payload.get('user_id')
    if not user_id:
        return jsonify({'is_authenticated': False}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({'is_authenticated': False}), 401

    return jsonify({'is_authenticated': True, 'user': user.to_dict()}), 200
