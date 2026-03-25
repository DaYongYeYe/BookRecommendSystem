from datetime import datetime, timedelta

import jwt
from flask import current_app, jsonify, request

from app import db
from app.auth import bp
from app.logging_utils import bind_identity, business_log_aspect
from app.models import User
from app.services.captcha import generate_captcha, verify_captcha


def _clean_geo(value: str | None, max_len: int = 64):
    text = (value or '').strip()
    return text[:max_len] if text else None


def _resolve_geo_from_request():
    # Prefer proxy-provided geo headers (CDN/Gateway), fallback to existing DB value.
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


@bp.route('/captcha', methods=['GET'])
@business_log_aspect('auth.captcha', tags=['auth', 'business', 'aop'])
def captcha():
    return jsonify(generate_captcha()), 200


@bp.route('/register', methods=['POST'])
@business_log_aspect('auth.register', tags=['auth', 'business', 'aop'])
def register():
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')
    age = data.get('age')
    captcha_id = data.get('captcha_id') or ''
    captcha_code = data.get('captcha_code') or ''

    if not username or not email or not password or not captcha_id or not captcha_code or age in (None, ''):
        return jsonify({'error': 'username, email, password, age and captcha are required'}), 400

    try:
        age = int(age)
    except (TypeError, ValueError):
        return jsonify({'error': 'age must be integer'}), 400

    if age < 1 or age > 120:
        return jsonify({'error': 'age must be between 1 and 120'}), 400

    if not verify_captcha(captcha_id, captcha_code):
        return jsonify({'error': 'captcha is invalid or expired'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username already exists'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'email already exists'}), 400

    user = User(username=username, name=username, email=email, age=age)
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
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'is_admin': user.is_admin(),
        'exp': datetime.utcnow() + expires_delta,
    }
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256'),
    )
    bind_identity(user, auth_state='authenticated')

    return jsonify({'message': 'login success', 'token': token, 'user': user.to_dict()}), 200


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
