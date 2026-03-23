from flask import request, jsonify, current_app
from app.auth import bp
from app import db
from app.models import User
from app.services.captcha import generate_captcha, verify_captcha
from app.logging_utils import bind_identity, business_log_aspect
import jwt
from datetime import datetime, timedelta

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
    captcha_id = data.get('captcha_id') or ''
    captcha_code = data.get('captcha_code') or ''

    # 检查必需字段
    if not username or not email or not password or not captcha_id or not captcha_code:
        return jsonify({'error': '用户名、邮箱、密码和验证码是必需的'}), 400

    if not verify_captcha(captcha_id, captcha_code):
        return jsonify({'error': '验证码错误或已过期'}), 400

    # 检查用户是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({'error': '用户名已存在'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': '邮箱已被注册'}), 400

    # 创建新用户
    user = User(username=username, name=username, email=email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()
    bind_identity(user, auth_state='authenticated')

    return jsonify({'message': '用户注册成功', 'user': user.to_dict()}), 201

@bp.route('/login', methods=['POST'])
@business_log_aspect('auth.login', tags=['auth', 'business', 'aop'])
def login():
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    password = data.get('password')
    captcha_id = data.get('captcha_id') or ''
    captcha_code = data.get('captcha_code') or ''

    # 检查必需字段
    if not username or not password or not captcha_id or not captcha_code:
        return jsonify({'error': '用户名、密码和验证码是必需的'}), 400

    if not verify_captcha(captcha_id, captcha_code):
        return jsonify({'error': '验证码错误或已过期'}), 400

    # 查找用户
    user = User.query.filter_by(username=username).first()

    # 验证用户和密码
    if not user or not user.check_password(password):
        return jsonify({'error': '用户名或密码错误'}), 401

    # 生成 JWT
    expires_delta = timedelta(seconds=current_app.config.get('JWT_EXPIRES_IN', 7200))
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'is_admin': user.is_admin(),
        'exp': datetime.utcnow() + expires_delta
    }
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256')
    )
    bind_identity(user, auth_state='authenticated')

    return jsonify({
        'message': '登录成功',
        'token': token,
        'user': user.to_dict()
    }), 200

@bp.route('/logout', methods=['POST'])
@business_log_aspect('auth.logout', tags=['auth', 'business', 'aop'])
def logout():
    # 使用 JWT 为无状态认证，后端无法真正“注销”一个 token，
    # 前端只需丢弃本地保存的 token 即可视为登出。
    return jsonify({'message': '已退出登录（请在客户端删除 Token）'}), 200

@bp.route('/check', methods=['GET'])
def check_auth():
    """
    基于 Authorization Bearer Token 检查认证状态
    """
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
            algorithms=[current_app.config.get('JWT_ALGORITHM', 'HS256')]
        )
    except Exception:
        return jsonify({'is_authenticated': False}), 401

    user_id = payload.get('user_id')
    if not user_id:
        return jsonify({'is_authenticated': False}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({'is_authenticated': False}), 401

    return jsonify({
        'is_authenticated': True,
        'user': user.to_dict()
    }), 200
