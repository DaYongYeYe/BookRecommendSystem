from functools import wraps
from flask import request, jsonify, current_app
from app.models import User, Role, Permission, RolePermission, UserRole
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError


def _get_token_from_header():
    """
    从 Authorization 头中解析 Bearer Token
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    return auth_header.split(' ', 1)[1].strip() or None


def _get_current_user():
    """
    根据 JWT 获取当前用户对象
    """
    token = _get_token_from_header()
    if not token:
        return None, (jsonify({'error': '缺少或非法的 Authorization 头'}), 401)

    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=[current_app.config.get('JWT_ALGORITHM', 'HS256')]
        )
    except ExpiredSignatureError:
        return None, (jsonify({'error': 'Token 已过期'}), 401)
    except InvalidTokenError:
        return None, (jsonify({'error': '无效的 Token'}), 401)

    user_id = payload.get('user_id')
    if not user_id:
        return None, (jsonify({'error': 'Token 中缺少用户信息'}), 401)

    user = User.query.get(user_id)
    if not user:
        return None, (jsonify({'error': '用户不存在'}), 404)

    return user, None


def login_required(f):
    """
    登录验证装饰器（基于 JWT）
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, error_response = _get_current_user()
        if error_response:
            return error_response
        # 将 user 挂到视图函数参数上，方便使用
        return f(current_user=user, *args, **kwargs)

    return decorated_function


def admin_required(f):
    """
    管理员权限验证装饰器（统一使用）
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, error_response = _get_current_user()
        if error_response:
            return error_response

        if not user.is_admin():
            return jsonify({'error': '需要管理员权限'}), 403

        return f(current_user=user, *args, **kwargs)

    return decorated_function


def permission_required(permission_name):
    """
    权限验证装饰器
    检查当前用户是否具有指定权限（基于 RBAC 表）
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user, error_response = _get_current_user()
            if error_response:
                return error_response

            # 管理员拥有所有权限
            if user.is_admin():
                return f(current_user=user, *args, **kwargs)

            # 获取用户的所有角色
            user_roles = UserRole.query.filter_by(user_id=user.id).all()
            role_ids = [ur.role_id for ur in user_roles]

            if not role_ids:
                return jsonify({'error': f'需要"{permission_name}"权限'}), 403

            # 获取这些角色拥有的所有权限，并检查是否包含指定权限
            role_permissions = RolePermission.query.filter(
                RolePermission.role_id.in_(role_ids)
            ).all()

            permission_ids = [rp.permission_id for rp in role_permissions]
            if not permission_ids:
                return jsonify({'error': f'需要"{permission_name}"权限'}), 403

            has_permission = Permission.query.filter(
                Permission.id.in_(permission_ids),
                Permission.name == permission_name
            ).first()

            if not has_permission:
                return jsonify({'error': f'需要"{permission_name}"权限'}), 403

            return f(current_user=user, *args, **kwargs)

        return decorated_function

    return decorator


def role_required(role_name):
    """
    角色验证装饰器
    检查当前用户是否具有指定角色（基于 RBAC 表）
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user, error_response = _get_current_user()
            if error_response:
                return error_response

            # 获取用户的所有角色
            user_roles = UserRole.query.filter_by(user_id=user.id).all()
            role_ids = [ur.role_id for ur in user_roles]

            if not role_ids:
                return jsonify({'error': f'需要"{role_name}"角色'}), 403

            role = Role.query.filter(
                Role.id.in_(role_ids),
                Role.name == role_name
            ).first()

            if not role:
                return jsonify({'error': f'需要"{role_name}"角色'}), 403

            return f(current_user=user, *args, **kwargs)

        return decorated_function

    return decorator