from functools import wraps
from flask import request, jsonify, session
from app.models import User, Role, Permission, RolePermission, UserRole

def permission_required(permission_name):
    """
    权限验证装饰器
    检查当前用户是否具有指定权限
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 检查用户是否登录
            if 'user_id' not in session:
                return jsonify({'error': '需要登录'}), 401
            
            user = User.query.get(session['user_id'])
            if not user:
                return jsonify({'error': '用户不存在'}), 404
            
            # 获取用户的所有角色
            user_roles = UserRole.query.filter_by(user_id=user.id).all()
            role_ids = [ur.role_id for ur in user_roles]
            
            # 如果用户是管理员，拥有所有权限
            if user.is_admin():
                return f(*args, **kwargs)
            
            # 获取这些角色拥有的所有权限
            role_permissions = RolePermission.query.filter(
                RolePermission.role_id.in_(role_ids)
            ).all()
            
            permission_ids = [rp.permission_id for rp in role_permissions]
            permissions = Permission.query.filter(
                Permission.id.in_(permission_ids),
                Permission.name == permission_name
            ).all()
            
            # 检查用户是否拥有指定权限
            if not permissions:
                return jsonify({'error': f'需要"{permission_name}"权限'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_required(role_name):
    """
    角色验证装饰器
    检查当前用户是否具有指定角色
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 检查用户是否登录
            if 'user_id' not in session:
                return jsonify({'error': '需要登录'}), 401
            
            user = User.query.get(session['user_id'])
            if not user:
                return jsonify({'error': '用户不存在'}), 404
            
            # 获取用户的所有角色
            user_roles = UserRole.query.filter_by(user_id=user.id).all()
            role_ids = [ur.role_id for ur in user_roles]
            
            # 检查用户是否拥有指定角色
            role = Role.query.filter(
                Role.id.in_(role_ids),
                Role.name == role_name
            ).first()
            
            if not role:
                return jsonify({'error': f'需要"{role_name}"角色'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator