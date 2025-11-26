from flask import request, jsonify, session
from app.rbac import bp
from app import db
from app.models import User, Role, Permission, RolePermission, UserRole
from functools import wraps

def admin_required(f):
    """
    管理员权限验证装饰器
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '需要登录'}), 401
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            return jsonify({'error': '需要管理员权限'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/roles', methods=['GET'])
@admin_required
def get_roles():
    """
    获取所有角色列表
    """
    roles = Role.query.all()
    return jsonify({
        'roles': [role.to_dict() for role in roles]
    }), 200

@bp.route('/roles', methods=['POST'])
@admin_required
def create_role():
    """
    创建新角色
    """
    data = request.get_json()
    
    if not data or not data.get('name'):
        return jsonify({'error': '角色名是必需的'}), 400
    
    # 检查角色是否已存在
    if Role.query.filter_by(name=data['name']).first():
        return jsonify({'error': '角色已存在'}), 400
    
    role = Role(
        name=data['name'],
        description=data.get('description', '')
    )
    
    db.session.add(role)
    db.session.commit()
    
    return jsonify({
        'message': '角色创建成功',
        'role': role.to_dict()
    }), 201

@bp.route('/roles/<int:role_id>', methods=['PUT'])
@admin_required
def update_role(role_id):
    """
    更新角色信息
    """
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400
    
    if 'name' in data:
        # 检查新角色名是否与其他角色冲突
        existing_role = Role.query.filter_by(name=data['name']).first()
        if existing_role and existing_role.id != role.id:
            return jsonify({'error': '角色名已存在'}), 400
        role.name = data['name']
    
    if 'description' in data:
        role.description = data['description']
    
    db.session.commit()
    
    return jsonify({
        'message': '角色更新成功',
        'role': role.to_dict()
    }), 200

@bp.route('/roles/<int:role_id>', methods=['DELETE'])
@admin_required
def delete_role(role_id):
    """
    删除角色
    """
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404
    
    # 检查是否有用户拥有该角色
    user_roles = UserRole.query.filter_by(role_id=role_id).all()
    if user_roles:
        return jsonify({'error': '无法删除正在使用的角色，请先移除所有用户的角色分配'}), 400
    
    db.session.delete(role)
    db.session.commit()
    
    return jsonify({'message': '角色删除成功'}), 200

@bp.route('/permissions', methods=['GET'])
@admin_required
def get_permissions():
    """
    获取所有权限列表
    """
    permissions = Permission.query.all()
    return jsonify({
        'permissions': [permission.to_dict() for permission in permissions]
    }), 200

@bp.route('/permissions', methods=['POST'])
@admin_required
def create_permission():
    """
    创建新权限
    """
    data = request.get_json()
    
    if not data or not data.get('name'):
        return jsonify({'error': '权限名是必需的'}), 400
    
    # 检查权限是否已存在
    if Permission.query.filter_by(name=data['name']).first():
        return jsonify({'error': '权限已存在'}), 400
    
    permission = Permission(
        name=data['name'],
        description=data.get('description', '')
    )
    
    db.session.add(permission)
    db.session.commit()
    
    return jsonify({
        'message': '权限创建成功',
        'permission': permission.to_dict()
    }), 201

@bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@admin_required
def assign_permission_to_role(role_id):
    """
    为角色分配权限
    """
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404
    
    data = request.get_json()
    if not data or not data.get('permission_id'):
        return jsonify({'error': '权限ID是必需的'}), 400
    
    permission = Permission.query.get(data['permission_id'])
    if not permission:
        return jsonify({'error': '权限不存在'}), 404
    
    # 检查权限是否已分配给该角色
    existing_assignment = RolePermission.query.filter_by(
        role_id=role_id, 
        permission_id=data['permission_id']
    ).first()
    
    if existing_assignment:
        return jsonify({'error': '权限已分配给该角色'}), 400
    
    role_permission = RolePermission(
        role_id=role_id,
        permission_id=data['permission_id']
    )
    
    db.session.add(role_permission)
    db.session.commit()
    
    return jsonify({
        'message': '权限分配成功',
        'assignment': role_permission.to_dict()
    }), 201

@bp.route('/roles/<int:role_id>/permissions/<int:permission_id>', methods=['DELETE'])
@admin_required
def remove_permission_from_role(role_id, permission_id):
    """
    移除角色的权限
    """
    role_permission = RolePermission.query.filter_by(
        role_id=role_id,
        permission_id=permission_id
    ).first()
    
    if not role_permission:
        return jsonify({'error': '角色未拥有该权限'}), 404
    
    db.session.delete(role_permission)
    db.session.commit()
    
    return jsonify({'message': '权限移除成功'}), 200

@bp.route('/users/<int:user_id>/roles', methods=['POST'])
@admin_required
def assign_role_to_user(user_id):
    """
    为用户分配角色
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    data = request.get_json()
    if not data or not data.get('role_id'):
        return jsonify({'error': '角色ID是必需的'}), 400
    
    role = Role.query.get(data['role_id'])
    if not role:
        return jsonify({'error': '角色不存在'}), 404
    
    # 检查角色是否已分配给该用户
    existing_assignment = UserRole.query.filter_by(
        user_id=user_id,
        role_id=data['role_id']
    ).first()
    
    if existing_assignment:
        return jsonify({'error': '角色已分配给该用户'}), 400
    
    user_role = UserRole(
        user_id=user_id,
        role_id=data['role_id']
    )
    
    db.session.add(user_role)
    db.session.commit()
    
    return jsonify({
        'message': '角色分配成功',
        'assignment': user_role.to_dict()
    }), 201

@bp.route('/users/<int:user_id>/roles/<int:role_id>', methods=['DELETE'])
@admin_required
def remove_role_from_user(user_id, role_id):
    """
    移除用户的角色
    """
    user_role = UserRole.query.filter_by(
        user_id=user_id,
        role_id=role_id
    ).first()
    
    if not user_role:
        return jsonify({'error': '用户未拥有该角色'}), 404
    
    # 检查是否是最后一个管理员
    if role_id == 1:  # 假设管理员角色ID为1
        admin_users = UserRole.query.filter_by(role_id=1).all()
        if len(admin_users) <= 1:
            return jsonify({'error': '不能移除最后一个管理员'}), 400
    
    db.session.delete(user_role)
    db.session.commit()
    
    return jsonify({'message': '角色移除成功'}), 200

@bp.route('/users/<int:user_id>/permissions', methods=['GET'])
@admin_required
def get_user_permissions(user_id):
    """
    获取用户的所有权限（基于其角色）
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 获取用户的所有角色
    user_roles = UserRole.query.filter_by(user_id=user_id).all()
    role_ids = [ur.role_id for ur in user_roles]
    
    # 获取这些角色的所有权限
    role_permissions = RolePermission.query.filter(
        RolePermission.role_id.in_(role_ids)
    ).all()
    
    permission_ids = [rp.permission_id for rp in role_permissions]
    permissions = Permission.query.filter(
        Permission.id.in_(permission_ids)
    ).all()
    
    return jsonify({
        'permissions': [p.to_dict() for p in permissions]
    }), 200