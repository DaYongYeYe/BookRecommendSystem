from flask import request, jsonify

from app import db
from app.models import Permission, Role, RolePermission, User, UserRole
from app.rbac import bp
from app.rbac.decorators import super_admin_required


@bp.route('/roles', methods=['GET'])
@super_admin_required
def get_roles(current_user):
    roles = Role.query.all()
    return (
        jsonify(
            {
                'roles': [
                    {
                        **role.to_dict(),
                        'permission_count': RolePermission.query.filter_by(role_id=role.id).count(),
                        'user_count': UserRole.query.filter_by(role_id=role.id).count(),
                    }
                    for role in roles
                ]
            }
        ),
        200,
    )


@bp.route('/roles', methods=['POST'])
@super_admin_required
def create_role(current_user):
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'error': '角色名称是必填项'}), 400
    if Role.query.filter_by(name=name).first():
        return jsonify({'error': '角色已存在'}), 400

    role = Role(name=name, description=(data.get('description') or '').strip())
    db.session.add(role)
    db.session.commit()

    return jsonify({'message': '角色创建成功', 'role': role.to_dict()}), 201


@bp.route('/roles/<int:role_id>', methods=['PUT'])
@super_admin_required
def update_role(current_user, role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404

    data = request.get_json() or {}
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400

    if 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': '角色名称是必填项'}), 400
        existing_role = Role.query.filter_by(name=name).first()
        if existing_role and existing_role.id != role.id:
            return jsonify({'error': '角色名称已存在'}), 400
        role.name = name

    if 'description' in data:
        role.description = (data.get('description') or '').strip()

    db.session.commit()
    return jsonify({'message': '角色更新成功', 'role': role.to_dict()}), 200


@bp.route('/roles/<int:role_id>', methods=['DELETE'])
@super_admin_required
def delete_role(current_user, role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404

    if UserRole.query.filter_by(role_id=role_id).first():
        return jsonify({'error': '存在用户绑定，无法删除该角色，请先移除用户角色分配'}), 400

    db.session.delete(role)
    db.session.commit()
    return jsonify({'message': '角色删除成功'}), 200


@bp.route('/permissions', methods=['GET'])
@super_admin_required
def get_permissions(current_user):
    permissions = Permission.query.all()
    return jsonify({'permissions': [permission.to_dict() for permission in permissions]}), 200


@bp.route('/permissions', methods=['POST'])
@super_admin_required
def create_permission(current_user):
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'error': '权限名称是必填项'}), 400
    if Permission.query.filter_by(name=name).first():
        return jsonify({'error': '权限已存在'}), 400

    permission = Permission(name=name, description=(data.get('description') or '').strip())
    db.session.add(permission)
    db.session.commit()

    return jsonify({'message': '权限创建成功', 'permission': permission.to_dict()}), 201


@bp.route('/roles/<int:role_id>/permissions', methods=['GET'])
@super_admin_required
def get_role_permissions(current_user, role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404

    assignments = RolePermission.query.filter_by(role_id=role_id).all()
    permission_ids = [assignment.permission_id for assignment in assignments]
    permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all() if permission_ids else []

    return jsonify({'permissions': [permission.to_dict() for permission in permissions]}), 200


@bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@super_admin_required
def assign_permission_to_role(current_user, role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404

    data = request.get_json() or {}
    permission_id = data.get('permission_id')
    if not permission_id:
        return jsonify({'error': '权限ID是必需的'}), 400

    permission = Permission.query.get(permission_id)
    if not permission:
        return jsonify({'error': '权限不存在'}), 404

    existing_assignment = RolePermission.query.filter_by(role_id=role_id, permission_id=permission_id).first()
    if existing_assignment:
        return jsonify({'error': '权限已分配给该角色'}), 400

    role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
    db.session.add(role_permission)
    db.session.commit()

    return jsonify({'message': '权限分配成功', 'assignment': role_permission.to_dict()}), 201


@bp.route('/roles/<int:role_id>/permissions/<int:permission_id>', methods=['DELETE'])
@super_admin_required
def remove_permission_from_role(current_user, role_id, permission_id):
    role_permission = RolePermission.query.filter_by(role_id=role_id, permission_id=permission_id).first()
    if not role_permission:
        return jsonify({'error': '角色未拥有该权限'}), 404

    db.session.delete(role_permission)
    db.session.commit()
    return jsonify({'message': '权限移除成功'}), 200


@bp.route('/users/<int:user_id>/roles', methods=['GET'])
@super_admin_required
def get_user_roles(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    assignments = UserRole.query.filter_by(user_id=user_id).all()
    role_ids = [assignment.role_id for assignment in assignments]
    roles = Role.query.filter(Role.id.in_(role_ids)).all() if role_ids else []

    return jsonify({'roles': [role.to_dict() for role in roles]}), 200


@bp.route('/users/<int:user_id>/roles', methods=['POST'])
@super_admin_required
def assign_role_to_user(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    data = request.get_json() or {}
    role_id = data.get('role_id')
    if not role_id:
        return jsonify({'error': '角色ID是必需的'}), 400

    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': '角色不存在'}), 404

    existing_assignment = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
    if existing_assignment:
        return jsonify({'error': '角色已分配给该用户'}), 400

    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.session.add(user_role)
    db.session.commit()

    return jsonify({'message': '角色分配成功', 'assignment': user_role.to_dict()}), 201


@bp.route('/users/<int:user_id>/roles/<int:role_id>', methods=['DELETE'])
@super_admin_required
def remove_role_from_user(current_user, user_id, role_id):
    user_role = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
    if not user_role:
        return jsonify({'error': '用户未拥有该角色'}), 404

    if role_id == 1:
        admin_users = UserRole.query.filter_by(role_id=1).all()
        if len(admin_users) <= 1:
            return jsonify({'error': '不能移除最后一个管理员'}), 400

    db.session.delete(user_role)
    db.session.commit()
    return jsonify({'message': '角色移除成功'}), 200


@bp.route('/users/<int:user_id>/permissions', methods=['GET'])
@super_admin_required
def get_user_permissions(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    user_roles = UserRole.query.filter_by(user_id=user_id).all()
    role_ids = [assignment.role_id for assignment in user_roles]
    role_permissions = RolePermission.query.filter(RolePermission.role_id.in_(role_ids)).all() if role_ids else []

    permission_ids = [assignment.permission_id for assignment in role_permissions]
    permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all() if permission_ids else []

    return jsonify({'permissions': [permission.to_dict() for permission in permissions]}), 200
