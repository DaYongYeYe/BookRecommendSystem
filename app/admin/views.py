from flask import request, jsonify
from app.admin import bp
from app import db
from app.models import User
from app.rbac.decorators import admin_required


@bp.route('/users', methods=['GET'])
@admin_required
def get_users(current_user):
    users = User.query.all()
    return jsonify({
        'users': [user.to_dict() for user in users]
    }), 200

@bp.route('/users/<int:user_id>', methods=['GET'])
@admin_required
def get_user(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({'user': user.to_dict()}), 200

@bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400
    
    # 更新用户信息
    if 'username' in data:
        # 检查用户名是否已被其他用户使用
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': '用户名已被其他用户使用'}), 400
        user.username = data['username']
    
    if 'email' in data:
        # 检查邮箱是否已被其他用户使用
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': '邮箱已被其他用户使用'}), 400
        user.email = data['email']
    
    if 'role' in data:
        if data['role'] in ['user', 'admin']:
            user.role = data['role']
        else:
            return jsonify({'error': '角色必须是"user"或"admin"'}), 400
    
    db.session.commit()
    
    return jsonify({'message': '用户信息更新成功', 'user': user.to_dict()}), 200

@bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 不允许用户删除自己
    if user.id == current_user.id:
        return jsonify({'error': '不能删除自己的账户'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': '用户删除成功'}), 200