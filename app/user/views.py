from flask import request, jsonify, session
from app.user import bp
from app import db
from app.models import User
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '需要登录'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '需要登录'}), 401
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            return jsonify({'error': '需要管理员权限'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({'user': user.to_dict()}), 200

@bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400
    
    # 更新用户信息（不包括密码）
    if 'email' in data:
        # 检查邮箱是否已被其他用户使用
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': '邮箱已被其他用户使用'}), 400
        user.email = data['email']
    
    db.session.commit()
    
    return jsonify({'message': '用户信息更新成功', 'user': user.to_dict()}), 200

@bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    data = request.get_json()
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({'error': '请提供旧密码和新密码'}), 400
    
    # 验证旧密码
    if not user.check_password(data['old_password']):
        return jsonify({'error': '旧密码错误'}), 400
    
    # 设置新密码
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': '密码修改成功'}), 200