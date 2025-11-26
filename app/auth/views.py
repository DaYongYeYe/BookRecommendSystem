from flask import request, jsonify, session
from app.auth import bp
from app import db
from app.models import User
from werkzeug.security import check_password_hash

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # 检查必需字段
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': '用户名、邮箱和密码是必需的'}), 400
    
    # 检查用户是否已存在
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': '用户名已存在'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': '邮箱已被注册'}), 400
    
    # 创建新用户
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': '用户注册成功', 'user': user.to_dict()}), 201

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # 检查必需字段
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': '用户名和密码是必需的'}), 400
    
    # 查找用户
    user = User.query.filter_by(username=data['username']).first()
    
    # 验证用户和密码
    if not user or not user.check_password(data['password']):
        return jsonify({'error': '用户名或密码错误'}), 401
    
    # 设置会话
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    
    return jsonify({
        'message': '登录成功', 
        'user': user.to_dict()
    }), 200

@bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': '已退出登录'}), 200

@bp.route('/check', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({
                'is_authenticated': True,
                'user': user.to_dict()
            }), 200
    
    return jsonify({'is_authenticated': False}), 401