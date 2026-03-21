from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, current_app
from app.admin import bp
from app import db
from app.models import User, Book, BookManuscript
from app.rbac.decorators import admin_required
from app.services.publishing_service import publish_manuscript


@bp.route('/auth/register', methods=['POST'])
def admin_register():
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    register_code = data.get('register_code') or ''

    if not username or not email or not password:
        return jsonify({'error': '用户名、邮箱和密码是必需的'}), 400

    expected_code = current_app.config.get('ADMIN_REGISTER_CODE', '')
    if not expected_code:
        return jsonify({'error': '当前环境未开启管理员注册'}), 403
    if register_code != expected_code:
        return jsonify({'error': '管理员注册码错误'}), 403

    if User.query.filter_by(username=username).first():
        return jsonify({'error': '用户名已存在'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': '邮箱已被注册'}), 400

    user = User(username=username, name=username, email=email, role='admin')
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': '管理员注册成功', 'user': user.to_dict()}), 201


@bp.route('/auth/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': '用户名和密码是必需的'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': '用户名或密码错误'}), 401
    if not user.is_admin():
        return jsonify({'error': '该账号无管理后台访问权限'}), 403

    expires_delta = timedelta(seconds=current_app.config.get('JWT_EXPIRES_IN', 7200))
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'is_admin': True,
        'exp': datetime.utcnow() + expires_delta
    }
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256')
    )

    return jsonify({
        'message': '登录成功',
        'token': token,
        'user': user.to_dict()
    }), 200


@bp.route('/users', methods=['GET'])
@admin_required
def get_users(current_user):
    keyword = (request.args.get('keyword') or '').strip()
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get('page_size', 10))
    except ValueError:
        page_size = 10
    page_size = min(max(page_size, 1), 100)

    query = User.query
    if keyword:
        query = query.filter(
            (User.username.like(f'%{keyword}%')) |
            (User.email.like(f'%{keyword}%'))
        )

    total = query.count()
    users = query.order_by(User.id.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return jsonify({
        'users': [user.to_dict() for user in users],
        'pagination': {
            'page': page,
            'page_size': page_size,
            'total': total,
        }
    }), 200


@bp.route('/users', methods=['POST'])
@admin_required
def create_user(current_user):
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    role = (data.get('role') or 'user').strip()

    if not username or not email or not password:
        return jsonify({'error': '用户名、邮箱和密码是必需的'}), 400
    if role not in ['user', 'admin', 'creator', 'editor']:
        return jsonify({'error': '角色必须是"user"或"admin"'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': '用户名已存在'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': '邮箱已被注册'}), 400

    user = User(username=username, name=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': '用户创建成功', 'user': user.to_dict()}), 201

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
        if data['role'] in ['user', 'admin', 'creator', 'editor']:
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


@bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@admin_required
def reset_user_password(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    data = request.get_json() or {}
    new_password = data.get('new_password') or ''
    if not new_password:
        return jsonify({'error': '新密码不能为空'}), 400

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': '用户密码重置成功'}), 200


@bp.route('/books', methods=['GET'])
@admin_required
def get_books(current_user):
    keyword = (request.args.get('keyword') or '').strip()
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get('page_size', 10))
    except ValueError:
        page_size = 10
    page_size = min(max(page_size, 1), 100)

    query = Book.query
    if keyword:
        query = query.filter(
            (Book.title.like(f'%{keyword}%')) |
            (Book.author.like(f'%{keyword}%'))
        )

    total = query.count()
    books = query.order_by(Book.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return jsonify({
        'books': [book.to_dict() for book in books],
        'pagination': {
            'page': page,
            'page_size': page_size,
            'total': total,
        }
    }), 200


@bp.route('/books', methods=['POST'])
@admin_required
def create_book(current_user):
    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': '书名不能为空'}), 400

    def parse_float(value):
        if value in [None, '']:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def parse_int(value, default=0):
        if value in [None, '']:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    book = Book(
        title=title,
        subtitle=(data.get('subtitle') or '').strip() or None,
        author=(data.get('author') or '').strip() or None,
        description=(data.get('description') or '').strip() or None,
        cover=(data.get('cover') or '').strip() or None,
        score=parse_float(data.get('score')),
        rating=parse_float(data.get('rating')),
        rating_count=parse_int(data.get('rating_count'), 0),
        recent_reads=parse_int(data.get('recent_reads'), 0),
        is_featured=bool(data.get('is_featured', False)),
        category_id=parse_int(data.get('category_id'), None),
    )
    db.session.add(book)
    db.session.commit()
    return jsonify({'message': '图书创建成功', 'book': book.to_dict()}), 201


@bp.route('/books/<int:book_id>', methods=['PUT'])
@admin_required
def update_book(current_user, book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'error': '图书不存在'}), 404

    data = request.get_json() or {}
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400

    def parse_float(value):
        if value in [None, '']:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def parse_int(value, keep_none=False):
        if value in [None, '']:
            return None if keep_none else 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return None if keep_none else 0

    if 'title' in data:
        title = (data.get('title') or '').strip()
        if not title:
            return jsonify({'error': '书名不能为空'}), 400
        book.title = title
    if 'subtitle' in data:
        book.subtitle = (data.get('subtitle') or '').strip() or None
    if 'author' in data:
        book.author = (data.get('author') or '').strip() or None
    if 'description' in data:
        book.description = (data.get('description') or '').strip() or None
    if 'cover' in data:
        book.cover = (data.get('cover') or '').strip() or None
    if 'score' in data:
        book.score = parse_float(data.get('score'))
    if 'rating' in data:
        book.rating = parse_float(data.get('rating'))
    if 'rating_count' in data:
        book.rating_count = parse_int(data.get('rating_count'))
    if 'recent_reads' in data:
        book.recent_reads = parse_int(data.get('recent_reads'))
    if 'is_featured' in data:
        book.is_featured = bool(data.get('is_featured'))
    if 'category_id' in data:
        book.category_id = parse_int(data.get('category_id'), keep_none=True)

    db.session.commit()
    return jsonify({'message': '图书更新成功', 'book': book.to_dict()}), 200


@bp.route('/books/<int:book_id>', methods=['DELETE'])
@admin_required
def delete_book(current_user, book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'error': '图书不存在'}), 404
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': '图书删除成功'}), 200

@bp.route('/manuscripts', methods=['GET'])
@admin_required
def get_manuscripts(current_user):
    status = (request.args.get('status') or '').strip()
    creator_id = request.args.get('creator_id')

    query = BookManuscript.query
    if status:
        query = query.filter_by(status=status)
    if creator_id not in (None, ''):
        try:
            query = query.filter_by(creator_id=int(creator_id))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid creator_id'}), 400

    manuscripts = query.order_by(BookManuscript.updated_at.desc(), BookManuscript.id.desc()).all()
    return jsonify({'items': [row.to_dict() for row in manuscripts]}), 200


@bp.route('/manuscripts/<int:manuscript_id>/review', methods=['POST'])
@admin_required
def review_manuscript(current_user, manuscript_id):
    manuscript = BookManuscript.query.get(manuscript_id)
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404

    payload = request.get_json() or {}
    action = (payload.get('action') or '').strip().lower()
    review_comment = (payload.get('review_comment') or '').strip() or None
    if action not in ('approve', 'reject'):
        return jsonify({'error': 'action must be approve or reject'}), 400
    if manuscript.status not in ('submitted', 'approved', 'rejected'):
        return jsonify({'error': 'manuscript is not in reviewable status'}), 400

    manuscript.reviewed_by = current_user.id
    manuscript.reviewed_at = datetime.utcnow()
    manuscript.review_comment = review_comment
    manuscript.status = 'approved' if action == 'approve' else 'rejected'
    db.session.commit()
    return jsonify({'message': 'review updated', 'manuscript': manuscript.to_dict()}), 200


@bp.route('/manuscripts/<int:manuscript_id>/publish', methods=['POST'])
@admin_required
def publish_reviewed_manuscript(current_user, manuscript_id):
    manuscript = BookManuscript.query.get(manuscript_id)
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404

    version, error = publish_manuscript(manuscript, current_user)
    if error:
        return jsonify({'error': error}), 400

    return jsonify({
        'message': 'manuscript published',
        'book_id': manuscript.book_id,
        'manuscript': manuscript.to_dict(),
        'version': version.to_dict(),
    }), 200
