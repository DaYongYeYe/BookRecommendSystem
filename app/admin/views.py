from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, current_app
from sqlalchemy import func, literal
from sqlalchemy.exc import IntegrityError
from app.admin import bp
from app import db
from app.models import (
    User,
    Book,
    BookManuscript,
    ReaderBookComment,
    ReaderHighlightComment,
    ReaderHighlight,
    Category,
    Tag,
    BookTag,
)
from app.logging_utils import business_log_aspect
from app.rbac.decorators import admin_required
from app.services.publishing_service import publish_manuscript
from app.services.captcha import generate_captcha, verify_captcha

BOOK_STATUSES = ['published', 'draft', 'archived']


def _tenant_id(user):
    return int(getattr(user, 'tenant_id', 1) or 1)


def _is_super_admin(user):
    return bool(getattr(user, 'is_super_admin', False))


def _parse_category_id(raw_value):
    if raw_value in (None, ''):
        return None, None

    try:
        category_id = int(raw_value)
    except (TypeError, ValueError):
        return None, 'invalid category_id'

    category = Category.query.get(category_id)
    if not category:
        return None, 'category not found'

    return category_id, None


def _utc_day_range(day):
    start = datetime.combine(day, datetime.min.time())
    end = start + timedelta(days=1)
    return start, end


@bp.route('/dashboard/overview', methods=['GET'])
@admin_required
def get_dashboard_overview(current_user):
    today = datetime.utcnow().date()
    today_start, tomorrow_start = _utc_day_range(today)
    tenant_id = _tenant_id(current_user)

    total_users = User.query.filter_by(tenant_id=tenant_id).count()
    today_new_users = User.query.filter(
        User.tenant_id == tenant_id,
        User.created_at.isnot(None),
        User.created_at >= today_start,
        User.created_at < tomorrow_start,
    ).count()

    pending_manuscripts = BookManuscript.query.filter_by(status='submitted', tenant_id=tenant_id).count()

    violated_book_comments = ReaderBookComment.query.filter_by(is_violation=True, tenant_id=tenant_id).count()
    violated_highlight_comments = ReaderHighlightComment.query.filter_by(is_violation=True, tenant_id=tenant_id).count()
    violation_comments_total = violated_book_comments + violated_highlight_comments

    violated_today_book = ReaderBookComment.query.filter(
        ReaderBookComment.tenant_id == tenant_id,
        ReaderBookComment.is_violation.is_(True),
        ReaderBookComment.moderated_at.isnot(None),
        ReaderBookComment.moderated_at >= today_start,
        ReaderBookComment.moderated_at < tomorrow_start,
    ).count()
    violated_today_highlight = ReaderHighlightComment.query.filter(
        ReaderHighlightComment.tenant_id == tenant_id,
        ReaderHighlightComment.is_violation.is_(True),
        ReaderHighlightComment.moderated_at.isnot(None),
        ReaderHighlightComment.moderated_at >= today_start,
        ReaderHighlightComment.moderated_at < tomorrow_start,
    ).count()

    today_published_books = Book.query.filter(
        Book.tenant_id == tenant_id,
        Book.status == 'published',
        Book.published_at.isnot(None),
        Book.published_at >= today_start,
        Book.published_at < tomorrow_start,
    ).count()

    trend_days = []
    trend_series = []
    for delta in range(13, -1, -1):
        day = today - timedelta(days=delta)
        start, end = _utc_day_range(day)
        published_count = Book.query.filter(
            Book.tenant_id == tenant_id,
            Book.status == 'published',
            Book.published_at.isnot(None),
            Book.published_at >= start,
            Book.published_at < end,
        ).count()
        new_users_count = User.query.filter(
            User.tenant_id == tenant_id,
            User.created_at.isnot(None),
            User.created_at >= start,
            User.created_at < end,
        ).count()
        trend_days.append(day.isoformat())
        trend_series.append({
            'date': day.isoformat(),
            'published_books': int(published_count),
            'new_users': int(new_users_count),
        })

    return jsonify({
        'cards': {
            'pending_manuscripts': int(pending_manuscripts),
            'today_new_users': int(today_new_users),
            'violation_comments_total': int(violation_comments_total),
            'today_violation_comments': int(violated_today_book + violated_today_highlight),
            'today_published_books': int(today_published_books),
            'total_users': int(total_users),
        },
        'trend': {
            'dates': trend_days,
            'series': trend_series,
        },
    }), 200


@bp.route('/auth/register', methods=['POST'])
@business_log_aspect('admin.auth.register', tags=['admin', 'auth', 'business', 'aop'])
def admin_register():
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    register_code = data.get('register_code') or ''
    captcha_id = data.get('captcha_id') or ''
    captcha_code = data.get('captcha_code') or ''

    if not username or not email or not password or not captcha_id or not captcha_code:
        return jsonify({'error': '用户名、邮箱、密码和验证码是必需的'}), 400

    if not verify_captcha(captcha_id, captcha_code):
        return jsonify({'error': '验证码错误或已过期'}), 400

    expected_code = current_app.config.get('ADMIN_REGISTER_CODE', '')
    if not expected_code:
        return jsonify({'error': '当前环境未开启管理员注册'}), 403
    if register_code != expected_code:
        return jsonify({'error': '管理员注册码错误'}), 403

    tenant_id = int(current_app.config.get('DEFAULT_TENANT_ID', 1) or 1)

    if User.query.filter_by(username=username, tenant_id=tenant_id).first():
        return jsonify({'error': '用户名已存在'}), 400
    if User.query.filter_by(email=email, tenant_id=tenant_id).first():
        return jsonify({'error': '邮箱已被注册'}), 400

    has_super_admin = User.query.filter_by(tenant_id=tenant_id, is_super_admin=True).first() is not None
    user = User(
        username=username,
        name=username,
        email=email,
        role='admin',
        tenant_id=tenant_id,
        is_super_admin=(not has_super_admin),
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': '管理员注册成功', 'user': user.to_dict()}), 201


@bp.route('/auth/captcha', methods=['GET'])
def admin_captcha():
    return jsonify(generate_captcha()), 200


@bp.route('/auth/login', methods=['POST'])
@business_log_aspect('admin.auth.login', tags=['admin', 'auth', 'business', 'aop'])
def admin_login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    captcha_id = data.get('captcha_id') or ''
    captcha_code = data.get('captcha_code') or ''

    if not username or not password or not captcha_id or not captcha_code:
        return jsonify({'error': '用户名、密码和验证码是必需的'}), 400

    if not verify_captcha(captcha_id, captcha_code):
        return jsonify({'error': '验证码错误或已过期'}), 400

    tenant_id = int(current_app.config.get('DEFAULT_TENANT_ID', 1) or 1)
    user = User.query.filter_by(username=username, tenant_id=tenant_id).first()
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
        'is_super_admin': bool(user.is_super_admin),
        'tenant_id': int(user.tenant_id or tenant_id),
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
    tenant_id = _tenant_id(current_user)
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

    query = User.query.filter_by(tenant_id=tenant_id)
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
@business_log_aspect('admin.user.create', tags=['admin', 'user', 'business', 'aop'])
def create_user(current_user):
    tenant_id = _tenant_id(current_user)
    data = request.get_json() or {}

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    role = (data.get('role') or 'user').strip()
    is_super_admin = bool(data.get('is_super_admin', False))

    if not username or not email or not password:
        return jsonify({'error': '用户名、邮箱和密码是必需的'}), 400
    if role not in ['user', 'admin', 'creator', 'editor']:
        return jsonify({'error': '角色必须是"user"或"admin"'}), 400
    if is_super_admin and not _is_super_admin(current_user):
        return jsonify({'error': '仅超级管理员可以创建超级管理员'}), 403

    if User.query.filter_by(username=username, tenant_id=tenant_id).first():
        return jsonify({'error': '用户名已存在'}), 400
    if User.query.filter_by(email=email, tenant_id=tenant_id).first():
        return jsonify({'error': '邮箱已被注册'}), 400

    user = User(
        username=username,
        name=username,
        email=email,
        role=role,
        tenant_id=tenant_id,
        is_super_admin=is_super_admin and role == 'admin',
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': '用户创建成功', 'user': user.to_dict()}), 201

@bp.route('/users/<int:user_id>', methods=['GET'])
@admin_required
def get_user(current_user, user_id):
    user = User.query.filter_by(id=user_id, tenant_id=_tenant_id(current_user)).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({'user': user.to_dict()}), 200

@bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
@business_log_aspect('admin.user.update', tags=['admin', 'user', 'business', 'aop'])
def update_user(current_user, user_id):
    tenant_id = _tenant_id(current_user)
    user = User.query.filter_by(id=user_id, tenant_id=tenant_id).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400
    
    # 更新用户信息
    if 'username' in data:
        # 检查用户名是否已被其他用户使用
        existing_user = User.query.filter_by(username=data['username'], tenant_id=tenant_id).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': '用户名已被其他用户使用'}), 400
        user.username = data['username']
    
    if 'email' in data:
        # 检查邮箱是否已被其他用户使用
        existing_user = User.query.filter_by(email=data['email'], tenant_id=tenant_id).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': '邮箱已被其他用户使用'}), 400
        user.email = data['email']
    
    if 'role' in data:
        if data['role'] in ['user', 'admin', 'creator', 'editor']:
            user.role = data['role']
            if user.role != 'admin':
                user.is_super_admin = False
        else:
            return jsonify({'error': '角色必须是"user"或"admin"'}), 400
    if 'is_super_admin' in data:
        if not _is_super_admin(current_user):
            return jsonify({'error': '仅超级管理员可以修改超级管理员标记'}), 403
        user.is_super_admin = bool(data.get('is_super_admin')) and user.role == 'admin'
    
    db.session.commit()
    
    return jsonify({'message': '用户信息更新成功', 'user': user.to_dict()}), 200

@bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
@business_log_aspect('admin.user.delete', tags=['admin', 'user', 'business', 'aop'])
def delete_user(current_user, user_id):
    user = User.query.filter_by(id=user_id, tenant_id=_tenant_id(current_user)).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 不允许用户删除自己
    if user.id == current_user.id:
        return jsonify({'error': '不能删除自己的账户'}), 400
    if user.is_super_admin and not _is_super_admin(current_user):
        return jsonify({'error': '仅超级管理员可以删除超级管理员'}), 403
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': '用户删除成功'}), 200


@bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@admin_required
@business_log_aspect('admin.user.reset_password', tags=['admin', 'user', 'security', 'business', 'aop'])
def reset_user_password(current_user, user_id):
    user = User.query.filter_by(id=user_id, tenant_id=_tenant_id(current_user)).first()
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
    tenant_id = _tenant_id(current_user)
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

    query = Book.query.filter_by(tenant_id=tenant_id)
    if keyword:
        query = query.filter(
            (Book.title.like(f'%{keyword}%')) |
            (Book.author.like(f'%{keyword}%'))
        )

    total = query.count()
    books = query.order_by(Book.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    book_ids = [item.id for item in books]
    category_map = {}
    tag_map = {}

    if books:
        category_ids = list({item.category_id for item in books if item.category_id})
        if category_ids:
            categories = Category.query.filter(Category.id.in_(category_ids)).all()
            category_map = {item.id: item.name for item in categories}

        rows = (
            db.session.query(BookTag.book_id, Tag.id, Tag.label)
            .join(Tag, Tag.id == BookTag.tag_id)
            .filter(BookTag.book_id.in_(book_ids))
            .order_by(Tag.id.asc())
            .all()
        )
        for book_id, tag_id, tag_label in rows:
            tag_map.setdefault(book_id, []).append({'id': int(tag_id), 'label': tag_label})

    payload = []
    for book in books:
        item = book.to_dict()
        item['category_name'] = category_map.get(book.category_id)
        item['tags'] = tag_map.get(book.id, [])
        item['tag_ids'] = [entry['id'] for entry in item['tags']]
        payload.append(item)

    return jsonify({
        'books': payload,
        'pagination': {
            'page': page,
            'page_size': page_size,
            'total': total,
        }
    }), 200


@bp.route('/books', methods=['POST'])
@admin_required
@business_log_aspect('admin.book.create', tags=['admin', 'book', 'business', 'aop'])
def create_book(current_user):
    tenant_id = _tenant_id(current_user)
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

    status = (data.get('status') or 'published').strip().lower()
    if status not in BOOK_STATUSES:
        return jsonify({'error': 'invalid status'}), 400

    category_id, category_error = _parse_category_id(data.get('category_id'))
    if category_error:
        return jsonify({'error': category_error}), 400

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
        category_id=category_id,
        status=status,
        tenant_id=tenant_id,
        published_at=datetime.utcnow() if status == 'published' else None,
    )

    raw_tag_ids = data.get('tag_ids') or []
    if not isinstance(raw_tag_ids, list):
        return jsonify({'error': 'tag_ids must be an array'}), 400
    tag_ids = []
    for raw_tag_id in raw_tag_ids:
        try:
            tag_ids.append(int(raw_tag_id))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid tag_ids'}), 400
    tag_ids = list(set(tag_ids))
    if tag_ids:
        valid_tag_ids = {item.id for item in Tag.query.filter(Tag.id.in_(tag_ids)).all()}
        invalid_ids = [item for item in tag_ids if item not in valid_tag_ids]
        if invalid_ids:
            return jsonify({'error': f'invalid tag ids: {invalid_ids}'}), 400

    try:
        db.session.add(book)
        db.session.flush()
        for tag_id in tag_ids:
            db.session.add(BookTag(book_id=book.id, tag_id=tag_id))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'failed to create book'}), 400
    return jsonify({'message': '图书创建成功', 'book': book.to_dict()}), 201


@bp.route('/books/<int:book_id>', methods=['PUT'])
@admin_required
@business_log_aspect('admin.book.update', tags=['admin', 'book', 'business', 'aop'])
def update_book(current_user, book_id):
    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user)).first()
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
        category_id, category_error = _parse_category_id(data.get('category_id'))
        if category_error:
            return jsonify({'error': category_error}), 400
        book.category_id = category_id
    if 'status' in data:
        status = (data.get('status') or '').strip().lower()
        if status not in BOOK_STATUSES:
            return jsonify({'error': 'invalid status'}), 400
        book.status = status
        if status == 'published' and not book.published_at:
            book.published_at = datetime.utcnow()
        if status != 'published':
            book.published_at = None
    if 'tag_ids' in data:
        raw_tag_ids = data.get('tag_ids')
        if not isinstance(raw_tag_ids, list):
            return jsonify({'error': 'tag_ids must be an array'}), 400
        tag_ids = []
        for raw_tag_id in raw_tag_ids:
            try:
                tag_ids.append(int(raw_tag_id))
            except (TypeError, ValueError):
                return jsonify({'error': 'invalid tag_ids'}), 400
        tag_ids = list(set(tag_ids))
        if tag_ids:
            valid_tag_ids = {item.id for item in Tag.query.filter(Tag.id.in_(tag_ids)).all()}
            invalid_ids = [item for item in tag_ids if item not in valid_tag_ids]
            if invalid_ids:
                return jsonify({'error': f'invalid tag ids: {invalid_ids}'}), 400
        BookTag.query.filter_by(book_id=book.id).delete()
        for tag_id in tag_ids:
            db.session.add(BookTag(book_id=book.id, tag_id=tag_id))

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'failed to update book'}), 400
    return jsonify({'message': '图书更新成功', 'book': book.to_dict()}), 200


@bp.route('/books/<int:book_id>', methods=['DELETE'])
@admin_required
@business_log_aspect('admin.book.delete', tags=['admin', 'book', 'business', 'aop'])
def delete_book(current_user, book_id):
    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user)).first()
    if not book:
        return jsonify({'error': '图书不存在'}), 404
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': '图书删除成功'}), 200


@bp.route('/books/options', methods=['GET'])
@admin_required
def get_book_options(current_user):
    categories = Category.query.order_by(Category.name.asc()).all()
    tags = Tag.query.order_by(Tag.label.asc()).all()
    return jsonify({
        'categories': [item.to_dict() for item in categories],
        'tags': [item.to_dict() for item in tags],
        'statuses': [{'value': item, 'label': item} for item in BOOK_STATUSES],
    }), 200


@bp.route('/books/batch', methods=['POST'])
@admin_required
@business_log_aspect('admin.book.batch_update', tags=['admin', 'book', 'business', 'aop'])
def batch_update_books(current_user):
    tenant_id = _tenant_id(current_user)
    payload = request.get_json() or {}
    raw_book_ids = payload.get('book_ids')
    changes = payload.get('changes') or {}

    if not isinstance(raw_book_ids, list) or not raw_book_ids:
        return jsonify({'error': 'book_ids must be a non-empty array'}), 400
    if not isinstance(changes, dict) or not changes:
        return jsonify({'error': 'changes must be a non-empty object'}), 400

    book_ids = []
    for raw_book_id in raw_book_ids:
        try:
            book_ids.append(int(raw_book_id))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid book_ids'}), 400
    book_ids = list(set(book_ids))

    books = Book.query.filter(Book.tenant_id == tenant_id, Book.id.in_(book_ids)).all()
    found_ids = {item.id for item in books}
    missing_ids = [item for item in book_ids if item not in found_ids]
    if missing_ids:
        return jsonify({'error': f'books not found: {missing_ids}'}), 404

    parsed_status = None
    parsed_category_id = None
    parsed_is_featured = None
    parsed_tag_ids = None

    if 'status' in changes:
        parsed_status = (changes.get('status') or '').strip().lower()
        if parsed_status not in BOOK_STATUSES:
            return jsonify({'error': 'invalid status'}), 400

    if 'category_id' in changes:
        parsed_category_id, category_error = _parse_category_id(changes.get('category_id'))
        if category_error:
            return jsonify({'error': category_error}), 400

    if 'is_featured' in changes:
        parsed_is_featured = bool(changes.get('is_featured'))

    if 'tag_ids' in changes:
        raw_tag_ids = changes.get('tag_ids')
        if not isinstance(raw_tag_ids, list):
            return jsonify({'error': 'tag_ids must be an array'}), 400
        parsed_tag_ids = []
        for raw_tag_id in raw_tag_ids:
            try:
                parsed_tag_ids.append(int(raw_tag_id))
            except (TypeError, ValueError):
                return jsonify({'error': 'invalid tag_ids'}), 400
        parsed_tag_ids = list(set(parsed_tag_ids))
        if parsed_tag_ids:
            valid_tag_ids = {item.id for item in Tag.query.filter(Tag.id.in_(parsed_tag_ids)).all()}
            invalid_ids = [item for item in parsed_tag_ids if item not in valid_tag_ids]
            if invalid_ids:
                return jsonify({'error': f'invalid tag ids: {invalid_ids}'}), 400

    now = datetime.utcnow()
    updated_count = 0
    for book in books:
        touched = False
        if parsed_status is not None:
            book.status = parsed_status
            book.published_at = now if parsed_status == 'published' else None
            touched = True
        if 'category_id' in changes:
            book.category_id = parsed_category_id
            touched = True
        if parsed_is_featured is not None:
            book.is_featured = parsed_is_featured
            touched = True
        if touched:
            updated_count += 1

    if parsed_tag_ids is not None:
        BookTag.query.filter(BookTag.book_id.in_(book_ids)).delete(synchronize_session=False)
        for book_id in book_ids:
            for tag_id in parsed_tag_ids:
                db.session.add(BookTag(book_id=book_id, tag_id=tag_id))

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'failed to batch update books'}), 400
    return jsonify({'message': 'batch updated', 'updated_count': updated_count}), 200

@bp.route('/manuscripts', methods=['GET'])
@admin_required
def get_manuscripts(current_user):
    tenant_id = _tenant_id(current_user)
    status = (request.args.get('status') or '').strip()
    creator_id = request.args.get('creator_id')

    query = BookManuscript.query.filter_by(tenant_id=tenant_id)
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
@business_log_aspect('admin.manuscript.review', tags=['admin', 'manuscript', 'review', 'business', 'aop'])
def review_manuscript(current_user, manuscript_id):
    manuscript = BookManuscript.query.filter_by(id=manuscript_id, tenant_id=_tenant_id(current_user)).first()
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
@business_log_aspect('admin.manuscript.publish', tags=['admin', 'manuscript', 'publish', 'business', 'aop'])
def publish_reviewed_manuscript(current_user, manuscript_id):
    manuscript = BookManuscript.query.filter_by(id=manuscript_id, tenant_id=_tenant_id(current_user)).first()
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


@bp.route('/comments', methods=['GET'])
@admin_required
def get_comments(current_user):
    tenant_id = _tenant_id(current_user)
    comment_type = (request.args.get('type') or '').strip().lower()
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

    def _build_book_comment_query():
        query = db.session.query(
            ReaderBookComment.id.label('id'),
            literal('book').label('type'),
            ReaderBookComment.book_id.label('book_id'),
            Book.title.label('book_title'),
            literal(None).label('highlight_id'),
            ReaderBookComment.author.label('author'),
            ReaderBookComment.content.label('content'),
            ReaderBookComment.is_violation.label('is_violation'),
            ReaderBookComment.violation_reason.label('violation_reason'),
            ReaderBookComment.moderated_at.label('moderated_at'),
            ReaderBookComment.created_at.label('created_at'),
        ).outerjoin(
            Book, ReaderBookComment.book_id == Book.id
        )
        query = query.filter(ReaderBookComment.tenant_id == tenant_id)
        if keyword:
            query = query.filter(
                (ReaderBookComment.content.like(f'%{keyword}%')) |
                (ReaderBookComment.author.like(f'%{keyword}%')) |
                (Book.title.like(f'%{keyword}%'))
            )
        return query

    def _build_highlight_comment_query():
        query = db.session.query(
            ReaderHighlightComment.id.label('id'),
            literal('highlight').label('type'),
            ReaderHighlight.book_id.label('book_id'),
            Book.title.label('book_title'),
            ReaderHighlightComment.highlight_id.label('highlight_id'),
            ReaderHighlightComment.author.label('author'),
            ReaderHighlightComment.content.label('content'),
            ReaderHighlightComment.is_violation.label('is_violation'),
            ReaderHighlightComment.violation_reason.label('violation_reason'),
            ReaderHighlightComment.moderated_at.label('moderated_at'),
            ReaderHighlightComment.created_at.label('created_at'),
        ).outerjoin(
            ReaderHighlight, ReaderHighlightComment.highlight_id == ReaderHighlight.id
        ).outerjoin(
            Book, ReaderHighlight.book_id == Book.id
        )
        query = query.filter(ReaderHighlightComment.tenant_id == tenant_id)
        if keyword:
            query = query.filter(
                (ReaderHighlightComment.content.like(f'%{keyword}%')) |
                (ReaderHighlightComment.author.like(f'%{keyword}%')) |
                (Book.title.like(f'%{keyword}%'))
            )
        return query

    def _serialize_comment_row(row):
        return {
            'id': row.id,
            'type': row.type,
            'book_id': row.book_id,
            'book_title': row.book_title,
            'highlight_id': row.highlight_id,
            'author': row.author,
            'content': row.content,
            'is_violation': bool(row.is_violation),
            'violation_reason': row.violation_reason,
            'moderated_at': row.moderated_at.isoformat() if row.moderated_at else None,
            'created_at': row.created_at.isoformat() if row.created_at else None,
        }

    if comment_type == 'book':
        union_query = _build_book_comment_query()
    elif comment_type == 'highlight':
        union_query = _build_highlight_comment_query()
    else:
        union_query = _build_book_comment_query().union_all(_build_highlight_comment_query())

    query = union_query.subquery()
    total = db.session.query(func.count()).select_from(query).scalar() or 0
    rows = (
        db.session.query(query)
        .order_by(query.c.created_at.desc(), query.c.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = [_serialize_comment_row(row) for row in rows]

    return jsonify({
        'items': items,
        'pagination': {
            'page': page,
            'page_size': page_size,
            'total': total,
        }
    }), 200


@bp.route('/comments/<string:comment_type>/<int:comment_id>', methods=['DELETE'])
@admin_required
@business_log_aspect('admin.comment.delete', tags=['admin', 'comment', 'business', 'aop'])
def delete_comment(current_user, comment_type, comment_id):
    kind = (comment_type or '').strip().lower()
    if kind == 'book':
        comment = ReaderBookComment.query.filter_by(id=comment_id, tenant_id=_tenant_id(current_user)).first()
    elif kind == 'highlight':
        comment = ReaderHighlightComment.query.filter_by(id=comment_id, tenant_id=_tenant_id(current_user)).first()
    else:
        return jsonify({'error': 'invalid comment type'}), 400

    if not comment:
        return jsonify({'error': '评论不存在'}), 404

    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': '评论删除成功'}), 200


@bp.route('/comments/<string:comment_type>/<int:comment_id>/violation', methods=['POST'])
@admin_required
@business_log_aspect('admin.comment.violation', tags=['admin', 'comment', 'business', 'aop'])
def mark_comment_violation(current_user, comment_type, comment_id):
    kind = (comment_type or '').strip().lower()
    if kind == 'book':
        comment = ReaderBookComment.query.filter_by(id=comment_id, tenant_id=_tenant_id(current_user)).first()
    elif kind == 'highlight':
        comment = ReaderHighlightComment.query.filter_by(id=comment_id, tenant_id=_tenant_id(current_user)).first()
    else:
        return jsonify({'error': 'invalid comment type'}), 400

    if not comment:
        return jsonify({'error': '评论不存在'}), 404

    payload = request.get_json() or {}
    is_violation = bool(payload.get('is_violation'))
    violation_reason = (payload.get('violation_reason') or '').strip() or None

    comment.is_violation = is_violation
    comment.violation_reason = violation_reason
    comment.moderated_by = current_user.id
    comment.moderated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': '评论违规状态已更新'}), 200
