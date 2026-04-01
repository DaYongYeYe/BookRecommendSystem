from flask import current_app, request, jsonify

from app import db
from app.models import User, Book, UserShelf, UserReadingProgress
from app.rbac.decorators import login_required
from app.services.tencent_cos import upload_image
from app.logging_utils import business_log_aspect
from app.user import bp

ALLOWED_AVATAR_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}


@bp.route('/profile', methods=['GET'])
@login_required
def get_profile(current_user):
    return jsonify({'user': current_user.to_dict()}), 200


@bp.route('/profile', methods=['PUT'])
@login_required
@business_log_aspect('user.profile_update', tags=['user', 'business', 'aop'])
def update_profile(current_user):
    data = request.get_json() or {}
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400

    if 'name' in data:
        current_user.name = (data.get('name') or '').strip() or None

    if 'pen_name' in data:
        pen_name = (data.get('pen_name') or '').strip()
        if pen_name and len(pen_name) > 80:
            return jsonify({'error': '笔名长度不能超过 80 个字符'}), 400
        current_user.pen_name = pen_name or None

    if 'avatar_url' in data:
        current_user.avatar_url = (data.get('avatar_url') or '').strip() or None

    if 'age' in data:
        raw_age = data.get('age')
        if raw_age in (None, ''):
            current_user.age = None
        else:
            try:
                parsed_age = int(raw_age)
            except (TypeError, ValueError):
                return jsonify({'error': '年龄必须是数字'}), 400
            if parsed_age < 1 or parsed_age > 120:
                return jsonify({'error': '年龄需在 1-120 之间'}), 400
            current_user.age = parsed_age

    if 'province' in data:
        current_user.province = (data.get('province') or '').strip() or None

    if 'city' in data:
        current_user.city = (data.get('city') or '').strip() or None

    if 'email' in data:
        email = (data.get('email') or '').strip()
        if not email:
            return jsonify({'error': '邮箱不能为空'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != current_user.id:
            return jsonify({'error': '邮箱已被其他用户使用'}), 400

        current_user.email = email

    db.session.commit()
    return jsonify({'message': '用户信息更新成功', 'user': current_user.to_dict()}), 200


@bp.route('/avatar/upload', methods=['POST'])
@login_required
@business_log_aspect('user.avatar_upload', tags=['user', 'business', 'avatar', 'aop'])
def upload_avatar(current_user):
    file_obj = request.files.get('avatar')
    max_size = int(current_app.config.get('MAX_AVATAR_UPLOAD_SIZE', 2 * 1024 * 1024))
    avatar_url, error = upload_image(
        file_obj,
        folder=f'avatars/{current_user.id}',
        allowed_extensions=ALLOWED_AVATAR_EXTENSIONS,
        max_size=max_size,
    )
    if error:
        status = 500 if error in ('cos not configured', 'invalid cos secret id', 'cos upload failed') else 400
        return jsonify({'error': error}), status

    current_user.avatar_url = avatar_url
    db.session.commit()
    return jsonify({'message': '头像上传成功', 'avatar_url': avatar_url, 'user': current_user.to_dict()}), 200


@bp.route('/change_password', methods=['POST'])
@login_required
@business_log_aspect('user.change_password', tags=['user', 'business', 'security', 'aop'])
def change_password(current_user):
    data = request.get_json() or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not old_password or not new_password:
        return jsonify({'error': '请提供旧密码和新密码'}), 400

    if not current_user.check_password(old_password):
        return jsonify({'error': '旧密码错误'}), 400

    current_user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': '密码修改成功'}), 200


@bp.route('/favorites', methods=['GET'])
@login_required
def get_favorites(current_user):
    records = (
        UserShelf.query.filter_by(user_id=current_user.id)
        .order_by(UserShelf.created_at.desc(), UserShelf.id.desc())
        .all()
    )
    book_ids = [record.book_id for record in records]
    books = Book.query.filter(Book.id.in_(book_ids), Book.status == 'published').all() if book_ids else []
    books_map = {book.id: book for book in books}

    items = []
    for record in records:
        book = books_map.get(record.book_id)
        if not book:
            continue
        payload = book.to_dict()
        payload['favorited_at'] = record.created_at.isoformat() if record.created_at else None
        items.append(payload)

    return jsonify({'items': items}), 200


@bp.route('/history', methods=['GET'])
@login_required
def get_history(current_user):
    progress_items = (
        UserReadingProgress.query.filter_by(user_id=current_user.id)
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .all()
    )
    book_ids = [item.book_id for item in progress_items]
    books = Book.query.filter(Book.id.in_(book_ids), Book.status == 'published').all() if book_ids else []
    books_map = {book.id: book for book in books}

    items = []
    for progress in progress_items:
        book = books_map.get(progress.book_id)
        if not book:
            continue
        payload = book.to_dict()
        payload['history'] = {
            'section_id': progress.section_id,
            'paragraph_id': progress.paragraph_id,
            'scroll_percent': float(progress.scroll_percent or 0),
            'updated_at': progress.updated_at.isoformat() if progress.updated_at else None,
        }
        items.append(payload)

    return jsonify({'items': items}), 200
