from flask import request, jsonify

from app import db
from app.models import User, Book, UserShelf, UserReadingProgress
from app.rbac.decorators import login_required
from app.user import bp


@bp.route('/profile', methods=['GET'])
@login_required
def get_profile(current_user):
    return jsonify({'user': current_user.to_dict()}), 200


@bp.route('/profile', methods=['PUT'])
@login_required
def update_profile(current_user):
    data = request.get_json() or {}
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400

    if 'name' in data:
        current_user.name = (data.get('name') or '').strip() or None

    if 'avatar_url' in data:
        current_user.avatar_url = (data.get('avatar_url') or '').strip() or None

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


@bp.route('/change_password', methods=['POST'])
@login_required
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
    books = Book.query.filter(Book.id.in_(book_ids)).all() if book_ids else []
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
    books = Book.query.filter(Book.id.in_(book_ids)).all() if book_ids else []
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
