from flask import jsonify, request

from app import db
from app.api import bp
from app.models import UserReadingProgress
from app.rbac.decorators import login_required
from app.services.reader_service import (
    build_reader_payload,
    create_book_comment,
    create_highlight,
    create_highlight_comment,
)


@bp.route('/books/<int:book_id>/reader', methods=['GET'])
def api_get_book_reader(book_id: int):
    payload = build_reader_payload(book_id)
    if not payload:
        return jsonify({'error': 'book not found'}), 404
    return jsonify(payload), 200


@bp.route('/books/<int:book_id>/landing', methods=['GET'])
def api_get_book_landing(book_id: int):
    payload = build_reader_payload(book_id)
    if not payload:
        return jsonify({'error': 'book not found'}), 404
    return jsonify({'book': payload['book'], 'book_comments': payload['book_comments'], 'outline': payload['outline']}), 200


@bp.route('/books/<int:book_id>/highlights', methods=['POST'])
@login_required
def api_create_highlight(current_user, book_id: int):
    highlight, error = create_highlight(book_id, request.get_json() or {})
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'highlight created', 'highlight': highlight}), 201


@bp.route('/books/<int:book_id>/highlights/<int:highlight_id>/comments', methods=['POST'])
@login_required
def api_create_highlight_comment(current_user, book_id: int, highlight_id: int):
    comment, error = create_highlight_comment(book_id, highlight_id, request.get_json() or {})
    if error == 'highlight not found':
        return jsonify({'error': error}), 404
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'comment created', 'comment': comment}), 201


@bp.route('/books/<int:book_id>/comments', methods=['POST'])
@login_required
def api_create_book_comment(current_user, book_id: int):
    comment, error = create_book_comment(book_id, request.get_json() or {})
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'book comment created', 'comment': comment}), 201


@bp.route('/books/<int:book_id>/progress', methods=['GET'])
@login_required
def api_get_book_progress(current_user, book_id: int):
    progress = UserReadingProgress.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if not progress:
        return jsonify({'has_progress': False, 'progress': None}), 200
    return jsonify({'has_progress': True, 'progress': progress.to_dict()}), 200


@bp.route('/books/<int:book_id>/progress', methods=['POST'])
@login_required
def api_save_book_progress(current_user, book_id: int):
    data = request.get_json() or {}
    section_id = (data.get('section_id') or '').strip() or None
    paragraph_id = (data.get('paragraph_id') or '').strip() or None
    scroll_percent = data.get('scroll_percent', 0)

    try:
        scroll_percent = float(scroll_percent)
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid scroll_percent'}), 400

    scroll_percent = max(0.0, min(100.0, scroll_percent))

    progress = UserReadingProgress.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if not progress:
        progress = UserReadingProgress(
            user_id=current_user.id,
            book_id=book_id,
            section_id=section_id,
            paragraph_id=paragraph_id,
            scroll_percent=scroll_percent,
        )
        db.session.add(progress)
    else:
        progress.section_id = section_id
        progress.paragraph_id = paragraph_id
        progress.scroll_percent = scroll_percent

    db.session.commit()
    return jsonify({'message': 'progress saved', 'progress': progress.to_dict()}), 200
