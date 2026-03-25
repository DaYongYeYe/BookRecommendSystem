from uuid import uuid4

from flask import jsonify, request

from app import db
from app.api import bp
from app.models import BookAnalyticsEvent, UserReadingProgress
from app.rbac.decorators import login_optional, login_required
from app.services.reader_service import (
    build_reader_payload,
    create_book_comment,
    create_highlight,
    create_highlight_comment,
    get_reader_preferences,
    save_reader_preferences,
)


def _clean_text(value, max_len: int):
    text = (value or '').strip()
    if not text:
        return None
    return text[:max_len]


def _track_book_event(
    *,
    book_id: int,
    current_user,
    event_type: str,
    session_id: str | None = None,
    read_duration_seconds: int = 0,
    geo_label: str | None = None,
    age_group: str | None = None,
):
    db.session.add(
        BookAnalyticsEvent(
            book_id=book_id,
            user_id=getattr(current_user, 'id', None),
            event_type=event_type,
            session_id=_clean_text(session_id, 64) or uuid4().hex,
            read_duration_seconds=max(0, int(read_duration_seconds or 0)),
            geo_label=_clean_text(geo_label, 100),
            age_group=_clean_text(age_group, 32),
        )
    )


@bp.route('/books/<int:book_id>/reader', methods=['GET'])
@login_optional
def api_get_book_reader(current_user, book_id: int):
    payload = build_reader_payload(book_id)
    if not payload:
        return jsonify({'error': 'book not found'}), 404

    _track_book_event(
        book_id=book_id,
        current_user=current_user,
        event_type='reader_open',
        session_id=request.args.get('session_id'),
        geo_label=request.args.get('geo_label'),
        age_group=request.args.get('age_group'),
    )

    if current_user:
        progress = UserReadingProgress.query.filter_by(user_id=current_user.id, book_id=book_id).first()
        if not progress:
            db.session.add(UserReadingProgress(user_id=current_user.id, book_id=book_id, scroll_percent=0))
        else:
            # Touch the record when opening reader so history gets refreshed.
            progress.updated_at = db.func.now()
    db.session.commit()
    return jsonify(payload), 200


@bp.route('/books/<int:book_id>/landing', methods=['GET'])
def api_get_book_landing(book_id: int):
    payload = build_reader_payload(book_id)
    if not payload:
        return jsonify({'error': 'book not found'}), 404
    _track_book_event(
        book_id=book_id,
        current_user=None,
        event_type='impression',
        session_id=request.args.get('session_id'),
        geo_label=request.args.get('geo_label'),
        age_group=request.args.get('age_group'),
    )
    db.session.commit()
    return jsonify({'book': payload['book'], 'book_comments': payload['book_comments'], 'outline': payload['outline']}), 200


@bp.route('/books/<int:book_id>/highlights', methods=['POST'])
@login_required
def api_create_highlight(current_user, book_id: int):
    highlight, error = create_highlight(book_id, request.get_json() or {}, current_user)
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'highlight created', 'highlight': highlight}), 201


@bp.route('/books/<int:book_id>/highlights/<int:highlight_id>/comments', methods=['POST'])
@login_required
def api_create_highlight_comment(current_user, book_id: int, highlight_id: int):
    comment, error = create_highlight_comment(book_id, highlight_id, request.get_json() or {}, current_user)
    if error == 'highlight not found':
        return jsonify({'error': error}), 404
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'comment created', 'comment': comment}), 201


@bp.route('/books/<int:book_id>/comments', methods=['POST'])
@login_required
def api_create_book_comment(current_user, book_id: int):
    comment, error = create_book_comment(book_id, request.get_json() or {}, current_user)
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'book comment created', 'comment': comment}), 201


@bp.route('/books/<int:book_id>/progress', methods=['GET'])
@login_optional
def api_get_book_progress(current_user, book_id: int):
    if not current_user:
        return jsonify({'has_progress': False, 'progress': None}), 200
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
    analytics_payload = data.get('analytics') or {}
    if not isinstance(analytics_payload, dict):
        analytics_payload = {}

    try:
        scroll_percent = float(scroll_percent)
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid scroll_percent'}), 400

    scroll_percent = max(0.0, min(100.0, scroll_percent))
    try:
        read_seconds_delta = int(float(analytics_payload.get('read_seconds_delta', 0) or 0))
    except (TypeError, ValueError):
        read_seconds_delta = 0
    read_seconds_delta = max(0, min(read_seconds_delta, 600))

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

    has_analytics = any(
        [
            analytics_payload.get('session_id'),
            analytics_payload.get('geo_label'),
            analytics_payload.get('age_group'),
            read_seconds_delta > 0,
        ]
    )
    if has_analytics:
        _track_book_event(
            book_id=book_id,
            current_user=current_user,
            event_type='read_heartbeat',
            session_id=analytics_payload.get('session_id'),
            geo_label=analytics_payload.get('geo_label'),
            age_group=analytics_payload.get('age_group'),
            read_duration_seconds=read_seconds_delta,
        )

    db.session.commit()
    return jsonify({'message': 'progress saved', 'progress': progress.to_dict()}), 200


@bp.route('/reader/preferences', methods=['GET'])
@login_optional
def api_get_reader_preferences(current_user):
    return jsonify(get_reader_preferences(current_user)), 200


@bp.route('/reader/preferences', methods=['POST'])
@login_required
def api_save_reader_preferences(current_user):
    preference, error = save_reader_preferences(current_user, request.get_json() or {})
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'preferences saved', 'preferences': preference}), 200
