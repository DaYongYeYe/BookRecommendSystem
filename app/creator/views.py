from datetime import datetime

from flask import current_app, jsonify, request
from sqlalchemy import func

from app import db
from app.creator import bp
from app.logging_utils import business_log_aspect
from app.models import Book, BookAnalyticsEvent, BookManuscript, UserReadingProgress
from app.rbac.decorators import login_required
from app.services.tencent_cos import upload_image

ALLOWED_COVER_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}


def _is_creator(user):
    return user and user.role in ('creator', 'admin')


def _save_cover_file(file_obj):
    if not file_obj:
        return None, None

    max_size = int(current_app.config.get('MAX_COVER_UPLOAD_SIZE', 5 * 1024 * 1024))
    folder = current_app.config.get('COVER_UPLOAD_SUBDIR', 'book_covers')
    return upload_image(
        file_obj,
        folder=folder,
        allowed_extensions=ALLOWED_COVER_EXTENSIONS,
        max_size=max_size,
    )


def _extract_payload():
    if request.content_type and 'multipart/form-data' in request.content_type.lower():
        form = request.form
        files = request.files
        cover, error = _save_cover_file(files.get('cover_file'))
        if error:
            return None, error
        content_text = (form.get('content_text') or '').strip()
        content_file = files.get('content_file')
        if not content_text and content_file:
            raw = content_file.read()
            content_text = raw.decode('utf-8', errors='ignore').strip()
        data = {
            'book_id': form.get('book_id'),
            'title': (form.get('title') or '').strip(),
            'description': (form.get('description') or '').strip() or None,
            'cover': cover or (form.get('cover') or '').strip() or None,
            'content_text': content_text or None,
        }
        return data, None

    data = request.get_json() or {}
    return {
        'book_id': data.get('book_id'),
        'title': (data.get('title') or '').strip(),
        'description': (data.get('description') or '').strip() or None,
        'cover': (data.get('cover') or '').strip() or None,
        'content_text': (data.get('content_text') or '').strip() or None,
    }, None


@bp.route('/manuscripts', methods=['GET'])
@login_required
def list_creator_manuscripts(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    status = (request.args.get('status') or '').strip()
    query = BookManuscript.query.filter_by(creator_id=current_user.id)
    if status:
        query = query.filter_by(status=status)
    rows = query.order_by(BookManuscript.updated_at.desc(), BookManuscript.id.desc()).all()
    return jsonify({'items': [row.to_dict() for row in rows]}), 200


@bp.route('/manuscripts', methods=['POST'])
@login_required
@business_log_aspect('creator.manuscript.create', tags=['creator', 'manuscript', 'business', 'aop'])
def create_creator_manuscript(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    payload, error = _extract_payload()
    if error:
        return jsonify({'error': error}), 400

    title = payload.get('title')
    if not title:
        return jsonify({'error': 'title is required'}), 400

    book_id = payload.get('book_id')
    book = None
    if book_id not in (None, ''):
        try:
            book_id = int(book_id)
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid book_id'}), 400
        book = Book.query.get(book_id)
        if not book:
            return jsonify({'error': 'book not found'}), 404
        if book.creator_id not in (None, current_user.id) and not current_user.is_admin():
            return jsonify({'error': 'cannot edit this book'}), 403
    else:
        book = Book(
            title=title,
            description=payload.get('description'),
            cover=payload.get('cover'),
            status='draft',
            creator_id=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.session.add(book)
        db.session.flush()

    manuscript = BookManuscript(
        book_id=book.id,
        creator_id=current_user.id,
        title=title,
        cover=payload.get('cover'),
        description=payload.get('description'),
        content_text=payload.get('content_text'),
        status='draft',
    )
    db.session.add(manuscript)
    db.session.commit()
    return jsonify({'message': 'draft created', 'manuscript': manuscript.to_dict()}), 201


@bp.route('/manuscripts/<int:manuscript_id>', methods=['PUT'])
@login_required
@business_log_aspect('creator.manuscript.update', tags=['creator', 'manuscript', 'business', 'aop'])
def update_creator_manuscript(current_user, manuscript_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    manuscript = BookManuscript.query.get(manuscript_id)
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'cannot edit this manuscript'}), 403
    if manuscript.status not in ('draft', 'rejected'):
        return jsonify({'error': 'only draft/rejected manuscript can be edited'}), 400

    payload, error = _extract_payload()
    if error:
        return jsonify({'error': error}), 400

    if 'title' in payload and payload.get('title'):
        manuscript.title = payload['title']
    if 'cover' in payload and payload.get('cover') is not None:
        manuscript.cover = payload.get('cover')
    if 'description' in payload:
        manuscript.description = payload.get('description')
    if 'content_text' in payload and payload.get('content_text') is not None:
        manuscript.content_text = payload.get('content_text')

    manuscript.status = 'draft'
    manuscript.review_comment = None

    db.session.commit()
    return jsonify({'message': 'draft updated', 'manuscript': manuscript.to_dict()}), 200


@bp.route('/manuscripts/<int:manuscript_id>/submit', methods=['POST'])
@login_required
@business_log_aspect('creator.manuscript.submit', tags=['creator', 'manuscript', 'workflow', 'business', 'aop'])
def submit_creator_manuscript(current_user, manuscript_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    manuscript = BookManuscript.query.get(manuscript_id)
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'cannot submit this manuscript'}), 403
    if manuscript.status not in ('draft', 'rejected'):
        return jsonify({'error': 'manuscript status cannot submit'}), 400
    if not (manuscript.title or '').strip():
        return jsonify({'error': 'title is required'}), 400
    if not (manuscript.content_text or '').strip():
        return jsonify({'error': 'content_text is required'}), 400

    manuscript.status = 'submitted'
    manuscript.submitted_at = datetime.utcnow()
    manuscript.review_comment = None
    db.session.commit()
    return jsonify({'message': 'manuscript submitted', 'manuscript': manuscript.to_dict()}), 200


def _seconds_to_label(seconds: float):
    total = int(max(0, round(seconds or 0)))
    minutes = total // 60
    remain = total % 60
    if minutes <= 0:
        return f'{remain}s'
    return f'{minutes}m {remain}s'


@bp.route('/books/analytics', methods=['GET'])
@login_required
def get_creator_books_analytics(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    try:
        limit = min(max(int(request.args.get('limit', 50)), 1), 100)
    except (TypeError, ValueError):
        limit = 50

    books = (
        Book.query.filter_by(creator_id=current_user.id)
        .order_by(Book.created_at.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    if not books:
        return jsonify({'items': []}), 200

    book_ids = [book.id for book in books]

    event_counts_rows = (
        db.session.query(
            BookAnalyticsEvent.book_id,
            BookAnalyticsEvent.event_type,
            func.count(BookAnalyticsEvent.id).label('total'),
        )
        .filter(
            BookAnalyticsEvent.book_id.in_(book_ids),
            BookAnalyticsEvent.event_type.in_(('impression', 'reader_open')),
        )
        .group_by(BookAnalyticsEvent.book_id, BookAnalyticsEvent.event_type)
        .all()
    )
    event_counts = {}
    for row in event_counts_rows:
        event_counts.setdefault(row.book_id, {})[row.event_type] = int(row.total or 0)

    read_user_rows = (
        db.session.query(
            UserReadingProgress.book_id,
            func.count(func.distinct(UserReadingProgress.user_id)).label('read_users'),
        )
        .filter(UserReadingProgress.book_id.in_(book_ids))
        .group_by(UserReadingProgress.book_id)
        .all()
    )
    read_users_map = {row.book_id: int(row.read_users or 0) for row in read_user_rows}

    session_duration_rows = (
        db.session.query(
            BookAnalyticsEvent.book_id,
            BookAnalyticsEvent.session_id,
            func.sum(BookAnalyticsEvent.read_duration_seconds).label('duration_total'),
        )
        .filter(
            BookAnalyticsEvent.book_id.in_(book_ids),
            BookAnalyticsEvent.event_type == 'read_heartbeat',
            BookAnalyticsEvent.read_duration_seconds > 0,
        )
        .group_by(BookAnalyticsEvent.book_id, BookAnalyticsEvent.session_id)
        .all()
    )
    duration_by_book = {}
    for row in session_duration_rows:
        duration_by_book.setdefault(row.book_id, []).append(int(row.duration_total or 0))

    geo_rows = (
        db.session.query(
            BookAnalyticsEvent.book_id,
            BookAnalyticsEvent.geo_label,
            func.count(BookAnalyticsEvent.id).label('total'),
        )
        .filter(
            BookAnalyticsEvent.book_id.in_(book_ids),
            BookAnalyticsEvent.geo_label.isnot(None),
            BookAnalyticsEvent.geo_label != '',
        )
        .group_by(BookAnalyticsEvent.book_id, BookAnalyticsEvent.geo_label)
        .all()
    )
    geo_map = {}
    for row in geo_rows:
        geo_map.setdefault(row.book_id, []).append((row.geo_label, int(row.total or 0)))

    age_rows = (
        db.session.query(
            BookAnalyticsEvent.book_id,
            BookAnalyticsEvent.age_group,
            func.count(BookAnalyticsEvent.id).label('total'),
        )
        .filter(BookAnalyticsEvent.book_id.in_(book_ids))
        .group_by(BookAnalyticsEvent.book_id, BookAnalyticsEvent.age_group)
        .all()
    )
    age_map = {}
    for row in age_rows:
        label = (row.age_group or 'unknown').strip() or 'unknown'
        age_map.setdefault(row.book_id, []).append((label, int(row.total or 0)))

    items = []
    for book in books:
        counts = event_counts.get(book.id, {})
        sessions = duration_by_book.get(book.id, [])
        avg_duration = (sum(sessions) / len(sessions)) if sessions else 0

        geo_bucket = sorted(geo_map.get(book.id, []), key=lambda x: x[1], reverse=True)
        geo_total = sum(count for _, count in geo_bucket) or 1
        geo_distribution = [
            {
                'label': label,
                'count': count,
                'percent': round(count * 100 / geo_total, 2),
            }
            for label, count in geo_bucket[:8]
        ]

        age_bucket = sorted(age_map.get(book.id, []), key=lambda x: x[1], reverse=True)
        age_total = sum(count for _, count in age_bucket) or 1
        age_distribution = [
            {
                'label': label,
                'count': count,
                'percent': round(count * 100 / age_total, 2),
            }
            for label, count in age_bucket
        ]

        items.append(
            {
                'book_id': book.id,
                'title': book.title,
                'status': book.status,
                'metrics': {
                    'impressions': int(counts.get('impression', 0)),
                    'reads': int(counts.get('reader_open', 0)),
                    'read_users': int(read_users_map.get(book.id, 0)),
                    'avg_read_duration_seconds': round(avg_duration, 2),
                    'avg_read_duration_label': _seconds_to_label(avg_duration),
                },
                'geo_distribution': geo_distribution,
                'age_distribution': age_distribution,
            }
        )

    return jsonify({'items': items}), 200
