import json
from datetime import datetime

from flask import current_app, jsonify, request
from sqlalchemy import func

from app import db
from app.creator import bp
from app.logging_utils import business_log_aspect
from app.models import (
    Book,
    BookAnalyticsEvent,
    BookManuscript,
    BookVersion,
    ReaderParagraph,
    ReaderSection,
    UserReadingProgress,
)
from app.rbac.decorators import login_required
from app.services.publishing_service import parse_content_sections
from app.services.tencent_cos import upload_image

ALLOWED_COVER_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
MANUSCRIPT_UPDATE_MODES = {'create', 'full', 'append'}


def _is_creator(user):
    return user and user.role in ('creator', 'admin')


def _tenant_id(user):
    return int(getattr(user, 'tenant_id', 1) or 1)


def _creator_pen_name(user):
    return (getattr(user, 'pen_name', None) or '').strip()


def _ensure_creator_pen_name(current_user):
    if _creator_pen_name(current_user):
        return None
    return jsonify({'error': 'creator pen_name is required'}), 400


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


def _normalize_update_mode(raw_mode, has_existing_book: bool):
    mode = (raw_mode or '').strip().lower()
    if not mode:
        return 'append' if has_existing_book else 'create', None
    if mode not in MANUSCRIPT_UPDATE_MODES:
        return None, 'invalid update_mode'
    if has_existing_book and mode == 'create':
        return None, 'existing book does not support create mode'
    if not has_existing_book and mode != 'create':
        return None, 'new book must use create mode'
    return mode, None


def _chapters_from_sections(sections: list[dict]):
    chapters = []
    for index, section in enumerate(sections, start=1):
        content_text = '\n\n'.join((section.get('paragraphs') or [])).strip()
        if not content_text:
            continue
        chapters.append(
            {
                'section_key': None,
                'title': (section.get('title') or f'第 {index} 章').strip(),
                'content_text': content_text,
            }
        )
    return chapters


def _parse_chapters_payload(raw_value):
    if raw_value in (None, ''):
        return None, None

    data = raw_value
    if isinstance(raw_value, str):
        try:
            data = json.loads(raw_value)
        except (TypeError, ValueError):
            return None, 'invalid chapters payload'

    if not isinstance(data, list):
        return None, 'chapters must be an array'

    chapters = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            return None, f'chapter {index} must be an object'

        title = (item.get('title') or '').strip() or f'第 {index} 章'
        content_text = (item.get('content_text') or '').strip()
        if not content_text:
            return None, f'chapter {index} content is required'

        chapters.append(
            {
                'section_key': (item.get('section_key') or '').strip() or None,
                'title': title,
                'content_text': content_text,
            }
        )

    return chapters, None


def _compile_chapters(chapters: list[dict]):
    return '\n\n'.join(f"{chapter['title']}\n{chapter['content_text']}" for chapter in chapters if chapter.get('content_text'))


def _serialize_published_book_chapters(book_id: int):
    sections = ReaderSection.query.filter_by(book_id=book_id).order_by(ReaderSection.order_no.asc()).all()
    section_ids = [section.id for section in sections]
    paragraphs_map = {}
    if section_ids:
        rows = (
            ReaderParagraph.query.filter(ReaderParagraph.section_id.in_(section_ids))
            .order_by(ReaderParagraph.section_id.asc(), ReaderParagraph.order_no.asc())
            .all()
        )
        for row in rows:
            paragraphs_map.setdefault(row.section_id, []).append((row.paragraph_key, row.text))

    items = []
    for section in sections:
        paragraphs = paragraphs_map.get(section.id, [])
        items.append(
            {
                'section_key': section.section_key,
                'title': section.title,
                'content_text': '\n\n'.join((text or '').strip() for _, text in paragraphs if (text or '').strip()),
                'paragraph_ids': [paragraph_key for paragraph_key, _ in paragraphs],
                'order_no': int(section.order_no or 0),
            }
        )
    return items


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

        chapters, chapter_error = _parse_chapters_payload(form.get('chapters_json'))
        if chapter_error:
            return None, chapter_error
        if chapters is None and content_text:
            chapters = _chapters_from_sections(parse_content_sections(content_text))

        return {
            'book_id': form.get('book_id'),
            'title': (form.get('title') or '').strip(),
            'description': (form.get('description') or '').strip() or None,
            'cover': cover or (form.get('cover') or '').strip() or None,
            'content_text': content_text or None,
            'chapters': chapters,
            'update_mode': (form.get('update_mode') or '').strip().lower() or None,
        }, None

    data = request.get_json() or {}
    chapters, chapter_error = _parse_chapters_payload(data.get('chapters'))
    if chapter_error:
        return None, chapter_error

    content_text = (data.get('content_text') or '').strip() or None
    if chapters is None and content_text:
        chapters = _chapters_from_sections(parse_content_sections(content_text))

    return {
        'book_id': data.get('book_id'),
        'title': (data.get('title') or '').strip(),
        'description': (data.get('description') or '').strip() or None,
        'cover': (data.get('cover') or '').strip() or None,
        'content_text': content_text,
        'chapters': chapters,
        'update_mode': (data.get('update_mode') or '').strip().lower() or None,
    }, None


def _creator_book_query(current_user):
    return Book.query.filter_by(creator_id=current_user.id, tenant_id=_tenant_id(current_user))


def _serialize_creator_book(book, *, section_count=0, version_count=0):
    payload = book.to_dict()
    payload['section_count'] = int(section_count or 0)
    payload['version_count'] = int(version_count or 0)
    return payload


@bp.route('/books', methods=['GET'])
@login_required
def list_creator_books(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    books = _creator_book_query(current_user).order_by(Book.created_at.desc(), Book.id.desc()).all()
    if not books:
        return jsonify({'items': []}), 200

    book_ids = [book.id for book in books]
    section_rows = (
        db.session.query(ReaderSection.book_id, func.count(ReaderSection.id).label('total'))
        .filter(ReaderSection.book_id.in_(book_ids))
        .group_by(ReaderSection.book_id)
        .all()
    )
    version_rows = (
        db.session.query(BookVersion.book_id, func.count(BookVersion.id).label('total'))
        .filter(BookVersion.book_id.in_(book_ids))
        .group_by(BookVersion.book_id)
        .all()
    )
    section_map = {row.book_id: int(row.total or 0) for row in section_rows}
    version_map = {row.book_id: int(row.total or 0) for row in version_rows}

    items = [
        _serialize_creator_book(
            book,
            section_count=section_map.get(book.id, 0),
            version_count=version_map.get(book.id, 0),
        )
        for book in books
    ]
    return jsonify({'items': items}), 200


@bp.route('/books/<int:book_id>/chapters', methods=['GET'])
@login_required
def get_creator_book_chapters(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user)).first()
    if not book:
        return jsonify({'error': 'book not found'}), 404
    if book.creator_id not in (None, current_user.id) and not current_user.is_admin():
        return jsonify({'error': 'cannot access this book'}), 403

    return jsonify({'items': _serialize_published_book_chapters(book.id)}), 200


@bp.route('/manuscripts', methods=['GET'])
@login_required
def list_creator_manuscripts(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    status = (request.args.get('status') or '').strip()
    query = BookManuscript.query.filter_by(creator_id=current_user.id, tenant_id=_tenant_id(current_user))
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

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    payload, error = _extract_payload()
    if error:
        return jsonify({'error': error}), 400

    raw_book_id = payload.get('book_id')
    tenant_id = _tenant_id(current_user)
    has_existing_book = raw_book_id not in (None, '')
    update_mode, mode_error = _normalize_update_mode(payload.get('update_mode'), has_existing_book)
    if mode_error:
        return jsonify({'error': mode_error}), 400

    book = None
    if has_existing_book:
        try:
            book_id = int(raw_book_id)
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid book_id'}), 400
        book = Book.query.filter_by(id=book_id, tenant_id=tenant_id).first()
        if not book:
            return jsonify({'error': 'book not found'}), 404
        if book.creator_id not in (None, current_user.id) and not current_user.is_admin():
            return jsonify({'error': 'cannot edit this book'}), 403
    else:
        title = payload.get('title')
        if not title:
            return jsonify({'error': 'title is required'}), 400
        book = Book(
            title=title,
            author=_creator_pen_name(current_user),
            description=payload.get('description'),
            cover=payload.get('cover'),
            status='draft',
            creator_id=current_user.id,
            tenant_id=tenant_id,
            created_at=datetime.utcnow(),
        )
        db.session.add(book)
        db.session.flush()

    chapters = payload.get('chapters') or []
    compiled_content = _compile_chapters(chapters) if chapters else (payload.get('content_text') or None)

    title = payload.get('title') or book.title
    if not title:
        return jsonify({'error': 'title is required'}), 400

    manuscript = BookManuscript(
        book_id=book.id,
        creator_id=current_user.id,
        title=title,
        cover=payload.get('cover') if payload.get('cover') is not None else book.cover,
        description=payload.get('description') if payload.get('description') is not None else book.description,
        content_text=compiled_content,
        chapter_payload=json.dumps(chapters, ensure_ascii=False) if chapters else None,
        update_mode=update_mode,
        status='draft',
        tenant_id=tenant_id,
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

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    manuscript = BookManuscript.query.filter_by(id=manuscript_id, tenant_id=_tenant_id(current_user)).first()
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'cannot edit this manuscript'}), 403
    if manuscript.status not in ('draft', 'rejected'):
        return jsonify({'error': 'only draft/rejected manuscript can be edited'}), 400

    payload, error = _extract_payload()
    if error:
        return jsonify({'error': error}), 400

    if payload.get('update_mode') is not None:
        update_mode, mode_error = _normalize_update_mode(payload.get('update_mode'), manuscript.book_id is not None)
        if mode_error:
            return jsonify({'error': mode_error}), 400
        manuscript.update_mode = update_mode

    if payload.get('title'):
        manuscript.title = payload['title']
    if 'cover' in payload and payload.get('cover') is not None:
        manuscript.cover = payload.get('cover')
    if 'description' in payload:
        manuscript.description = payload.get('description')
    if 'content_text' in payload and payload.get('content_text') is not None:
        manuscript.content_text = payload.get('content_text')
    if 'chapters' in payload and payload.get('chapters') is not None:
        chapters = payload.get('chapters') or []
        manuscript.chapter_payload = json.dumps(chapters, ensure_ascii=False) if chapters else None
        manuscript.content_text = _compile_chapters(chapters) if chapters else manuscript.content_text

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

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    manuscript = BookManuscript.query.filter_by(id=manuscript_id, tenant_id=_tenant_id(current_user)).first()
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

    books = _creator_book_query(current_user).order_by(Book.created_at.desc(), Book.id.desc()).limit(limit).all()
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
