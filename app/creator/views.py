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
    BookChapter,
    BookChapterRevision,
    CreatorApplication,
    BookManuscript,
    BookVersion,
    BookTag,
    Category,
    ReaderParagraph,
    ReaderSection,
    Tag,
    User,
    UserReadingProgress,
)
from app.rbac.decorators import login_required
from app.services.work_catalog import (
    WORK_CATEGORY_MAP,
    WORK_TAG_MAP,
    get_category_tag_codes,
    get_subcategories,
)
from app.services.publishing_service import parse_content_sections
from app.services.publishing_service import (
    create_chapter_draft,
    ensure_chapter_workflow_seed,
    list_book_chapters,
    submit_chapter_for_review,
    update_chapter_draft,
)
from app.services.tencent_cos import upload_image

ALLOWED_COVER_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
MANUSCRIPT_UPDATE_MODES = {'create', 'full', 'append'}
WORK_AUDIT_STATUSES = {'draft', 'pending', 'approved', 'rejected'}
WORK_SHELF_STATUSES = {'up', 'down', 'forced_down'}
WORK_COMPLETION_STATUSES = {'ongoing', 'paused', 'completed'}
WORK_PRICE_TYPES = {'free', 'paid'}
WORK_CREATION_TYPES = {'original', 'fanfic', 'derivative'}
WORK_REQUIRED_TAG_MIN = 3
WORK_REQUIRED_TAG_MAX = 8
WORK_DESCRIPTION_MIN_LENGTH = 20


def _is_creator(user):
    return user and user.role == 'creator'


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
    book = Book.query.get(book_id)
    if not book:
        return []

    chapter_items = list_book_chapters(book)
    if chapter_items:
        return [
            {
                'id': item['id'],
                'section_key': item.get('chapter_key'),
                'title': item.get('title'),
                'content_text': (item.get('published_revision') or item.get('latest_revision') or {}).get('content_text') or '',
                'order_no': item.get('chapter_no'),
                'status': item.get('status'),
                'latest_revision': item.get('latest_revision'),
                'published_revision': item.get('published_revision'),
                'can_edit': item.get('can_edit'),
                'can_submit': item.get('can_submit'),
            }
            for item in chapter_items
        ]

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
                'status': 'published',
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


def _creator_book_query(current_user, *, include_deleted=False):
    query = Book.query.filter_by(creator_id=current_user.id, tenant_id=_tenant_id(current_user))
    if not include_deleted:
        query = query.filter(Book.is_deleted.is_(False))
    return query


def _serialize_creator_application(item):
    if not item:
        return None
    user = User.query.filter_by(id=item.user_id).first()
    reviewer = User.query.filter_by(id=item.reviewed_by).first() if item.reviewed_by else None
    payload = item.to_dict()
    payload['username'] = user.username if user else None
    payload['reviewed_by_name'] = reviewer.username if reviewer else None
    return payload


def _serialize_creator_book(book, *, section_count=0, version_count=0):
    payload = book.to_dict()
    payload['section_count'] = int(section_count or 0)
    payload['version_count'] = int(version_count or 0)
    return payload


def _parse_jsonish_list(raw_value):
    if raw_value in (None, ''):
        return []

    if isinstance(raw_value, list):
        return raw_value

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return parsed
        except (TypeError, ValueError):
            return [item.strip() for item in stripped.split(',') if item.strip()]

    return []


def _parse_tag_ids(raw_value):
    items = _parse_jsonish_list(raw_value)
    tag_ids = []
    for item in items:
        try:
            tag_ids.append(int(item))
        except (TypeError, ValueError):
            return None, 'invalid tag_ids'
    return list(dict.fromkeys(tag_ids)), None


def _serialize_work_options():
    ordered_category_codes = list(WORK_CATEGORY_MAP.keys())
    categories = Category.query.filter(Category.code.in_(ordered_category_codes)).all()
    category_map = {item.code: item for item in categories}

    ordered_tag_codes = list(WORK_TAG_MAP.keys())
    tags = Tag.query.filter(Tag.code.in_(ordered_tag_codes)).all()
    tag_map = {item.code: item for item in tags}

    return {
        'categories': [
            {
                'id': category_map[item['code']].id,
                'code': item['code'],
                'name': item['name'],
                'subcategories': get_subcategories(item['code']),
                'tag_candidates': [
                    {
                        'id': tag_map[tag_code].id,
                        'code': tag_code,
                        'label': tag_map[tag_code].label,
                        'is_hot': True,
                    }
                    for tag_code in get_category_tag_codes(item['code'])
                    if tag_code in tag_map
                ],
            }
            for item in [WORK_CATEGORY_MAP[code] for code in ordered_category_codes]
            if item['code'] in category_map
        ],
        'rules': {
            'description_min_length': WORK_DESCRIPTION_MIN_LENGTH,
            'tag_min_count': WORK_REQUIRED_TAG_MIN,
            'tag_max_count': WORK_REQUIRED_TAG_MAX,
            'cover_formats': sorted(ALLOWED_COVER_EXTENSIONS),
            'cover_max_size': int(current_app.config.get('MAX_COVER_UPLOAD_SIZE', 5 * 1024 * 1024)),
            'cover_ratio_hint': '3:4',
        },
        'enum_options': {
            'audit_statuses': sorted(WORK_AUDIT_STATUSES),
            'shelf_statuses': sorted(WORK_SHELF_STATUSES),
            'completion_statuses': sorted(WORK_COMPLETION_STATUSES),
            'price_types': sorted(WORK_PRICE_TYPES),
            'creation_types': sorted(WORK_CREATION_TYPES),
        },
    }


def _extract_work_payload():
    if request.content_type and 'multipart/form-data' in request.content_type.lower():
        form = request.form
        files = request.files
        cover, error = _save_cover_file(files.get('cover_file'))
        if error:
            return None, error

        tag_ids, tag_error = _parse_tag_ids(form.get('tag_ids_json') or form.getlist('tag_ids'))
        if tag_error:
            return None, tag_error

        raw_category_id = form.get('category_id')
        category_id = None
        if raw_category_id not in (None, ''):
            try:
                category_id = int(raw_category_id)
            except (TypeError, ValueError):
                return None, 'invalid category_id'

        return {
            'title': (form.get('title') or '').strip(),
            'subtitle': (form.get('subtitle') or '').strip() or None,
            'description': (form.get('description') or '').strip() or None,
            'cover': cover or (form.get('cover') or '').strip() or None,
            'category_id': category_id,
            'subcategory_code': (form.get('subcategory_code') or '').strip() or None,
            'tag_ids': tag_ids,
            'completion_status': (form.get('completion_status') or '').strip().lower() or 'ongoing',
            'price_type': (form.get('price_type') or '').strip().lower() or 'free',
            'creation_type': (form.get('creation_type') or '').strip().lower() or 'original',
            'protagonist': (form.get('protagonist') or '').strip() or None,
            'worldview': (form.get('worldview') or '').strip() or None,
            'author_message': (form.get('author_message') or '').strip() or None,
            'author_notice': (form.get('author_notice') or '').strip() or None,
            'copyright_notice': (form.get('copyright_notice') or '').strip() or None,
            'update_note': (form.get('update_note') or '').strip() or None,
        }, None

    data = request.get_json() or {}
    tag_ids, tag_error = _parse_tag_ids(data.get('tag_ids'))
    if tag_error:
        return None, tag_error

    category_id = data.get('category_id')
    if category_id not in (None, ''):
        try:
            category_id = int(category_id)
        except (TypeError, ValueError):
            return None, 'invalid category_id'
    else:
        category_id = None

    return {
        'title': (data.get('title') or '').strip(),
        'subtitle': (data.get('subtitle') or '').strip() or None,
        'description': (data.get('description') or '').strip() or None,
        'cover': (data.get('cover') or '').strip() or None,
        'category_id': category_id,
        'subcategory_code': (data.get('subcategory_code') or '').strip() or None,
        'tag_ids': tag_ids,
        'completion_status': (data.get('completion_status') or '').strip().lower() or 'ongoing',
        'price_type': (data.get('price_type') or '').strip().lower() or 'free',
        'creation_type': (data.get('creation_type') or '').strip().lower() or 'original',
        'protagonist': (data.get('protagonist') or '').strip() or None,
        'worldview': (data.get('worldview') or '').strip() or None,
        'author_message': (data.get('author_message') or '').strip() or None,
        'author_notice': (data.get('author_notice') or '').strip() or None,
        'copyright_notice': (data.get('copyright_notice') or '').strip() or None,
        'update_note': (data.get('update_note') or '').strip() or None,
    }, None


def _validate_work_payload(payload, *, strict=False, current_book=None, tenant_id=1):
    title = (payload.get('title') or '').strip()
    if not title:
        return 'title is required'

    duplicate_query = Book.query.filter(
        Book.title == title,
        Book.tenant_id == int(getattr(current_book, 'tenant_id', tenant_id) or tenant_id),
    )
    if current_book is not None:
        duplicate_query = duplicate_query.filter(Book.id != current_book.id)
    if duplicate_query.first():
        return 'book title already exists'

    completion_status = payload.get('completion_status') or 'ongoing'
    if completion_status not in WORK_COMPLETION_STATUSES:
        return 'invalid completion_status'
    if (payload.get('price_type') or 'free') not in WORK_PRICE_TYPES:
        return 'invalid price_type'
    if (payload.get('creation_type') or 'original') not in WORK_CREATION_TYPES:
        return 'invalid creation_type'

    category_id = payload.get('category_id')
    category = None
    if category_id is not None:
        category = Category.query.get(category_id)
        if not category:
            return 'category not found'

    subcategory_code = payload.get('subcategory_code')
    if subcategory_code:
        valid_subcategory_codes = {item['code'] for item in get_subcategories(category.code if category else None)}
        if subcategory_code not in valid_subcategory_codes:
            return 'invalid subcategory_code'

    tag_ids = payload.get('tag_ids') or []
    if tag_ids:
        valid_tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
        valid_tag_map = {item.id: item for item in valid_tags}
        if len(valid_tag_map) != len(tag_ids):
            return 'tag not found'
        if category is not None:
            allowed_tag_codes = set(get_category_tag_codes(category.code))
            if allowed_tag_codes:
                for tag_id in tag_ids:
                    tag = valid_tag_map.get(tag_id)
                    if tag and tag.code not in allowed_tag_codes:
                        return 'tag does not match selected category'

    if strict:
        description = (payload.get('description') or '').strip()
        if len(description) < WORK_DESCRIPTION_MIN_LENGTH:
            return f'description must be at least {WORK_DESCRIPTION_MIN_LENGTH} characters'
        if category is None:
            return 'category_id is required'
        if not payload.get('cover'):
            return 'cover is required'
        if len(tag_ids) < WORK_REQUIRED_TAG_MIN or len(tag_ids) > WORK_REQUIRED_TAG_MAX:
            return f'tag count must be between {WORK_REQUIRED_TAG_MIN} and {WORK_REQUIRED_TAG_MAX}'

    return None


def _book_tag_payload_map(book_ids: list[int]):
    if not book_ids:
        return {}

    rows = (
        db.session.query(BookTag.book_id, Tag.id, Tag.code, Tag.label)
        .join(Tag, Tag.id == BookTag.tag_id)
        .filter(BookTag.book_id.in_(book_ids))
        .order_by(Tag.id.asc())
        .all()
    )
    tag_map = {}
    for book_id, tag_id, tag_code, tag_label in rows:
        tag_map.setdefault(book_id, []).append(
            {
                'id': int(tag_id),
                'code': tag_code,
                'label': tag_label,
            }
        )
    return tag_map


def _book_section_count_map(book_ids: list[int]):
    if not book_ids:
        return {}
    section_rows = (
        db.session.query(ReaderSection.book_id, func.count(ReaderSection.id).label('total'))
        .filter(ReaderSection.book_id.in_(book_ids))
        .group_by(ReaderSection.book_id)
        .all()
    )
    chapter_rows = (
        db.session.query(BookChapter.book_id, func.count(BookChapter.id).label('total'))
        .filter(BookChapter.book_id.in_(book_ids), BookChapter.published_revision_id.isnot(None))
        .group_by(BookChapter.book_id)
        .all()
    )
    result = {row.book_id: int(row.total or 0) for row in section_rows}
    for row in chapter_rows:
        result[row.book_id] = max(int(row.total or 0), int(result.get(row.book_id, 0)))
    return result


def _serialize_creator_work(book, *, tag_items=None, section_count=0):
    payload = book.to_dict()
    category = Category.query.get(book.category_id) if book.category_id else None
    payload['category_name'] = category.name if category else None
    payload['category_code'] = category.code if category else None
    payload['subcategories'] = get_subcategories(category.code if category else None)
    payload['tags'] = tag_items or []
    payload['tag_ids'] = [item['id'] for item in payload['tags']]
    payload['section_count'] = int(section_count or 0)
    payload['ready_for_audit'] = bool(
        payload.get('category_id')
        and payload.get('cover')
        and len((payload.get('description') or '').strip()) >= WORK_DESCRIPTION_MIN_LENGTH
        and WORK_REQUIRED_TAG_MIN <= len(payload['tag_ids']) <= WORK_REQUIRED_TAG_MAX
    )
    payload['ready_for_publish'] = bool(payload['ready_for_audit'] and int(section_count or 0) > 0 and payload.get('audit_status') == 'approved')
    return payload


def _apply_work_tag_changes(book_id: int, tag_ids: list[int]):
    BookTag.query.filter_by(book_id=book_id).delete(synchronize_session=False)
    for tag_id in tag_ids:
        db.session.add(BookTag(book_id=book_id, tag_id=tag_id))


def _has_critical_work_changes(book, payload):
    critical_fields = [
        'title',
        'subtitle',
        'description',
        'cover',
        'category_id',
        'subcategory_code',
        'completion_status',
        'price_type',
        'creation_type',
    ]
    return any(getattr(book, field) != payload.get(field) for field in critical_fields)


def _work_publish_readiness(book):
    section_count = ReaderSection.query.filter_by(book_id=book.id).count()
    chapter_count = BookChapter.query.filter(
        BookChapter.book_id == book.id,
        BookChapter.published_revision_id.isnot(None),
    ).count()
    published_section_count = max(int(section_count or 0), int(chapter_count or 0))
    tag_count = BookTag.query.filter_by(book_id=book.id).count()
    errors = []
    if not book.category_id:
        errors.append('请选择主分类')
    if len((book.description or '').strip()) < WORK_DESCRIPTION_MIN_LENGTH:
        errors.append(f'简介不少于 {WORK_DESCRIPTION_MIN_LENGTH} 字')
    if not book.cover:
        errors.append('请上传作品封面')
    if tag_count < WORK_REQUIRED_TAG_MIN or tag_count > WORK_REQUIRED_TAG_MAX:
        errors.append(f'标签数量需在 {WORK_REQUIRED_TAG_MIN}-{WORK_REQUIRED_TAG_MAX} 个之间')
    if published_section_count <= 0:
        errors.append('请至少发布首章后再上架')
    if (book.audit_status or 'draft') != 'approved':
        errors.append('基础资料审核通过后才能上架')
    if (book.shelf_status or 'down') == 'forced_down':
        errors.append('该作品当前为平台强制下架状态，无法自行恢复')
    return errors


@bp.route('/application', methods=['GET'])
@login_required
def get_creator_application(current_user):
    tenant_id = _tenant_id(current_user)
    latest = (
        CreatorApplication.query.filter_by(user_id=current_user.id, tenant_id=tenant_id)
        .order_by(CreatorApplication.id.desc())
        .first()
    )
    return jsonify(
        {
            'application': _serialize_creator_application(latest),
            'can_apply': bool(current_user.role == 'user' and (latest is None or latest.status in ('rejected', 'approved'))),
            'already_creator': bool(current_user.role == 'creator'),
        }
    ), 200


@bp.route('/application', methods=['POST'])
@login_required
@business_log_aspect('creator.application.submit', tags=['creator', 'application', 'business', 'aop'])
def submit_creator_application(current_user):
    tenant_id = _tenant_id(current_user)
    if current_user.role == 'creator':
        return jsonify({'error': 'current user is already creator'}), 400
    if current_user.role != 'user':
        return jsonify({'error': 'only normal users can apply'}), 400

    latest = (
        CreatorApplication.query.filter_by(user_id=current_user.id, tenant_id=tenant_id)
        .order_by(CreatorApplication.id.desc())
        .first()
    )
    if latest and latest.status == 'pending':
        return jsonify({'error': 'application is pending'}), 400

    payload = request.get_json() or {}
    apply_reason = (payload.get('apply_reason') or '').strip()
    if len(apply_reason) < 10:
        return jsonify({'error': 'apply_reason must be at least 10 characters'}), 400
    if len(apply_reason) > 1000:
        return jsonify({'error': 'apply_reason cannot exceed 1000 characters'}), 400

    application = CreatorApplication(
        user_id=current_user.id,
        tenant_id=tenant_id,
        status='pending',
        apply_reason=apply_reason,
    )
    db.session.add(application)
    db.session.commit()
    return jsonify({'message': 'creator application submitted', 'application': _serialize_creator_application(application)}), 201


@bp.route('/books', methods=['GET'])
@login_required
def list_creator_books(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    books = _creator_book_query(current_user).order_by(Book.created_at.desc(), Book.id.desc()).all()
    if not books:
        return jsonify({'items': []}), 200

    book_ids = [book.id for book in books]
    section_map = _book_section_count_map(book_ids)
    version_rows = (
        db.session.query(BookVersion.book_id, func.count(BookVersion.id).label('total'))
        .filter(BookVersion.book_id.in_(book_ids))
        .group_by(BookVersion.book_id)
        .all()
    )
    version_map = {row.book_id: int(row.total or 0) for row in version_rows}
    tag_map = _book_tag_payload_map(book_ids)

    items = [
        {
            **_serialize_creator_book(
                book,
                section_count=section_map.get(book.id, 0),
                version_count=version_map.get(book.id, 0),
            ),
            'tags': tag_map.get(book.id, []),
            'tag_ids': [item['id'] for item in tag_map.get(book.id, [])],
        }
        for book in books
    ]
    return jsonify({'items': items}), 200


@bp.route('/work-options', methods=['GET'])
@login_required
def get_creator_work_options(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403
    return jsonify(_serialize_work_options()), 200


@bp.route('/works', methods=['GET'])
@login_required
def list_creator_works(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    keyword = (request.args.get('keyword') or '').strip()
    audit_status = (request.args.get('audit_status') or '').strip().lower()
    shelf_status = (request.args.get('shelf_status') or '').strip().lower()
    completion_status = (request.args.get('completion_status') or '').strip().lower()
    recycle = (request.args.get('recycle') or '0').strip() in ('1', 'true')

    query = _creator_book_query(current_user, include_deleted=True if recycle else False)
    if recycle:
        query = query.filter(Book.is_deleted.is_(True))
    if keyword:
        query = query.filter(Book.title.like(f'%{keyword}%'))
    if audit_status:
        query = query.filter(Book.audit_status == audit_status)
    if shelf_status:
        query = query.filter(Book.shelf_status == shelf_status)
    if completion_status:
        query = query.filter(Book.completion_status == completion_status)

    books = query.order_by(Book.updated_at.desc(), Book.id.desc()).all()
    if not books:
        return jsonify({'items': [], 'summary': {'total': 0, 'up': 0, 'pending': 0, 'completed': 0}}), 200

    book_ids = [book.id for book in books]
    section_map = _book_section_count_map(book_ids)
    tag_map = _book_tag_payload_map(book_ids)

    items = [_serialize_creator_work(book, tag_items=tag_map.get(book.id, []), section_count=section_map.get(book.id, 0)) for book in books]
    return jsonify(
        {
            'items': items,
            'summary': {
                'total': len(items),
                'up': sum(1 for item in items if item.get('shelf_status') == 'up'),
                'pending': sum(1 for item in items if item.get('audit_status') == 'pending'),
                'completed': sum(1 for item in items if item.get('completion_status') == 'completed'),
            },
        }
    ), 200


@bp.route('/works/<int:book_id>', methods=['GET'])
@login_required
def get_creator_work_detail(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'work is in recycle bin'}), 400

    tag_map = _book_tag_payload_map([book.id])
    section_count = ReaderSection.query.filter_by(book_id=book.id).count()
    return jsonify({'item': _serialize_creator_work(book, tag_items=tag_map.get(book.id, []), section_count=section_count)}), 200


@bp.route('/works', methods=['POST'])
@login_required
@business_log_aspect('creator.work.create', tags=['creator', 'work', 'business', 'aop'])
def create_creator_work(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    payload, error = _extract_work_payload()
    if error:
        return jsonify({'error': error}), 400

    validation_error = _validate_work_payload(payload, strict=False, tenant_id=_tenant_id(current_user))
    if validation_error:
        return jsonify({'error': validation_error}), 400

    book = Book(
        title=payload['title'],
        subtitle=payload.get('subtitle'),
        author=_creator_pen_name(current_user),
        description=payload.get('description'),
        cover=payload.get('cover'),
        category_id=payload.get('category_id'),
        subcategory_code=payload.get('subcategory_code'),
        completion_status=payload.get('completion_status') or 'ongoing',
        price_type=payload.get('price_type') or 'free',
        creation_type=payload.get('creation_type') or 'original',
        protagonist=payload.get('protagonist'),
        worldview=payload.get('worldview'),
        author_message=payload.get('author_message'),
        author_notice=payload.get('author_notice'),
        copyright_notice=payload.get('copyright_notice'),
        update_note=payload.get('update_note'),
        audit_status='draft',
        shelf_status='down',
        status='draft',
        creator_id=current_user.id,
        tenant_id=_tenant_id(current_user),
        created_at=datetime.utcnow(),
    )
    db.session.add(book)
    db.session.flush()
    _apply_work_tag_changes(book.id, payload.get('tag_ids') or [])
    db.session.commit()

    tag_map = _book_tag_payload_map([book.id])
    return jsonify({'message': 'work created', 'item': _serialize_creator_work(book, tag_items=tag_map.get(book.id, []), section_count=0)}), 201


@bp.route('/works/<int:book_id>', methods=['PUT'])
@login_required
@business_log_aspect('creator.work.update', tags=['creator', 'work', 'business', 'aop'])
def update_creator_work(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'work is in recycle bin'}), 400

    payload, error = _extract_work_payload()
    if error:
        return jsonify({'error': error}), 400

    validation_error = _validate_work_payload(payload, strict=False, current_book=book, tenant_id=_tenant_id(current_user))
    if validation_error:
        return jsonify({'error': validation_error}), 400

    re_audit_required = _has_critical_work_changes(book, payload)
    book.title = payload['title']
    book.subtitle = payload.get('subtitle')
    book.description = payload.get('description')
    if payload.get('cover') is not None:
        book.cover = payload.get('cover')
    book.category_id = payload.get('category_id')
    book.subcategory_code = payload.get('subcategory_code')
    book.completion_status = payload.get('completion_status') or 'ongoing'
    book.price_type = payload.get('price_type') or 'free'
    book.creation_type = payload.get('creation_type') or 'original'
    book.protagonist = payload.get('protagonist')
    book.worldview = payload.get('worldview')
    book.author_message = payload.get('author_message')
    book.author_notice = payload.get('author_notice')
    book.copyright_notice = payload.get('copyright_notice')
    book.update_note = payload.get('update_note')
    book.author = _creator_pen_name(current_user) or book.author

    _apply_work_tag_changes(book.id, payload.get('tag_ids') or [])

    if re_audit_required and (book.audit_status or 'draft') == 'approved':
        book.audit_status = 'pending'
        book.audit_comment = '核心资料已变更，请重新审核'

    db.session.commit()
    tag_map = _book_tag_payload_map([book.id])
    section_count = ReaderSection.query.filter_by(book_id=book.id).count()
    return jsonify(
        {
            'message': 'work updated',
            're_audit_required': bool(re_audit_required),
            'item': _serialize_creator_work(book, tag_items=tag_map.get(book.id, []), section_count=section_count),
        }
    ), 200


@bp.route('/works/<int:book_id>/submit-audit', methods=['POST'])
@login_required
@business_log_aspect('creator.work.submit_audit', tags=['creator', 'work', 'review', 'business', 'aop'])
def submit_creator_work_audit(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'work is in recycle bin'}), 400
    if (book.shelf_status or 'down') == 'forced_down':
        return jsonify({'error': 'forced down work cannot submit audit'}), 400

    payload = {
        'title': book.title,
        'subtitle': book.subtitle,
        'description': book.description,
        'cover': book.cover,
        'category_id': book.category_id,
        'subcategory_code': book.subcategory_code,
        'tag_ids': [item.tag_id for item in BookTag.query.filter_by(book_id=book.id).all()],
        'completion_status': book.completion_status,
        'price_type': book.price_type,
        'creation_type': book.creation_type,
    }
    validation_error = _validate_work_payload(payload, strict=True, current_book=book, tenant_id=_tenant_id(current_user))
    if validation_error:
        return jsonify({'error': validation_error}), 400

    book.audit_status = 'pending'
    book.audit_comment = None
    book.audit_submitted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'work submitted for audit', 'audit_status': book.audit_status}), 200


@bp.route('/works/<int:book_id>/shelf', methods=['POST'])
@login_required
@business_log_aspect('creator.work.shelf', tags=['creator', 'work', 'status', 'business', 'aop'])
def update_creator_work_shelf(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'work is in recycle bin'}), 400

    payload = request.get_json() or {}
    action = (payload.get('action') or '').strip().lower()
    if action not in {'up', 'down'}:
        return jsonify({'error': 'action must be up or down'}), 400

    if action == 'up':
        errors = _work_publish_readiness(book)
        if errors:
            return jsonify({'error': 'work is not ready for publish', 'details': errors}), 400
        book.shelf_status = 'up'
        book.status = 'published'
        if not book.published_at:
            book.published_at = datetime.utcnow()
        book.off_shelf_reason = None
    else:
        if (book.shelf_status or 'down') == 'forced_down':
            return jsonify({'error': 'forced down work cannot be changed'}), 400
        book.shelf_status = 'down'
        book.status = 'draft'
        book.off_shelf_reason = (payload.get('reason') or '').strip() or None

    db.session.commit()
    return jsonify({'message': 'work shelf updated', 'shelf_status': book.shelf_status, 'status': book.status}), 200


@bp.route('/works/<int:book_id>/completion-status', methods=['POST'])
@login_required
@business_log_aspect('creator.work.completion_status', tags=['creator', 'work', 'status', 'business', 'aop'])
def update_creator_work_completion_status(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'work is in recycle bin'}), 400

    payload = request.get_json() or {}
    completion_status = (payload.get('completion_status') or '').strip().lower()
    if completion_status not in WORK_COMPLETION_STATUSES:
        return jsonify({'error': 'invalid completion_status'}), 400

    if completion_status == 'completed' and (payload.get('confirm') is not True):
        return jsonify({'error': 'complete action requires confirmation'}), 400

    book.completion_status = completion_status
    if completion_status == 'completed' and book.status == 'published':
        book.status = 'published'
    db.session.commit()
    return jsonify({'message': 'completion status updated', 'completion_status': book.completion_status}), 200


@bp.route('/works/<int:book_id>', methods=['DELETE'])
@login_required
@business_log_aspect('creator.work.delete', tags=['creator', 'work', 'recycle', 'business', 'aop'])
def delete_creator_work(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'work already deleted'}), 400

    snapshot = {
        'status': book.status,
        'shelf_status': book.shelf_status,
    }
    book.delete_snapshot = json.dumps(snapshot, ensure_ascii=False)
    book.is_deleted = True
    book.deleted_at = datetime.utcnow()
    book.deleted_by = current_user.id
    book.shelf_status = 'down'
    book.status = 'archived'
    db.session.commit()
    return jsonify({'message': 'work moved to recycle bin'}), 200


@bp.route('/works/<int:book_id>/restore', methods=['POST'])
@login_required
@business_log_aspect('creator.work.restore', tags=['creator', 'work', 'recycle', 'business', 'aop'])
def restore_creator_work(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user), creator_id=current_user.id).first()
    if not book:
        return jsonify({'error': 'work not found'}), 404
    if not book.is_deleted:
        return jsonify({'error': 'work is not deleted'}), 400

    snapshot = {}
    if book.delete_snapshot:
        try:
            snapshot = json.loads(book.delete_snapshot)
        except (TypeError, ValueError):
            snapshot = {}
    book.is_deleted = False
    book.deleted_at = None
    book.deleted_by = None
    book.status = snapshot.get('status') or 'draft'
    book.shelf_status = snapshot.get('shelf_status') or 'down'
    book.delete_snapshot = None
    db.session.commit()
    return jsonify({'message': 'work restored'}), 200


@bp.route('/books/<int:book_id>/chapters', methods=['GET'])
@login_required
def get_creator_book_chapters(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user)).first()
    if not book:
        return jsonify({'error': 'book not found'}), 404
    if book.is_deleted:
        return jsonify({'error': 'book is in recycle bin'}), 400
    if book.creator_id not in (None, current_user.id):
        return jsonify({'error': 'cannot access this book'}), 403

    ensure_chapter_workflow_seed(book)
    return jsonify({'items': _serialize_published_book_chapters(book.id)}), 200


def _load_owned_book_for_chapter(current_user, book_id: int):
    book = Book.query.filter_by(id=book_id, tenant_id=_tenant_id(current_user)).first()
    if not book:
        return None, jsonify({'error': 'book not found'}), 404
    if book.is_deleted:
        return None, jsonify({'error': 'book is in recycle bin'}), 400
    if book.creator_id not in (None, current_user.id):
        return None, jsonify({'error': 'cannot edit this book'}), 403
    return book, None, None


@bp.route('/books/<int:book_id>/chapters', methods=['POST'])
@login_required
@business_log_aspect('creator.chapter.create', tags=['creator', 'chapter', 'workflow', 'business', 'aop'])
def create_creator_book_chapter(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    book, error_response, status_code = _load_owned_book_for_chapter(current_user, book_id)
    if error_response:
        return error_response, status_code

    payload = request.get_json() or {}
    title = (payload.get('title') or '').strip()
    content_text = (payload.get('content_text') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400
    if not content_text:
        return jsonify({'error': 'content_text is required'}), 400

    chapter, revision = create_chapter_draft(book, title=title, content_text=content_text, creator=current_user)
    return jsonify({'message': 'chapter draft created', 'chapter': chapter.to_dict(), 'revision': revision.to_dict()}), 201


@bp.route('/books/<int:book_id>/chapters/<int:chapter_id>', methods=['PUT'])
@login_required
@business_log_aspect('creator.chapter.update', tags=['creator', 'chapter', 'workflow', 'business', 'aop'])
def update_creator_book_chapter(current_user, book_id: int, chapter_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    book, error_response, status_code = _load_owned_book_for_chapter(current_user, book_id)
    if error_response:
        return error_response, status_code

    chapter = BookChapter.query.filter_by(id=chapter_id, book_id=book.id).first()
    if not chapter:
        return jsonify({'error': 'chapter not found'}), 404

    payload = request.get_json() or {}
    title = (payload.get('title') or '').strip()
    content_text = (payload.get('content_text') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400
    if not content_text:
        return jsonify({'error': 'content_text is required'}), 400

    revision = update_chapter_draft(chapter, title=title, content_text=content_text, creator=current_user)
    return jsonify({'message': 'chapter draft updated', 'chapter': chapter.to_dict(), 'revision': revision.to_dict()}), 200


@bp.route('/books/<int:book_id>/chapters/<int:chapter_id>/submit', methods=['POST'])
@login_required
@business_log_aspect('creator.chapter.submit', tags=['creator', 'chapter', 'workflow', 'business', 'aop'])
def submit_creator_book_chapter(current_user, book_id: int, chapter_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    pen_name_error = _ensure_creator_pen_name(current_user)
    if pen_name_error:
        return pen_name_error

    book, error_response, status_code = _load_owned_book_for_chapter(current_user, book_id)
    if error_response:
        return error_response, status_code

    chapter = BookChapter.query.filter_by(id=chapter_id, book_id=book.id).first()
    if not chapter:
        return jsonify({'error': 'chapter not found'}), 404

    revision, error = submit_chapter_for_review(chapter)
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'message': 'chapter submitted for review', 'chapter': chapter.to_dict(), 'revision': revision.to_dict()}), 200


@bp.route('/books/<int:book_id>/chapters/<int:chapter_id>/versions', methods=['GET'])
@login_required
def get_creator_book_chapter_versions(current_user, book_id: int, chapter_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book, error_response, status_code = _load_owned_book_for_chapter(current_user, book_id)
    if error_response:
        return error_response, status_code

    chapter = BookChapter.query.filter_by(id=chapter_id, book_id=book.id).first()
    if not chapter:
        return jsonify({'error': 'chapter not found'}), 404
    revisions = (
        BookChapterRevision.query.filter_by(chapter_id=chapter.id)
        .order_by(BookChapterRevision.version_no.desc(), BookChapterRevision.id.desc())
        .all()
    )
    return jsonify({'items': [item.to_dict() for item in revisions]}), 200


@bp.route('/books/<int:book_id>/chapters/reorder', methods=['POST'])
@login_required
@business_log_aspect('creator.chapter.reorder', tags=['creator', 'chapter', 'workflow', 'business', 'aop'])
def reorder_creator_book_chapters(current_user, book_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    book, error_response, status_code = _load_owned_book_for_chapter(current_user, book_id)
    if error_response:
        return error_response, status_code

    payload = request.get_json() or {}
    chapter_ids = payload.get('chapter_ids') or []
    if not isinstance(chapter_ids, list) or not chapter_ids:
        return jsonify({'error': 'chapter_ids is required'}), 400

    chapters = BookChapter.query.filter(BookChapter.book_id == book.id).order_by(BookChapter.chapter_no.asc()).all()
    current_ids = [int(item.id) for item in chapters]
    try:
        requested_ids = [int(item) for item in chapter_ids]
    except (TypeError, ValueError):
        return jsonify({'error': 'chapter_ids must be integers'}), 400

    if sorted(current_ids) != sorted(requested_ids):
        return jsonify({'error': 'chapter_ids does not match current chapter set'}), 400

    chapter_map = {item.id: item for item in chapters}
    for index, chapter_id in enumerate(requested_ids, start=1):
        chapter = chapter_map[chapter_id]
        chapter.chapter_no = index
        section = ReaderSection.query.filter_by(book_id=book.id, section_key=chapter.chapter_key).first()
        if section:
            section.order_no = index

    db.session.commit()
    return jsonify({'message': 'chapter order updated', 'items': _serialize_published_book_chapters(book.id)}), 200


@bp.route('/manuscripts', methods=['GET'])
@login_required
def list_creator_manuscripts(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    status = (request.args.get('status') or '').strip()
    recycle = (request.args.get('recycle') or '0').strip() in ('1', 'true')
    query = BookManuscript.query.filter_by(creator_id=current_user.id, tenant_id=_tenant_id(current_user))
    query = query.filter(BookManuscript.is_deleted.is_(True if recycle else False))
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
        if book.is_deleted:
            return jsonify({'error': 'book is in recycle bin'}), 400
        if book.creator_id not in (None, current_user.id):
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
    if manuscript.is_deleted:
        return jsonify({'error': 'manuscript is in recycle bin'}), 400
    if manuscript.creator_id != current_user.id:
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
    if manuscript.is_deleted:
        return jsonify({'error': 'manuscript is in recycle bin'}), 400
    if manuscript.creator_id != current_user.id:
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


@bp.route('/manuscripts/<int:manuscript_id>', methods=['DELETE'])
@login_required
@business_log_aspect('creator.manuscript.delete', tags=['creator', 'manuscript', 'recycle', 'business', 'aop'])
def delete_creator_manuscript(current_user, manuscript_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    manuscript = BookManuscript.query.filter_by(id=manuscript_id, tenant_id=_tenant_id(current_user)).first()
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id:
        return jsonify({'error': 'cannot delete this manuscript'}), 403
    if manuscript.is_deleted:
        return jsonify({'error': 'manuscript already deleted'}), 400
    if manuscript.status == 'published':
        return jsonify({'error': 'published manuscript cannot be deleted'}), 400

    manuscript.is_deleted = True
    manuscript.deleted_at = datetime.utcnow()
    manuscript.deleted_by = current_user.id
    db.session.commit()
    return jsonify({'message': 'manuscript moved to recycle bin'}), 200


@bp.route('/manuscripts/<int:manuscript_id>/restore', methods=['POST'])
@login_required
@business_log_aspect('creator.manuscript.restore', tags=['creator', 'manuscript', 'recycle', 'business', 'aop'])
def restore_creator_manuscript(current_user, manuscript_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    manuscript = BookManuscript.query.filter_by(id=manuscript_id, tenant_id=_tenant_id(current_user)).first()
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id:
        return jsonify({'error': 'cannot restore this manuscript'}), 403
    if not manuscript.is_deleted:
        return jsonify({'error': 'manuscript is not deleted'}), 400

    manuscript.is_deleted = False
    manuscript.deleted_at = None
    manuscript.deleted_by = None
    if manuscript.status not in ('draft', 'rejected'):
        manuscript.status = 'draft'
    db.session.commit()
    return jsonify({'message': 'manuscript restored', 'manuscript': manuscript.to_dict()}), 200


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
