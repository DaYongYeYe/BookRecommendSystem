import json
import re
from datetime import datetime

from app import db
from app.models import (
    Book,
    BookChapter,
    BookChapterRevision,
    BookVersion,
    ReaderHighlight,
    ReaderParagraph,
    ReaderSection,
    User,
)

CHAPTER_PATTERN = re.compile(
    r'^\s*((?:\u7b2c[\d\u4e00-\u5341\u767e\u5343]+[\u7ae0\u8282\u5377\u7bc7].*)|(?:chapter\s+\d+.*))$',
    re.IGNORECASE,
)
SECTION_KEY_PATTERN = re.compile(r'^chapter-(\d+)$', re.IGNORECASE)
PARAGRAPH_KEY_PATTERN = re.compile(r'^p(\d+)$', re.IGNORECASE)
CHAPTER_REVISION_STATUSES = {'draft', 'pending', 'approved', 'rejected', 'published', 'superseded'}


def parse_content_sections(content_text: str):
    raw_text = (content_text or '').replace('\r\n', '\n').strip()
    if not raw_text:
        return []

    lines = raw_text.split('\n')
    sections = []
    current_title = '正文'
    paragraph_buffer = []
    paragraphs = []

    def flush_paragraph():
        nonlocal paragraph_buffer, paragraphs
        text = ' '.join(item.strip() for item in paragraph_buffer if item.strip()).strip()
        if text:
            paragraphs.append(text)
        paragraph_buffer = []

    def flush_section():
        nonlocal paragraphs, sections
        flush_paragraph()
        if paragraphs:
            sections.append({'title': current_title, 'paragraphs': paragraphs[:]})
        paragraphs = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            continue

        if CHAPTER_PATTERN.match(stripped):
            if paragraphs or paragraph_buffer:
                flush_section()
            current_title = stripped
            continue

        paragraph_buffer.append(stripped)

    if paragraphs or paragraph_buffer:
        flush_section()

    if not sections and raw_text:
        sections = [{'title': '正文', 'paragraphs': [raw_text]}]

    return sections


def _build_chapters_from_text(content_text: str):
    sections = parse_content_sections(content_text or '')
    chapters = []
    for index, section in enumerate(sections, start=1):
        chapter_text = '\n\n'.join(section.get('paragraphs') or []).strip()
        if not chapter_text:
            continue
        chapters.append(
            {
                'section_key': None,
                'title': (section.get('title') or f'第 {index} 章').strip(),
                'content_text': chapter_text,
            }
        )
    return chapters


def _load_manuscript_chapters(manuscript):
    raw_payload = getattr(manuscript, 'chapter_payload', None)
    if raw_payload:
        try:
            data = json.loads(raw_payload)
        except (TypeError, ValueError):
            data = []
        if isinstance(data, list):
            chapters = []
            for index, item in enumerate(data, start=1):
                if not isinstance(item, dict):
                    continue
                content_text = (item.get('content_text') or '').strip()
                if not content_text:
                    continue
                chapters.append(
                    {
                        'section_key': (item.get('section_key') or '').strip() or None,
                        'title': (item.get('title') or f'第 {index} 章').strip(),
                        'content_text': content_text,
                    }
                )
            if chapters:
                return chapters
    return _build_chapters_from_text(getattr(manuscript, 'content_text', '') or '')


def _chapter_to_paragraphs(chapter):
    parts = []
    for block in re.split(r'\n\s*\n+', (chapter.get('content_text') or '').strip()):
        paragraph = block.strip()
        if paragraph:
            parts.append(paragraph)
    return parts or [(chapter.get('content_text') or '').strip()]


def _build_chapter_summary(content_text: str, limit: int = 120):
    text = ' '.join((content_text or '').replace('\n', ' ').split()).strip()
    if not text:
        return ''
    return text[:limit]


def _next_chapter_no(book_id: int):
    latest = db.session.query(db.func.max(BookChapter.chapter_no)).filter(BookChapter.book_id == book_id).scalar() or 0
    return int(latest) + 1


def _next_revision_no(chapter_id: int):
    latest = (
        db.session.query(db.func.max(BookChapterRevision.version_no))
        .filter(BookChapterRevision.chapter_id == chapter_id)
        .scalar()
        or 0
    )
    return int(latest) + 1


def _latest_revision(chapter_id: int):
    return (
        BookChapterRevision.query.filter_by(chapter_id=chapter_id)
        .order_by(BookChapterRevision.version_no.desc(), BookChapterRevision.id.desc())
        .first()
    )


def _get_max_paragraph_key_no():
    rows = db.session.query(ReaderParagraph.paragraph_key).all()
    return max((_match_key_number(PARAGRAPH_KEY_PATTERN, row.paragraph_key) for row in rows), default=0)


def _sync_reader_section_with_revision(book_id: int, chapter: BookChapter, revision: BookChapterRevision):
    section = ReaderSection.query.filter_by(book_id=book_id, section_key=chapter.chapter_key).first()
    if not section:
        section = ReaderSection(
            book_id=book_id,
            section_key=chapter.chapter_key,
            title=revision.title,
            summary=revision.summary or '',
            level=1,
            order_no=chapter.chapter_no,
        )
        db.session.add(section)
        db.session.flush()
    else:
        old_paragraphs = ReaderParagraph.query.filter_by(section_id=section.id).order_by(ReaderParagraph.order_no.asc()).all()
        old_keys = [item.paragraph_key for item in old_paragraphs if item.paragraph_key]
        if old_keys:
            ReaderHighlight.query.filter(
                ReaderHighlight.book_id == book_id,
                ReaderHighlight.paragraph_key.in_(old_keys),
            ).delete(synchronize_session=False)
        ReaderParagraph.query.filter_by(section_id=section.id).delete(synchronize_session=False)
        section.title = revision.title
        section.summary = revision.summary or ''
        section.order_no = chapter.chapter_no

    next_paragraph_key_no = _get_max_paragraph_key_no()
    for paragraph_order, paragraph_text in enumerate(_chapter_to_paragraphs({'content_text': revision.content_text}), start=1):
        next_paragraph_key_no += 1
        db.session.add(
            ReaderParagraph(
                section_id=section.id,
                paragraph_key=f'p{next_paragraph_key_no}',
                text=paragraph_text,
                order_no=paragraph_order,
            )
        )


def ensure_chapter_workflow_seed(book: Book):
    if not book:
        return
    existing = BookChapter.query.filter_by(book_id=book.id).first()
    if existing:
        return

    sections = ReaderSection.query.filter_by(book_id=book.id).order_by(ReaderSection.order_no.asc()).all()
    for index, section in enumerate(sections, start=1):
        chapter = BookChapter(
            book_id=book.id,
            chapter_key=section.section_key or f'chapter-{index}',
            chapter_no=int(section.order_no or index),
            title=section.title or f'第 {index} 章',
            status='published',
            tenant_id=int(getattr(book, 'tenant_id', 1) or 1),
            created_by=book.creator_id,
        )
        db.session.add(chapter)
        db.session.flush()

        paragraphs = ReaderParagraph.query.filter_by(section_id=section.id).order_by(ReaderParagraph.order_no.asc()).all()
        content_text = '\n\n'.join((item.text or '').strip() for item in paragraphs if (item.text or '').strip())
        revision = BookChapterRevision(
            chapter_id=chapter.id,
            version_no=1,
            title=chapter.title,
            content_text=content_text or '',
            summary=section.summary or _build_chapter_summary(content_text or ''),
            status='published',
            published_at=datetime.utcnow(),
            reviewed_at=datetime.utcnow(),
            reviewed_by=book.creator_id,
            created_by=book.creator_id,
            tenant_id=chapter.tenant_id,
        )
        db.session.add(revision)
        db.session.flush()
        chapter.published_revision_id = revision.id


def list_book_chapters(book: Book):
    ensure_chapter_workflow_seed(book)
    chapters = (
        BookChapter.query.filter_by(book_id=book.id)
        .order_by(BookChapter.chapter_no.asc(), BookChapter.id.asc())
        .all()
    )

    items = []
    for chapter in chapters:
        latest = _latest_revision(chapter.id)
        published = BookChapterRevision.query.get(chapter.published_revision_id) if chapter.published_revision_id else None
        payload = chapter.to_dict()
        payload['latest_revision'] = latest.to_dict() if latest else None
        payload['published_revision'] = published.to_dict() if published else None
        payload['can_submit'] = bool(latest and latest.status in ('draft', 'rejected'))
        payload['can_edit'] = bool(latest and latest.status in ('draft', 'rejected'))
        items.append(payload)
    return items


def create_chapter_draft(book: Book, *, title: str, content_text: str, creator):
    ensure_chapter_workflow_seed(book)
    chapter_no = _next_chapter_no(book.id)
    chapter_key = f'chapter-{chapter_no}'
    chapter = BookChapter(
        book_id=book.id,
        chapter_key=chapter_key,
        chapter_no=chapter_no,
        title=title,
        status='draft',
        tenant_id=int(getattr(book, 'tenant_id', 1) or 1),
        created_by=creator.id if creator else None,
    )
    db.session.add(chapter)
    db.session.flush()

    revision = BookChapterRevision(
        chapter_id=chapter.id,
        version_no=1,
        title=title,
        content_text=content_text,
        summary=_build_chapter_summary(content_text),
        status='draft',
        created_by=creator.id if creator else None,
        tenant_id=chapter.tenant_id,
    )
    db.session.add(revision)
    db.session.commit()
    return chapter, revision


def update_chapter_draft(chapter: BookChapter, *, title: str, content_text: str, creator):
    latest = _latest_revision(chapter.id)
    if latest and latest.status in ('draft', 'rejected'):
        revision = latest
    else:
        revision = BookChapterRevision(
            chapter_id=chapter.id,
            version_no=_next_revision_no(chapter.id),
            title=title,
            content_text=content_text,
            summary=_build_chapter_summary(content_text),
            status='draft',
            created_by=creator.id if creator else None,
            tenant_id=chapter.tenant_id,
        )
        db.session.add(revision)
        db.session.flush()

    revision.title = title
    revision.content_text = content_text
    revision.summary = _build_chapter_summary(content_text)
    revision.status = 'draft'
    revision.review_comment = None
    revision.submitted_at = None
    revision.reviewed_at = None
    revision.reviewed_by = None
    chapter.title = title
    chapter.status = 'draft'
    db.session.commit()
    return revision


def submit_chapter_for_review(chapter: BookChapter):
    latest = _latest_revision(chapter.id)
    if not latest or latest.status not in ('draft', 'rejected'):
        return None, 'chapter current revision cannot submit'
    now = datetime.utcnow()
    latest.status = 'pending'
    latest.submitted_at = now
    latest.review_comment = None
    chapter.status = 'pending'
    db.session.commit()
    return latest, None


def review_chapter_revision(chapter: BookChapter, *, action: str, review_comment: str | None, reviewer):
    latest = _latest_revision(chapter.id)
    if not latest or latest.status != 'pending':
        return None, 'chapter is not in pending review status'
    if action not in ('approve', 'reject'):
        return None, 'action must be approve or reject'

    now = datetime.utcnow()
    latest.review_comment = review_comment or None
    latest.reviewed_at = now
    latest.reviewed_by = reviewer.id if reviewer else None

    if action == 'reject':
        latest.status = 'rejected'
        chapter.status = 'rejected'
        db.session.commit()
        return latest, None

    previous_published = BookChapterRevision.query.get(chapter.published_revision_id) if chapter.published_revision_id else None
    if previous_published:
        previous_published.status = 'superseded'
    latest.status = 'published'
    latest.published_at = now
    chapter.published_revision_id = latest.id
    chapter.status = 'published'
    chapter.title = latest.title

    _sync_reader_section_with_revision(chapter.book_id, chapter, latest)
    book = Book.query.get(chapter.book_id)
    if book:
        book.word_count = _calculate_book_word_count(book.id)
        if (book.shelf_status or 'down') == 'up':
            book.status = 'published'
            if not book.published_at:
                book.published_at = now

    db.session.commit()
    return latest, None

def _match_key_number(pattern, value: str | None):
    if not value:
        return 0
    matched = pattern.match(value.strip())
    if not matched:
        return 0
    try:
        return int(matched.group(1))
    except (TypeError, ValueError):
        return 0


def _resolve_author_name(manuscript, book):
    creator = User.query.get(manuscript.creator_id) if getattr(manuscript, 'creator_id', None) else None
    pen_name = (getattr(creator, 'pen_name', None) or '').strip()
    if pen_name:
        return pen_name
    return (book.author or '').strip() or None


def _current_section_state(book_id: int):
    sections = ReaderSection.query.filter_by(book_id=book_id).order_by(ReaderSection.order_no.asc()).all()
    section_ids = [section.id for section in sections]
    paragraphs = []
    if section_ids:
        paragraphs = ReaderParagraph.query.filter(ReaderParagraph.section_id.in_(section_ids)).all()

    section_map = {section.section_key: section for section in sections}
    max_section_order = max((int(section.order_no or 0) for section in sections), default=0)
    max_section_key_no = max((_match_key_number(SECTION_KEY_PATTERN, section.section_key) for section in sections), default=0)
    max_paragraph_key_no = max(
        (_match_key_number(PARAGRAPH_KEY_PATTERN, paragraph.paragraph_key) for paragraph in paragraphs),
        default=0,
    )
    return {
        'sections': sections,
        'section_ids': section_ids,
        'section_map': section_map,
        'max_section_order': max_section_order,
        'max_section_key_no': max_section_key_no,
        'max_paragraph_key_no': max_paragraph_key_no,
    }


def _append_new_section(book_id: int, chapter: dict, *, section_order: int, section_key_no: int, paragraph_key_no: int):
    section = ReaderSection(
        book_id=book_id,
        section_key=f'chapter-{section_key_no}',
        title=chapter.get('title') or f'第 {section_key_no} 章',
        summary='',
        level=1,
        order_no=section_order,
    )
    db.session.add(section)
    db.session.flush()

    next_paragraph_key_no = int(paragraph_key_no or 0)
    for paragraph_order, paragraph_text in enumerate(_chapter_to_paragraphs(chapter), start=1):
        next_paragraph_key_no += 1
        db.session.add(
            ReaderParagraph(
                section_id=section.id,
                paragraph_key=f'p{next_paragraph_key_no}',
                text=paragraph_text,
                order_no=paragraph_order,
            )
        )

    return next_paragraph_key_no


def _replace_section_content(section, chapter: dict, *, paragraph_key_start: int):
    old_paragraphs = ReaderParagraph.query.filter_by(section_id=section.id).order_by(ReaderParagraph.order_no.asc()).all()
    old_paragraph_keys = [paragraph.paragraph_key for paragraph in old_paragraphs if paragraph.paragraph_key]
    if old_paragraph_keys:
        ReaderHighlight.query.filter(
            ReaderHighlight.book_id == section.book_id,
            ReaderHighlight.paragraph_key.in_(old_paragraph_keys),
        ).delete(synchronize_session=False)
    ReaderParagraph.query.filter_by(section_id=section.id).delete(synchronize_session=False)

    section.title = chapter.get('title') or section.title

    next_paragraph_key_no = int(paragraph_key_start or 0)
    for paragraph_order, paragraph_text in enumerate(_chapter_to_paragraphs(chapter), start=1):
        next_paragraph_key_no += 1
        db.session.add(
            ReaderParagraph(
                section_id=section.id,
                paragraph_key=f'p{next_paragraph_key_no}',
                text=paragraph_text,
                order_no=paragraph_order,
            )
        )
    return next_paragraph_key_no


def _calculate_book_word_count(book_id: int):
    rows = (
        db.session.query(ReaderParagraph.text)
        .join(ReaderSection, ReaderParagraph.section_id == ReaderSection.id)
        .filter(ReaderSection.book_id == book_id)
        .all()
    )
    return sum(len((row.text or '').strip()) for row in rows)


def _publish_full_book(book_id: int, chapters: list[dict], current_state: dict):
    if current_state['section_ids']:
        ReaderParagraph.query.filter(ReaderParagraph.section_id.in_(current_state['section_ids'])).delete(
            synchronize_session=False
        )
    ReaderSection.query.filter_by(book_id=book_id).delete(synchronize_session=False)
    ReaderHighlight.query.filter_by(book_id=book_id).delete(synchronize_session=False)

    next_paragraph_key_no = 0
    for order_no, chapter in enumerate(chapters, start=1):
        next_paragraph_key_no = _append_new_section(
            book_id,
            chapter,
            section_order=order_no,
            section_key_no=order_no,
            paragraph_key_no=next_paragraph_key_no,
        )


def _publish_incremental_update(book_id: int, chapters: list[dict], current_state: dict):
    next_section_order = int(current_state['max_section_order'] or 0)
    next_section_key_no = int(current_state['max_section_key_no'] or 0)
    next_paragraph_key_no = int(current_state['max_paragraph_key_no'] or 0)

    for chapter in chapters:
        section_key = (chapter.get('section_key') or '').strip()
        section = current_state['section_map'].get(section_key) if section_key else None
        if section:
            next_paragraph_key_no = _replace_section_content(section, chapter, paragraph_key_start=next_paragraph_key_no)
            continue

        next_section_order += 1
        next_section_key_no += 1
        next_paragraph_key_no = _append_new_section(
            book_id,
            chapter,
            section_order=next_section_order,
            section_key_no=next_section_key_no,
            paragraph_key_no=next_paragraph_key_no,
        )


def _sync_chapter_workflow_after_manuscript_publish(book: Book, chapters: list[dict], reviewer, now: datetime):
    ensure_chapter_workflow_seed(book)
    chapter_map = {
        item.chapter_key: item
        for item in BookChapter.query.filter_by(book_id=book.id).all()
    }
    next_no = _next_chapter_no(book.id)
    for chapter_data in chapters:
        key = (chapter_data.get('section_key') or '').strip()
        chapter = chapter_map.get(key) if key else None
        if not chapter:
            chapter = BookChapter(
                book_id=book.id,
                chapter_key=key or f'chapter-{next_no}',
                chapter_no=next_no,
                title=chapter_data.get('title') or f'第 {next_no} 章',
                status='published',
                tenant_id=int(getattr(book, 'tenant_id', 1) or 1),
                created_by=reviewer.id if reviewer else book.creator_id,
            )
            next_no += 1
            db.session.add(chapter)
            db.session.flush()
            chapter_map[chapter.chapter_key] = chapter

        revision = BookChapterRevision(
            chapter_id=chapter.id,
            version_no=_next_revision_no(chapter.id),
            title=chapter_data.get('title') or chapter.title,
            content_text=(chapter_data.get('content_text') or '').strip(),
            summary=_build_chapter_summary((chapter_data.get('content_text') or '').strip()),
            status='published',
            review_comment=None,
            submitted_at=now,
            reviewed_at=now,
            reviewed_by=reviewer.id if reviewer else None,
            published_at=now,
            created_by=reviewer.id if reviewer else book.creator_id,
            tenant_id=chapter.tenant_id,
        )
        db.session.add(revision)
        db.session.flush()
        previous = BookChapterRevision.query.get(chapter.published_revision_id) if chapter.published_revision_id else None
        if previous:
            previous.status = 'superseded'
        chapter.title = revision.title
        chapter.status = 'published'
        chapter.published_revision_id = revision.id


def publish_manuscript(manuscript, reviewer):
    if manuscript.status != 'approved':
        return None, 'manuscript status must be approved before publish'

    chapters = _load_manuscript_chapters(manuscript)
    if not chapters:
        return None, 'content_text is required for publish'

    book = Book.query.get(manuscript.book_id)
    if not book:
        return None, 'book not found'

    update_mode = (getattr(manuscript, 'update_mode', None) or 'create').strip().lower()
    if update_mode not in {'create', 'full', 'append'}:
        return None, 'invalid manuscript update_mode'

    now = datetime.utcnow()
    current_state = _current_section_state(book.id)

    book.title = manuscript.title or book.title
    if manuscript.cover is not None:
        book.cover = manuscript.cover
    if manuscript.description is not None:
        book.description = manuscript.description
    author_name = _resolve_author_name(manuscript, book)
    if author_name:
        book.author = author_name
    book.status = 'published'
    book.published_at = now

    if update_mode in {'create', 'full'}:
        _publish_full_book(book.id, chapters, current_state)
    else:
        _publish_incremental_update(book.id, chapters, current_state)

    _sync_chapter_workflow_after_manuscript_publish(book, chapters, reviewer, now)
    book.word_count = _calculate_book_word_count(book.id)

    latest = db.session.query(db.func.max(BookVersion.version_no)).filter(BookVersion.book_id == book.id).scalar() or 0
    version = BookVersion(
        book_id=book.id,
        manuscript_id=manuscript.id,
        version_no=int(latest) + 1,
        title=manuscript.title,
        cover=manuscript.cover,
        description=manuscript.description,
        content_text=manuscript.content_text,
        created_by=reviewer.id if reviewer else None,
    )
    db.session.add(version)

    manuscript.status = 'published'
    manuscript.reviewed_by = reviewer.id if reviewer else manuscript.reviewed_by
    manuscript.reviewed_at = now
    manuscript.published_at = now
    if not manuscript.submitted_at:
        manuscript.submitted_at = now

    db.session.commit()
    return version, None
