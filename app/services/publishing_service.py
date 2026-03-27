import re
from datetime import datetime

from app import db
from app.models import (
    Book,
    BookVersion,
    ReaderHighlight,
    ReaderParagraph,
    ReaderSection,
)

CHAPTER_PATTERN = re.compile(
    r'^\s*((?:\u7b2c[\d\u4e00-\u5341\u767e\u5343]+[\u7ae0\u8282\u5377\u7bc7].*)|(?:chapter\s+\d+.*))$',
    re.IGNORECASE,
)


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


def publish_manuscript(manuscript, reviewer):
    if manuscript.status != 'approved':
        return None, 'manuscript status must be approved before publish'

    sections = parse_content_sections(manuscript.content_text or '')
    if not sections:
        return None, 'content_text is required for publish'

    book = Book.query.get(manuscript.book_id)
    if not book:
        return None, 'book not found'

    book.title = manuscript.title
    book.cover = manuscript.cover
    book.description = manuscript.description
    book.status = 'published'
    book.published_at = datetime.utcnow()

    section_rows = ReaderSection.query.filter_by(book_id=book.id).all()
    section_ids = [row.id for row in section_rows]
    if section_ids:
        ReaderParagraph.query.filter(ReaderParagraph.section_id.in_(section_ids)).delete(synchronize_session=False)
    ReaderSection.query.filter_by(book_id=book.id).delete(synchronize_session=False)
    ReaderHighlight.query.filter_by(book_id=book.id).delete(synchronize_session=False)

    for section_index, section_data in enumerate(sections, start=1):
        section = ReaderSection(
            book_id=book.id,
            section_key=f'section-{section_index}',
            title=section_data.get('title') or f'Section {section_index}',
            summary='',
            level=1,
            order_no=section_index,
        )
        db.session.add(section)
        db.session.flush()

        for paragraph_index, paragraph_text in enumerate(section_data.get('paragraphs') or [], start=1):
            db.session.add(
                ReaderParagraph(
                    section_id=section.id,
                    paragraph_key=f'p{paragraph_index}',
                    text=paragraph_text,
                    order_no=paragraph_index,
                )
            )

    latest = (
        db.session.query(db.func.max(BookVersion.version_no))
        .filter(BookVersion.book_id == book.id)
        .scalar()
    ) or 0
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
    manuscript.reviewed_at = datetime.utcnow()
    manuscript.published_at = datetime.utcnow()
    if not manuscript.submitted_at:
        manuscript.submitted_at = datetime.utcnow()

    db.session.commit()
    return version, None
