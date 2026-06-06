from __future__ import annotations

import argparse
from datetime import datetime

from app import create_app, db
from app.models import Book, BookChapter, BookChapterRevision, BookManuscript, BookVersion, ReaderParagraph, ReaderSection
from app.services.chapter_content import get_record_text, store_manuscript_chapters, store_text_on_record


def _limit_query(query, limit: int | None):
    return query.limit(limit) if limit else query


def _verify(record) -> None:
    text = get_record_text(record)
    if not text.strip():
        raise RuntimeError('stored content is empty after upload')


def migrate_revisions(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None) -> int:
    query = BookChapterRevision.query.join(BookChapter, BookChapter.id == BookChapterRevision.chapter_id).filter(
        BookChapterRevision.content_text.isnot(None),
        BookChapterRevision.content_text != '',
    )
    if book_id:
        query = query.filter(BookChapter.book_id == book_id)

    count = 0
    for revision in _limit_query(query.order_by(BookChapterRevision.id.asc()), limit).all():
        count += 1
        if dry_run:
            continue
        original = revision.content_text
        store_text_on_record(revision, original, folder='book_chapters', clear_inline=clear_db_content)
        if not clear_db_content:
            revision.content_text = original
        _verify(revision)
        db.session.commit()
    return count


def migrate_manuscripts(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None) -> int:
    query = BookManuscript.query
    if book_id:
        query = query.filter(BookManuscript.book_id == book_id)
    query = query.filter(
        (BookManuscript.content_text.isnot(None) & (BookManuscript.content_text != ''))
        | (BookManuscript.chapter_payload.isnot(None) & (BookManuscript.chapter_payload != ''))
    )

    count = 0
    for manuscript in _limit_query(query.order_by(BookManuscript.id.asc()), limit).all():
        count += 1
        if dry_run:
            continue
        original_content = manuscript.content_text
        original_payload = manuscript.chapter_payload
        if original_content:
            store_text_on_record(manuscript, original_content, folder='book_manuscripts', clear_inline=clear_db_content)
            if not clear_db_content:
                manuscript.content_text = original_content
            _verify(manuscript)
        if original_payload:
            import json

            chapters = json.loads(original_payload)
            store_manuscript_chapters(manuscript, chapters)
            if not clear_db_content:
                manuscript.chapter_payload = original_payload
        db.session.commit()
    return count


def migrate_versions(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None) -> int:
    query = BookVersion.query.filter(BookVersion.content_text.isnot(None), BookVersion.content_text != '')
    if book_id:
        query = query.filter(BookVersion.book_id == book_id)

    count = 0
    for version in _limit_query(query.order_by(BookVersion.id.asc()), limit).all():
        count += 1
        if dry_run:
            continue
        original = version.content_text
        store_text_on_record(version, original, folder='book_versions', clear_inline=clear_db_content)
        if not clear_db_content:
            version.content_text = original
        _verify(version)
        db.session.commit()
    return count


def migrate_legacy_reader_paragraphs(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None) -> int:
    book_query = Book.query
    if book_id:
        book_query = book_query.filter(Book.id == book_id)
    books = _limit_query(book_query.order_by(Book.id.asc()), limit).all()
    count = 0

    for book in books:
        if BookChapter.query.filter_by(book_id=book.id).first():
            continue
        sections = ReaderSection.query.filter_by(book_id=book.id).order_by(ReaderSection.order_no.asc()).all()
        if not sections:
            continue
        for index, section in enumerate(sections, start=1):
            paragraphs = ReaderParagraph.query.filter_by(section_id=section.id).order_by(ReaderParagraph.order_no.asc()).all()
            content = '\n\n'.join((item.text or '').strip() for item in paragraphs if (item.text or '').strip())
            if not content:
                continue
            count += 1
            if dry_run:
                continue
            chapter = BookChapter(
                book_id=book.id,
                chapter_key=section.section_key or f'chapter-{index}',
                chapter_no=int(section.order_no or index),
                title=section.title,
                status='published',
                tenant_id=int(getattr(book, 'tenant_id', 1) or 1),
                created_by=book.creator_id,
            )
            db.session.add(chapter)
            db.session.flush()
            revision = BookChapterRevision(
                chapter_id=chapter.id,
                version_no=1,
                title=section.title,
                content_text=None,
                summary=section.summary or '',
                status='published',
                reviewed_at=datetime.utcnow(),
                published_at=datetime.utcnow(),
                created_by=book.creator_id,
                tenant_id=chapter.tenant_id,
            )
            store_text_on_record(revision, content, folder='book_chapters', clear_inline=True)
            db.session.add(revision)
            db.session.flush()
            chapter.published_revision_id = revision.id
            if clear_db_content:
                ReaderParagraph.query.filter_by(section_id=section.id).delete(synchronize_session=False)
            db.session.commit()
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description='Migrate book/chapter content from MySQL text fields to Tencent COS.')
    parser.add_argument('--dry-run', action='store_true', help='Only count rows that would be migrated.')
    parser.add_argument('--limit', type=int, default=None, help='Maximum rows/books per phase.')
    parser.add_argument('--book-id', type=int, default=None, help='Limit migration to one book.')
    parser.add_argument('--clear-db-content', action='store_true', help='Clear inline content after COS upload and MD5 verification.')
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        stats = {
            'book_chapter_revisions': migrate_revisions(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
            ),
            'book_manuscripts': migrate_manuscripts(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
            ),
            'book_versions': migrate_versions(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
            ),
            'legacy_reader_sections': migrate_legacy_reader_paragraphs(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
            ),
        }
    print(stats)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
