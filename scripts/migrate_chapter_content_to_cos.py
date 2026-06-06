from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app import create_app, db
from app.models import Book, BookChapter, BookChapterRevision, BookManuscript, BookVersion, ReaderParagraph, ReaderSection
from app.services.chapter_content import get_record_text, store_manuscript_chapters, store_text_on_record


def _limit_query(query, limit: int | None):
    return query.limit(limit) if limit else query


def _verify(record) -> None:
    text = get_record_text(record)
    if not text.strip():
        raise RuntimeError('stored content is empty after upload')


class ProgressTracker:
    """Thread-safe progress tracker."""

    def __init__(self, total: int, phase_name: str):
        self._total = total
        self._phase_name = phase_name
        self._completed = 0
        self._failed = 0
        self._lock = threading.Lock()
        self._start_time = time.time()

    def update(self, success: bool = True):
        with self._lock:
            if success:
                self._completed += 1
            else:
                self._failed += 1
            elapsed = time.time() - self._start_time
            done = self._completed + self._failed
            rate = done / elapsed if elapsed > 0 else 0
            eta = (self._total - done) / rate if rate > 0 else 0
            print(
                f'\r[{self._phase_name}] {done}/{self._total} '
                f'({self._completed} ok, {self._failed} fail) '
                f'[{rate:.1f} it/s, ETA {int(eta)}s]',
                end='', flush=True,
            )
            if done >= self._total:
                print()  # newline at end


def _migrate_single_revision(app, revision_id: int, clear_db_content: bool) -> bool:
    """Migrate a single revision in its own app context (for thread pool)."""
    with app.app_context():
        try:
            revision = db.session.get(BookChapterRevision, revision_id)
            if not revision:
                return False
            original = revision.content_text
            store_text_on_record(revision, original, folder='book_chapters', clear_inline=clear_db_content)
            if not clear_db_content:
                revision.content_text = original
            _verify(revision)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f'\nError migrating revision {revision_id}: {e}')
            return False


def migrate_revisions(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1) -> int:
    query = BookChapterRevision.query.join(BookChapter, BookChapter.id == BookChapterRevision.chapter_id).filter(
        BookChapterRevision.content_text.isnot(None),
        BookChapterRevision.content_text != '',
    )
    if book_id:
        query = query.filter(BookChapter.book_id == book_id)

    records = _limit_query(query.order_by(BookChapterRevision.id.asc()), limit).all()
    count = len(records)
    if dry_run or count == 0:
        return count

    revision_ids = [r.id for r in records]
    progress = ProgressTracker(count, 'revisions')

    app = create_app()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_migrate_single_revision, app, rid, clear_db_content): rid
            for rid in revision_ids
        }
        for future in as_completed(futures):
            success = future.result()
            progress.update(success)
    return count


def _migrate_single_manuscript(app, manuscript_id: int, clear_db_content: bool) -> bool:
    """Migrate a single manuscript in its own app context."""
    with app.app_context():
        try:
            manuscript = db.session.get(BookManuscript, manuscript_id)
            if not manuscript:
                return False
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
            return True
        except Exception as e:
            db.session.rollback()
            print(f'\nError migrating manuscript {manuscript_id}: {e}')
            return False


def migrate_manuscripts(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1) -> int:
    query = BookManuscript.query
    if book_id:
        query = query.filter(BookManuscript.book_id == book_id)
    query = query.filter(
        (BookManuscript.content_text.isnot(None) & (BookManuscript.content_text != ''))
        | (BookManuscript.chapter_payload.isnot(None) & (BookManuscript.chapter_payload != ''))
    )

    records = _limit_query(query.order_by(BookManuscript.id.asc()), limit).all()
    count = len(records)
    if dry_run or count == 0:
        return count

    manuscript_ids = [m.id for m in records]
    progress = ProgressTracker(count, 'manuscripts')

    app = create_app()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_migrate_single_manuscript, app, mid, clear_db_content): mid
            for mid in manuscript_ids
        }
        for future in as_completed(futures):
            success = future.result()
            progress.update(success)
    return count


def _migrate_single_version(app, version_id: int, clear_db_content: bool) -> bool:
    """Migrate a single version in its own app context."""
    with app.app_context():
        try:
            version = db.session.get(BookVersion, version_id)
            if not version:
                return False
            original = version.content_text
            store_text_on_record(version, original, folder='book_versions', clear_inline=clear_db_content)
            if not clear_db_content:
                version.content_text = original
            _verify(version)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f'\nError migrating version {version_id}: {e}')
            return False


def migrate_versions(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1) -> int:
    query = BookVersion.query.filter(BookVersion.content_text.isnot(None), BookVersion.content_text != '')
    if book_id:
        query = query.filter(BookVersion.book_id == book_id)

    records = _limit_query(query.order_by(BookVersion.id.asc()), limit).all()
    count = len(records)
    if dry_run or count == 0:
        return count

    version_ids = [v.id for v in records]
    progress = ProgressTracker(count, 'versions')

    app = create_app()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_migrate_single_version, app, vid, clear_db_content): vid
            for vid in version_ids
        }
        for future in as_completed(futures):
            success = future.result()
            progress.update(success)
    return count


def _migrate_single_book_legacy(app, book_id: int, clear_db_content: bool) -> int:
    """Migrate legacy reader paragraphs for a single book in its own app context."""
    with app.app_context():
        try:
            book = db.session.get(Book, book_id)
            if not book:
                return 0
            if BookChapter.query.filter_by(book_id=book.id).first():
                return 0
            sections = ReaderSection.query.filter_by(book_id=book.id).order_by(ReaderSection.order_no.asc()).all()
            if not sections:
                return 0

            migrated = 0
            for index, section in enumerate(sections, start=1):
                paragraphs = ReaderParagraph.query.filter_by(section_id=section.id).order_by(ReaderParagraph.order_no.asc()).all()
                content = '\n\n'.join((item.text or '').strip() for item in paragraphs if (item.text or '').strip())
                if not content:
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
                    reviewed_at=datetime.now(timezone.utc),
                    published_at=datetime.now(timezone.utc),
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
                migrated += 1
            return migrated
        except Exception as e:
            db.session.rollback()
            print(f'\nError migrating book {book_id} legacy paragraphs: {e}')
            return 0


def migrate_legacy_reader_paragraphs(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1) -> int:
    book_query = Book.query
    if book_id:
        book_query = book_query.filter(Book.id == book_id)
    books = _limit_query(book_query.order_by(Book.id.asc()), limit).all()
    total = len(books)

    if dry_run or total == 0:
        # Count how many would be migrated
        count = 0
        for book in books:
            if BookChapter.query.filter_by(book_id=book.id).first():
                continue
            sections = ReaderSection.query.filter_by(book_id=book.id).all()
            if sections:
                count += len(sections)
        return count

    book_ids = [b.id for b in books]
    progress = ProgressTracker(total, 'legacy_books')

    app = create_app()
    total_migrated = 0
    lock = threading.Lock()

    def _on_done(future):
        nonlocal total_migrated
        result = future.result()
        with lock:
            total_migrated += result
        progress.update(success=result > 0)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for bid in book_ids:
            future = executor.submit(_migrate_single_book_legacy, app, bid, clear_db_content)
            future.add_done_callback(_on_done)
            futures.append(future)
        # Wait for all to complete
        for future in futures:
            future.result()

    return total_migrated


def main() -> int:
    parser = argparse.ArgumentParser(description='Migrate book/chapter content from MySQL text fields to Tencent COS.')
    parser.add_argument('--dry-run', action='store_true', help='Only count rows that would be migrated.')
    parser.add_argument('--limit', type=int, default=None, help='Maximum rows/books per phase.')
    parser.add_argument('--book-id', type=int, default=None, help='Limit migration to one book.')
    parser.add_argument('--clear-db-content', action='store_true', help='Clear inline content after COS upload and MD5 verification.')
    parser.add_argument('--workers', type=int, default=4, help='Number of concurrent worker threads (default: 4).')
    args = parser.parse_args()

    workers = max(1, args.workers)
    print(f'Starting migration with {workers} worker thread(s)...')

    app = create_app()
    with app.app_context():
        stats = {
            'book_chapter_revisions': migrate_revisions(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
                workers=workers,
            ),
            'book_manuscripts': migrate_manuscripts(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
                workers=workers,
            ),
            'book_versions': migrate_versions(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
                workers=workers,
            ),
            'legacy_reader_sections': migrate_legacy_reader_paragraphs(
                dry_run=args.dry_run,
                clear_db_content=args.clear_db_content,
                limit=args.limit,
                book_id=args.book_id,
                workers=workers,
            ),
        }
    print('\nMigration complete:')
    for phase, count in stats.items():
        print(f'  {phase}: {count}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
