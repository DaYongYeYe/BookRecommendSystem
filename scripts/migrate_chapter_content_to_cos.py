from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from app import create_app, db
from app.models import Book, BookChapter, BookChapterRevision, BookManuscript, BookVersion, ReaderParagraph, ReaderSection
from app.services.chapter_content import get_record_text, store_manuscript_chapters, store_text_on_record


def _limit_query(query, limit: int | None):
    return query.limit(limit) if limit else query


def _verify(record) -> None:
    text = get_record_text(record)
    if not text.strip():
        raise RuntimeError('stored content is empty after upload')


def _retry(func, *args, retries: int = 3, delay: float = 1.0, backoff: float = 2.0) -> Any:
    """Retry a function with exponential backoff."""
    last_error = None
    for attempt in range(retries):
        try:
            return func(*args)
        except Exception as e:
            last_error = e
            if attempt < retries - 1:
                wait = delay * (backoff ** attempt)
                time.sleep(wait)
    raise last_error


class ProgressTracker:
    """Thread-safe progress tracker."""

    def __init__(self, total: int, phase_name: str):
        self._total = total
        self._phase_name = phase_name
        self._completed = 0
        self._failed = 0
        self._failed_ids: list[int] = []
        self._lock = threading.Lock()
        self._start_time = time.time()

    def update(self, success: bool = True, record_id: int | None = None):
        with self._lock:
            if success:
                self._completed += 1
            else:
                self._failed += 1
                if record_id is not None:
                    self._failed_ids.append(record_id)
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

    @property
    def failed_ids(self) -> list[int]:
        with self._lock:
            return list(self._failed_ids)


def _do_migrate_revision(app, revision_id: int, clear_db_content: bool) -> None:
    """Core logic for migrating a single revision (called by retry wrapper)."""
    with app.app_context():
        revision = db.session.get(BookChapterRevision, revision_id)
        if not revision:
            raise ValueError(f'Revision {revision_id} not found')
        original = revision.content_text
        store_text_on_record(revision, original, folder='book_chapters', clear_inline=clear_db_content)
        if not clear_db_content:
            revision.content_text = original
        _verify(revision)
        db.session.commit()


def _migrate_single_revision(app, revision_id: int, clear_db_content: bool, retries: int, retry_delay: float) -> bool:
    """Migrate a single revision with retry logic."""
    try:
        _retry(_do_migrate_revision, app, revision_id, clear_db_content, retries=retries, delay=retry_delay)
        return True
    except Exception as e:
        with app.app_context():
            db.session.rollback()
        print(f'\nError migrating revision {revision_id} after {retries} retries: {e}')
        return False


def migrate_revisions(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1, retries: int = 3, retry_delay: float = 1.0) -> tuple[int, list[int]]:
    query = BookChapterRevision.query.join(BookChapter, BookChapter.id == BookChapterRevision.chapter_id).filter(
        BookChapterRevision.content_text.isnot(None),
        BookChapterRevision.content_text != '',
    )
    if book_id:
        query = query.filter(BookChapter.book_id == book_id)

    records = _limit_query(query.order_by(BookChapterRevision.id.asc()), limit).all()
    count = len(records)
    if dry_run or count == 0:
        return count, []

    revision_ids = [r.id for r in records]
    progress = ProgressTracker(count, 'revisions')

    app = create_app()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_migrate_single_revision, app, rid, clear_db_content, retries, retry_delay): rid
            for rid in revision_ids
        }
        for future in as_completed(futures):
            rid = futures[future]
            success = future.result()
            progress.update(success, record_id=rid if not success else None)
    return count, progress.failed_ids


def _do_migrate_manuscript(app, manuscript_id: int, clear_db_content: bool) -> None:
    """Core logic for migrating a single manuscript."""
    import json
    with app.app_context():
        manuscript = db.session.get(BookManuscript, manuscript_id)
        if not manuscript:
            raise ValueError(f'Manuscript {manuscript_id} not found')
        original_content = manuscript.content_text
        original_payload = manuscript.chapter_payload
        if original_content:
            store_text_on_record(manuscript, original_content, folder='book_manuscripts', clear_inline=clear_db_content)
            if not clear_db_content:
                manuscript.content_text = original_content
            _verify(manuscript)
        if original_payload:
            chapters = json.loads(original_payload)
            store_manuscript_chapters(manuscript, chapters)
            if not clear_db_content:
                manuscript.chapter_payload = original_payload
        db.session.commit()


def _migrate_single_manuscript(app, manuscript_id: int, clear_db_content: bool, retries: int, retry_delay: float) -> bool:
    """Migrate a single manuscript with retry logic."""
    try:
        _retry(_do_migrate_manuscript, app, manuscript_id, clear_db_content, retries=retries, delay=retry_delay)
        return True
    except Exception as e:
        with app.app_context():
            db.session.rollback()
        print(f'\nError migrating manuscript {manuscript_id} after {retries} retries: {e}')
        return False


def migrate_manuscripts(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1, retries: int = 3, retry_delay: float = 1.0) -> tuple[int, list[int]]:
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
        return count, []

    manuscript_ids = [m.id for m in records]
    progress = ProgressTracker(count, 'manuscripts')

    app = create_app()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_migrate_single_manuscript, app, mid, clear_db_content, retries, retry_delay): mid
            for mid in manuscript_ids
        }
        for future in as_completed(futures):
            mid = futures[future]
            success = future.result()
            progress.update(success, record_id=mid if not success else None)
    return count, progress.failed_ids


def _do_migrate_version(app, version_id: int, clear_db_content: bool) -> None:
    """Core logic for migrating a single version."""
    with app.app_context():
        version = db.session.get(BookVersion, version_id)
        if not version:
            raise ValueError(f'Version {version_id} not found')
        original = version.content_text
        store_text_on_record(version, original, folder='book_versions', clear_inline=clear_db_content)
        if not clear_db_content:
            version.content_text = original
        _verify(version)
        db.session.commit()


def _migrate_single_version(app, version_id: int, clear_db_content: bool, retries: int, retry_delay: float) -> bool:
    """Migrate a single version with retry logic."""
    try:
        _retry(_do_migrate_version, app, version_id, clear_db_content, retries=retries, delay=retry_delay)
        return True
    except Exception as e:
        with app.app_context():
            db.session.rollback()
        print(f'\nError migrating version {version_id} after {retries} retries: {e}')
        return False


def migrate_versions(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1, retries: int = 3, retry_delay: float = 1.0) -> tuple[int, list[int]]:
    query = BookVersion.query.filter(BookVersion.content_text.isnot(None), BookVersion.content_text != '')
    if book_id:
        query = query.filter(BookVersion.book_id == book_id)

    records = _limit_query(query.order_by(BookVersion.id.asc()), limit).all()
    count = len(records)
    if dry_run or count == 0:
        return count, []

    version_ids = [v.id for v in records]
    progress = ProgressTracker(count, 'versions')

    app = create_app()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_migrate_single_version, app, vid, clear_db_content, retries, retry_delay): vid
            for vid in version_ids
        }
        for future in as_completed(futures):
            vid = futures[future]
            success = future.result()
            progress.update(success, record_id=vid if not success else None)
    return count, progress.failed_ids


def _do_migrate_book_legacy(app, book_id: int, clear_db_content: bool) -> int:
    """Core logic for migrating legacy reader paragraphs for a single book."""
    with app.app_context():
        book = db.session.get(Book, book_id)
        if not book:
            raise ValueError(f'Book {book_id} not found')
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


def _migrate_single_book_legacy(app, book_id: int, clear_db_content: bool, retries: int, retry_delay: float) -> int:
    """Migrate legacy reader paragraphs for a single book with retry logic."""
    try:
        return _retry(_do_migrate_book_legacy, app, book_id, clear_db_content, retries=retries, delay=retry_delay)
    except Exception as e:
        with app.app_context():
            db.session.rollback()
        print(f'\nError migrating book {book_id} legacy paragraphs after {retries} retries: {e}')
        return -1  # Return -1 to indicate failure (0 means no sections to migrate)


def migrate_legacy_reader_paragraphs(*, dry_run: bool, clear_db_content: bool, limit: int | None, book_id: int | None, workers: int = 1, retries: int = 3, retry_delay: float = 1.0) -> tuple[int, list[int]]:
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
        return count, []

    book_ids = [b.id for b in books]
    progress = ProgressTracker(total, 'legacy_books')

    app = create_app()
    total_migrated = 0
    lock = threading.Lock()

    def _on_done(future):
        nonlocal total_migrated
        bid = futures[future]
        result = future.result()
        with lock:
            if result >= 0:
                total_migrated += result
            else:
                total_migrated += 0  # Failed, don't add
        progress.update(success=result >= 0, record_id=bid if result < 0 else None)

    futures = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for bid in book_ids:
            future = executor.submit(_migrate_single_book_legacy, app, bid, clear_db_content, retries, retry_delay)
            futures[future] = bid
            future.add_done_callback(_on_done)
        # Wait for all to complete
        for future in futures:
            future.result()

    return total_migrated, progress.failed_ids


def main() -> int:
    parser = argparse.ArgumentParser(description='Migrate book/chapter content from MySQL text fields to Tencent COS.')
    parser.add_argument('--dry-run', action='store_true', help='Only count rows that would be migrated.')
    parser.add_argument('--limit', type=int, default=None, help='Maximum rows/books per phase.')
    parser.add_argument('--book-id', type=int, default=None, help='Limit migration to one book.')
    parser.add_argument('--clear-db-content', action='store_true', help='Clear inline content after COS upload and MD5 verification.')
    parser.add_argument('--workers', type=int, default=4, help='Number of concurrent worker threads (default: 4).')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries per failed upload (default: 3).')
    parser.add_argument('--retry-delay', type=float, default=1.0, help='Initial delay between retries in seconds (default: 1.0).')
    args = parser.parse_args()

    workers = max(1, args.workers)
    retries = max(1, args.retries)
    retry_delay = max(0.1, args.retry_delay)
    print(f'Starting migration with {workers} worker thread(s), {retries} retries per failure...')

    app = create_app()
    all_failed_ids: dict[str, list[int]] = {}

    with app.app_context():
        count, failed = migrate_revisions(
            dry_run=args.dry_run,
            clear_db_content=args.clear_db_content,
            limit=args.limit,
            book_id=args.book_id,
            workers=workers,
            retries=retries,
            retry_delay=retry_delay,
        )
        if failed:
            all_failed_ids['book_chapter_revisions'] = failed

        count, failed = migrate_manuscripts(
            dry_run=args.dry_run,
            clear_db_content=args.clear_db_content,
            limit=args.limit,
            book_id=args.book_id,
            workers=workers,
            retries=retries,
            retry_delay=retry_delay,
        )
        if failed:
            all_failed_ids['book_manuscripts'] = failed

        count, failed = migrate_versions(
            dry_run=args.dry_run,
            clear_db_content=args.clear_db_content,
            limit=args.limit,
            book_id=args.book_id,
            workers=workers,
            retries=retries,
            retry_delay=retry_delay,
        )
        if failed:
            all_failed_ids['book_versions'] = failed

        count, failed = migrate_legacy_reader_paragraphs(
            dry_run=args.dry_run,
            clear_db_content=args.clear_db_content,
            limit=args.limit,
            book_id=args.book_id,
            workers=workers,
            retries=retries,
            retry_delay=retry_delay,
        )
        if failed:
            all_failed_ids['legacy_books'] = failed

    if all_failed_ids:
        print('\n[!] Failed records (can be retried with --book-id):')
        for phase, ids in all_failed_ids.items():
            print(f'  {phase}: {ids}')
        return 1
    else:
        print('\n[OK] Migration complete - all records processed successfully.')
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
