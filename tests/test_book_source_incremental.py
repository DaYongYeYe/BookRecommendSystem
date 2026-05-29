import unittest
from datetime import datetime

from app import create_app, db
from app.models import Book, BookChapter, BookChapterRevision
from app.services.book_source_importer import BookInfo, HttpClient, _book_has_source_url, _find_existing_book
from app.services.book_source_importer import import_chapters


class TestConfig:
    TESTING = True
    SECRET_KEY = 'test-secret'
    JWT_SECRET_KEY = 'test-secret'
    JWT_ALGORITHM = 'HS256'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = None
    AUTH_CODE_REQUIRE_CAPTCHA = False
    DEFAULT_TENANT_ID = 1
    LOG_DIR = 'instance/logs'
    LOG_LEVEL = 'ERROR'


class FakeClient(HttpClient):
    def __init__(self, pages: dict[str, str]):
        super().__init__()
        self.pages = pages
        self.requested_urls: list[str] = []

    def get_text(self, url: str) -> str:
        self.requested_urls.append(url)
        return self.pages[url]


class BookSourceImporterIncrementalTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_import_chapters_adds_missing_content_without_replacing_existing_revision(self):
        book = Book(
            title='Incremental Book',
            author='Author',
            status='published',
            shelf_status='up',
            created_at=datetime.utcnow(),
        )
        db.session.add(book)
        db.session.flush()
        existing = BookChapter(
            book_id=book.id,
            chapter_key='chapter-1',
            chapter_no=1,
            title='Chapter 1',
            status='published',
        )
        db.session.add(existing)
        db.session.flush()
        existing_revision = BookChapterRevision(
            chapter_id=existing.id,
            version_no=1,
            title='Chapter 1',
            content_text='Existing content',
            status='published',
            published_at=datetime.utcnow(),
        )
        db.session.add(existing_revision)
        db.session.flush()
        existing.published_revision_id = existing_revision.id
        db.session.commit()

        toc_url = 'https://example.test/book/1/'
        first_url = 'https://example.test/book/1/1.html'
        second_url = 'https://example.test/book/1/2.html'
        client = FakeClient(
            {
                toc_url: '<a href="/book/1/1.html">Chapter 1</a><a href="/book/1/2.html">Chapter 2</a>',
                second_url: '<div id="chaptercontent">New chapter paragraph one.<br><br>New chapter paragraph two with enough content for parsing.</div>',
            }
        )
        info = type('Info', (), {'toc_url': toc_url})()

        stats = import_chapters(
            book,
            info,
            client,
            base_url='https://example.test',
            include_content=True,
            max_chapters=0,
        )

        self.assertEqual(stats['chapters'], 1)
        self.assertEqual(stats['skipped_chapters'], 1)
        self.assertNotIn(first_url, client.requested_urls)
        self.assertIn(second_url, client.requested_urls)
        self.assertEqual(BookChapter.query.filter_by(book_id=book.id).count(), 2)
        self.assertEqual(BookChapterRevision.query.filter_by(chapter_id=existing.id).count(), 1)
        added = BookChapter.query.filter_by(book_id=book.id, chapter_key='chapter-2').first()
        self.assertIsNotNone(added)
        self.assertIsNotNone(added.published_revision_id)

    def test_overwrite_content_creates_new_revision_for_existing_chapter(self):
        book = Book(title='Overwrite Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        chapter = BookChapter(
            book_id=book.id,
            chapter_key='chapter-1',
            chapter_no=1,
            title='Chapter 1',
            status='published',
        )
        db.session.add(chapter)
        db.session.flush()
        revision = BookChapterRevision(
            chapter_id=chapter.id,
            version_no=1,
            title='Chapter 1',
            content_text='Old content',
            status='published',
        )
        db.session.add(revision)
        db.session.flush()
        chapter.published_revision_id = revision.id
        db.session.commit()

        toc_url = 'https://example.test/book/2/'
        chapter_url = 'https://example.test/book/2/1.html'
        client = FakeClient(
            {
                toc_url: '<a href="/book/2/1.html">Chapter 1</a>',
                chapter_url: '<div id="chaptercontent">Replacement content with enough words to pass parsing.</div>',
            }
        )
        info = type('Info', (), {'toc_url': toc_url})()

        stats = import_chapters(
            book,
            info,
            client,
            base_url='https://example.test',
            include_content=True,
            overwrite_content=True,
        )

        self.assertEqual(stats['chapters'], 1)
        self.assertEqual(BookChapterRevision.query.filter_by(chapter_id=chapter.id).count(), 2)
        db.session.refresh(chapter)
        latest = BookChapterRevision.query.get(chapter.published_revision_id)
        self.assertEqual(latest.version_no, 2)

    def test_duplicate_book_from_different_source_is_detected_by_title_and_author(self):
        book = Book(
            title='Same Book',
            author='Known Author',
            update_note='external source: https://source-one.test/book/100.html',
            status='published',
            shelf_status='up',
        )
        db.session.add(book)
        db.session.commit()

        info = BookInfo(
            title='Same Book',
            author='Known Author',
            url='https://source-two.test/book/200.html',
        )

        existing = _find_existing_book(info)

        self.assertEqual(existing.id, book.id)
        self.assertFalse(_book_has_source_url(existing, info.url))

    def test_same_source_book_can_be_updated(self):
        source_url = 'https://source-one.test/book/100.html'
        book = Book(
            title='Same Source Book',
            author='Known Author',
            update_note=f'external source: {source_url}',
            status='published',
            shelf_status='up',
        )
        db.session.add(book)
        db.session.commit()

        info = BookInfo(
            title='Same Source Book',
            author='Known Author',
            url=source_url,
        )

        existing = _find_existing_book(info)

        self.assertEqual(existing.id, book.id)
        self.assertTrue(_book_has_source_url(existing, info.url))

    def test_duplicate_book_without_author_is_detected_by_title(self):
        book = Book(
            title='Untitled Source Book',
            author='',
            update_note='external source: https://source-one.test/book/300.html',
            status='published',
            shelf_status='up',
        )
        db.session.add(book)
        db.session.commit()

        info = BookInfo(
            title='Untitled Source Book',
            author='',
            url='https://source-two.test/book/301.html',
        )

        existing = _find_existing_book(info)

        self.assertEqual(existing.id, book.id)
        self.assertFalse(_book_has_source_url(existing, info.url))


if __name__ == '__main__':
    unittest.main()
