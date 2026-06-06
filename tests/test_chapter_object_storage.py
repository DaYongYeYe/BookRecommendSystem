import unittest
from unittest.mock import patch

from app import create_app, db
from app.models import Book, BookChapter, BookChapterRevision
from app.services.publishing_service import create_chapter_draft
from app.services.reader_service import build_reader_payload
from scripts.migrate_chapter_content_to_cos import migrate_revisions


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


class FakeTextStorage:
    def __init__(self):
        self.items: dict[str, str] = {}

    def upload_text(self, content: str, *, folder: str = 'book_chapters'):
        url = f'https://cos.example/{folder}/{len(self.items) + 1}.txt'
        self.items[url] = content
        return {'url': url, 'md5': 'f' * 32}, None

    def fetch_text(self, url: str, expected_md5: str | None = None):
        return self.items.get(url, ''), None


class ChapterObjectStorageTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()
        self.storage = FakeTextStorage()
        self.upload_patcher = patch('app.services.chapter_content.upload_text', self.storage.upload_text)
        self.fetch_patcher = patch('app.services.chapter_content.fetch_text', self.storage.fetch_text)
        self.upload_patcher.start()
        self.fetch_patcher.start()

    def tearDown(self):
        self.fetch_patcher.stop()
        self.upload_patcher.stop()
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_chapter_draft_stores_url_and_serializes_content(self):
        book = Book(title='Storage Book', author='Author', status='draft', shelf_status='down')
        db.session.add(book)
        db.session.commit()

        _, revision = create_chapter_draft(book, title='Chapter 1', content_text='A\n\nB', creator=None)

        self.assertIsNone(revision.content_text)
        self.assertTrue(revision.content_url)
        self.assertEqual(revision.content_md5, 'f' * 32)
        self.assertEqual(self.storage.items[revision.content_url], 'A\n\nB')

    def test_reader_payload_reads_paragraphs_from_object_storage(self):
        book = Book(id=42, title='Reader Book', author='Author', status='published', shelf_status='up')
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
            content_text=None,
            content_url='https://cos.example/book_chapters/reader.txt',
            content_md5='f' * 32,
            status='published',
        )
        self.storage.items[revision.content_url] = 'First paragraph.\n\nSecond paragraph.'
        db.session.add(revision)
        db.session.flush()
        chapter.published_revision_id = revision.id
        db.session.commit()

        payload = build_reader_payload(book.id, section_limit=5)

        self.assertEqual(payload['sections'][0]['paragraphs'][0]['text'], 'First paragraph.')
        self.assertEqual(payload['sections'][0]['paragraphs'][1]['text'], 'Second paragraph.')
        self.assertEqual(payload['book']['total_words'], len('First paragraph.\n\nSecond paragraph.'))

    def test_migration_uploads_revision_and_clears_inline_content(self):
        book = Book(title='Legacy Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        chapter = BookChapter(book_id=book.id, chapter_key='chapter-1', chapter_no=1, title='Chapter 1')
        db.session.add(chapter)
        db.session.flush()
        revision = BookChapterRevision(
            chapter_id=chapter.id,
            version_no=1,
            title='Chapter 1',
            content_text='Legacy content',
            status='published',
        )
        db.session.add(revision)
        db.session.flush()
        chapter.published_revision_id = revision.id
        db.session.commit()

        migrated = migrate_revisions(dry_run=False, clear_db_content=True, limit=None, book_id=None)
        db.session.refresh(revision)

        self.assertEqual(migrated, 1)
        self.assertIsNone(revision.content_text)
        self.assertTrue(revision.content_url)
        self.assertEqual(self.storage.items[revision.content_url], 'Legacy content')


if __name__ == '__main__':
    unittest.main()
