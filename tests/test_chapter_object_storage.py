import unittest
from unittest.mock import patch

from app import create_app, db
from app.models import Book, BookChapter, BookChapterRevision, ReaderParagraph, ReaderSection
from app.services.chapter_content import get_record_text
from app.services.publishing_service import create_chapter_draft
from app.services.reader_service import build_reader_payload, build_reader_sections_payload
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
        self.fetched_urls: list[str] = []

    def upload_text(self, content: str, *, folder: str = 'book_chapters'):
        url = f'https://cos.example/{folder}/{len(self.items) + 1}.txt'
        self.items[url] = content
        return {'url': url, 'md5': 'f' * 32}, None

    def fetch_text(self, url: str, expected_md5: str | None = None):
        self.fetched_urls.append(url)
        return self.items.get(url, ''), None


class FakeRedis:
    def __init__(self):
        self.items: dict[str, str] = {}

    def get(self, key: str):
        value = self.items.get(key)
        return value.encode('utf-8') if value is not None else None

    def setex(self, key: str, ttl: int, value: str):
        self.items[key] = value

    def set(self, key: str, value: str):
        self.items[key] = value


class FailingRedis:
    def get(self, key: str):
        raise RuntimeError('redis unavailable')

    def setex(self, key: str, ttl: int, value: str):
        raise RuntimeError('redis unavailable')

    def set(self, key: str, value: str):
        raise RuntimeError('redis unavailable')


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

    def _create_published_chapter(self, book: Book, index: int, content: str, content_md5: str = 'f' * 32):
        chapter = BookChapter(
            book_id=book.id,
            chapter_key=f'chapter-{index}',
            chapter_no=index,
            title=f'Chapter {index}',
            status='published',
        )
        db.session.add(chapter)
        db.session.flush()
        content_url = f'https://cos.example/book_chapters/cache-{book.id}-{index}.txt'
        revision = BookChapterRevision(
            chapter_id=chapter.id,
            version_no=1,
            title=f'Chapter {index}',
            content_text=None,
            content_url=content_url,
            content_md5=content_md5,
            status='published',
        )
        self.storage.items[content_url] = content
        db.session.add(revision)
        db.session.flush()
        chapter.published_revision_id = revision.id
        return chapter, revision

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

    def test_chapter_content_is_cached_after_first_object_storage_read(self):
        book = Book(id=46, title='Cached Content Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        _, revision = self._create_published_chapter(book, 1, 'Cached paragraph.')
        db.session.commit()
        fake_redis = FakeRedis()
        self.app.config['REDIS_URL'] = 'redis://test/0'

        with patch('app.services.cache_service.redis_client', fake_redis):
            first = get_record_text(revision)
            second = get_record_text(revision)

        self.assertEqual(first, 'Cached paragraph.')
        self.assertEqual(second, 'Cached paragraph.')
        self.assertEqual(self.storage.fetched_urls, [revision.content_url])

    def test_chapter_content_cache_falls_back_when_redis_fails(self):
        book = Book(id=47, title='Redis Fallback Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        _, revision = self._create_published_chapter(book, 1, 'Fallback paragraph.')
        db.session.commit()
        self.app.config['REDIS_URL'] = 'redis://test/0'

        with patch('app.services.cache_service.redis_client', FailingRedis()):
            text = get_record_text(revision)

        self.assertEqual(text, 'Fallback paragraph.')
        self.assertEqual(self.storage.fetched_urls, [revision.content_url])

    def test_chapter_content_cache_key_changes_with_content_fingerprint(self):
        book = Book(id=48, title='Fingerprint Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        _, revision = self._create_published_chapter(book, 1, 'Old paragraph.', content_md5='a' * 32)
        db.session.commit()
        fake_redis = FakeRedis()
        self.app.config['REDIS_URL'] = 'redis://test/0'

        with patch('app.services.cache_service.redis_client', fake_redis):
            self.assertEqual(get_record_text(revision), 'Old paragraph.')
            revision.content_md5 = 'b' * 32
            self.storage.items[revision.content_url] = 'New paragraph.'
            self.assertEqual(get_record_text(revision), 'New paragraph.')

        self.assertEqual(self.storage.fetched_urls, [revision.content_url, revision.content_url])

    def test_reader_sections_payload_is_cached_by_window(self):
        book = Book(id=49, title='Cached Sections Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        self._create_published_chapter(book, 1, 'First cached section.')
        self._create_published_chapter(book, 2, 'Second cached section.')
        db.session.commit()
        fake_redis = FakeRedis()
        self.app.config['REDIS_URL'] = 'redis://test/0'

        with patch('app.services.cache_service.redis_client', fake_redis):
            first = build_reader_sections_payload(book.id, offset=0, limit=1)
            second = build_reader_sections_payload(book.id, offset=0, limit=1)

        self.assertEqual(first, second)
        self.assertEqual(len(first['sections']), 1)
        self.assertEqual(self.storage.fetched_urls, ['https://cos.example/book_chapters/cache-49-1.txt'])

    def test_reader_sections_cache_does_not_mix_different_windows(self):
        book = Book(id=50, title='Windowed Sections Book', author='Author', status='published', shelf_status='up')
        db.session.add(book)
        db.session.flush()
        self._create_published_chapter(book, 1, 'First window section.')
        self._create_published_chapter(book, 2, 'Second window section.')
        db.session.commit()
        fake_redis = FakeRedis()
        self.app.config['REDIS_URL'] = 'redis://test/0'

        with patch('app.services.cache_service.redis_client', fake_redis):
            first = build_reader_sections_payload(book.id, offset=0, limit=1)
            second = build_reader_sections_payload(book.id, offset=0, limit=2)

        self.assertEqual(len(first['sections']), 1)
        self.assertEqual(len(second['sections']), 2)
        self.assertEqual(
            self.storage.fetched_urls,
            [
                'https://cos.example/book_chapters/cache-50-1.txt',
                'https://cos.example/book_chapters/cache-50-2.txt',
            ],
        )

    def test_reader_payload_fetches_only_current_page_sections(self):
        book = Book(
            id=43,
            title='Paged Reader Book',
            author='Author',
            status='published',
            shelf_status='up',
            word_count=1000,
        )
        db.session.add(book)
        db.session.flush()

        for index in range(1, 6):
            chapter = BookChapter(
                book_id=book.id,
                chapter_key=f'chapter-{index}',
                chapter_no=index,
                title=f'Chapter {index}',
                status='published',
            )
            db.session.add(chapter)
            db.session.flush()
            content_url = f'https://cos.example/book_chapters/chapter-{index}.txt'
            revision = BookChapterRevision(
                chapter_id=chapter.id,
                version_no=1,
                title=f'Chapter {index}',
                content_text=None,
                content_url=content_url,
                content_md5='f' * 32,
                status='published',
            )
            self.storage.items[content_url] = f'Chapter {index} paragraph.'
            db.session.add(revision)
            db.session.flush()
            chapter.published_revision_id = revision.id

        db.session.commit()
        self.storage.fetched_urls.clear()

        payload = build_reader_payload(book.id, section_limit=3)

        self.assertEqual(len(payload['outline']), 5)
        self.assertEqual(len(payload['sections']), 3)
        self.assertEqual(
            self.storage.fetched_urls,
            [
                'https://cos.example/book_chapters/chapter-1.txt',
                'https://cos.example/book_chapters/chapter-2.txt',
                'https://cos.example/book_chapters/chapter-3.txt',
            ],
        )

    def test_landing_endpoint_does_not_fetch_chapter_content(self):
        book = Book(
            id=44,
            title='Landing Reader Book',
            author='Author',
            status='published',
            shelf_status='up',
            word_count=1000,
        )
        db.session.add(book)
        db.session.flush()

        for index in range(1, 4):
            chapter = BookChapter(
                book_id=book.id,
                chapter_key=f'chapter-{index}',
                chapter_no=index,
                title=f'Chapter {index}',
                status='published',
            )
            db.session.add(chapter)
            db.session.flush()
            content_url = f'https://cos.example/book_chapters/landing-{index}.txt'
            revision = BookChapterRevision(
                chapter_id=chapter.id,
                version_no=1,
                title=f'Chapter {index}',
                content_text=None,
                content_url=content_url,
                content_md5='f' * 32,
                status='published',
            )
            self.storage.items[content_url] = f'Landing chapter {index} paragraph.'
            db.session.add(revision)
            db.session.flush()
            chapter.published_revision_id = revision.id

        db.session.commit()
        self.storage.fetched_urls.clear()

        response = self.app.test_client().get(f'/api/books/{book.id}/landing')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()['outline']), 3)
        self.assertEqual(self.storage.fetched_urls, [])

    def test_legacy_reader_sections_page_without_chapter_revisions(self):
        book = Book(
            id=45,
            title='Legacy Reader Book',
            author='Author',
            status='published',
            shelf_status='up',
        )
        db.session.add(book)
        db.session.flush()

        for index in range(1, 5):
            section = ReaderSection(
                book_id=book.id,
                section_key=f'legacy-{index}',
                title=f'Legacy {index}',
                summary=f'Summary {index}',
                level=1,
                order_no=index,
            )
            db.session.add(section)
            db.session.flush()
            db.session.add(
                ReaderParagraph(
                    section_id=section.id,
                    paragraph_key=f'legacy-{index}-p1',
                    text=f'Legacy paragraph {index}.',
                    order_no=1,
                )
            )

        db.session.commit()

        payload = build_reader_payload(book.id, section_limit=3)

        self.assertEqual(len(payload['outline']), 4)
        self.assertEqual(len(payload['sections']), 3)
        self.assertEqual(payload['sections_pagination']['next_offset'], 3)
        self.assertEqual(payload['book']['total_words'], sum(len(f'Legacy paragraph {index}.') for index in range(1, 5)))

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
