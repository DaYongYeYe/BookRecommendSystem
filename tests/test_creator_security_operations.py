import unittest
from datetime import datetime, timedelta

import jwt

from app import create_app, db
from app.models import (
    Book,
    BookAnalyticsEvent,
    BookReview,
    CreatorProfile,
    ReaderBookComment,
    User,
    UserReadingProgress,
    UserShelf,
)


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


class CreatorSecurityOperationsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()

            creator = User(username='creator_test', name='Creator', pen_name='Creator Pen', email='creator@test.local')
            creator.set_password('123456')
            reader = User(username='reader_test', name='Reader', email='reader@test.local')
            reader.set_password('123456')
            old_reader = User(username='old_reader', name='Old Reader', email='old-reader@test.local')
            old_reader.set_password('123456')
            db.session.add_all([creator, reader, old_reader])
            db.session.flush()

            self.creator_id = creator.id
            self.reader_id = reader.id
            self.old_reader_id = old_reader.id
            db.session.add(CreatorProfile(user_id=creator.id, tenant_id=1, status='active'))

            owned_book = Book(
                id=1,
                title='Owned Book',
                author='Creator Pen',
                status='published',
                shelf_status='up',
                audit_status='approved',
                creator_id=creator.id,
                tenant_id=1,
                created_at=datetime.utcnow(),
            )
            second_owned_book = Book(
                id=3,
                title='Second Owned Book',
                author='Creator Pen',
                status='published',
                shelf_status='up',
                audit_status='approved',
                creator_id=creator.id,
                tenant_id=1,
                created_at=datetime.utcnow(),
            )
            legacy_book = Book(
                id=2,
                title='Legacy Book',
                author='Legacy',
                status='published',
                shelf_status='up',
                creator_id=None,
                tenant_id=1,
                created_at=datetime.utcnow(),
            )
            db.session.add_all([owned_book, second_owned_book, legacy_book])

            now = datetime.utcnow()
            old = now - timedelta(days=20)
            db.session.add_all(
                [
                    BookAnalyticsEvent(book_id=1, user_id=reader.id, event_type='reader_open', created_at=now),
                    BookAnalyticsEvent(book_id=1, user_id=old_reader.id, event_type='reader_open', created_at=old),
                    UserShelf(user_id=reader.id, book_id=1, created_at=now),
                    UserShelf(user_id=old_reader.id, book_id=1, created_at=old),
                    UserReadingProgress(user_id=reader.id, book_id=1, scroll_percent=90, updated_at=now),
                    UserReadingProgress(user_id=old_reader.id, book_id=1, scroll_percent=90, updated_at=old),
                    ReaderBookComment(book_id=1, author='reader', content='fresh comment', tenant_id=1, created_at=now),
                    ReaderBookComment(book_id=1, author='old', content='old comment', tenant_id=1, created_at=old),
                    BookReview(user_id=reader.id, book_id=1, title='fresh review', content='fresh', visibility='public', created_at=now),
                    BookReview(user_id=old_reader.id, book_id=1, title='old review', content='old', visibility='public', created_at=old),
                ]
            )
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _creator_headers(self):
        token = jwt.encode(
            {
                'user_id': self.creator_id,
                'username': 'creator_test',
                'role': 'user',
                'tenant_id': 1,
                'exp': datetime.utcnow() + timedelta(hours=1),
            },
            TestConfig.JWT_SECRET_KEY,
            algorithm=TestConfig.JWT_ALGORITHM,
        )
        return {'Authorization': f'Bearer {token}'}

    def test_creator_cannot_manage_unclaimed_legacy_book(self):
        headers = self._creator_headers()

        chapters_response = self.client.get('/creator/books/2/chapters', headers=headers)
        self.assertEqual(chapters_response.status_code, 403)

        create_chapter_response = self.client.post(
            '/creator/books/2/chapters',
            json={'title': 'Chapter 1', 'content_text': 'Body'},
            headers=headers,
        )
        self.assertEqual(create_chapter_response.status_code, 403)

        manuscript_response = self.client.post(
            '/creator/manuscripts',
            json={'book_id': 2, 'title': 'Legacy Book', 'content_text': 'New content'},
            headers=headers,
        )
        self.assertEqual(manuscript_response.status_code, 403)

    def test_creator_operations_respects_days_window(self):
        response = self.client.get('/creator/operations?days=7', headers=self._creator_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()

        self.assertEqual(payload['summary']['favorites'], 1)
        self.assertEqual(payload['summary']['comments'], 2)
        self.assertEqual(payload['summary']['completion_rate'], 100.0)
        self.assertEqual(payload['income']['items'][0]['reads'], 1)
        self.assertEqual(payload['income']['items'][0]['read_users'], 1)
        self.assertEqual(len(payload['fans']['top_readers']), 1)
        self.assertEqual(len(payload['fans']['recent_feedback']), 2)
        self.assertEqual(payload['scope']['total_books'], 2)
        self.assertEqual(payload['scope']['included_books'], 2)

    def test_creator_operations_limits_book_scope(self):
        response = self.client.get('/creator/operations?days=7&limit=1', headers=self._creator_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()

        self.assertEqual(payload['scope']['total_books'], 2)
        self.assertEqual(payload['scope']['included_books'], 1)
        self.assertEqual(payload['scope']['limit'], 1)
        self.assertTrue(payload['scope']['has_more'])


if __name__ == '__main__':
    unittest.main()
