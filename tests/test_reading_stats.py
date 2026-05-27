import unittest
from datetime import datetime, timedelta

import jwt

from app import create_app, db
from app.models import (
    Book,
    BookAnalyticsEvent,
    ReaderBookmark,
    ReaderHighlight,
    ReaderUserPreference,
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


class ReadingStatsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            user = User(username='reader_test', name='Reader Test', email='reader@test.local', age=22)
            user.set_password('123456')
            book = Book(
                id=1,
                title='测试书籍',
                author='测试作者',
                status='published',
                shelf_status='up',
                word_count=12000,
                created_at=datetime.utcnow(),
            )
            db.session.add_all([user, book])
            db.session.flush()
            self.user_id = user.id
            db.session.add(UserShelf(user_id=user.id, book_id=book.id))
            db.session.add(
                UserReadingProgress(
                    user_id=user.id,
                    book_id=book.id,
                    section_id='chapter-1',
                    paragraph_id='p1',
                    scroll_percent=92,
                )
            )
            db.session.add(
                ReaderBookmark(
                    user_id=user.id,
                    book_id=book.id,
                    section_id='chapter-1',
                    paragraph_id='p1',
                    note='测试书签',
                )
            )
            db.session.add(
                ReaderHighlight(
                    book_id=book.id,
                    paragraph_key='p1',
                    start_offset=0,
                    end_offset=4,
                    selected_text='测试文本',
                    created_by='reader_test',
                )
            )
            db.session.add(
                ReaderUserPreference(
                    user_id=user.id,
                    theme='green',
                    font_size=22,
                    line_height=2.2,
                    margin='wide',
                    show_highlights=True,
                    show_comments=False,
                )
            )
            for days_ago, seconds in [(0, 900), (1, 1200), (2, 600)]:
                db.session.add(
                    BookAnalyticsEvent(
                        book_id=book.id,
                        user_id=user.id,
                        event_type='read_heartbeat',
                        session_id=f'session-{days_ago}',
                        read_duration_seconds=seconds,
                        created_at=datetime.utcnow() - timedelta(days=days_ago),
                    )
                )
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _auth_headers(self):
        token = jwt.encode(
            {
                'user_id': self.user_id,
                'username': 'reader_test',
                'role': 'user',
                'tenant_id': 1,
                'exp': datetime.utcnow() + timedelta(hours=1),
            },
            TestConfig.JWT_SECRET_KEY,
            algorithm=TestConfig.JWT_ALGORITHM,
        )
        return {'Authorization': f'Bearer {token}'}

    def test_reading_stats_payload(self):
        response = self.client.get('/user/reading-stats', headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()

        self.assertEqual(payload['stats']['shelf_count'], 1)
        self.assertEqual(payload['stats']['bookmark_count'], 1)
        self.assertEqual(payload['stats']['highlight_count'], 1)
        self.assertEqual(payload['stats']['completed_chapter_count'], 1)
        self.assertGreaterEqual(payload['stats']['weekly_read_minutes'], 45)
        self.assertEqual(payload['preferences']['theme'], 'green')
        self.assertEqual(payload['preferences']['margin'], 'wide')
        self.assertTrue(any(item['achievement_key'] == 'first_shelf' and item['unlocked'] for item in payload['achievements']))
        self.assertTrue(any(item['achievement_key'] == 'weekly_half_hour' and item['unlocked'] for item in payload['achievements']))
        self.assertEqual(payload['recent_books'][0]['title'], '测试书籍')


if __name__ == '__main__':
    unittest.main()
