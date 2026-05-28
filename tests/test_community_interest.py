import unittest
from datetime import datetime, timedelta

import jwt

from app import create_app, db
from app.models import (
    Book,
    BookTag,
    Category,
    RecommendationFeedback,
    RecommendationPlacement,
    Tag,
    User,
    UserReadingProgress,
    UserSearchHistory,
    UserShelf,
    UserInterestTag,
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


class CommunityInterestTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            user = User(username='community_reader', name='社区读者', email='community@test.local', age=25)
            user.set_password('123456')
            category = Category(id=1, code='literature', name='文学', is_highlighted=True)
            tag_healing = Tag(id=1, code='healing', label='治愈')
            tag_memory = Tag(id=2, code='memory', label='记忆')
            book = Book(
                id=1,
                title='海边的治愈书',
                author='测试作者',
                description='适合慢慢读的故事',
                status='published',
                shelf_status='up',
                rating=9.1,
                score=9.1,
                category_id=1,
                recent_reads=100,
                created_at=datetime.utcnow(),
            )
            second_book = Book(
                id=2,
                title='记忆练习',
                author='测试作者',
                status='published',
                shelf_status='up',
                rating=8.8,
                score=8.8,
                category_id=1,
                recent_reads=80,
                created_at=datetime.utcnow(),
            )
            other_category = Category(id=2, code='sci-fi', name='科幻', is_highlighted=False)
            third_book = Book(
                id=3,
                title='星港迁跃',
                author='测试作者',
                status='published',
                shelf_status='up',
                rating=8.2,
                score=8.2,
                category_id=2,
                recent_reads=40,
                created_at=datetime.utcnow(),
            )
            placement = RecommendationPlacement(
                code='home_hero',
                name='首页主推',
                description='首页首屏主推荐位',
                scene='home',
                strategy='featured',
                max_items=1,
                sort_order=10,
            )
            db.session.add_all([user, category, other_category, tag_healing, tag_memory, book, second_book, third_book, placement])
            db.session.flush()
            self.user_id = user.id
            db.session.add_all(
                [
                    BookTag(book_id=1, tag_id=1),
                    BookTag(book_id=1, tag_id=2),
                    BookTag(book_id=2, tag_id=2),
                    BookTag(book_id=3, tag_id=2),
                    UserShelf(user_id=user.id, book_id=1),
                    UserReadingProgress(user_id=user.id, book_id=1, section_id='chapter-1', scroll_percent=60),
                    UserSearchHistory(user_id=user.id, keyword='治愈', search_count=3),
                    RecommendationFeedback(user_id=user.id, book_id=1, action='more_like_this'),
                    UserSearchHistory(user_id=user.id, keyword='星港', search_count=4),
                ]
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
                'username': 'community_reader',
                'role': 'user',
                'tenant_id': 1,
                'exp': datetime.utcnow() + timedelta(hours=1),
            },
            TestConfig.JWT_SECRET_KEY,
            algorithm=TestConfig.JWT_ALGORITHM,
        )
        return {'Authorization': f'Bearer {token}'}

    def test_booklist_create_query_and_add_book(self):
        create_response = self.client.post(
            '/api/community/booklists',
            json={'title': '治愈夜读清单', 'description': '适合夜晚看的书'},
            headers=self._auth_headers(),
        )
        self.assertEqual(create_response.status_code, 201)
        created = create_response.get_json()['item']
        self.assertEqual(created['title'], '治愈夜读清单')

        add_response = self.client.post(
            f"/api/community/booklists/{created['id']}/books",
            json={'book_id': 1, 'note': '第一本就从它开始'},
            headers=self._auth_headers(),
        )
        self.assertEqual(add_response.status_code, 200)
        self.assertEqual(add_response.get_json()['item']['book_count'], 1)

        list_response = self.client.get('/api/community/booklists')
        self.assertEqual(list_response.status_code, 200)
        payload = list_response.get_json()
        self.assertEqual(payload['items'][0]['books'][0]['title'], '海边的治愈书')

    def test_review_publish_query_and_like(self):
        create_response = self.client.post(
            '/api/community/reviews',
            json={
                'book_id': 1,
                'title': '很安静的一本书',
                'content': '这本书适合晚上慢慢读，情绪很稳。',
                'rating': 5,
            },
            headers=self._auth_headers(),
        )
        self.assertEqual(create_response.status_code, 201)
        review = create_response.get_json()['item']

        list_response = self.client.get('/api/community/reviews')
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_response.get_json()['items'][0]['title'], '很安静的一本书')

        like_response = self.client.post(
            f"/api/community/reviews/{review['id']}/reaction",
            json={'liked': True},
            headers=self._auth_headers(),
        )
        self.assertEqual(like_response.status_code, 200)
        self.assertTrue(like_response.get_json()['item']['liked_by_me'])
        self.assertEqual(like_response.get_json()['item']['likes_count'], 1)

    def test_interest_tags_are_generated_from_behavior(self):
        response = self.client.get('/api/recommendations/interest-tags', headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        labels = [item['label'] for item in payload['items']]
        self.assertIn('治愈', labels)
        self.assertEqual(payload['generated_from'], 'user_behavior')

        with self.app.app_context():
            saved = UserInterestTag.query.filter_by(user_id=self.user_id, tag_id=1).first()
            self.assertIsNotNone(saved)
            self.assertGreater(saved.weight, 0)

    def test_hot_search_terms_include_real_stats(self):
        response = self.client.get('/api/search/hot-terms?limit=5')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        history_terms = [item for item in payload['items'] if item.get('source') == 'search_history']
        self.assertTrue(history_terms)
        self.assertIn('search_count', history_terms[0])
        self.assertIn('trend', history_terms[0])

    def test_rankings_accept_period_and_category(self):
        response = self.client.get('/api/books/rankings?type=hot&period=month&category_id=1&limit=10')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['period'], 'month')
        self.assertEqual(payload['category_id'], 1)
        self.assertTrue(payload['available_periods'])
        self.assertTrue(payload['items'])
        self.assertTrue(all(item['category_id'] == 1 for item in payload['items']))

    def test_recommendation_placements_endpoint(self):
        response = self.client.get('/api/recommendations/placements?scene=home')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['items'][0]['code'], 'home_hero')
        self.assertEqual(payload['items'][0]['scene'], 'home')


if __name__ == '__main__':
    unittest.main()
