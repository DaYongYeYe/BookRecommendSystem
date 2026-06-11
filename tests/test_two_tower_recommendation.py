import unittest
from datetime import datetime, timedelta

import jwt

from app import create_app, db
from app.models import (
    Book,
    BookTag,
    Category,
    RecommendationCandidate,
    RecommendationFeedback,
    RecommendationModelVersion,
    Tag,
    User,
    UserReadingProgress,
    UserSearchHistory,
    UserShelf,
)
from app.services.recommendation.features import collect_training_samples
from app.services.recommendation.online import get_two_tower_recommendations


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


class TwoTowerRecommendationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            user = User(username='reader', name='reader', email='reader@test.local', age=22)
            user.set_password('123456')
            category = Category(id=1, code='fantasy', name='Fantasy', is_highlighted=True)
            tag_fast = Tag(id=1, code='fast', label='Fast')
            tag_warm = Tag(id=2, code='warm', label='Warm')
            books = [
                Book(id=1, title='Current Book', author='A', status='published', shelf_status='up', rating=8.0, score=8.0, category_id=1, recent_reads=100, created_at=datetime.utcnow()),
                Book(id=2, title='Tower First', author='B', status='published', shelf_status='up', rating=8.5, score=8.5, category_id=1, recent_reads=90, created_at=datetime.utcnow()),
                Book(id=3, title='Tower Hidden', author='C', status='published', shelf_status='up', rating=9.0, score=9.0, category_id=1, recent_reads=80, created_at=datetime.utcnow()),
                Book(id=4, title='Rule Fallback', author='D', status='published', shelf_status='up', rating=7.5, score=7.5, category_id=1, recent_reads=70, created_at=datetime.utcnow()),
            ]
            db.session.add_all([user, category, tag_fast, tag_warm, *books])
            db.session.flush()
            self.user_id = user.id
            db.session.add_all(
                [
                    BookTag(book_id=1, tag_id=1),
                    BookTag(book_id=2, tag_id=1),
                    BookTag(book_id=3, tag_id=2),
                    BookTag(book_id=4, tag_id=2),
                    UserShelf(user_id=user.id, book_id=1),
                    UserReadingProgress(user_id=user.id, book_id=1, section_id='chapter-1', scroll_percent=50),
                    UserSearchHistory(user_id=user.id, keyword='Fast', search_count=3),
                    RecommendationFeedback(user_id=user.id, book_id=2, action='more_like_this'),
                    RecommendationFeedback(user_id=user.id, book_id=3, action='hide'),
                    RecommendationModelVersion(version='test-model', embedding_dim=16, artifact_dir='instance/test-model', is_active=True, trained_at=datetime.utcnow()),
                    RecommendationCandidate(user_id=user.id, model_version='test-model', book_id=3, rank_no=1, score=0.99),
                    RecommendationCandidate(user_id=user.id, model_version='test-model', book_id=2, rank_no=2, score=0.80),
                    RecommendationCandidate(user_id=user.id, model_version='test-model', book_id=4, rank_no=3, score=0.70),
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
                'username': 'reader',
                'role': 'user',
                'tenant_id': 1,
                'exp': datetime.utcnow() + timedelta(hours=1),
            },
            TestConfig.JWT_SECRET_KEY,
            algorithm=TestConfig.JWT_ALGORITHM,
        )
        return {'Authorization': f'Bearer {token}'}

    def test_training_samples_include_behavior_signals(self):
        with self.app.app_context():
            samples = collect_training_samples()
            positives = {(sample.user_id, sample.book_id) for sample in samples if sample.label == 1.0}
            negatives = {(sample.user_id, sample.book_id) for sample in samples if sample.label == 0.0}
            self.assertIn((self.user_id, 1), positives)
            self.assertIn((self.user_id, 2), positives)
            self.assertIn((self.user_id, 3), negatives)

    def test_online_candidates_filter_hidden_and_keep_two_tower_meta(self):
        with self.app.app_context():
            items = get_two_tower_recommendations(self.user_id, limit=3)
            ids = [item.book_id for item in items]
            self.assertNotIn(3, ids)
            self.assertEqual(ids[0], 2)
            self.assertEqual(items[0].model_version, 'test-model')

    def test_feed_prefers_two_tower_candidates(self):
        response = self.client.get('/api/recommendations/feed?limit=2', headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        picked = next(section for section in payload['sections'] if section['key'] == 'picked_for_you')
        self.assertTrue(picked['items'])
        self.assertEqual(picked['items'][0]['id'], 2)
        self.assertEqual(picked['items'][0]['reason_type'], 'two_tower')
        self.assertEqual(picked['items'][0]['model_version'], 'test-model')
        self.assertNotIn(3, [item['id'] for item in picked['items']])

    def test_personalized_keeps_legacy_shape_with_two_tower_fields(self):
        response = self.client.get('/api/recommendations/personalized?limit=2', headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['items'])
        self.assertEqual(payload['items'][0]['id'], 2)
        self.assertIn('recommend_reason', payload['items'][0])
        self.assertEqual(payload['items'][0]['reason_type'], 'two_tower')

    def test_anonymous_feed_falls_back_to_rules(self):
        response = self.client.get('/api/recommendations/feed?limit=2')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        picked = next(section for section in payload['sections'] if section['key'] == 'picked_for_you')
        self.assertTrue(picked['items'])


if __name__ == '__main__':
    unittest.main()
