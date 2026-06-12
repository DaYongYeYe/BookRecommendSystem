import unittest
from datetime import datetime

from app import create_app, db
from app.models import Book, Category


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
    SITE_PUBLIC_URL = 'https://books.example.test'


class SeoEndpointsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            db.session.add(Category(id=1, code='fiction', name='Fiction', is_highlighted=True))
            db.session.add(
                Book(
                    id=1,
                    title='A <Book>',
                    author='Alice Author',
                    description='Readable description with enough context for search snippets.',
                    cover='/uploads/covers/book.png',
                    status='published',
                    shelf_status='up',
                    rating=9.2,
                    rating_count=5,
                    category_id=1,
                    word_count=128000,
                    created_at=datetime(2026, 1, 1),
                    updated_at=datetime(2026, 1, 2),
                )
            )
            db.session.add(
                Book(
                    id=2,
                    title='Draft Book',
                    status='draft',
                    shelf_status='up',
                    created_at=datetime(2026, 1, 3),
                )
            )
            db.session.add(
                Book(
                    id=3,
                    title='Hidden Book',
                    status='published',
                    shelf_status='down',
                    created_at=datetime(2026, 1, 4),
                )
            )
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_robots_txt_points_to_sitemap_and_blocks_private_paths(self):
        response = self.client.get('/robots.txt')

        self.assertEqual(response.status_code, 200)
        self.assertIn('text/plain', response.content_type)
        body = response.get_data(as_text=True)
        self.assertIn('Sitemap: https://books.example.test/sitemap.xml', body)
        self.assertIn('Disallow: /admin', body)
        self.assertIn('Disallow: /auth', body)
        self.assertIn('Disallow: /creator', body)
        self.assertIn('Disallow: /reader', body)
        self.assertIn('Disallow: /user', body)

    def test_sitemap_includes_public_routes_and_only_visible_books(self):
        response = self.client.get('/sitemap.xml')

        self.assertEqual(response.status_code, 200)
        self.assertIn('application/xml', response.content_type)
        body = response.get_data(as_text=True)
        self.assertIn('<loc>https://books.example.test/</loc>', body)
        self.assertIn('<loc>https://books.example.test/rankings</loc>', body)
        self.assertIn('<loc>https://books.example.test/books/1</loc>', body)
        self.assertIn('<lastmod>2026-01-02</lastmod>', body)
        self.assertNotIn('/books/2', body)
        self.assertNotIn('/books/3', body)
        self.assertNotIn('/reader', body)

    def test_book_seo_page_contains_safe_metadata_and_json_ld(self):
        response = self.client.get('/books/1')

        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.content_type)
        body = response.get_data(as_text=True)
        self.assertIn('A &lt;Book&gt; - Alice Author', body)
        self.assertIn('<link rel="canonical" href="https://books.example.test/books/1">', body)
        self.assertIn('<meta property="og:type" content="book">', body)
        self.assertIn('<meta property="og:image" content="https://books.example.test/uploads/covers/book.png">', body)
        self.assertIn('"@type": "Book"', body)
        self.assertIn('"ratingValue": 9.2', body)

    def test_unavailable_book_seo_page_is_404_noindex(self):
        response = self.client.get('/books/2')

        self.assertEqual(response.status_code, 404)
        body = response.get_data(as_text=True)
        self.assertIn('noindex,nofollow', body)


if __name__ == '__main__':
    unittest.main()
