import json
from datetime import datetime
from html import escape
from urllib.parse import urljoin
from xml.sax.saxutils import escape as xml_escape

from flask import Response, current_app, request

from app import db
from app.models import Book, Category


SITE_NAME = '阿书铺子'
DEFAULT_DESCRIPTION = '阿书铺子是一个现代图书推荐系统，提供热门榜单、分类发现、个性化推荐和沉浸式阅读体验。'
PUBLIC_ROUTES = ('/', '/search', '/categories', '/rankings', '/recommendations', '/community', '/creator-center')
DISALLOWED_ROUTES = ('/admin', '/api', '/auth', '/creator', '/manage', '/rbac', '/reader', '/user')


def register_seo_routes(app):
    @app.route('/robots.txt', methods=['GET'])
    def robots_txt():
        base_url = _site_url()
        lines = [
            'User-agent: *',
            'Allow: /',
            *[f'Disallow: {path}' for path in DISALLOWED_ROUTES],
            f'Sitemap: {_absolute_url("/sitemap.xml", base_url=base_url)}',
            '',
        ]
        return Response('\n'.join(lines), mimetype='text/plain; charset=utf-8')

    @app.route('/sitemap.xml', methods=['GET'])
    def sitemap_xml():
        base_url = _site_url()
        entries = [{'loc': _absolute_url(path, base_url=base_url), 'priority': _route_priority(path)} for path in PUBLIC_ROUTES]
        books = (
            Book.query.filter(Book.status == 'published', Book.shelf_status == 'up')
            .order_by(Book.updated_at.desc(), Book.id.desc())
            .all()
        )
        for book in books:
            lastmod = book.updated_at or book.published_at or book.created_at
            entries.append(
                {
                    'loc': _absolute_url(f'/books/{book.id}', base_url=base_url),
                    'lastmod': _format_sitemap_date(lastmod),
                    'priority': '0.80',
                }
            )
        xml = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
        ]
        for entry in entries:
            xml.append('  <url>')
            xml.append(f'    <loc>{xml_escape(entry["loc"])}</loc>')
            if entry.get('lastmod'):
                xml.append(f'    <lastmod>{entry["lastmod"]}</lastmod>')
            xml.append(f'    <priority>{entry["priority"]}</priority>')
            xml.append('  </url>')
        xml.append('</urlset>')
        return Response('\n'.join(xml), mimetype='application/xml; charset=utf-8')

    @app.route('/books/<int:book_id>', methods=['GET'])
    def book_seo_page(book_id: int):
        book = db.session.get(Book, book_id)
        if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
            return Response(_not_found_html(), status=404, mimetype='text/html; charset=utf-8')

        category = db.session.get(Category, book.category_id) if book.category_id else None
        html = _book_html(book, category)
        return Response(html, mimetype='text/html; charset=utf-8')


def _site_url():
    configured = (current_app.config.get('SITE_PUBLIC_URL') or '').strip().rstrip('/')
    if configured:
        return configured
    return request.host_url.rstrip('/')


def _absolute_url(path_or_url: str | None, *, base_url: str | None = None):
    value = (path_or_url or '').strip()
    if not value:
        return ''
    if value.startswith(('http://', 'https://')):
        return value
    base = (base_url or _site_url()).rstrip('/') + '/'
    return urljoin(base, value.lstrip('/'))


def _route_priority(path: str):
    if path == '/':
        return '1.00'
    if path in {'/rankings', '/categories', '/recommendations'}:
        return '0.90'
    return '0.70'


def _format_sitemap_date(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    return str(value)[:10]


def _compact_text(value: str | None, max_len: int):
    text = ' '.join((value or '').split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + '…'


def _book_title(book: Book):
    author = f' - {book.author}' if book.author else ''
    return f'{book.title}{author} | {SITE_NAME}'


def _book_description(book: Book):
    return _compact_text(book.description, 150) or f'在{SITE_NAME}查看《{book.title}》的简介、评分、分类和相关推荐。'


def _book_json_ld(book: Book, category: Category | None, canonical_url: str, image_url: str):
    payload = {
        '@context': 'https://schema.org',
        '@type': 'Book',
        'name': book.title,
        'url': canonical_url,
        'description': _book_description(book),
    }
    if book.author:
        payload['author'] = {'@type': 'Person', 'name': book.author}
    if image_url:
        payload['image'] = image_url
    if category:
        payload['genre'] = category.name
    rating = float(book.rating or book.score or 0)
    if rating > 0:
        payload['aggregateRating'] = {
            '@type': 'AggregateRating',
            'ratingValue': round(rating, 1),
            'bestRating': 10,
            'ratingCount': int(book.rating_count or 1),
        }
    return json.dumps(payload, ensure_ascii=False)


def _book_html(book: Book, category: Category | None):
    base_url = _site_url()
    canonical_url = _absolute_url(f'/books/{book.id}', base_url=base_url)
    image_url = _absolute_url(book.cover, base_url=base_url)
    title = _book_title(book)
    description = _book_description(book)
    json_ld = _book_json_ld(book, category, canonical_url, image_url).replace('</', '<\\/')
    category_label = category.name if category else '精选图书'
    rating = float(book.rating or book.score or 0)
    rating_text = f'{rating:.1f} 分' if rating > 0 else '暂无评分'
    word_count = int(book.word_count or 0)
    word_count_text = f'{word_count // 10000} 万字' if word_count >= 10000 else (f'{word_count} 字' if word_count else '字数待更新')
    reader_url = _absolute_url(f'/reader/{book.id}', base_url=base_url)

    return f"""<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(title)}</title>
    <meta name="description" content="{escape(description)}">
    <meta name="robots" content="index,follow">
    <link rel="canonical" href="{escape(canonical_url)}">
    <meta property="og:site_name" content="{escape(SITE_NAME)}">
    <meta property="og:type" content="book">
    <meta property="og:title" content="{escape(title)}">
    <meta property="og:description" content="{escape(description)}">
    <meta property="og:url" content="{escape(canonical_url)}">
    <meta property="og:image" content="{escape(image_url)}">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{escape(title)}">
    <meta name="twitter:description" content="{escape(description)}">
    <meta name="twitter:image" content="{escape(image_url)}">
    <script type="application/ld+json">{json_ld}</script>
    <style>
      body {{ margin: 0; background: #fdfcf8; color: #1c1917; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
      main {{ max-width: 880px; margin: 0 auto; padding: 48px 20px; }}
      .book {{ display: grid; grid-template-columns: 180px minmax(0, 1fr); gap: 32px; align-items: start; }}
      img {{ width: 180px; aspect-ratio: 3 / 4; object-fit: cover; border-radius: 16px; box-shadow: 0 20px 45px rgba(28, 25, 23, 0.16); }}
      h1 {{ margin: 0 0 12px; font-size: clamp(2rem, 5vw, 3.25rem); line-height: 1.1; }}
      p {{ line-height: 1.8; }}
      .meta {{ color: #78716c; }}
      .actions {{ margin-top: 28px; display: flex; gap: 12px; flex-wrap: wrap; }}
      a {{ color: inherit; }}
      .button {{ display: inline-flex; align-items: center; border-radius: 999px; background: #1c1917; color: #fff; padding: 12px 18px; text-decoration: none; font-weight: 700; }}
      @media (max-width: 640px) {{ .book {{ grid-template-columns: 1fr; }} img {{ width: min(64vw, 220px); }} }}
    </style>
  </head>
  <body>
    <main>
      <article class="book">
        {'<img src="' + escape(image_url) + '" alt="' + escape(book.title) + '">' if image_url else ''}
        <div>
          <p class="meta">{escape(category_label)} · {escape(rating_text)} · {escape(word_count_text)}</p>
          <h1>{escape(book.title)}</h1>
          <p class="meta">{escape(book.author or '作者待补充')}</p>
          <p>{escape(description)}</p>
          <div class="actions">
            <a class="button" href="{escape(reader_url)}">开始阅读</a>
            <a href="{escape(canonical_url)}">查看图书详情</a>
          </div>
        </div>
      </article>
    </main>
  </body>
</html>"""


def _not_found_html():
    return """<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,nofollow">
    <title>图书未找到 | 阿书铺子</title>
  </head>
  <body><h1>图书未找到</h1></body>
</html>"""
