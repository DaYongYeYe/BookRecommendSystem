from __future__ import annotations

import html
import json
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from sqlalchemy import or_

from app import db
from app.models import (
    Book,
    BookChapter,
    BookChapterRevision,
    Category,
    ReaderParagraph,
    ReaderSection,
)


DEFAULT_SOURCE_JSON_URL = 'https://www.yckceo.com/yuedu/shuyuan/json/id/7283.json'
DEFAULT_SOURCE_PAGE_URL = 'https://www.yckceo.com/yuedu/shuyuan/content/id/7283.html'
DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
)

SOURCE_CATEGORY_CODES = {
    'xuanhuan': 'fantasy',
    'wuxia': 'fantasy',
    'dushi': 'urban',
    'lishi': 'history',
    'kehuan': 'scifi',
    'youxi': 'scifi',
    'qita': 'literature',
}

SOURCE_CATEGORY_NAMES = {
    'fantasy': '玄幻',
    'urban': '都市',
    'history': '历史',
    'scifi': '科幻',
    'literature': '其他',
}

TEXT_CATEGORY_CODES = [
    (('玄幻', '奇幻', '武侠', '仙侠', '修真'), 'fantasy'),
    (('都市', '现实', '职场'), 'urban'),
    (('历史', '架空', '军事', '战争'), 'history'),
    (('科幻', '游戏', '网游', '末世', '星际'), 'scifi'),
    (('悬疑', '灵异', '推理'), 'suspense'),
    (('言情', '爱情', '校园'), 'romance'),
]


@dataclass(slots=True)
class HttpClient:
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 20
    retries: int = 2
    delay_seconds: float = 0.2

    def get_text(self, url: str) -> str:
        last_error: Exception | None = None
        for attempt in range(max(1, self.retries + 1)):
            try:
                request = Request(url, headers=self.headers)
                with urlopen(request, timeout=self.timeout) as response:
                    charset = response.headers.get_content_charset() or 'utf-8'
                    data = response.read()
                return data.decode(charset, errors='replace')
            except Exception as exc:  # noqa: BLE001 - surface URL and final error to CLI.
                last_error = exc
                if attempt < self.retries:
                    time.sleep(self.delay_seconds * (attempt + 1))
        raise RuntimeError(f'Failed to fetch {url}: {last_error}') from last_error


@dataclass(slots=True)
class BookCandidate:
    title: str
    url: str
    source_category_path: str = ''
    source_category_title: str = ''


@dataclass(slots=True)
class ChapterInfo:
    title: str
    url: str


@dataclass(slots=True)
class BookInfo:
    title: str
    url: str
    author: str = ''
    cover: str = ''
    description: str = ''
    category_code: str | None = None
    source_category: str = ''
    word_count: int = 0
    completion_status: str = 'ongoing'
    last_chapter: str = ''
    toc_url: str = ''


@dataclass(slots=True)
class ImportStats:
    candidates: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    failed: int = 0
    chapters: int = 0
    paragraphs: int = 0
    failed_chapters: int = 0
    skipped_chapters: int = 0
    errors: list[str] = field(default_factory=list)


def load_source_config(location: str = DEFAULT_SOURCE_JSON_URL, client: HttpClient | None = None) -> dict:
    raw = _read_text_location(_normalize_source_location(location), client)
    payload = raw.strip()
    if payload.startswith('<'):
        payload = extract_source_json_from_page(payload)
    source_config = json.loads(payload)
    if isinstance(source_config, list):
        source_config = next((item for item in source_config if isinstance(item, dict)), None)
    if not isinstance(source_config, dict):
        raise ValueError('Book source JSON must be an object or a list containing an object')
    return source_config


def extract_source_json_from_page(page_html: str) -> str:
    match = re.search(
        r'<pre[^>]+id=["\']jsonpre["\'][^>]*>(?P<json>.*?)</pre>',
        page_html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise ValueError('Source page does not contain <pre id="jsonpre"> JSON')
    return html.unescape(match.group('json')).strip()


def build_http_client(source_config: dict, *, cookie: str | None = None, timeout: int = 20, retries: int = 2, delay: float = 0.2) -> HttpClient:
    headers = {'User-Agent': DEFAULT_USER_AGENT}
    raw_header = source_config.get('header')
    if raw_header:
        try:
            parsed = json.loads(raw_header)
            headers.update({str(key): str(value) for key, value in parsed.items()})
        except (TypeError, ValueError):
            pass
    if cookie:
        headers['Cookie'] = cookie
    return HttpClient(headers=headers, timeout=timeout, retries=retries, delay_seconds=delay)


def collect_book_candidates(
    source_config: dict,
    client: HttpClient,
    *,
    limit: int = 1000,
    max_pages: int = 60,
    random_sample: bool = False,
) -> list[BookCandidate]:
    base_url = source_config.get('bookSourceUrl') or ''
    seen_urls: set[str] = set()
    candidates: list[BookCandidate] = []
    categories = _explore_categories(source_config)
    if random_sample:
        random.shuffle(categories)
    for category_title, category_path in categories:
        for page_url in _category_page_urls(base_url, category_path, max_pages=max_pages):
            page = client.get_text(page_url)
            page_candidates = extract_book_candidates(
                page,
                base_url=base_url,
                source_category_path=category_path,
                source_category_title=category_title,
            )
            if random_sample:
                random.shuffle(page_candidates)
            added_this_page = 0
            for item in page_candidates:
                if item.url in seen_urls:
                    continue
                seen_urls.add(item.url)
                candidates.append(item)
                added_this_page += 1
                if len(candidates) >= limit:
                    return candidates
            if added_this_page == 0:
                break
            _sleep(client.delay_seconds)
    return candidates


def extract_book_candidates(
    page_html: str,
    *,
    base_url: str,
    source_category_path: str = '',
    source_category_title: str = '',
) -> list[BookCandidate]:
    result: list[BookCandidate] = []
    seen: set[str] = set()
    anchor_pattern = re.compile(
        r'<a\b(?P<attrs>[^>]*\bhref=["\'](?P<href>[^"\']*/book/\d+(?:/|\.html))["\'][^>]*)>(?P<label>.*?)</a>',
        flags=re.IGNORECASE | re.DOTALL,
    )
    for match in anchor_pattern.finditer(page_html):
        title = _clean_text(match.group('label'))
        if not title or title in {'目录', '章节目录', '最新章节'}:
            continue
        url = urljoin(base_url, html.unescape(match.group('href')))
        if url in seen:
            continue
        seen.add(url)
        result.append(BookCandidate(title=title, url=url, source_category_path=source_category_path, source_category_title=source_category_title))
    return result


def parse_book_info(page_html: str, candidate: BookCandidate, *, base_url: str) -> BookInfo:
    h2_text = _clean_text(_first_match(page_html, r'<h2[^>]*>(.*?)</h2>'))
    author = _clean_text(_first_match(page_html, r'<h2[^>]*>.*?<span[^>]*>\s*<a[^>]*>(.*?)</a>.*?</span>.*?</h2>'))
    if not author:
        author = _extract_label(h2_text, '作者')
    if not author:
        author = _clean_text(_first_match(page_html, r'<meta[^>]+property=["\']og:novel:author["\'][^>]+content=["\']([^"\']+)["\']'))
    title = _clean_text(_first_match(page_html, r'<h1[^>]*>(.*?)</h1>')) or candidate.title
    if not title:
        title = _clean_text(_first_match(page_html, r'<meta[^>]+property=["\']og:novel:book_name["\'][^>]+content=["\']([^"\']+)["\']')) or candidate.title
    cover = _first_match(page_html, r'<div[^>]+class=["\'][^"\']*\bcover\b[^"\']*["\'][^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']')
    if not cover:
        cover = _first_match(page_html, r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']')
    intro = _clean_text(_first_match(page_html, r'<div[^>]+class=["\'][^"\']*\bintro\b[^"\']*["\'][^>]*>.*?<p[^>]*>(.*?)</p>'))
    if not intro:
        intro = _clean_text(_first_match(page_html, r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']'))
    if not intro:
        intro = _clean_text(_first_match(page_html, r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']'))
    kind = _clean_text(' '.join(_sort_anchor_labels(page_html)))
    source_category = candidate.source_category_title or kind
    last_chapter = _clean_text(_first_match(page_html, r'<p[^>]*>[^<]*(?:最新章节|最新).*?<a[^>]*>(.*?)</a>'))
    if not last_chapter:
        last_chapter = _clean_text(_first_match(page_html, r'<meta[^>]+property=["\']og:novel:latest_chapter_name["\'][^>]+content=["\']([^"\']+)["\']'))
    toc_url = _href_with_class(page_html, 'chapterlist')
    if not toc_url:
        toc_url = _first_match(page_html, r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>\s*(?:章节目录|目录|查看目录)\s*</a>')
    return BookInfo(
        title=title,
        url=candidate.url,
        author=author,
        cover=urljoin(base_url, html.unescape(cover)) if cover else '',
        description=intro,
        category_code=_category_code(candidate.source_category_path, ' '.join([kind, h2_text, source_category])),
        source_category=source_category,
        word_count=parse_word_count(_extract_label(h2_text, '字数') or h2_text),
        completion_status='completed' if re.search(r'完结|已完结|全本', page_html) else 'ongoing',
        last_chapter=last_chapter,
        toc_url=urljoin(base_url, html.unescape(toc_url)) if toc_url else candidate.url,
    )


def parse_chapters(toc_html: str, *, base_url: str) -> list[ChapterInfo]:
    result: list[ChapterInfo] = []
    seen: set[str] = set()
    for match in re.finditer(
        r'<a\b[^>]*href=["\'](?P<href>[^"\']*/book/\d+/\d+\.html)["\'][^>]*>(?P<title>.*?)</a>',
        toc_html,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        title = _clean_text(match.group('title'))
        if not title:
            continue
        url = urljoin(base_url, html.unescape(match.group('href')))
        if url in seen:
            continue
        seen.add(url)
        result.append(ChapterInfo(title=title, url=url))
    return result


def parse_chapter_content(chapter_html: str) -> str:
    candidates = [
        r'<div[^>]+id=["\']chaptercontent["\'][^>]*>(.*?)</div>',
        r'<div[^>]+id=["\']content["\'][^>]*>(.*?)</div>',
        r'<div[^>]+class=["\'][^"\']*\bchapter-content\b[^"\']*["\'][^>]*>(.*?)</div>',
        r'<article[^>]*>(.*?)</article>',
    ]
    for pattern in candidates:
        raw = _first_match(chapter_html, pattern)
        text = _clean_content(raw)
        if len(text) > 50:
            return text
    text = _clean_content(chapter_html)
    return _strip_nav_noise(text)


def parse_word_count(raw: str | None) -> int:
    text = _clean_text(raw or '')
    match = re.search(r'([\d.]+)\s*(万|千|字)?', text)
    if not match:
        return 0
    number = float(match.group(1))
    unit = match.group(2) or ''
    if unit == '万':
        number *= 10000
    elif unit == '千':
        number *= 1000
    return int(number)


def import_book_source(
    *,
    source_location: str = DEFAULT_SOURCE_JSON_URL,
    limit: int = 1000,
    max_pages: int = 60,
    include_toc: bool = False,
    include_content: bool = False,
    max_chapters_per_book: int = 0,
    cookie: str | None = None,
    timeout: int = 20,
    retries: int = 2,
    delay: float = 0.2,
    dry_run: bool = False,
    overwrite_content: bool = False,
    random_sample: bool = False,
) -> ImportStats:
    source_locations = _split_source_locations(source_location)
    if len(source_locations) > 1:
        return import_book_sources(
            source_locations=source_locations,
            limit=limit,
            max_pages=max_pages,
            include_toc=include_toc,
            include_content=include_content,
            max_chapters_per_book=max_chapters_per_book,
            cookie=cookie,
            timeout=timeout,
            retries=retries,
            delay=delay,
            dry_run=dry_run,
            overwrite_content=overwrite_content,
            random_sample=random_sample,
        )

    bootstrap_client = HttpClient(headers={'User-Agent': DEFAULT_USER_AGENT}, timeout=timeout, retries=retries, delay_seconds=delay)
    source_config = load_source_config(source_locations[0], bootstrap_client)
    client = build_http_client(source_config, cookie=cookie, timeout=timeout, retries=retries, delay=delay)
    base_url = source_config.get('bookSourceUrl') or ''
    candidates = collect_book_candidates(source_config, client, limit=limit, max_pages=max_pages, random_sample=random_sample)
    stats = ImportStats(candidates=len(candidates))

    for rank_no, candidate in enumerate(candidates, start=1):
        try:
            page = client.get_text(candidate.url)
            info = parse_book_info(page, candidate, base_url=base_url)
            if dry_run:
                stats.skipped += 1
                continue
            existing_duplicate = _find_existing_book(info)
            if existing_duplicate and not _book_has_source_url(existing_duplicate, info.url):
                stats.skipped += 1
                continue
            book, created = upsert_book(info, rank_no=rank_no, source_name=source_config.get('bookSourceName') or 'book source')
            if include_toc or include_content:
                chapter_stats = import_chapters(
                    book,
                    info,
                    client,
                    base_url=base_url,
                    include_content=include_content,
                    max_chapters=max_chapters_per_book,
                    overwrite_content=overwrite_content,
                )
                stats.chapters += chapter_stats['chapters']
                stats.paragraphs += chapter_stats['paragraphs']
                stats.failed_chapters += chapter_stats.get('failed_chapters', 0)
                stats.skipped_chapters += chapter_stats.get('skipped_chapters', 0)
                stats.errors.extend(chapter_stats.get('errors', []))
            stats.created += 1 if created else 0
            stats.updated += 0 if created else 1
            if include_toc or include_content:
                db.session.commit()
            elif rank_no % 20 == 0:
                db.session.commit()
            _sleep(client.delay_seconds)
        except Exception as exc:  # noqa: BLE001 - keep importing other books.
            stats.failed += 1
            stats.errors.append(f'{candidate.title} {candidate.url}: {exc}')
            db.session.rollback()
    if not dry_run:
        db.session.commit()
    return stats


def import_book_sources(
    *,
    source_locations: list[str] | tuple[str, ...],
    limit: int = 1000,
    max_pages: int = 60,
    include_toc: bool = False,
    include_content: bool = False,
    max_chapters_per_book: int = 0,
    cookie: str | None = None,
    timeout: int = 20,
    retries: int = 2,
    delay: float = 0.2,
    dry_run: bool = False,
    overwrite_content: bool = False,
    random_sample: bool = False,
) -> ImportStats:
    total = ImportStats()
    for location in source_locations:
        stats = import_book_source(
            source_location=location,
            limit=limit,
            max_pages=max_pages,
            include_toc=include_toc,
            include_content=include_content,
            max_chapters_per_book=max_chapters_per_book,
            cookie=cookie,
            timeout=timeout,
            retries=retries,
            delay=delay,
            dry_run=dry_run,
            overwrite_content=overwrite_content,
            random_sample=random_sample,
        )
        total.candidates += stats.candidates
        total.created += stats.created
        total.updated += stats.updated
        total.skipped += stats.skipped
        total.failed += stats.failed
        total.chapters += stats.chapters
        total.paragraphs += stats.paragraphs
        total.failed_chapters += stats.failed_chapters
        total.skipped_chapters += stats.skipped_chapters
        total.errors.extend(stats.errors)
    return total


def import_existing_book_content(
    *,
    source_location: str = DEFAULT_SOURCE_JSON_URL,
    limit: int = 1000,
    book_ids: list[int] | None = None,
    include_content: bool = True,
    max_chapters_per_book: int = 0,
    cookie: str | None = None,
    timeout: int = 20,
    retries: int = 2,
    delay: float = 0.2,
    overwrite_content: bool = False,
) -> ImportStats:
    bootstrap_client = HttpClient(headers={'User-Agent': DEFAULT_USER_AGENT}, timeout=timeout, retries=retries, delay_seconds=delay)
    source_config = load_source_config(source_location, bootstrap_client)
    client = build_http_client(source_config, cookie=cookie, timeout=timeout, retries=retries, delay=delay)
    base_url = source_config.get('bookSourceUrl') or ''
    books = _existing_source_books(base_url=base_url, limit=limit, book_ids=book_ids)
    stats = ImportStats(candidates=len(books))

    for book in books:
        source_url = _source_url_from_book(book, base_url=base_url)
        if not source_url:
            stats.skipped += 1
            continue
        try:
            page = client.get_text(source_url)
            info = parse_book_info(
                page,
                BookCandidate(
                    title=book.title,
                    url=source_url,
                ),
                base_url=base_url,
            )
            chapter_stats = import_chapters(
                book,
                info,
                client,
                base_url=base_url,
                include_content=include_content,
                max_chapters=max_chapters_per_book,
                overwrite_content=overwrite_content,
            )
            stats.chapters += chapter_stats['chapters']
            stats.paragraphs += chapter_stats['paragraphs']
            stats.failed_chapters += chapter_stats.get('failed_chapters', 0)
            stats.skipped_chapters += chapter_stats.get('skipped_chapters', 0)
            stats.errors.extend(chapter_stats.get('errors', []))
            stats.updated += 1
            db.session.commit()
            _sleep(client.delay_seconds)
        except Exception as exc:  # noqa: BLE001 - keep importing other books.
            stats.failed += 1
            stats.errors.append(f'{book.title} {source_url}: {exc}')
            db.session.rollback()
    db.session.commit()
    return stats


def upsert_book(info: BookInfo, *, rank_no: int, source_name: str) -> tuple[Book, bool]:
    book = _find_existing_book(info)
    created = book is None
    now = datetime.utcnow()
    if book is None:
        book = Book(title=info.title, author=info.author or '未知作者', created_at=now)
        db.session.add(book)

    category = _ensure_category(info.category_code)
    synthetic_heat = max(1000, (1001 - min(rank_no, 1000)) * 120)
    rating = max(7.0, 9.3 - min(rank_no, 1000) / 800)
    keywords = _join_keywords([info.title, info.author, info.source_category, info.last_chapter])

    book.title = info.title
    book.author = info.author or book.author or '未知作者'
    book.description = info.description or book.description
    book.cover = info.cover or book.cover
    book.category_id = category.id if category else book.category_id
    book.word_count = info.word_count or int(book.word_count or 0)
    book.completion_status = info.completion_status or book.completion_status or 'ongoing'
    book.score = float(book.score or rating)
    book.rating = float(book.rating or rating)
    book.rating_count = max(int(book.rating_count or 0), synthetic_heat // 18)
    book.recent_reads = max(int(book.recent_reads or 0), synthetic_heat)
    book.home_recommendation_reason = f'来自{source_name}热门榜第 {rank_no} 名'
    book.search_keywords = keywords[:255] if keywords else book.search_keywords
    book.is_featured = bool(book.is_featured or rank_no <= 24)
    book.price_type = book.price_type or 'free'
    book.creation_type = book.creation_type or 'original'
    book.shelf_status = 'up'
    book.audit_status = 'approved'
    book.status = 'published'
    book.published_at = book.published_at or now
    book.tenant_id = int(book.tenant_id or 1)
    book.copyright_notice = f'用户已声明获得授权；导入书源：{source_name}'
    book.update_note = f'外部来源：{info.url}；最后章节：{info.last_chapter or "未获取"}'
    db.session.flush()
    return book, created


def import_chapters(
    book: Book,
    info: BookInfo,
    client: HttpClient,
    *,
    base_url: str,
    include_content: bool,
    max_chapters: int = 0,
    overwrite_content: bool = False,
) -> dict:
    toc_html = client.get_text(info.toc_url)
    chapters = parse_chapters(toc_html, base_url=base_url)
    if max_chapters > 0:
        chapters = chapters[:max_chapters]
    if not chapters:
        return {'chapters': 0, 'paragraphs': 0, 'failed_chapters': 0, 'skipped_chapters': 0, 'errors': []}

    existing_chapters = {
        item.chapter_key: item
        for item in BookChapter.query.filter_by(book_id=book.id).all()
    }
    existing_sections = {
        item.section_key: item
        for item in ReaderSection.query.filter_by(book_id=book.id).all()
    }

    paragraph_count = 0
    imported_count = 0
    failed_count = 0
    skipped_count = 0
    errors = []
    for order_no, chapter in enumerate(chapters, start=1):
        chapter_key = _chapter_key(chapter.url, order_no)
        if include_content:
            chapter_row = existing_chapters.get(chapter_key)
            if chapter_row:
                chapter_row.chapter_no = order_no
                chapter_row.title = chapter.title
                chapter_row.status = 'published'
                chapter_row.tenant_id = int(book.tenant_id or 1)
                if chapter_row.published_revision_id and not overwrite_content:
                    skipped_count += 1
                    continue
            try:
                content = parse_chapter_content(client.get_text(chapter.url))
            except Exception as exc:  # noqa: BLE001 - keep the rest of the book importable.
                failed_count += 1
                errors.append(f'{book.title} {chapter.title} {chapter.url}: {exc}')
                continue
            if not content:
                failed_count += 1
                errors.append(f'{book.title} {chapter.title} {chapter.url}: empty content')
                continue
            if not chapter_row:
                chapter_row = BookChapter(
                    book_id=book.id,
                    chapter_key=chapter_key,
                    chapter_no=order_no,
                    title=chapter.title,
                    status='published',
                    tenant_id=int(book.tenant_id or 1),
                )
                db.session.add(chapter_row)
                db.session.flush()
                existing_chapters[chapter_key] = chapter_row
            chapter_row.chapter_no = order_no
            chapter_row.title = chapter.title
            chapter_row.status = 'published'
            chapter_row.tenant_id = int(book.tenant_id or 1)
            revision = BookChapterRevision(
                chapter_id=chapter_row.id,
                version_no=_next_revision_no(chapter_row.id),
                title=chapter.title,
                content_text=content,
                status='published',
                published_at=datetime.utcnow(),
                tenant_id=int(book.tenant_id or 1),
            )
            db.session.add(revision)
            db.session.flush()
            chapter_row.published_revision_id = revision.id
            imported_count += 1
            paragraph_count += len([part for part in content.split('\n\n') if part.strip()])
        else:
            section = existing_sections.get(chapter_key)
            if section:
                section.title = chapter.title
                section.order_no = order_no
                skipped_count += 1
                continue
            db.session.add(
                ReaderSection(
                    book_id=book.id,
                    section_key=chapter_key,
                    title=chapter.title,
                    summary='',
                    level=1,
                    order_no=order_no,
                )
            )
            imported_count += 1
    if include_content:
        book.word_count = _sum_published_word_count(book.id) or int(book.word_count or 0)
    return {
        'chapters': imported_count,
        'paragraphs': paragraph_count,
        'failed_chapters': failed_count,
        'skipped_chapters': skipped_count,
        'errors': errors,
    }


def _read_text_location(location: str, client: HttpClient | None = None) -> str:
    if re.match(r'^https?://', location):
        return (client or HttpClient(headers={'User-Agent': DEFAULT_USER_AGENT})).get_text(location)
    return Path(location).read_text(encoding='utf-8')


def _normalize_source_location(location: str) -> str:
    return re.sub(r'/content/id/(\d+)\.html$', r'/json/id/\1.json', location or '')


def _split_source_locations(location: str) -> list[str]:
    locations = [item.strip() for item in (location or '').split(',') if item.strip()]
    return locations or [DEFAULT_SOURCE_JSON_URL]


def _explore_categories(source_config: dict) -> list[tuple[str, str]]:
    explore = source_config.get('exploreUrl') or ''
    if explore.strip().startswith('['):
        try:
            entries = json.loads(explore)
        except (TypeError, ValueError):
            entries = []
        parsed_entries = [
            (str(item.get('title') or '').strip(), str(item.get('url') or '').strip())
            for item in entries
            if isinstance(item, dict) and str(item.get('url') or '').strip()
        ]
        if parsed_entries:
            return [(title, path) for title, path in parsed_entries]
    categories = re.findall(r"\['([^']+)'\s*,\s*'([^']+)'\]", explore)
    if categories:
        return [(html.unescape(title), html.unescape(path)) for title, path in categories]
    return [
        ('全部', '/sort/'),
        ('玄幻', '/sort/xuanhuan/'),
        ('武侠', '/sort/wuxia/'),
        ('都市', '/sort/dushi/'),
        ('历史', '/sort/lishi/'),
        ('科幻', '/sort/kehuan/'),
        ('游戏', '/sort/youxi/'),
        ('其他', '/sort/qita/'),
    ]


def _category_page_urls(base_url: str, category_path: str, *, max_pages: int) -> Iterable[str]:
    for page in range(1, max(1, max_pages) + 1):
        path = category_path
        if '{{page}}' in path:
            path = path.replace('{{page}}', str(page))
        elif page > 1:
            path = f'{category_path.rstrip("/")}/{page}.html'
        yield urljoin(base_url, path)


def _first_match(text: str, pattern: str) -> str:
    match = re.search(pattern, text or '', flags=re.IGNORECASE | re.DOTALL)
    return html.unescape(match.group(1)).strip() if match else ''


def _href_with_class(page_html: str, class_name: str) -> str:
    for match in re.finditer(r'<a\b(?P<attrs>[^>]*)>', page_html or '', flags=re.IGNORECASE | re.DOTALL):
        attrs = match.group('attrs')
        class_value = _attr_value(attrs, 'class')
        if class_name not in class_value.split():
            continue
        href = _attr_value(attrs, 'href')
        if href:
            return html.unescape(href).strip()
    return ''


def _attr_value(attrs: str, name: str) -> str:
    match = re.search(rf'\b{re.escape(name)}=["\']([^"\']+)["\']', attrs or '', flags=re.IGNORECASE)
    return html.unescape(match.group(1)).strip() if match else ''


def _clean_text(raw: str | None) -> str:
    if not raw:
        return ''
    text = re.sub(r'<br\s*/?>', '\n', raw, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    text = text.replace('\u3000', ' ')
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _clean_content(raw: str | None) -> str:
    if not raw:
        return ''
    text = re.sub(r'<script[\s\S]*?</script>', '', raw, flags=re.IGNORECASE)
    text = re.sub(r'<style[\s\S]*?</style>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'</p\s*>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text).replace('\r', '')
    text = re.sub(r'[ \t\u3000]{2,}', ' ', text)
    text = re.sub(r'\n[ \t\u3000]+', '\n', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return _strip_nav_noise(text.strip())


def _strip_nav_noise(text: str) -> str:
    noise_patterns = [
        r'上一章.*?下一章',
        r'请收藏本站[^\n]*',
        r'最新网址[^\n]*',
        r'手机用户请浏览[^\n]*',
        r'笔趣阁[^\n]*最快更新[^\n]*',
        r'本站所有小说[\s\S]*$',
        r'Copyright[\s\S]*$',
    ]
    result = text
    for pattern in noise_patterns:
        result = re.sub(pattern, '', result, flags=re.IGNORECASE)
    return result.strip()


def _sort_anchor_labels(page_html: str) -> list[str]:
    labels = []
    for match in re.finditer(r'<a[^>]+href=["\'][^"\']*/sort/[^"\']*["\'][^>]*>(.*?)</a>', page_html, flags=re.IGNORECASE | re.DOTALL):
        label = _clean_text(match.group(1))
        if label:
            labels.append(label)
    return labels


def _extract_label(text: str, label: str) -> str:
    match = re.search(rf'{re.escape(label)}[:：]\s*([^\s]+)', text or '')
    return match.group(1).strip() if match else ''


def _category_code(source_category_path: str, text: str) -> str | None:
    slug_match = re.search(r'/sort/([^/]+)/?', source_category_path or '')
    if slug_match and slug_match.group(1) in SOURCE_CATEGORY_CODES:
        return SOURCE_CATEGORY_CODES[slug_match.group(1)]
    for keywords, code in TEXT_CATEGORY_CODES:
        if any(keyword in text for keyword in keywords):
            return code
    return None


def _ensure_category(code: str | None) -> Category | None:
    if not code:
        return None
    category = Category.query.filter_by(code=code).first()
    if category:
        return category
    category = Category(
        code=code,
        name=SOURCE_CATEGORY_NAMES.get(code, code),
        description=f'{SOURCE_CATEGORY_NAMES.get(code, code)}频道',
        is_highlighted=True,
    )
    db.session.add(category)
    db.session.flush()
    return category


def _find_existing_book(info: BookInfo) -> Book | None:
    query = Book.query.filter(Book.title == info.title, or_(Book.is_deleted.is_(False), Book.is_deleted.is_(None)))
    if info.author:
        exact = query.filter(Book.author == info.author).first()
        if exact:
            return exact
    else:
        title_match = query.first()
        if title_match:
            return title_match
    return query.filter(Book.update_note.like(f'%{info.url}%')).first()


def _book_has_source_url(book: Book, source_url: str) -> bool:
    return bool(source_url and source_url in (book.update_note or ''))


def _existing_source_books(*, base_url: str, limit: int, book_ids: list[int] | None = None) -> list[Book]:
    query = Book.query.filter(or_(Book.is_deleted.is_(False), Book.is_deleted.is_(None)))
    if book_ids:
        query = query.filter(Book.id.in_(book_ids))
    elif base_url:
        query = query.filter(Book.update_note.like(f'%{base_url}%'))
    return query.order_by(Book.id.asc()).limit(limit).all()


def _source_url_from_book(book: Book, *, base_url: str) -> str:
    note = book.update_note or ''
    match = re.search(r'https?://[^\s；;，,]+', note)
    if match:
        return match.group(0)
    return ''


def _join_keywords(parts: list[str]) -> str:
    result: list[str] = []
    for part in parts:
        for token in re.split(r'[\s,，/|]+', part or ''):
            token = token.strip()
            if token and token not in result:
                result.append(token)
    return ' '.join(result)


def _chapter_key(url: str, order_no: int) -> str:
    parsed = urlparse(url)
    stem = Path(parsed.path).stem
    return f'chapter-{stem or order_no}'


def _next_revision_no(chapter_id: int) -> int:
    current = (
        db.session.query(db.func.max(BookChapterRevision.version_no))
        .filter(BookChapterRevision.chapter_id == chapter_id)
        .scalar()
        or 0
    )
    return int(current) + 1


def _sum_published_word_count(book_id: int) -> int:
    rows = (
        db.session.query(BookChapterRevision.content_text)
        .join(BookChapter, BookChapter.published_revision_id == BookChapterRevision.id)
        .filter(BookChapter.book_id == book_id)
        .all()
    )
    return sum(len((row[0] or '').replace('\n', '')) for row in rows)


def _sleep(seconds: float) -> None:
    if seconds and seconds > 0:
        time.sleep(seconds)
