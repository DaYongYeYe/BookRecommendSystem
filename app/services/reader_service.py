from datetime import datetime

from app import db
from app.models import (
    Book,
    BookAnalyticsEvent,
    BookChapter,
    BookChapterRevision,
    BookTag,
    Category,
    ReaderBookmark,
    ReaderBookComment,
    ReaderHighlight,
    ReaderHighlightComment,
    ReaderParagraph,
    ReaderSection,
    ReaderUserPreference,
    Tag,
    UserReadingProgress,
    UserShelf,
)


DEFAULT_BOOK_ID = 1

DEFAULT_BOOK = {
    'id': DEFAULT_BOOK_ID,
    'title': '样章阅读：漫长的余生',
    'subtitle': '在命运回声里重新找到彼此',
    'author': '罗欣',
    'description': (
        '这是一部适合沉浸式阅读的现代文学样章，节奏克制，情绪缓慢推进。'
        '你可以在这里体验目录跳转、进度续读、划线批注和评论互动。'
    ),
    'cover': 'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',
    'score': 9.4,
    'rating': 9.1,
    'rating_count': 12000,
    'recent_reads': 128000,
    'home_recommendation_reason': '适合喜欢慢热情绪和治愈氛围的读者。',
    'search_keywords': '治愈 海港 灯塔 慢热 情感 文学',
    'is_featured': True,
    'category_id': 1,
    'word_count': 8620,
    'completion_status': 'completed',
    'suitable_audience': '适合喜欢慢热、治愈、夜间阅读氛围的读者。',
    'status': 'published',
    'shelf_status': 'up',
}

DEFAULT_READER_SECTIONS = [
    {
        'section_key': 'chapter-1',
        'title': '第一章 抵达旧港',
        'summary': '她回到潮湿的海港小城，也重新靠近那些多年没有说完的话。',
        'level': 1,
        'paragraphs': [
            {
                'paragraph_key': 'p1',
                'text': '黄昏压低在港口上空，潮水拍打木栈桥。她拖着行李走下最后一级台阶，空气里混着海盐、铁锈和雨前石板的味道。',
            },
            {
                'paragraph_key': 'p2',
                'text': '旅馆老板递来钥匙，又朝远处灯塔抬了抬下巴，说今夜风会很大。她点头，却还是在门口站了几秒，像在等一个迟到了很多年的信号。',
            },
        ],
    },
    {
        'section_key': 'chapter-1-1',
        'title': '1.1 海雾中的来信',
        'summary': '一封没有署名的信，把她带回那段始终没有讲完的关系。',
        'level': 2,
        'paragraphs': [
            {
                'paragraph_key': 'p3',
                'text': '信纸边角被海风吹得卷起，字迹却比记忆里的任何一次都更安稳。上面只写着一句话：有些人要绕很远的路，才能回到最初想靠近的光。',
            },
            {
                'paragraph_key': 'p4',
                'text': '窗外的海雾越积越厚，路灯一盏接一盏地模糊开来。她把那封信放在桌上，忽然觉得多年压住的话，也许并没有真正沉到底。',
            },
        ],
    },
    {
        'section_key': 'chapter-1-2',
        'title': '1.2 灯塔下的谈话',
        'summary': '守塔人的一句话，让她第一次意识到，等待未必只是徒劳。',
        'level': 2,
        'paragraphs': [
            {
                'paragraph_key': 'p5',
                'text': '守塔人说，船不会因为灯塔沉默就停下，但只要那束光还在，迷路的人就会知道自己并不是被彻底遗忘。',
            },
            {
                'paragraph_key': 'p6',
                'text': '风穿过栏杆，海面一片碎银般的冷意。她忽然很想把这些年没寄出的句子，都讲给潮声听，哪怕它不会回答。',
            },
        ],
    },
    {
        'section_key': 'chapter-2',
        'title': '第二章 雨夜摘录',
        'summary': '在深夜整理旧笔记时，她终于理解有些答案不是为了原谅别人，而是为了安放自己。',
        'level': 1,
        'paragraphs': [
            {
                'paragraph_key': 'p7',
                'text': '夜色完全沉下去以后，雨终于落了。她翻开旧笔记，把那些曾经匆匆读过的句子一行一行抄下来，像在替过去的自己补一场迟到的停顿。',
            },
            {
                'paragraph_key': 'p8',
                'text': '理解并不是原谅的附录，而是留给自己的那盏小灯。它未必能照亮所有回忆，却足够让人不再害怕回头。',
            },
        ],
    },
]

DEFAULT_HIGHLIGHTS = [
    {
        'paragraph_key': 'p3',
        'selected_text': '有些人要绕很远的路，才能回到最初想靠近的光。',
        'start_offset': 33,
        'end_offset': 57,
        'color': 'amber',
        'note': '这一句像整本书的情感核心，关于迟到、绕路和重新靠近。',
        'created_by': 'Alice Lin',
        'comments': [
            {'author': 'Bob Chen', 'content': '这句和开头的港口意象连得特别好。'},
            {'author': 'Cindy Wu', 'content': '读到这里一下就记住这本书了。'},
        ],
    },
    {
        'paragraph_key': 'p5',
        'selected_text': '只要那束光还在，迷路的人就会知道自己并不是被彻底遗忘。',
        'start_offset': 17,
        'end_offset': 43,
        'color': 'sky',
        'note': '灯塔的比喻很克制，但很有力量。',
        'created_by': 'Bob Chen',
        'comments': [{'author': 'Alice Lin', 'content': '很适合收进阅读摘录。'}],
    },
]

DEFAULT_BOOK_COMMENTS = [
    {'author': 'Alice Lin', 'content': '节奏很稳，适合晚上安静读一会儿。'},
    {'author': 'Bob Chen', 'content': '灯塔那一节特别有画面感。'},
    {'author': 'Cindy Wu', 'content': '不是那种很吵闹的故事，但情绪会慢慢进来。'},
]


def _fmt(dt):
    if not dt:
        return None
    return dt.strftime('%Y-%m-%d %H:%M')


def _iso(dt):
    return dt.isoformat() if dt else None


def _display_name(user):
    if not user:
        return '当前读者'
    return (getattr(user, 'pen_name', None) or user.name or user.username or f'user-{user.id}').strip()


def _estimate_reading_minutes(word_count: int) -> int:
    if word_count <= 0:
        return 0
    return max(1, round(word_count / 450))


def _split_keywords(raw_keywords: str | None):
    if not raw_keywords:
        return []

    result = []
    for item in raw_keywords.replace('，', ' ').replace(',', ' ').split():
        item = item.strip()
        if item and item not in result:
            result.append(item)
    return result


def _build_decision_points(book: Book, category_name: str | None, tags: list[dict], total_words: int):
    points = []
    if category_name:
        points.append(f'分类：{category_name}')
    if tags:
        points.append(f'标签：{" / ".join(tag["label"] for tag in tags[:3])}')
    if total_words > 0:
        points.append(f'字数约 {total_words:,}，阅读负担比较明确')
    if book.suitable_audience:
        points.append(book.suitable_audience)
    if book.home_recommendation_reason:
        points.append(book.home_recommendation_reason)
    return points[:4]


def ensure_seed(book_id: int):
    if book_id != DEFAULT_BOOK_ID:
        return

    book = Book.query.get(book_id)
    if not book:
        book = Book(created_at=datetime.utcnow(), **DEFAULT_BOOK)
        db.session.add(book)
        db.session.flush()
    else:
        for key, value in DEFAULT_BOOK.items():
            setattr(book, key, value)

    if ReaderSection.query.filter_by(book_id=book_id).first():
        return

    for section_order, section_data in enumerate(DEFAULT_READER_SECTIONS, start=1):
        section = ReaderSection(
            book_id=book_id,
            section_key=section_data['section_key'],
            title=section_data['title'],
            summary=section_data['summary'],
            level=section_data['level'],
            order_no=section_order,
        )
        db.session.add(section)
        db.session.flush()

        for paragraph_order, paragraph in enumerate(section_data['paragraphs'], start=1):
            db.session.add(
                ReaderParagraph(
                    section_id=section.id,
                    paragraph_key=paragraph['paragraph_key'],
                    text=paragraph['text'],
                    order_no=paragraph_order,
                )
            )

    db.session.flush()

    tenant_id = int(getattr(book, 'tenant_id', 1) or 1)

    for highlight_data in DEFAULT_HIGHLIGHTS:
        highlight = ReaderHighlight(
            book_id=book_id,
            paragraph_key=highlight_data['paragraph_key'],
            start_offset=highlight_data['start_offset'],
            end_offset=highlight_data['end_offset'],
            selected_text=highlight_data['selected_text'],
            color=highlight_data['color'],
            note=highlight_data['note'],
            created_by=highlight_data['created_by'],
        )
        db.session.add(highlight)
        db.session.flush()

        for comment_data in highlight_data['comments']:
            db.session.add(
                ReaderHighlightComment(
                    highlight_id=highlight.id,
                    author=comment_data['author'],
                    content=comment_data['content'],
                    tenant_id=tenant_id,
                )
            )

    for comment_data in DEFAULT_BOOK_COMMENTS:
        db.session.add(
            ReaderBookComment(
                book_id=book_id,
                author=comment_data['author'],
                content=comment_data['content'],
                tenant_id=tenant_id,
            )
        )

    db.session.commit()


MAX_READER_SECTION_LIMIT = 5


def _clamp_section_window(offset: int = 0, limit: int | None = None):
    try:
        offset = int(offset or 0)
    except (TypeError, ValueError):
        offset = 0
    offset = max(0, offset)

    if limit is None:
        return offset, None
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = MAX_READER_SECTION_LIMIT
    limit = max(1, min(MAX_READER_SECTION_LIMIT, limit))
    return offset, limit


def _split_revision_paragraphs(section_key: str, content_text: str | None):
    return [
        {'id': f'{section_key}-p{idx}', 'text': text}
        for idx, text in enumerate(
            [part.strip() for part in (content_text or '').split('\n\n') if part.strip()],
            start=1,
        )
    ]


def _build_reader_sections(book_id: int, offset: int = 0, limit: int | None = None):
    offset, limit = _clamp_section_window(offset, limit)
    chapters = (
        BookChapter.query.filter(
            BookChapter.book_id == book_id,
            BookChapter.published_revision_id.isnot(None),
        )
        .order_by(BookChapter.chapter_no.asc(), BookChapter.id.asc())
        .all()
    )

    payload_outline = []
    payload_sections = []
    total_words = 0

    if chapters:
        revision_ids = [item.published_revision_id for item in chapters if item.published_revision_id]
        revisions = (
            BookChapterRevision.query.filter(BookChapterRevision.id.in_(revision_ids)).all()
            if revision_ids
            else []
        )
        revision_map = {item.id: item for item in revisions}
        section_records = []
        for chapter in chapters:
            revision = revision_map.get(chapter.published_revision_id)
            if not revision:
                continue
            section_key = chapter.chapter_key or f'chapter-{chapter.chapter_no}'
            section_records.append((section_key, revision))
            payload_outline.append({'id': section_key, 'title': revision.title, 'level': 1})
            total_words += len(revision.content_text or '')

        selected_records = section_records[offset:] if limit is None else section_records[offset:offset + limit]
        payload_sections = [
            {
                'id': section_key,
                'title': revision.title,
                'summary': revision.summary or '',
                'paragraphs': _split_revision_paragraphs(section_key, revision.content_text),
            }
            for section_key, revision in selected_records
        ]
        return payload_outline, payload_sections, len(section_records), total_words

    sections = ReaderSection.query.filter_by(book_id=book_id).order_by(ReaderSection.order_no.asc()).all()
    payload_outline = [{'id': s.section_key, 'title': s.title, 'level': s.level} for s in sections]
    total = len(sections)
    all_section_ids = [item.id for item in sections]
    selected_sections = sections[offset:] if limit is None else sections[offset:offset + limit]
    section_ids = [item.id for item in selected_sections]

    paragraph_map = {}
    if section_ids:
        paragraphs = (
            ReaderParagraph.query.filter(ReaderParagraph.section_id.in_(section_ids))
            .order_by(ReaderParagraph.section_id.asc(), ReaderParagraph.order_no.asc())
            .all()
        )
        for paragraph in paragraphs:
            paragraph_map.setdefault(paragraph.section_id, []).append({'id': paragraph.paragraph_key, 'text': paragraph.text})

    payload_sections = [
        {
            'id': s.section_key,
            'title': s.title,
            'summary': s.summary or '',
            'paragraphs': paragraph_map.get(s.id, []),
        }
        for s in selected_sections
    ]
    if limit is None:
        total_words = sum(len(paragraph['text']) for section in payload_sections for paragraph in section['paragraphs'])
    elif all_section_ids:
        total_words = sum(
            len(text or '')
            for (text,) in ReaderParagraph.query.with_entities(ReaderParagraph.text)
            .filter(ReaderParagraph.section_id.in_(all_section_ids))
            .all()
        )
    return payload_outline, payload_sections, total, total_words


def build_reader_sections_payload(book_id: int, offset: int = 0, limit: int = MAX_READER_SECTION_LIMIT):
    ensure_seed(book_id)
    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return None

    offset, limit = _clamp_section_window(offset, limit)
    _, payload_sections, total, _ = _build_reader_sections(book_id, offset=offset, limit=limit)
    next_offset = offset + len(payload_sections)
    return {
        'sections': payload_sections,
        'pagination': {
            'offset': offset,
            'limit': limit,
            'total': total,
            'next_offset': next_offset if next_offset < total else None,
            'has_more': next_offset < total,
        },
    }


def build_reader_payload(book_id: int, current_user=None, section_offset: int = 0, section_limit: int | None = None):
    ensure_seed(book_id)
    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return None

    payload_outline, payload_sections, total_sections, computed_total_words = _build_reader_sections(
        book_id,
        offset=section_offset,
        limit=section_limit,
    )

    highlights = ReaderHighlight.query.filter_by(book_id=book_id).order_by(ReaderHighlight.id.asc()).all()
    highlight_ids = [item.id for item in highlights]
    comments_map = {}
    if highlight_ids:
        comments = (
            ReaderHighlightComment.query.filter(ReaderHighlightComment.highlight_id.in_(highlight_ids))
            .order_by(ReaderHighlightComment.id.asc())
            .all()
        )
        for comment in comments:
            comments_map.setdefault(comment.highlight_id, []).append(
                {
                    'id': comment.id,
                    'author': comment.author,
                    'content': comment.content,
                    'created_at': _fmt(comment.created_at),
                }
            )

    payload_highlights = [
        {
            'id': h.id,
            'paragraph_id': h.paragraph_key,
            'start_offset': h.start_offset,
            'end_offset': h.end_offset,
            'selected_text': h.selected_text,
            'color': h.color,
            'note': h.note or '',
            'created_by': h.created_by,
            'created_at': _fmt(h.created_at),
            'comments': comments_map.get(h.id, []),
        }
        for h in highlights
    ]

    book_comments = ReaderBookComment.query.filter_by(book_id=book_id).order_by(ReaderBookComment.id.desc()).all()
    payload_book_comments = [
        {
            'id': c.id,
            'author': c.author,
            'content': c.content,
            'created_at': _fmt(c.created_at),
        }
        for c in book_comments
    ]

    category = Category.query.get(book.category_id) if book.category_id else None
    tag_rows = (
        db.session.query(Tag.id, Tag.code, Tag.label)
        .join(BookTag, BookTag.tag_id == Tag.id)
        .filter(BookTag.book_id == book.id)
        .order_by(Tag.id.asc())
        .all()
    )
    payload_tags = [{'id': int(tag_id), 'code': code, 'label': label} for tag_id, code, label in tag_rows]

    total_words = int(book.word_count or 0)
    if total_words <= 0:
        total_words = computed_total_words

    in_shelf = False
    if current_user:
        in_shelf = UserShelf.query.filter_by(user_id=current_user.id, book_id=book.id).first() is not None

    related_query = Book.query.filter(Book.status == 'published', Book.shelf_status == 'up', Book.id != book.id)
    if book.category_id:
        related_query = related_query.filter(Book.category_id == book.category_id)
    related_books = (
        related_query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(4)
        .all()
    )

    if len(related_books) < 4 and payload_tags:
        existing_ids = {item.id for item in related_books}
        extra_books = (
            Book.query.join(BookTag, BookTag.book_id == Book.id)
            .filter(
                Book.status == 'published',
                Book.shelf_status == 'up',
                Book.id != book.id,
                Book.id.notin_(existing_ids or {-1}),
                BookTag.tag_id.in_([item['id'] for item in payload_tags]),
            )
            .order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
            .limit(4 - len(related_books))
            .all()
        )
        related_books.extend(extra_books)

    payload_related_books = []
    for related_book in related_books[:4]:
        related_category = Category.query.get(related_book.category_id) if related_book.category_id else None
        payload = related_book.to_dict()
        payload['category_name'] = related_category.name if related_category else None
        payload_related_books.append(payload)

    same_tag_books = []
    if payload_tags:
        same_tag_ids = [item['id'] for item in payload_tags]
        same_tag_books = (
            Book.query.join(BookTag, BookTag.book_id == Book.id)
            .filter(
                Book.status == 'published',
                Book.shelf_status == 'up',
                Book.id != book.id,
                BookTag.tag_id.in_(same_tag_ids),
            )
            .order_by(Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
            .limit(4)
            .all()
        )

    popular_books = (
        Book.query.filter(Book.status == 'published', Book.shelf_status == 'up', Book.id != book.id)
        .order_by(Book.recent_reads.desc(), Book.rating.desc(), Book.id.desc())
        .limit(4)
        .all()
    )

    def related_payload(related_book: Book, reason: str):
        related_category = Category.query.get(related_book.category_id) if related_book.category_id else None
        payload = related_book.to_dict()
        payload['category_name'] = related_category.name if related_category else None
        payload['reason'] = reason
        return payload

    related_sections = [
        {
            'key': 'same_category',
            'title': '同分类作品',
            'description': '题材接近，阅读负担和期待更容易判断。',
            'items': [related_payload(item, f'同属“{category.name if category else "当前"}”分类') for item in related_books[:4]],
        },
        {
            'key': 'same_tags',
            'title': '同主题作品',
            'description': '从标签和关键词继续延展。',
            'items': [related_payload(item, '命中相近标签') for item in same_tag_books[:4]],
        },
        {
            'key': 'also_read',
            'title': '大家也在读',
            'description': '最近阅读热度较高的候选书。',
            'items': [related_payload(item, '近期在读热度靠前') for item in popular_books[:4]],
        },
    ]

    bookmarks = []
    reading_stats = {
        'last_read_at': None,
        'total_read_minutes': 0,
        'bookmark_count': 0,
        'highlight_count': len(payload_highlights),
        'comment_count': len(payload_book_comments),
    }
    if current_user:
        bookmarks = [
            item.to_dict()
            for item in ReaderBookmark.query.filter_by(user_id=current_user.id, book_id=book.id)
            .order_by(ReaderBookmark.created_at.desc(), ReaderBookmark.id.desc())
            .all()
        ]
        progress = UserReadingProgress.query.filter_by(user_id=current_user.id, book_id=book.id).first()
        total_seconds = (
            db.session.query(db.func.coalesce(db.func.sum(BookAnalyticsEvent.read_duration_seconds), 0))
            .filter(BookAnalyticsEvent.user_id == current_user.id, BookAnalyticsEvent.book_id == book.id)
            .scalar()
            or 0
        )
        reading_stats.update(
            {
                'last_read_at': _iso(progress.updated_at) if progress else None,
                'total_read_minutes': int(total_seconds / 60),
                'bookmark_count': len(bookmarks),
            }
        )

    next_offset = section_offset + len(payload_sections)
    return {
        'book': {
            'id': book.id,
            'title': book.title,
            'subtitle': book.subtitle or '',
            'author': book.author or '',
            'cover': book.cover or '',
            'description': book.description or '',
            'progress_percent': 42,
            'total_words': total_words,
            'rating': float(book.rating or 0),
            'rating_count': int(book.rating_count or 0),
            'recent_reads': int(book.recent_reads or 0),
            'category': category.to_dict() if category else None,
            'tags': payload_tags,
            'word_count': total_words,
            'estimated_reading_minutes': _estimate_reading_minutes(total_words),
            'completion_status': book.completion_status or 'ongoing',
            'suitable_audience': book.suitable_audience or '',
            'recommendation_reason': book.home_recommendation_reason or '',
            'keyword_tags': _split_keywords(book.search_keywords),
            'in_shelf': in_shelf,
            'decision_points': _build_decision_points(book, category.name if category else None, payload_tags, total_words),
        },
        'outline': payload_outline,
        'sections': payload_sections,
        'sections_pagination': {
            'offset': section_offset,
            'limit': section_limit,
            'total': total_sections,
            'next_offset': next_offset if section_limit is not None and next_offset < total_sections else None,
            'has_more': section_limit is not None and next_offset < total_sections,
        },
        'highlights': payload_highlights,
        'book_comments': payload_book_comments,
        'related_books': payload_related_books,
        'related_sections': related_sections,
        'bookmarks': bookmarks,
        'reading_stats': reading_stats,
    }


def get_bookmarks(book_id: int, user):
    if not user:
        return []
    return [
        item.to_dict()
        for item in ReaderBookmark.query.filter_by(user_id=user.id, book_id=book_id)
        .order_by(ReaderBookmark.created_at.desc(), ReaderBookmark.id.desc())
        .all()
    ]


def create_bookmark(book_id: int, payload: dict, user):
    if not user:
        return None, 'login required'
    ensure_seed(book_id)
    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return None, 'book not found'

    section_id = (payload.get('section_id') or '').strip()
    paragraph_id = (payload.get('paragraph_id') or '').strip() or None
    note = (payload.get('note') or '').strip()[:255]
    if not section_id:
        return None, 'section_id is required'

    bookmark = ReaderBookmark.query.filter_by(
        user_id=user.id,
        book_id=book_id,
        section_id=section_id,
        paragraph_id=paragraph_id,
    ).first()
    if bookmark:
        bookmark.note = note
    else:
        bookmark = ReaderBookmark(
            user_id=user.id,
            book_id=book_id,
            section_id=section_id,
            paragraph_id=paragraph_id,
            note=note,
        )
        db.session.add(bookmark)
    db.session.commit()
    return bookmark.to_dict(), None


def delete_bookmark(book_id: int, bookmark_id: int, user):
    if not user:
        return 'login required'
    bookmark = ReaderBookmark.query.filter_by(id=bookmark_id, user_id=user.id, book_id=book_id).first()
    if not bookmark:
        return 'bookmark not found'
    db.session.delete(bookmark)
    db.session.commit()
    return None


def create_highlight(book_id: int, payload: dict, user=None):
    ensure_seed(book_id)
    paragraph_id = (payload.get('paragraph_id') or '').strip()
    selected_text = (payload.get('selected_text') or '').strip()
    note = (payload.get('note') or '').strip()
    color = (payload.get('color') or 'amber').strip() or 'amber'
    author = _display_name(user)

    try:
        start_offset = int(payload.get('start_offset'))
        end_offset = int(payload.get('end_offset'))
    except (TypeError, ValueError):
        return None, 'invalid highlight range'

    if not paragraph_id or not selected_text:
        return None, 'missing paragraph_id or selected_text'
    if start_offset < 0 or end_offset <= start_offset:
        return None, 'invalid highlight range'

    highlight = ReaderHighlight(
        book_id=book_id,
        paragraph_key=paragraph_id,
        start_offset=start_offset,
        end_offset=end_offset,
        selected_text=selected_text,
        color=color,
        note=note,
        created_by=author,
    )
    db.session.add(highlight)
    db.session.commit()

    return {
        'id': highlight.id,
        'paragraph_id': highlight.paragraph_key,
        'start_offset': highlight.start_offset,
        'end_offset': highlight.end_offset,
        'selected_text': highlight.selected_text,
        'color': highlight.color,
        'note': highlight.note or '',
        'created_by': highlight.created_by,
        'created_at': _fmt(highlight.created_at),
        'comments': [],
    }, None


def create_highlight_comment(book_id: int, highlight_id: int, payload: dict, user=None):
    ensure_seed(book_id)
    highlight = ReaderHighlight.query.filter_by(id=highlight_id, book_id=book_id).first()
    if not highlight:
        return None, 'highlight not found'

    content = (payload.get('content') or '').strip()
    if not content:
        return None, 'content is required'

    tenant_id = int(getattr(user, 'tenant_id', 1) or 1) if user else 1
    comment = ReaderHighlightComment(
        highlight_id=highlight.id,
        author=_display_name(user),
        content=content,
        tenant_id=tenant_id,
    )
    db.session.add(comment)
    db.session.commit()

    return {
        'id': comment.id,
        'author': comment.author,
        'content': comment.content,
        'created_at': _fmt(comment.created_at),
    }, None


def create_book_comment(book_id: int, payload: dict, user=None):
    ensure_seed(book_id)
    content = (payload.get('content') or '').strip()
    if not content:
        return None, 'content is required'

    tenant_id = int(getattr(user, 'tenant_id', 1) or 1) if user else 1
    comment = ReaderBookComment(
        book_id=book_id,
        author=_display_name(user),
        content=content,
        tenant_id=tenant_id,
    )
    db.session.add(comment)
    db.session.commit()

    return {
        'id': comment.id,
        'author': comment.author,
        'content': comment.content,
        'created_at': _fmt(comment.created_at),
    }, None


def get_reader_preferences(user):
    defaults = {
        'theme': 'light',
        'font_size': 20,
        'line_height': 2.0,
        'margin': 'medium',
        'show_highlights': True,
        'show_comments': True,
    }
    if not user:
        return defaults

    preference = ReaderUserPreference.query.filter_by(user_id=user.id).first()
    if not preference:
        return defaults
    return preference.to_dict()


def save_reader_preferences(user, payload: dict):
    preference = ReaderUserPreference.query.filter_by(user_id=user.id).first()
    if not preference:
        preference = ReaderUserPreference(user_id=user.id)
        db.session.add(preference)

    theme = (payload.get('theme') or '').strip().lower()
    if theme in ('light', 'dark', 'green', 'parchment'):
        preference.theme = theme

    if payload.get('font_size') is not None:
        try:
            value = int(payload.get('font_size'))
        except (TypeError, ValueError):
            return None, 'invalid font_size'
        preference.font_size = max(16, min(30, value))

    if payload.get('line_height') is not None:
        try:
            lh = float(payload.get('line_height'))
        except (TypeError, ValueError):
            return None, 'invalid line_height'
        preference.line_height = max(1.2, min(3.0, lh))

    if payload.get('margin') is not None:
        margin = (payload.get('margin') or '').strip().lower()
        if margin in ('narrow', 'medium', 'wide'):
            preference.margin = margin

    if 'show_highlights' in payload:
        preference.show_highlights = bool(payload.get('show_highlights'))
    if 'show_comments' in payload:
        preference.show_comments = bool(payload.get('show_comments'))

    db.session.commit()
    return preference.to_dict(), None
