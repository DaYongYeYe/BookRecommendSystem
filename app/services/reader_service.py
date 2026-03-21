from datetime import datetime

from app import db
from app.models import (
    Book,
    ReaderBookComment,
    ReaderHighlight,
    ReaderHighlightComment,
    ReaderParagraph,
    ReaderSection,
    ReaderUserPreference,
)


DEFAULT_BOOK_ID = 1

DEFAULT_READER_SECTIONS = [
    {
        'section_key': 'chapter-1',
        'title': '第一章 抵达旧港',
        'summary': '旅人来到海港小城，在潮湿空气里重新辨认自己的来路。',
        'level': 1,
        'paragraphs': [
            {
                'paragraph_key': 'p1',
                'text': '黄昏压低在港口上空，潮水拍打着木栈桥。她拖着行李走下最后一级台阶，空气里是盐、铁锈和雨前石板的气味。'
            },
            {
                'paragraph_key': 'p2',
                'text': '旅馆老板递来钥匙，又指了指远处灯塔，说今晚风会很大。她点头，却仍在门口站了几秒，像在等待某个迟来的信号。'
            },
        ],
    },
    {
        'section_key': 'chapter-2',
        'title': '第二章 雨夜抄录',
        'summary': '她在夜里整理信件和手稿，逐渐看见关系裂缝背后的善意。',
        'level': 1,
        'paragraphs': [
            {
                'paragraph_key': 'p3',
                'text': '信纸被海风吹起细小纹路，字迹却比记忆里的任何一次都更稳。她反复读那句：有些人要绕远路，才能回到最初想靠近的光。'
            },
            {
                'paragraph_key': 'p4',
                'text': '夜色深下去之后，雨终于落了。她抄录那些曾被匆匆读过的句子，像把迟到的情绪一行行安放。'
            },
        ],
    },
]


def _fmt(dt):
    if not dt:
        return None
    return dt.strftime('%Y-%m-%d %H:%M')


def _display_name(user):
    if not user:
        return 'Current Reader'
    return (user.name or user.username or f'user-{user.id}').strip()


def ensure_seed(book_id: int):
    if book_id != DEFAULT_BOOK_ID:
        return

    book = Book.query.get(book_id)
    if not book:
        book = Book(
            id=DEFAULT_BOOK_ID,
            title='阅读样章：漫长的余生',
            subtitle='在命运的褶皱里寻找彼此照亮的时刻',
            author='罗新',
            description='一部带有纪实质感的文学样章，适合展示阅读器的大纲、划线和评论交互。',
            cover='https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',
            score=9.4,
            rating=9.1,
            rating_count=12000,
            recent_reads=128000,
            is_featured=True,
            created_at=datetime.utcnow(),
        )
        db.session.add(book)
        db.session.flush()

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

    db.session.add(
        ReaderHighlight(
            book_id=book_id,
            paragraph_key='p3',
            start_offset=18,
            end_offset=36,
            selected_text='有些人要绕远路，才能回到最初想靠近的光',
            color='amber',
            note='像是在写所有迟到但仍值得的靠近。',
            created_by='读者 阿遥',
        )
    )
    db.session.add(
        ReaderBookComment(
            book_id=book_id,
            author='读者 星槎',
            content='这个样章的节奏很舒服，适合夜里慢慢读。',
        )
    )
    db.session.commit()

    first_highlight = ReaderHighlight.query.filter_by(book_id=book_id).order_by(ReaderHighlight.id.asc()).first()
    if first_highlight and not ReaderHighlightComment.query.filter_by(highlight_id=first_highlight.id).first():
        db.session.add(
            ReaderHighlightComment(
                highlight_id=first_highlight.id,
                author='读者 阿遥',
                content='这一句很适合做章节题眼，整本书的回返感都在这里。',
            )
        )
        db.session.commit()


def build_reader_payload(book_id: int):
    ensure_seed(book_id)
    book = Book.query.get(book_id)
    if not book:
        return None

    sections = ReaderSection.query.filter_by(book_id=book_id).order_by(ReaderSection.order_no.asc()).all()
    section_ids = [item.id for item in sections]

    paragraph_map = {}
    if section_ids:
        paragraphs = (
            ReaderParagraph.query.filter(ReaderParagraph.section_id.in_(section_ids))
            .order_by(ReaderParagraph.section_id.asc(), ReaderParagraph.order_no.asc())
            .all()
        )
        for paragraph in paragraphs:
            paragraph_map.setdefault(paragraph.section_id, []).append({'id': paragraph.paragraph_key, 'text': paragraph.text})

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

    payload_outline = [{'id': s.section_key, 'title': s.title, 'level': s.level} for s in sections]
    payload_sections = [
        {
            'id': s.section_key,
            'title': s.title,
            'summary': s.summary or '',
            'paragraphs': paragraph_map.get(s.id, []),
        }
        for s in sections
    ]
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

    return {
        'book': {
            'id': book.id,
            'title': book.title,
            'subtitle': book.subtitle or '',
            'author': book.author or '',
            'cover': book.cover or '',
            'description': book.description or '',
            'progress_percent': 42,
            'total_words': 8620,
        },
        'outline': payload_outline,
        'sections': payload_sections,
        'highlights': payload_highlights,
        'book_comments': payload_book_comments,
    }


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
    author = _display_name(user)
    if not content:
        return None, 'content is required'

    comment = ReaderHighlightComment(highlight_id=highlight.id, author=author, content=content)
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
    author = _display_name(user)
    if not content:
        return None, 'content is required'

    comment = ReaderBookComment(book_id=book_id, author=author, content=content)
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
    if theme in ('light', 'dark'):
        preference.theme = theme

    font_size = payload.get('font_size')
    if font_size is not None:
        try:
            value = int(font_size)
            preference.font_size = max(16, min(30, value))
        except (TypeError, ValueError):
            return None, 'invalid font_size'

    if 'show_highlights' in payload:
        preference.show_highlights = bool(payload.get('show_highlights'))
    if 'show_comments' in payload:
        preference.show_comments = bool(payload.get('show_comments'))

    db.session.commit()
    return preference.to_dict(), None
