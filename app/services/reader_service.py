from datetime import datetime

from app import db
from app.models import (
    Book,
    ReaderBookComment,
    ReaderHighlight,
    ReaderHighlightComment,
    ReaderParagraph,
    ReaderSection,
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
                'text': '黄昏压低在港口上空，潮水把旧木栈桥拍得微微作响。她拖着行李走下最后一级台阶时，闻见了盐、铁锈和雨前石板的气味，那些气味像一封久未拆开的信，先于记忆抵达。'
            },
            {
                'paragraph_key': 'p2',
                'text': '旅馆老板递来钥匙，又指了指远处的灯塔，说今晚风会很大，最好别靠海走太久。她点头，却仍旧在门口站了几秒，因为天边那线将熄未熄的金光，让她忽然觉得自己并不是来避雨，而是来认领某段被搁置太久的人生。'
            },
        ],
    },
    {
        'section_key': 'chapter-1-1',
        'title': '1.1 海雾中的来信',
        'summary': '一封未署名的信，将旧日关系慢慢重新牵引出来。',
        'level': 2,
        'paragraphs': [
            {
                'paragraph_key': 'p3',
                'text': '信纸被海风吹得起了细小的波纹，字迹却比她记忆里的任何一次都更稳。写信的人没有解释离开的原因，只写道：有些人用一生绕远路，才走回最初想要靠近的灯。她把这句话读了三遍，像是把某种迟来的许可，轻轻压进心口。'
            },
            {
                'paragraph_key': 'p4',
                'text': '窗外的雾越来越浓，街灯在雾里化成模糊的圆斑。她突然意识到，自己这些年努力维持的秩序，并不是为了忘记谁，而是为了让某个名字不至于一出现，就立刻击穿全部防线。'
            },
        ],
    },
    {
        'section_key': 'chapter-1-2',
        'title': '1.2 灯塔下的对话',
        'summary': '她终于走向海边，和守塔人聊起等待、缺席与回声。',
        'level': 2,
        'paragraphs': [
            {
                'paragraph_key': 'p5',
                'text': '守塔人说，海上的船不会因为灯塔沉默而停下，但会因为看见那一点稳定的光，知道自己还在可归返的世界里。她听完笑了笑，像是终于明白，人并不总需要答案，有时只需要一个没有撤离的坐标。'
            },
            {
                'paragraph_key': 'p6',
                'text': '风穿过护栏，带来潮湿而锋利的凉意。她把外套裹紧，忽然很想把这些年所有未曾寄出的句子都说给海听，因为海从不追问，只负责把人类的犹豫反复拍回岸边，让他们自己看清。'
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
                'paragraph_key': 'p7',
                'text': '夜色深下去之后，雨终于落了。她摊开桌上的便笺，一张张抄录那些曾经被她匆匆读过的句子。墨水在纸面缓慢洇开，像迟到的情绪找到出口，也像时间终于允许某些痛感拥有更温柔的形状。'
            },
            {
                'paragraph_key': 'p8',
                'text': '她明白，真正难的从来不是离别本身，而是承认彼此都尽力了，却仍旧没能在同一场风暴里学会相同的航行方法。理解不是原谅的附庸，它更像深夜里为自己留的一盏小灯，照见那些不必再苛责的部分。'
            },
        ],
    },
]


def _fmt(dt):
    if not dt:
        return None
    return dt.strftime('%Y-%m-%d %H:%M')


def ensure_seed(book_id: int):
    if book_id != DEFAULT_BOOK_ID:
        return

    book = Book.query.get(book_id)
    if not book:
        book = Book(
            id=DEFAULT_BOOK_ID,
            title='阅读样章：漫长的余生',
            subtitle='在命运的褶皱里寻找互相照亮的时刻',
            author='罗新',
            description='一部带有纪实质感的文学样章，适合展示阅读器的大纲、划线和评论互动。',
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

    has_sections = ReaderSection.query.filter_by(book_id=book_id).first()
    if has_sections:
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
            start_offset=31,
            end_offset=53,
            selected_text='有些人用一生绕远路，才走回最初想要靠近的灯',
            color='amber',
            note='像是在写所有迟到但仍然值得的靠近。',
            created_by='读者 阿遥',
        )
    )
    db.session.add(
        ReaderBookComment(
            book_id=book_id,
            author='读者 星檐',
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
            paragraph_map.setdefault(paragraph.section_id, []).append(
                {'id': paragraph.paragraph_key, 'text': paragraph.text}
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

    payload_sections = []
    payload_outline = []
    for section in sections:
        payload_outline.append({'id': section.section_key, 'title': section.title, 'level': section.level})
        payload_sections.append(
            {
                'id': section.section_key,
                'title': section.title,
                'summary': section.summary or '',
                'paragraphs': paragraph_map.get(section.id, []),
            }
        )

    payload_highlights = []
    for highlight in highlights:
        payload_highlights.append(
            {
                'id': highlight.id,
                'paragraph_id': highlight.paragraph_key,
                'start_offset': highlight.start_offset,
                'end_offset': highlight.end_offset,
                'selected_text': highlight.selected_text,
                'color': highlight.color,
                'note': highlight.note or '',
                'created_by': highlight.created_by,
                'created_at': _fmt(highlight.created_at),
                'comments': comments_map.get(highlight.id, []),
            }
        )

    book_comments = ReaderBookComment.query.filter_by(book_id=book_id).order_by(ReaderBookComment.id.desc()).all()
    payload_book_comments = [
        {
            'id': comment.id,
            'author': comment.author,
            'content': comment.content,
            'created_at': _fmt(comment.created_at),
        }
        for comment in book_comments
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


def create_highlight(book_id: int, payload: dict):
    ensure_seed(book_id)
    paragraph_id = (payload.get('paragraph_id') or '').strip()
    selected_text = (payload.get('selected_text') or '').strip()
    note = (payload.get('note') or '').strip()
    color = (payload.get('color') or 'amber').strip() or 'amber'
    author = (payload.get('author') or '当前读者').strip() or '当前读者'

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


def create_highlight_comment(book_id: int, highlight_id: int, payload: dict):
    ensure_seed(book_id)
    highlight = ReaderHighlight.query.filter_by(id=highlight_id, book_id=book_id).first()
    if not highlight:
        return None, 'highlight not found'

    content = (payload.get('content') or '').strip()
    author = (payload.get('author') or '当前读者').strip() or '当前读者'
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


def create_book_comment(book_id: int, payload: dict):
    ensure_seed(book_id)
    content = (payload.get('content') or '').strip()
    author = (payload.get('author') or '当前读者').strip() or '当前读者'
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
