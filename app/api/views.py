from datetime import date, datetime, timedelta

from flask import jsonify, request
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app import db
from app.api import bp
from app.models import (
    Book,
    BookAnalyticsEvent,
    BookTag,
    Category,
    ReaderSection,
    Tag,
    UserReadingProgress,
    UserSearchHistory,
    UserShelf,
)
from app.rbac.decorators import login_optional, login_required

DEFAULT_HOT_SEARCH_TERMS = [
    '悬疑',
    '治愈',
    '都市',
    '成长',
    '古言',
    '科幻',
    '权谋',
    '轻松',
]
DEFAULT_SEARCH_HISTORY_LIMIT = 8
VALID_COMPLETION_STATUSES = {'ongoing', 'completed', 'paused'}
RANKING_WINDOW_DAYS = 7
RANKING_TYPE_ORDER = ['hot', 'new_book', 'surging', 'completed', 'collection', 'following']
RANKING_TYPE_CONFIG = {
    'hot': {
        'label': '热门榜',
        'description': '综合阅读热度、收藏人数和口碑表现排序。',
        'update_cycle': '每小时更新',
        'primary_metric': '综合热度',
    },
    'new_book': {
        'label': '新书榜',
        'description': '优先展示近期上架且热度起势明显的新作品。',
        'update_cycle': '每6小时更新',
        'primary_metric': '新书热度',
    },
    'surging': {
        'label': '飙升榜',
        'description': f'按近 {RANKING_WINDOW_DAYS} 天增长速度排序，适合发现趋势作品。',
        'update_cycle': '每2小时更新',
        'primary_metric': '增长速度',
    },
    'completed': {
        'label': '完结榜',
        'description': '优先展示已完结且口碑稳定的作品。',
        'update_cycle': '每日更新',
        'primary_metric': '完结口碑',
    },
    'collection': {
        'label': '收藏榜',
        'description': '按加入书架人数排序，反映用户长期收藏意愿。',
        'update_cycle': '每小时更新',
        'primary_metric': '收藏人数',
    },
    'following': {
        'label': '追更榜',
        'description': '聚焦连载作品的在读人数与近期追更活跃度。',
        'update_cycle': '每小时更新',
        'primary_metric': '追更热度',
    },
}
RANKING_TYPE_ALIASES = {
    'high_score': 'hot',
    'hot': 'hot',
    'popular': 'hot',
    'new': 'new_book',
    'new_book': 'new_book',
    'surging': 'surging',
    'rising': 'surging',
    'completed': 'completed',
    'finished': 'completed',
    'collection': 'collection',
    'favorite': 'collection',
    'following': 'following',
    'ongoing': 'following',
}


def _message(text: str, **extra):
    payload = {'message': text}
    payload.update(extra)
    return payload


def _format_compact_number(value: int | float | None):
    num = max(0, int(value or 0))
    if num >= 10000:
        return f'{num / 10000:.1f}万'
    return str(num)


def _normalize_ranking_type(value: str | None):
    return RANKING_TYPE_ALIASES.get((value or 'hot').strip(), None)


def _ranking_type_options():
    return [
        {
            'key': key,
            **RANKING_TYPE_CONFIG[key],
            'period_hint': '日榜/周榜/月榜后续开放',
        }
        for key in RANKING_TYPE_ORDER
    ]


def _collect_ranking_stats():
    window_start = datetime.utcnow() - timedelta(days=RANKING_WINDOW_DAYS)
    books = _visible_books_query().all()
    categories = {item.id: item for item in Category.query.all()}

    shelf_counts = {
        int(book_id): int(count or 0)
        for book_id, count in db.session.query(UserShelf.book_id, func.count(UserShelf.id))
        .group_by(UserShelf.book_id)
        .all()
    }
    reading_users = {
        int(book_id): int(count or 0)
        for book_id, count in db.session.query(UserReadingProgress.book_id, func.count(UserReadingProgress.id))
        .group_by(UserReadingProgress.book_id)
        .all()
    }
    recent_progress = {
        int(book_id): int(count or 0)
        for book_id, count in db.session.query(UserReadingProgress.book_id, func.count(UserReadingProgress.id))
        .filter(UserReadingProgress.updated_at >= window_start)
        .group_by(UserReadingProgress.book_id)
        .all()
    }
    recent_events = {
        int(book_id): {
            'count': int(count or 0),
            'read_minutes': int((seconds or 0) / 60),
        }
        for book_id, count, seconds in db.session.query(
            BookAnalyticsEvent.book_id,
            func.count(BookAnalyticsEvent.id),
            func.coalesce(func.sum(BookAnalyticsEvent.read_duration_seconds), 0),
        )
        .filter(BookAnalyticsEvent.created_at >= window_start)
        .group_by(BookAnalyticsEvent.book_id)
        .all()
    }

    return books, categories, shelf_counts, reading_users, recent_progress, recent_events


def _build_book_ranking_context(
    book: Book,
    shelf_counts: dict[int, int],
    reading_users: dict[int, int],
    recent_progress: dict[int, int],
    recent_events: dict[int, dict[str, int]],
):
    published_date = book.published_at.date() if book.published_at else None
    published_days = 999
    if published_date:
        published_days = max(1, (date.today() - published_date).days + 1)

    recent_reads = int(book.recent_reads or 0)
    rating = float(book.rating or book.score or 0)
    rating_count = int(book.rating_count or 0)
    shelf_count = shelf_counts.get(book.id, 0)
    reading_count = reading_users.get(book.id, 0)
    recent_progress_count = recent_progress.get(book.id, 0)
    recent_event_data = recent_events.get(book.id, {'count': 0, 'read_minutes': 0})
    recent_event_count = int(recent_event_data.get('count', 0))
    recent_read_minutes = int(recent_event_data.get('read_minutes', 0))
    freshness_bonus = max(0, 60 - min(published_days, 60)) if published_days != 999 else 0
    growth_points = recent_progress_count * 6 + recent_event_count * 3 + min(recent_read_minutes, 720)

    return {
        'published_days': published_days,
        'freshness_bonus': freshness_bonus,
        'recent_reads': recent_reads,
        'rating': rating,
        'rating_count': rating_count,
        'shelf_count': shelf_count,
        'reading_users': reading_count,
        'recent_progress': recent_progress_count,
        'recent_event_count': recent_event_count,
        'recent_read_minutes': recent_read_minutes,
        'growth_points': growth_points,
    }


def _score_book_for_ranking(book: Book, rank_type: str, context: dict):
    if rank_type == 'hot':
        return {
            'score': (
                context['recent_reads']
                + context['shelf_count'] * 220
                + context['reading_users'] * 200
                + context['recent_event_count'] * 45
                + context['rating_count'] * 30
                + context['rating'] * 120
            ),
            'heat_label': f"{_format_compact_number(max(context['recent_reads'], context['reading_users']))}热度",
            'ranking_note': '阅读、收藏与口碑综合表现领先',
        }

    if rank_type == 'new_book':
        return {
            'score': (
                context['freshness_bonus'] * 260
                + context['recent_reads'] * 0.55
                + context['recent_event_count'] * 70
                + context['rating'] * 100
                + context['shelf_count'] * 140
                + context['reading_users'] * 150
            ),
            'heat_label': (
                f"{context['published_days']}天内上新"
                if context['published_days'] != 999
                else '近期新作'
            ),
            'ranking_note': '近期上线且热度起势快',
        }

    if rank_type == 'surging':
        return {
            'score': (
                context['growth_points'] * 45
                + context['recent_progress'] * 180
                + context['recent_event_count'] * 80
                + context['recent_read_minutes'] * 2
                + context['recent_reads'] * 0.05
            ),
            'heat_label': f"近{RANKING_WINDOW_DAYS}日增长{_format_compact_number(context['growth_points'])}",
            'ranking_note': '最近一周增长速度最快',
        }

    if rank_type == 'completed':
        if book.completion_status != 'completed':
            return None
        return {
            'score': (
                context['rating'] * 220
                + context['rating_count'] * 40
                + context['recent_reads'] * 0.2
                + context['shelf_count'] * 180
                + context['reading_users'] * 120
            ),
            'heat_label': '已完结，可放心一口气读',
            'ranking_note': '完结作品中口碑与热度兼具',
        }

    if rank_type == 'collection':
        return {
            'score': (
                context['shelf_count'] * 320
                + context['rating'] * 120
                + context['rating_count'] * 25
                + context['recent_reads'] * 0.1
            ),
            'heat_label': f"{_format_compact_number(context['shelf_count'])}人收藏",
            'ranking_note': '加入书架人数领先',
        }

    if rank_type == 'following':
        if book.completion_status != 'ongoing':
            return None
        return {
            'score': (
                context['reading_users'] * 260
                + context['recent_progress'] * 210
                + context['recent_event_count'] * 70
                + context['shelf_count'] * 120
                + context['recent_reads'] * 0.12
            ),
            'heat_label': f"{_format_compact_number(max(context['reading_users'], context['recent_progress']))}人追更",
            'ranking_note': '连载作品中追更讨论最活跃',
        }

    return None


def _ranking_sort_key(item: dict, rank_type: str):
    context = item['context']
    rating = float(item['book'].rating or item['book'].score or 0)
    recent_reads = int(item['book'].recent_reads or 0)

    if rank_type == 'new_book':
        return (-item['score'], context['published_days'], -recent_reads, item['book'].id)
    if rank_type == 'surging':
        return (-item['score'], -context['recent_event_count'], -context['recent_progress'], item['book'].id)
    if rank_type == 'completed':
        return (-item['score'], -rating, -context['shelf_count'], item['book'].id)
    if rank_type == 'collection':
        return (-item['score'], -context['shelf_count'], -rating, item['book'].id)
    if rank_type == 'following':
        return (-item['score'], -context['reading_users'], -context['recent_progress'], item['book'].id)
    return (-item['score'], -rating, -recent_reads, item['book'].id)


def _build_ranking_payload(book: Book, category: Category | None, rank_type: str, rank_no: int, ranking: dict, context: dict):
    payload = _book_payload(book, recommend_reason=ranking['ranking_note'])
    payload.update(
        {
            'rank': rank_no,
            'category_name': category.name if category else None,
            'heat_label': ranking['heat_label'],
            'ranking_note': ranking['ranking_note'],
            'ranking_score': round(float(ranking['score']), 2),
            'shelf_count': context['shelf_count'],
            'reading_users': context['reading_users'],
            'recent_growth': context['growth_points'],
            'published_days': context['published_days'] if context['published_days'] != 999 else None,
        }
    )
    return payload


def _book_payload(book: Book, *, recommend_reason: str | None = None, extra: dict | None = None):
    payload = book.to_dict()
    payload['recommend_reason'] = recommend_reason or book.home_recommendation_reason or '高分口碑推荐'
    if extra:
        payload.update(extra)
    return payload


def _visible_books_query():
    return Book.query.filter(Book.status == 'published', Book.shelf_status == 'up')


def _get_continue_reading(current_user):
    if not current_user:
        return None

    row = (
        db.session.query(UserReadingProgress, Book)
        .join(Book, Book.id == UserReadingProgress.book_id)
        .filter(
            UserReadingProgress.user_id == current_user.id,
            Book.status == 'published',
            Book.shelf_status == 'up',
        )
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .first()
    )
    if not row:
        return None

    progress, book = row
    section = None
    if progress.section_id:
        section = ReaderSection.query.filter_by(book_id=book.id, section_key=progress.section_id).first()

    return {
        **_book_payload(book, recommend_reason='继续上次的阅读进度'),
        'section_id': progress.section_id,
        'paragraph_id': progress.paragraph_id,
        'section_title': section.title if section else None,
        'scroll_percent': float(progress.scroll_percent or 0),
        'updated_at': progress.updated_at.isoformat() if progress.updated_at else None,
        'resume_url': f'/reader/{book.id}?resume=1',
    }


def _build_recommendation_context(current_user):
    if not current_user:
        return {
            'latest_progress_book_id': None,
            'preferred_category_id': None,
            'preferred_tag_ids': set(),
        }

    latest_progress = (
        UserReadingProgress.query.filter_by(user_id=current_user.id)
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .first()
    )
    latest_progress_book_id = latest_progress.book_id if latest_progress else None

    preferred_category_id = None
    if latest_progress_book_id:
        latest_book = Book.query.get(latest_progress_book_id)
        preferred_category_id = latest_book.category_id if latest_book else None

    shelf_book_ids = [row.book_id for row in UserShelf.query.filter_by(user_id=current_user.id).all()]
    preferred_tag_ids = set()
    if shelf_book_ids:
        tag_rows = (
            db.session.query(BookTag.tag_id, func.count(BookTag.id).label('cnt'))
            .filter(BookTag.book_id.in_(shelf_book_ids))
            .group_by(BookTag.tag_id)
            .order_by(func.count(BookTag.id).desc(), BookTag.tag_id.asc())
            .limit(3)
            .all()
        )
        preferred_tag_ids = {int(tag_id) for tag_id, _cnt in tag_rows}

    return {
        'latest_progress_book_id': latest_progress_book_id,
        'preferred_category_id': preferred_category_id,
        'preferred_tag_ids': preferred_tag_ids,
    }


def _build_recommend_reason(book: Book, current_user=None, context: dict | None = None):
    context = context or {}
    preferred_category_id = context.get('preferred_category_id')
    preferred_tag_ids = context.get('preferred_tag_ids') or set()

    if current_user and preferred_category_id and book.category_id == preferred_category_id:
        category = Category.query.get(preferred_category_id)
        return f'延续你最近常读的“{category.name if category else "同类"}”题材'

    if current_user and preferred_tag_ids:
        matched_tag = (
            db.session.query(Tag)
            .join(BookTag, BookTag.tag_id == Tag.id)
            .filter(BookTag.book_id == book.id, Tag.id.in_(preferred_tag_ids))
            .order_by(Tag.id.asc())
            .first()
        )
        if matched_tag:
            return f'因为你最近常看“{matched_tag.label}”主题'

    if book.is_featured:
        return book.home_recommendation_reason or '本周主推，最近很多读者都在看'
    if int(book.recent_reads or 0) >= 100000:
        return '最近很多人在读，适合先加入你的候选书单'
    if float(book.rating or 0) >= 9:
        return '高分口碑稳定，适合先从这本开始'
    return book.home_recommendation_reason or '为你挑出的高分好书'


def _normalize_search_keyword(value, max_len: int = 100):
    keyword = ' '.join((value or '').split())
    return keyword[:max_len]


def _books_search_query(q: str):
    like = f'%{q}%'
    return (
        Book.query.outerjoin(Category, Category.id == Book.category_id)
        .outerjoin(BookTag, BookTag.book_id == Book.id)
        .outerjoin(Tag, Tag.id == BookTag.tag_id)
        .filter(
            Book.status == 'published',
            Book.shelf_status == 'up',
            or_(
                Book.title.ilike(like),
                Book.subtitle.ilike(like),
                Book.author.ilike(like),
                Book.description.ilike(like),
                Book.search_keywords.ilike(like),
                Category.name.ilike(like),
                Category.en_name.ilike(like),
                Tag.label.ilike(like),
                Tag.code.ilike(like),
            ),
        )
        .distinct()
    )


def _build_search_recommendations(limit: int = 4, exclude_ids: list[int] | None = None):
    query = _visible_books_query()
    if exclude_ids:
        query = query.filter(~Book.id.in_(exclude_ids))

    books = (
        query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    return [_book_payload(book, recommend_reason='大家都在看，也许这本正适合现在打开') for book in books]


def _record_search_history(current_user, keyword: str):
    if not current_user or not keyword:
        return

    history = UserSearchHistory.query.filter_by(user_id=current_user.id, keyword=keyword).first()
    if history:
        history.search_count = int(history.search_count or 0) + 1
        history.last_searched_at = db.func.now()
    else:
        db.session.add(
            UserSearchHistory(
                user_id=current_user.id,
                keyword=keyword,
                search_count=1,
            )
        )

    overflow_rows = (
        UserSearchHistory.query.filter_by(user_id=current_user.id)
        .order_by(UserSearchHistory.last_searched_at.desc(), UserSearchHistory.id.desc())
        .offset(20)
        .all()
    )
    for row in overflow_rows:
        db.session.delete(row)


def _get_hot_search_term_items(limit: int = 8):
    items = []
    seen = set()

    def append_term(keyword: str, source: str):
        text = _normalize_search_keyword(keyword, max_len=20)
        if not text or text in seen:
            return
        seen.add(text)
        items.append({'keyword': text, 'source': source})

    for keyword in DEFAULT_HOT_SEARCH_TERMS:
        append_term(keyword, 'configured')

    tag_rows = (
        db.session.query(Tag, func.count(BookTag.id).label('book_count'))
        .outerjoin(BookTag, BookTag.tag_id == Tag.id)
        .group_by(Tag.id)
        .order_by(func.count(BookTag.id).desc(), Tag.id.asc())
        .limit(limit)
        .all()
    )
    for tag, _book_count in tag_rows:
        append_term(tag.label, 'tag')

    category_rows = (
        Category.query.order_by(Category.is_highlighted.desc(), Category.id.asc())
        .limit(limit)
        .all()
    )
    for category in category_rows:
        append_term(category.name, 'category')

    return items[:limit]


@bp.route('/user/profile', methods=['GET'])
@login_required
def api_get_user_profile(current_user):
    return jsonify({'user': current_user.to_self_dict(), 'meta': {}}), 200


@bp.route('/notifications/unread-count', methods=['GET'])
@login_required
def api_get_unread_notifications_count(current_user):
    return jsonify({'unread_count': 3}), 200


@bp.route('/books/search-legacy', methods=['GET'])
def api_search_books():
    q = request.args.get('q', '').strip()
    try:
        limit = max(1, min(int(request.args.get('limit', 8)), 20))
    except ValueError:
        limit = 8

    if not q:
        return jsonify({'query': q, 'items': []}), 200

    books = (
        _books_search_query(q)
        .order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    items = []
    for book in books:
        items.append(
            _book_payload(
                book,
                recommend_reason=f'搜索“{q}”命中了书名、作者或主题词',
            )
        )
    return jsonify({'query': q, 'items': items}), 200


@bp.route('/search/hot-terms', methods=['GET'])
def api_get_search_hot_terms():
    try:
        limit = max(1, min(int(request.args.get('limit', 8)), 20))
    except ValueError:
        limit = 8

    return jsonify({'items': _get_hot_search_term_items(limit)}), 200


@bp.route('/search/history', methods=['GET'])
@login_optional
def api_get_search_history(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', DEFAULT_SEARCH_HISTORY_LIMIT)), 20))
    except ValueError:
        limit = DEFAULT_SEARCH_HISTORY_LIMIT

    if not current_user:
        return jsonify({'items': []}), 200

    items = (
        UserSearchHistory.query.filter_by(user_id=current_user.id)
        .order_by(UserSearchHistory.last_searched_at.desc(), UserSearchHistory.id.desc())
        .limit(limit)
        .all()
    )
    return jsonify({'items': [item.to_dict() for item in items]}), 200


@bp.route('/search/history', methods=['DELETE'])
@login_required
def api_clear_search_history(current_user):
    UserSearchHistory.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
    db.session.commit()
    return jsonify(_message('search history cleared')), 200


@bp.route('/books/search', methods=['GET'])
@login_optional
def api_search_books_v2(current_user):
    q = _normalize_search_keyword(request.args.get('q', ''))
    try:
        limit = max(1, min(int(request.args.get('limit', 12)), 30))
    except ValueError:
        limit = 12
    try:
        recommend_limit = max(1, min(int(request.args.get('recommend_limit', 4)), 8))
    except ValueError:
        recommend_limit = 4

    if not q:
        return jsonify({'query': q, 'total': 0, 'items': [], 'recommended_items': []}), 200

    books = (
        _books_search_query(q)
        .order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )

    if current_user:
        _record_search_history(current_user, q)
        db.session.commit()

    items = [
        _book_payload(book, recommend_reason=f'搜索“{q}”时命中了书名、作者、标签或简介关键词')
        for book in books
    ]
    recommended_items = []
    if not items:
        recommended_items = _build_search_recommendations(recommend_limit)

    return jsonify(
        {
            'query': q,
            'total': len(items),
            'items': items,
            'recommended_items': recommended_items,
        }
    ), 200


@bp.route('/home/continue-reading', methods=['GET'])
@login_optional
def api_get_continue_reading(current_user):
    return jsonify({'item': _get_continue_reading(current_user)}), 200


@bp.route('/books/featured', methods=['GET'])
def api_get_featured_book():
    book = (
        _visible_books_query()
        .order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.asc())
        .first()
    )
    if not book:
        return jsonify({'error': 'book not found'}), 404
    return jsonify(_book_payload(book, recommend_reason=book.home_recommendation_reason or '本周主推')), 200


@bp.route('/shelf', methods=['POST'])
@login_required
def api_add_to_shelf(current_user):
    data = request.get_json() or {}
    book_id = data.get('book_id')
    if not book_id:
        return jsonify({'error': 'missing book_id'}), 400
    try:
        book_id = int(book_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid book_id'}), 400

    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return jsonify({'error': 'book not found'}), 404

    existing = UserShelf.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if not existing:
        try:
            db.session.add(UserShelf(user_id=current_user.id, book_id=book_id))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'failed to add shelf item'}), 400
    return jsonify(_message('added to shelf', book_id=book_id)), 200


@bp.route('/books/<int:book_id>/preview', methods=['GET'])
def api_get_book_preview(book_id: int):
    sections = (
        ReaderSection.query.filter_by(book_id=book_id)
        .order_by(ReaderSection.order_no.asc())
        .limit(6)
        .all()
    )
    return jsonify(
        {
            'preview_url': f'/reader/{book_id}',
            'chapters': [{'id': item.id, 'title': item.title} for item in sections],
        }
    ), 200


@bp.route('/moods', methods=['GET'])
def api_get_moods():
    return jsonify(
        {
            'items': [
                {'id': 'healing', 'label': '治愈一下', 'icon': 'hugeicons:cloud-01'},
                {'id': 'brainstorm', 'label': '脑洞打开', 'icon': 'hugeicons:flash'},
                {'id': 'focus', 'label': '专注投入', 'icon': 'hugeicons:target-02'},
            ]
        }
    ), 200


@bp.route('/recommendations/by-mood', methods=['GET'])
def api_get_recommendations_by_mood():
    mood_id = request.args.get('mood_id', 'healing')
    books = (
        _visible_books_query()
        .order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.asc())
        .limit(4)
        .all()
    )
    return jsonify(
        {
            'mood_id': mood_id,
            'books': [
                _book_payload(book, recommend_reason='按当下阅读情绪为你挑选')
                for book in books
            ],
        }
    ), 200


@bp.route('/recommendations/personalized', methods=['GET'])
@login_optional
def api_get_personalized_recommendations(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', 8)), 30))
    except ValueError:
        limit = 8

    context = _build_recommendation_context(current_user)
    continue_item = _get_continue_reading(current_user)

    query = _visible_books_query()
    if continue_item:
        query = query.filter(Book.id != continue_item['id'])

    books = (
        query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    items = [_book_payload(book, recommend_reason=_build_recommend_reason(book, current_user, context)) for book in books]
    return jsonify({'items': items}), 200


@bp.route('/shelf/toggle', methods=['POST'])
@login_required
def api_toggle_shelf(current_user):
    data = request.get_json() or {}
    book_id = data.get('book_id')
    in_shelf = data.get('in_shelf')
    if book_id is None or in_shelf is None:
        return jsonify({'error': 'missing book_id or in_shelf'}), 400
    if not isinstance(in_shelf, bool):
        return jsonify({'error': 'in_shelf must be boolean'}), 400
    try:
        book_id = int(book_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid book_id'}), 400
    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return jsonify({'error': 'book not found'}), 404

    existing = UserShelf.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if in_shelf and not existing:
        try:
            db.session.add(UserShelf(user_id=current_user.id, book_id=book_id))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'failed to add shelf item'}), 400
    if (not in_shelf) and existing:
        try:
            db.session.delete(existing)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'failed to remove shelf item'}), 400

    action = 'added' if in_shelf else 'removed'
    return jsonify(_message(f'shelf {action}', book_id=book_id, in_shelf=in_shelf)), 200


@bp.route('/recommendations/feedback', methods=['POST'])
@login_required
def api_recommendation_feedback(current_user):
    data = request.get_json() or {}
    book_id = data.get('book_id')
    action = data.get('action')
    if not book_id or not action:
        return jsonify({'error': 'missing book_id or action'}), 400
    return jsonify(_message('feedback saved', book_id=book_id, action=action)), 200


@bp.route('/books/rankings', methods=['GET'])
def api_get_book_rankings():
    rank_type = _normalize_ranking_type(request.args.get('type', 'hot'))
    if not rank_type:
        return jsonify({'error': 'invalid type', 'available_types': _ranking_type_options()}), 400
    try:
        limit = max(1, min(int(request.args.get('limit', '10')), 50))
    except ValueError:
        limit = 10

    books, categories, shelf_counts, reading_users, recent_progress, recent_events = _collect_ranking_stats()

    ranked_items = []
    for book in books:
        context = _build_book_ranking_context(
            book,
            shelf_counts=shelf_counts,
            reading_users=reading_users,
            recent_progress=recent_progress,
            recent_events=recent_events,
        )
        ranking = _score_book_for_ranking(book, rank_type, context)
        if not ranking:
            continue
        ranked_items.append({'book': book, 'context': context, **ranking})

    ranked_items = sorted(ranked_items, key=lambda item: _ranking_sort_key(item, rank_type))[:limit]
    items = [
        _build_ranking_payload(
            item['book'],
            categories.get(item['book'].category_id),
            rank_type,
            idx,
            item,
            item['context'],
        )
        for idx, item in enumerate(ranked_items, start=1)
    ]

    return jsonify(
        {
            'type': rank_type,
            'meta': {
                'key': rank_type,
                **RANKING_TYPE_CONFIG[rank_type],
                'period_hint': '日榜/周榜/月榜后续开放',
            },
            'available_types': _ranking_type_options(),
            'snapshot_date': date.today().isoformat(),
            'items': items,
        }
    ), 200


@bp.route('/user/weekly-reading-task', methods=['GET'])
@login_required
def api_get_weekly_reading_task(current_user):
    return jsonify(
        {
            'target_books': 5,
            'finished_books': 3,
            'progress_percent': 60,
            'reward_desc': '完成后可领取春季限定书签。',
        }
    ), 200


@bp.route('/user/weekly-reading-task/progress', methods=['POST'])
@login_required
def api_update_weekly_reading_progress(current_user):
    data = request.get_json() or {}
    finished_books = data.get('finished_books')
    if finished_books is None:
        return jsonify({'error': 'missing finished_books'}), 400

    target = 5
    progress_percent = max(0, min(100, int(finished_books / target * 100))) if target else 0
    return jsonify(
        {
            'target_books': target,
            'finished_books': finished_books,
            'progress_percent': progress_percent,
            'reward_desc': '完成后可领取春季限定书签。',
        }
    ), 200


@bp.route('/categories/highlighted', methods=['GET'])
def api_get_highlighted_categories():
    categories = (
        Category.query.order_by(Category.is_highlighted.desc(), Category.id.asc())
        .limit(12)
        .all()
    )
    return jsonify({'items': [item.to_dict() for item in categories]}), 200


@bp.route('/categories', methods=['GET'])
def api_get_categories():
    rows = (
        db.session.query(Category, func.count(Book.id).label('book_count'))
        .outerjoin(Book, db.and_(Book.category_id == Category.id, Book.status == 'published', Book.shelf_status == 'up'))
        .group_by(Category.id)
        .order_by(Category.is_highlighted.desc(), Category.name.asc(), Category.id.asc())
        .all()
    )

    items = []
    for category, book_count in rows:
        payload = category.to_dict()
        payload['book_count'] = int(book_count or 0)
        items.append(payload)
    return jsonify({'items': items}), 200


@bp.route('/tags/hot', methods=['GET'])
def api_get_hot_tags():
    rows = (
        db.session.query(Tag, func.count(BookTag.id).label('book_count'))
        .outerjoin(BookTag, BookTag.tag_id == Tag.id)
        .group_by(Tag.id)
        .order_by(func.count(BookTag.id).desc(), Tag.id.asc())
        .limit(20)
        .all()
    )
    items = []
    for tag, book_count in rows:
        payload = tag.to_dict()
        payload['book_count'] = int(book_count or 0)
        items.append(payload)
    return jsonify({'items': items}), 200


@bp.route('/books/by-category', methods=['GET'])
def api_get_books_by_category_or_tag():
    category_id = request.args.get('category_id')
    tag_id = request.args.get('tag_id')
    if not category_id and not tag_id:
        return jsonify({'error': 'missing category_id or tag_id'}), 400

    query = _visible_books_query()
    category = None
    tag = None

    if category_id:
        try:
            category_id = int(category_id)
        except ValueError:
            return jsonify({'error': 'invalid category_id'}), 400
        query = query.filter(Book.category_id == category_id)
        category = Category.query.get(category_id)

    if tag_id:
        try:
            tag_id = int(tag_id)
        except ValueError:
            return jsonify({'error': 'invalid tag_id'}), 400
        query = query.join(BookTag, BookTag.book_id == Book.id).filter(BookTag.tag_id == tag_id)
        tag = Tag.query.get(tag_id)

    books = (
        query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(30)
        .all()
    )
    reason = None
    if category:
        reason = f'因为你正在浏览“{category.name}”分类'
    elif tag:
        reason = f'因为你点开了“{tag.label}”标签'

    return jsonify(
        {
            'category_id': category_id,
            'tag_id': tag_id,
            'items': [_book_payload(book, recommend_reason=reason) for book in books],
        }
    ), 200


@bp.route('/recommendations/more', methods=['GET'])
def api_get_more_recommendations():
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except ValueError:
        page = 1
    try:
        page_size = min(max(int(request.args.get('page_size', 12)), 1), 30)
    except ValueError:
        page_size = 12

    category_id = request.args.get('category_id')
    tag_id = request.args.get('tag_id')
    completion_status = request.args.get('completion_status')
    keyword = _normalize_search_keyword(request.args.get('keyword', ''), max_len=40)

    query = _visible_books_query()
    if category_id not in (None, ''):
        try:
            query = query.filter(Book.category_id == int(category_id))
        except ValueError:
            return jsonify({'error': 'invalid category_id'}), 400
    if tag_id not in (None, ''):
        try:
            query = query.join(BookTag, BookTag.book_id == Book.id).filter(BookTag.tag_id == int(tag_id))
        except ValueError:
            return jsonify({'error': 'invalid tag_id'}), 400
    if completion_status not in (None, ''):
        if completion_status not in VALID_COMPLETION_STATUSES:
            return jsonify({'error': 'invalid completion_status'}), 400
        query = query.filter(Book.completion_status == completion_status)
    if keyword:
        like = f'%{keyword}%'
        query = (
            query.outerjoin(Category, Category.id == Book.category_id)
            .filter(
                or_(
                    Book.title.ilike(like),
                    Book.subtitle.ilike(like),
                    Book.author.ilike(like),
                    Book.description.ilike(like),
                    Book.search_keywords.ilike(like),
                    Category.name.ilike(like),
                    Category.en_name.ilike(like),
                )
            )
            .distinct()
        )

    total = query.count()
    books = (
        query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return jsonify(
        {
            'items': [_book_payload(book) for book in books],
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total': total,
            },
        }
    ), 200


@bp.route('/reviews/highlighted', methods=['GET'])
def api_get_highlighted_reviews():
    return jsonify(
        {
            'items': [
                {
                    'id': 701,
                    'user': {
                        'id': 10,
                        'nickname': '木心追随者',
                        'avatar': 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&w=200&q=80',
                    },
                    'book': {'id': 1, 'title': '样章阅读：漫长的余生'},
                    'content': '这本书像在夜色里慢慢点灯，读着读着，人就安静下来了。',
                    'likes': 1200,
                    'comments': 82,
                    'created_at': '2026-03-15',
                }
            ]
        }
    ), 200


@bp.route('/reviews/<int:review_id>/like', methods=['POST'])
@login_required
def api_like_review(current_user, review_id: int):
    data = request.get_json() or {}
    like = data.get('like', True)
    return jsonify(_message('ok', review_id=review_id, like=like)), 200


@bp.route('/reviews/<int:review_id>/comments', methods=['POST'])
@login_required
def api_comment_on_review(current_user, review_id: int):
    data = request.get_json() or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error': 'content is required'}), 400

    return jsonify(
        {
            'message': 'comment created',
            'review_id': review_id,
            'comment': {'id': 1, 'user_id': current_user.id, 'content': content},
        }
    ), 201
