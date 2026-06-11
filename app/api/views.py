from datetime import date, datetime, timedelta

from flask import jsonify, request
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app import db
from app.api import bp
from app.models import (
    Book,
    BookAnalyticsEvent,
    BookList,
    BookListItem,
    BookRanking,
    BookReview,
    BookReviewReaction,
    BookTag,
    Category,
    ReaderSection,
    RecommendationFeedback,
    RecommendationPlacement,
    Tag,
    User,
    UserInterestTag,
    UserReadingProgress,
    UserSearchHistory,
    UserShelf,
)
from app.rbac.decorators import login_optional, login_required
from app.services.recommendation.online import get_two_tower_recommendations

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
VALID_RECOMMENDATION_ACTIONS = {'hide', 'more_like_this', 'read_later', 'add_to_shelf'}
VALID_COMMUNITY_VISIBILITIES = {'public', 'private'}
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


def _normalize_ranking_period(value: str | None):
    period = (value or 'week').strip().lower()
    aliases = {
        'day': 'day',
        'daily': 'day',
        'week': 'week',
        'weekly': 'week',
        'month': 'month',
        'monthly': 'month',
    }
    return aliases.get(period)


def _ranking_period_options():
    return [
        {'key': 'day', 'label': '日榜', 'days': 1},
        {'key': 'week', 'label': '周榜', 'days': 7},
        {'key': 'month', 'label': '月榜', 'days': 30},
    ]


def _ranking_period_days(period: str):
    if period == 'day':
        return 1
    if period == 'month':
        return 30
    return 7


def _collect_ranking_stats(*, window_days: int = RANKING_WINDOW_DAYS, category_id: int | None = None):
    window_start = datetime.utcnow() - timedelta(days=max(1, int(window_days or RANKING_WINDOW_DAYS)))
    book_query = _visible_books_query()
    if category_id:
        book_query = book_query.filter(Book.category_id == category_id)
    books = book_query.all()
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


def _feedback_state_for_user(current_user):
    if not current_user:
        return {}

    rows = (
        RecommendationFeedback.query.filter_by(user_id=current_user.id)
        .order_by(RecommendationFeedback.created_at.desc(), RecommendationFeedback.id.desc())
        .all()
    )
    states = {}
    for row in rows:
        states.setdefault(row.book_id, row.action)
    return states


def _shelf_ids_for_user(current_user):
    if not current_user:
        return set()
    return {int(row.book_id) for row in UserShelf.query.filter_by(user_id=current_user.id).all()}


def _category_name_map():
    return {item.id: item.name for item in Category.query.all()}


def _feed_item(book: Book, *, reason: str, reason_type: str, source_section: str, current_user=None, category_names=None, shelf_ids=None, feedback_states=None, extra=None):
    category_names = category_names or {}
    shelf_ids = shelf_ids or set()
    feedback_states = feedback_states or {}
    payload = _book_payload(book, recommend_reason=reason)
    payload.update(
        {
            'reason': reason,
            'reason_type': reason_type,
            'source_section': source_section,
            'category_name': category_names.get(book.category_id),
            'in_shelf': book.id in shelf_ids,
            'feedback_state': feedback_states.get(book.id),
            'metrics': {
                'rating': float(book.rating or book.score or 0),
                'rating_count': int(book.rating_count or 0),
                'recent_reads': int(book.recent_reads or 0),
                'word_count': int(book.word_count or 0),
                'completion_status': book.completion_status or 'ongoing',
            },
        }
    )
    if extra:
        payload.update(extra)
    return payload


def _choose_books(query, *, limit: int, hidden_ids: set[int], used_ids: set[int], boost_ids: set[int] | None = None):
    books = query.limit(max(limit * 4, limit)).all()
    boost_ids = boost_ids or set()
    boosted = []
    regular = []
    for book in books:
        if book.id in hidden_ids or book.id in used_ids:
            continue
        if book.id in boost_ids:
            boosted.append(book)
        else:
            regular.append(book)
    picked = boosted + regular
    result = picked[:limit]
    used_ids.update(book.id for book in result)
    return result


def _two_tower_books(current_user, *, limit: int, hidden_ids: set[int], used_ids: set[int]):
    candidates = get_two_tower_recommendations(
        current_user.id if current_user else None,
        limit=limit,
        hidden_ids=hidden_ids,
        used_ids=used_ids,
        exclude_shelf=False,
    )
    if not candidates:
        return [], {}

    book_ids = [item.book_id for item in candidates]
    books = Book.query.filter(Book.id.in_(book_ids)).all()
    book_map = {int(book.id): book for book in books}
    ordered_books = []
    meta = {}
    for item in candidates:
        book = book_map.get(int(item.book_id))
        if not book:
            continue
        ordered_books.append(book)
        meta[int(book.id)] = {
            'reason_type': 'two_tower',
            'model_version': item.model_version,
            'recall_score': round(float(item.score), 6),
        }
    used_ids.update(int(book.id) for book in ordered_books)
    return ordered_books, meta


def _build_recommendation_feed(current_user, limit_per_section: int = 6):
    context = _build_recommendation_context(current_user)
    feedback_states = _feedback_state_for_user(current_user)
    hidden_ids = {book_id for book_id, action in feedback_states.items() if action == 'hide'}
    boost_ids = {book_id for book_id, action in feedback_states.items() if action == 'more_like_this'}
    shelf_ids = _shelf_ids_for_user(current_user)
    category_names = _category_name_map()
    used_ids = set()

    continue_item = _get_continue_reading(current_user)
    if continue_item:
        used_ids.add(continue_item['id'])
        continue_item.update(
            {
                'reason': '继续上次的阅读进度',
                'reason_type': 'continue_reading',
                'source_section': 'continue_reading',
                'category_name': category_names.get(continue_item.get('category_id')),
                'in_shelf': continue_item['id'] in shelf_ids,
                'feedback_state': feedback_states.get(continue_item['id']),
                'metrics': {
                    'rating': float(continue_item.get('rating') or continue_item.get('score') or 0),
                    'recent_reads': int(continue_item.get('recent_reads') or 0),
                    'completion_status': continue_item.get('completion_status') or 'ongoing',
                },
            }
        )

    base_query = _visible_books_query()
    picked_books, picked_meta = _two_tower_books(
        current_user,
        limit=limit_per_section,
        hidden_ids=hidden_ids,
        used_ids=used_ids,
    )
    if len(picked_books) < limit_per_section:
        picked_books.extend(
            _choose_books(
                base_query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc()),
                limit=limit_per_section - len(picked_books),
                hidden_ids=hidden_ids,
                used_ids=used_ids,
                boost_ids=boost_ids,
            )
        )

    popular_books = _choose_books(
        base_query.order_by(Book.recent_reads.desc(), Book.rating.desc(), Book.id.desc()),
        limit=limit_per_section,
        hidden_ids=hidden_ids,
        used_ids=used_ids,
    )

    same_category_books = []
    preferred_category_id = context.get('preferred_category_id')
    if preferred_category_id:
        same_category_books = _choose_books(
            base_query.filter(Book.category_id == preferred_category_id).order_by(Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc()),
            limit=limit_per_section,
            hidden_ids=hidden_ids,
            used_ids=used_ids,
            boost_ids=boost_ids,
        )
    if not same_category_books:
        same_category_books = _choose_books(
            base_query.order_by(Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc()),
            limit=limit_per_section,
            hidden_ids=hidden_ids,
            used_ids=used_ids,
        )

    new_books = _choose_books(
        base_query.order_by(Book.published_at.desc(), Book.recent_reads.desc(), Book.id.desc()),
        limit=limit_per_section,
        hidden_ids=hidden_ids,
        used_ids=used_ids,
    )
    completed_books = _choose_books(
        base_query.filter(Book.completion_status == 'completed').order_by(Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc()),
        limit=limit_per_section,
        hidden_ids=hidden_ids,
        used_ids=used_ids,
    )

    def items(books, source, reason_type, fallback_reason):
        return [
            _feed_item(
                book,
                reason=_build_recommend_reason(book, current_user, context) if source == 'picked_for_you' else fallback_reason,
                reason_type=picked_meta.get(int(book.id), {}).get('reason_type', reason_type) if source == 'picked_for_you' else reason_type,
                source_section=source,
                current_user=current_user,
                category_names=category_names,
                shelf_ids=shelf_ids,
                feedback_states=feedback_states,
                extra=picked_meta.get(int(book.id)) if source == 'picked_for_you' else None,
            )
            for book in books
        ]

    sections = [
        {
            'key': 'continue_reading',
            'title': '继续阅读',
            'description': '把上次停下的位置接回来。',
            'items': [continue_item] if continue_item else [],
        },
        {
            'key': 'picked_for_you',
            'title': '今日推荐',
            'description': '结合你的书架、阅读进度和近期偏好。',
            'items': items(picked_books, 'picked_for_you', 'personalized', '为你挑出的高分好书'),
        },
        {
            'key': 'popular_now',
            'title': '大家都在读',
            'description': '近期热度更高，适合快速判断是否跟读。',
            'items': items(popular_books, 'popular_now', 'popular', '最近很多人在读'),
        },
        {
            'key': 'same_category',
            'title': '延续你的口味',
            'description': '从最近阅读题材和书架标签继续扩展。',
            'items': items(same_category_books, 'same_category', 'same_category', '与你最近关注的题材接近'),
        },
        {
            'key': 'new_or_surging',
            'title': '新书与上升作品',
            'description': '近期上架或热度开始起势的作品。',
            'items': items(new_books, 'new_or_surging', 'surging', '近期热度起势快'),
        },
        {
            'key': 'completed_good_reads',
            'title': '完结好书',
            'description': '可以放心一口气读完的高口碑作品。',
            'items': items(completed_books, 'completed_good_reads', 'completed', '已完结，适合完整阅读'),
        },
    ]
    return {'sections': sections}


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


def _user_display_payload(user_id: int | None):
    user = User.query.get(user_id) if user_id else None
    if not user:
        return {'id': user_id, 'nickname': '读者', 'avatar': None}
    return {
        'id': user.id,
        'nickname': user.name or user.pen_name or user.username,
        'avatar': user.avatar_url,
    }


def _book_card_payload(book: Book | None):
    if not book:
        return None
    return {
        'id': book.id,
        'title': book.title,
        'author': book.author,
        'cover': book.cover,
        'rating': float(book.rating or book.score or 0),
        'category_id': book.category_id,
    }


def _community_booklist_payload(book_list: BookList):
    rows = (
        db.session.query(BookListItem, Book)
        .join(Book, Book.id == BookListItem.book_id)
        .filter(BookListItem.list_id == book_list.id)
        .order_by(BookListItem.sort_order.asc(), BookListItem.id.asc())
        .all()
    )
    books = []
    for item, book in rows:
        payload = _book_card_payload(book) or {}
        payload.update({'note': item.note, 'sort_order': int(item.sort_order or 0)})
        books.append(payload)

    payload = book_list.to_dict()
    payload.update(
        {
            'user': _user_display_payload(book_list.user_id),
            'book_count': len(books),
            'books': books,
            'cover': book_list.cover or (books[0].get('cover') if books else None),
        }
    )
    return payload


def _community_review_payload(review: BookReview, current_user=None):
    book = Book.query.get(review.book_id)
    payload = review.to_dict()
    payload.update(
        {
            'user': _user_display_payload(review.user_id),
            'book': _book_card_payload(book),
            'liked_by_me': bool(
                current_user
                and BookReviewReaction.query.filter_by(
                    review_id=review.id,
                    user_id=current_user.id,
                    reaction='like',
                ).first()
            ),
        }
    )
    return payload


def _parse_positive_int(value, field_name: str):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, jsonify({'error': f'invalid {field_name}'}), 400
    if parsed <= 0:
        return None, jsonify({'error': f'invalid {field_name}'}), 400
    return parsed, None, None


def _visible_book_by_id(book_id: int):
    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return None
    return book


def _bump_interest_score(score_map: dict, tag_id: int, points: int, source: str):
    entry = score_map.setdefault(int(tag_id), {'weight': 0, 'sources': set()})
    entry['weight'] += int(points)
    if source:
        entry['sources'].add(source)


def _book_tag_ids_for_books(book_ids: list[int] | set[int]):
    if not book_ids:
        return []
    return [
        int(tag_id)
        for tag_id, in db.session.query(BookTag.tag_id)
        .filter(BookTag.book_id.in_(list(book_ids)))
        .all()
    ]


def _fallback_interest_tags(limit: int):
    rows = (
        db.session.query(Tag, func.count(BookTag.id).label('book_count'))
        .outerjoin(BookTag, BookTag.tag_id == Tag.id)
        .group_by(Tag.id)
        .order_by(func.count(BookTag.id).desc(), Tag.id.asc())
        .limit(limit)
        .all()
    )
    return [
        {
            **tag.to_dict(),
            'weight': int(book_count or 0),
            'source_summary': '热门标签',
        }
        for tag, book_count in rows
    ]


def _build_user_interest_tags(current_user, limit: int = 10):
    if not current_user:
        return _fallback_interest_tags(limit)

    scores: dict[int, dict] = {}

    shelf_book_ids = [row.book_id for row in UserShelf.query.filter_by(user_id=current_user.id).all()]
    for tag_id in _book_tag_ids_for_books(shelf_book_ids):
        _bump_interest_score(scores, tag_id, 5, '书架收藏')

    progress_book_ids = [
        row.book_id
        for row in UserReadingProgress.query.filter_by(user_id=current_user.id)
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .limit(20)
        .all()
    ]
    for tag_id in _book_tag_ids_for_books(progress_book_ids):
        _bump_interest_score(scores, tag_id, 4, '阅读历史')

    feedback_rows = (
        RecommendationFeedback.query.filter_by(user_id=current_user.id)
        .order_by(RecommendationFeedback.created_at.desc(), RecommendationFeedback.id.desc())
        .limit(40)
        .all()
    )
    for row in feedback_rows:
        tag_ids = _book_tag_ids_for_books([row.book_id])
        if row.action == 'hide':
            for tag_id in tag_ids:
                _bump_interest_score(scores, tag_id, -3, '已减少推荐')
            continue
        if row.action in {'more_like_this', 'add_to_shelf', 'read_later'}:
            points = 6 if row.action == 'more_like_this' else 4
            for tag_id in tag_ids:
                _bump_interest_score(scores, tag_id, points, '推荐反馈')

    tags = Tag.query.all()
    search_rows = (
        UserSearchHistory.query.filter_by(user_id=current_user.id)
        .order_by(UserSearchHistory.last_searched_at.desc(), UserSearchHistory.id.desc())
        .limit(12)
        .all()
    )
    for row in search_rows:
        keyword = (row.keyword or '').lower()
        if not keyword:
            continue
        for tag in tags:
            label = (tag.label or '').lower()
            code = (tag.code or '').lower()
            if keyword in label or label in keyword or keyword in code or code in keyword:
                _bump_interest_score(scores, tag.id, min(10, max(1, int(row.search_count or 1)) * 2), '搜索历史')
        matched_books = _books_search_query(row.keyword).limit(5).all()
        for tag_id in _book_tag_ids_for_books([book.id for book in matched_books]):
            _bump_interest_score(scores, tag_id, 2, '搜索命中作品')

    ranked = [
        (tag_id, data)
        for tag_id, data in scores.items()
        if int(data.get('weight') or 0) > 0
    ]
    ranked.sort(key=lambda item: (-int(item[1]['weight']), item[0]))
    ranked = ranked[:limit]

    if not ranked:
        return _fallback_interest_tags(limit)

    tag_map = {tag.id: tag for tag in Tag.query.filter(Tag.id.in_([tag_id for tag_id, _ in ranked])).all()}
    UserInterestTag.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
    items = []
    for tag_id, data in ranked:
        tag = tag_map.get(tag_id)
        if not tag:
            continue
        source_summary = '、'.join(sorted(data['sources']))[:255]
        db.session.add(
            UserInterestTag(
                user_id=current_user.id,
                tag_id=tag_id,
                weight=int(data['weight']),
                source_summary=source_summary,
            )
        )
        items.append(
            {
                **tag.to_dict(),
                'weight': int(data['weight']),
                'source_summary': source_summary,
            }
        )
    return items


def _get_hot_search_term_items(limit: int = 8):
    items = []
    seen = set()

    def append_term(keyword: str, source: str):
        text = _normalize_search_keyword(keyword, max_len=20)
        if not text or text in seen:
            return
        seen.add(text)
        items.append(
            {
                'keyword': text,
                'source': source,
                'search_count': 0,
                'last_searched_at': None,
                'trend': 'steady',
                'matched_book_title': None,
            }
        )

    history_rows = (
        db.session.query(
            UserSearchHistory.keyword,
            func.coalesce(func.sum(UserSearchHistory.search_count), 0).label('search_count'),
            func.max(UserSearchHistory.last_searched_at).label('last_searched_at'),
        )
        .group_by(UserSearchHistory.keyword)
        .order_by(func.coalesce(func.sum(UserSearchHistory.search_count), 0).desc(), func.max(UserSearchHistory.last_searched_at).desc())
        .limit(limit * 2)
        .all()
    )
    for keyword, search_count, last_searched_at in history_rows:
        text = _normalize_search_keyword(keyword, max_len=20)
        if not text or text in seen:
            continue
        seen.add(text)
        matched_book = _books_search_query(text).order_by(Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc()).first()
        items.append(
            {
                'keyword': text,
                'source': 'search_history',
                'search_count': int(search_count or 0),
                'last_searched_at': last_searched_at.isoformat() if last_searched_at else None,
                'trend': 'rising' if int(search_count or 0) >= 3 else 'steady',
                'matched_book_title': matched_book.title if matched_book else None,
            }
        )

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
    feedback_states = _feedback_state_for_user(current_user)
    hidden_ids = {book_id for book_id, action in feedback_states.items() if action == 'hide'}
    used_ids = {continue_item['id']} if continue_item else set()

    query = _visible_books_query()
    if continue_item:
        query = query.filter(Book.id != continue_item['id'])

    books, meta = _two_tower_books(current_user, limit=limit, hidden_ids=hidden_ids, used_ids=used_ids)
    if len(books) < limit:
        books.extend(
            _choose_books(
                query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc()),
                limit=limit - len(books),
                hidden_ids=hidden_ids,
                used_ids=used_ids,
            )
        )
    items = [
        _book_payload(
            book,
            recommend_reason=_build_recommend_reason(book, current_user, context),
            extra=meta.get(int(book.id)),
        )
        for book in books
    ]
    return jsonify({'items': items}), 200


@bp.route('/recommendations/feed', methods=['GET'])
@login_optional
def api_get_recommendation_feed(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', 6)), 12))
    except ValueError:
        limit = 6
    return jsonify(_build_recommendation_feed(current_user, limit_per_section=limit)), 200


@bp.route('/recommendations/interest-tags', methods=['GET'])
@login_optional
def api_get_interest_tags(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', 10)), 20))
    except ValueError:
        limit = 10

    items = _build_user_interest_tags(current_user, limit=limit)
    if current_user:
        db.session.commit()
    return jsonify({'items': items, 'generated_from': 'user_behavior' if current_user else 'popular_tags'}), 200


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
    action = (data.get('action') or '').strip()
    source_section = (data.get('source_section') or '').strip()[:64] or None
    if not book_id or not action:
        return jsonify({'error': 'missing book_id or action'}), 400
    if action not in VALID_RECOMMENDATION_ACTIONS:
        return jsonify({'error': 'invalid action', 'available_actions': sorted(VALID_RECOMMENDATION_ACTIONS)}), 400
    try:
        book_id = int(book_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid book_id'}), 400

    book = Book.query.get(book_id)
    if not book or (book.status or 'published') != 'published' or (book.shelf_status or 'down') != 'up':
        return jsonify({'error': 'book not found'}), 404

    feedback = RecommendationFeedback(
        user_id=current_user.id,
        book_id=book_id,
        action=action,
        source_section=source_section,
    )
    db.session.add(feedback)

    if action == 'add_to_shelf':
        existing = UserShelf.query.filter_by(user_id=current_user.id, book_id=book_id).first()
        if not existing:
            db.session.add(UserShelf(user_id=current_user.id, book_id=book_id))

    db.session.commit()
    return jsonify(_message('feedback saved', feedback=feedback.to_dict())), 200


@bp.route('/books/rankings', methods=['GET'])
def api_get_book_rankings():
    rank_type = _normalize_ranking_type(request.args.get('type', 'hot'))
    if not rank_type:
        return jsonify({'error': 'invalid type', 'available_types': _ranking_type_options()}), 400
    period = _normalize_ranking_period(request.args.get('period', 'week'))
    if not period:
        return jsonify({'error': 'invalid period', 'available_periods': _ranking_period_options()}), 400
    try:
        limit = max(1, min(int(request.args.get('limit', '10')), 50))
    except ValueError:
        limit = 10
    category_id = None
    raw_category_id = request.args.get('category_id')
    if raw_category_id not in (None, ''):
        category_id, error_response, error_status = _parse_positive_int(raw_category_id, 'category_id')
        if error_response:
            return error_response, error_status
        if not Category.query.get(category_id):
            return jsonify({'error': 'category not found'}), 404

    snapshot_date = date.today()

    books, categories, shelf_counts, reading_users, recent_progress, recent_events = _collect_ranking_stats(
        window_days=_ranking_period_days(period),
        category_id=category_id,
    )
    book_map = {book.id: book for book in books}

    manual_rows = (
        BookRanking.query.filter_by(type=rank_type, snapshot_date=snapshot_date)
        .order_by(BookRanking.rank_no.asc(), BookRanking.id.asc())
        .limit(limit)
        .all()
    )
    if manual_rows:
        manual_items = []
        for row in manual_rows:
            book = book_map.get(row.book_id)
            if not book:
                continue
            context = _build_book_ranking_context(
                book,
                shelf_counts=shelf_counts,
                reading_users=reading_users,
                recent_progress=recent_progress,
                recent_events=recent_events,
            )
            ranking = _score_book_for_ranking(book, rank_type, context) or {
                'score': max(context['recent_reads'], context['reading_users'], context['shelf_count']),
                'heat_label': RANKING_TYPE_CONFIG[rank_type]['primary_metric'],
                'ranking_note': '后台手动配置榜单',
            }
            manual_items.append(_build_ranking_payload(book, categories.get(book.category_id), rank_type, row.rank_no, ranking, context))

        return jsonify(
            {
                'type': rank_type,
                'period': period,
                'category_id': category_id,
                'meta': {
                    'key': rank_type,
                    **RANKING_TYPE_CONFIG[rank_type],
                    'period_hint': '当前展示后台手动配置榜单',
                },
                'available_types': _ranking_type_options(),
                'available_periods': _ranking_period_options(),
                'snapshot_date': snapshot_date.isoformat(),
                'items': manual_items,
            }
        ), 200

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
            'period': period,
            'category_id': category_id,
            'meta': {
                'key': rank_type,
                **RANKING_TYPE_CONFIG[rank_type],
                'period_hint': '支持 day/week/month 与 category_id 筛选',
            },
            'available_types': _ranking_type_options(),
            'available_periods': _ranking_period_options(),
            'snapshot_date': date.today().isoformat(),
            'items': items,
        }
    ), 200


@bp.route('/recommendations/placements', methods=['GET'])
def api_get_recommendation_placements():
    scene = _normalize_search_keyword(request.args.get('scene', ''), max_len=64)
    query = RecommendationPlacement.query.filter_by(is_active=True)
    if scene:
        query = query.filter(RecommendationPlacement.scene == scene)
    items = query.order_by(RecommendationPlacement.sort_order.asc(), RecommendationPlacement.id.asc()).all()
    return jsonify({'items': [item.to_dict() for item in items]}), 200


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


@bp.route('/community/booklists', methods=['GET'])
@login_optional
def api_get_community_booklists(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', 12)), 30))
    except ValueError:
        limit = 12

    query = BookList.query
    if current_user:
        query = query.filter(or_(BookList.visibility == 'public', BookList.user_id == current_user.id))
    else:
        query = query.filter(BookList.visibility == 'public')

    q = _normalize_search_keyword(request.args.get('q', ''), max_len=40)
    if q:
        like = f'%{q}%'
        query = query.filter(or_(BookList.title.ilike(like), BookList.description.ilike(like)))

    rows = (
        query.order_by(BookList.likes_count.desc(), BookList.updated_at.desc(), BookList.id.desc())
        .limit(limit)
        .all()
    )
    return jsonify({'items': [_community_booklist_payload(item) for item in rows]}), 200


@bp.route('/community/booklists', methods=['POST'])
@login_required
def api_create_community_booklist(current_user):
    data = request.get_json() or {}
    title = _normalize_search_keyword(data.get('title', ''), max_len=120)
    description = _normalize_search_keyword(data.get('description', ''), max_len=500)
    visibility = (data.get('visibility') or 'public').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400
    if visibility not in VALID_COMMUNITY_VISIBILITIES:
        return jsonify({'error': 'invalid visibility'}), 400

    book_list = BookList(
        user_id=current_user.id,
        title=title,
        description=description or None,
        visibility=visibility,
    )
    db.session.add(book_list)
    db.session.commit()
    return jsonify({'message': 'booklist created', 'item': _community_booklist_payload(book_list)}), 201


@bp.route('/community/booklists/<int:list_id>/books', methods=['POST'])
@login_required
def api_add_book_to_community_booklist(current_user, list_id: int):
    data = request.get_json() or {}
    book_id, error_response, error_status = _parse_positive_int(data.get('book_id'), 'book_id')
    if error_response:
        return error_response, error_status
    note = _normalize_search_keyword(data.get('note', ''), max_len=255)

    book_list = BookList.query.get(list_id)
    if not book_list:
        return jsonify({'error': 'booklist not found'}), 404
    if book_list.user_id != current_user.id:
        return jsonify({'error': 'forbidden'}), 403
    book = _visible_book_by_id(book_id)
    if not book:
        return jsonify({'error': 'book not found'}), 404

    existing = BookListItem.query.filter_by(list_id=list_id, book_id=book_id).first()
    if existing:
        existing.note = note or existing.note
    else:
        max_order = db.session.query(func.coalesce(func.max(BookListItem.sort_order), 0)).filter_by(list_id=list_id).scalar() or 0
        db.session.add(
            BookListItem(
                list_id=list_id,
                book_id=book_id,
                note=note or None,
                sort_order=int(max_order) + 1,
            )
        )
    book_list.updated_at = db.func.now()
    db.session.commit()
    return jsonify({'message': 'book added', 'item': _community_booklist_payload(book_list)}), 200


@bp.route('/community/reviews', methods=['GET'])
@login_optional
def api_get_community_reviews(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', 12)), 30))
    except ValueError:
        limit = 12

    query = BookReview.query.filter(BookReview.visibility == 'public', BookReview.is_violation == False)  # noqa: E712
    book_id = request.args.get('book_id')
    if book_id not in (None, ''):
        parsed_book_id, error_response, error_status = _parse_positive_int(book_id, 'book_id')
        if error_response:
            return error_response, error_status
        query = query.filter(BookReview.book_id == parsed_book_id)

    rows = (
        query.order_by(BookReview.likes_count.desc(), BookReview.created_at.desc(), BookReview.id.desc())
        .limit(limit)
        .all()
    )
    return jsonify({'items': [_community_review_payload(item, current_user) for item in rows]}), 200


@bp.route('/community/reviews', methods=['POST'])
@login_required
def api_create_community_review(current_user):
    data = request.get_json() or {}
    book_id, error_response, error_status = _parse_positive_int(data.get('book_id'), 'book_id')
    if error_response:
        return error_response, error_status
    title = _normalize_search_keyword(data.get('title', ''), max_len=120)
    content = (data.get('content') or '').strip()
    visibility = (data.get('visibility') or 'public').strip()
    rating = data.get('rating')

    if not title:
        return jsonify({'error': 'title is required'}), 400
    if len(content) < 8:
        return jsonify({'error': 'content is too short'}), 400
    if visibility not in VALID_COMMUNITY_VISIBILITIES:
        return jsonify({'error': 'invalid visibility'}), 400
    if rating not in (None, ''):
        try:
            rating = max(1, min(int(rating), 5))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid rating'}), 400
    else:
        rating = None
    if not _visible_book_by_id(book_id):
        return jsonify({'error': 'book not found'}), 404

    review = BookReview(
        user_id=current_user.id,
        book_id=book_id,
        title=title,
        content=content[:2000],
        rating=rating,
        visibility=visibility,
    )
    db.session.add(review)
    db.session.commit()
    return jsonify({'message': 'review created', 'item': _community_review_payload(review, current_user)}), 201


@bp.route('/community/reviews/<int:review_id>/reaction', methods=['POST'])
@login_required
def api_react_community_review(current_user, review_id: int):
    data = request.get_json() or {}
    liked = data.get('liked', True)
    if not isinstance(liked, bool):
        return jsonify({'error': 'liked must be boolean'}), 400

    review = BookReview.query.get(review_id)
    if not review or review.visibility != 'public' or review.is_violation:
        return jsonify({'error': 'review not found'}), 404

    existing = BookReviewReaction.query.filter_by(review_id=review_id, user_id=current_user.id).first()
    if liked and not existing:
        db.session.add(BookReviewReaction(review_id=review_id, user_id=current_user.id, reaction='like'))
    if (not liked) and existing:
        db.session.delete(existing)

    db.session.flush()
    review.likes_count = (
        BookReviewReaction.query.filter_by(review_id=review_id, reaction='like').count()
    )
    db.session.commit()
    return jsonify({'message': 'reaction saved', 'item': _community_review_payload(review, current_user)}), 200


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
