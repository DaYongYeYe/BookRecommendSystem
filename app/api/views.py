from datetime import date

from flask import jsonify, request
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app import db
from app.api import bp
from app.models import (
    Book,
    BookRanking,
    BookTag,
    Category,
    ReaderSection,
    Tag,
    UserReadingProgress,
    UserShelf,
)
from app.rbac.decorators import login_optional, login_required


def _message(text: str, **extra):
    payload = {'message': text}
    payload.update(extra)
    return payload


def _book_payload(book: Book, *, recommend_reason: str | None = None, extra: dict | None = None):
    payload = book.to_dict()
    payload['recommend_reason'] = recommend_reason or book.home_recommendation_reason or '高分口碑推荐'
    if extra:
        payload.update(extra)
    return payload


def _get_continue_reading(current_user):
    if not current_user:
        return None

    row = (
        db.session.query(UserReadingProgress, Book)
        .join(Book, Book.id == UserReadingProgress.book_id)
        .filter(
            UserReadingProgress.user_id == current_user.id,
            Book.status == 'published',
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


def _books_search_query(q: str):
    like = f'%{q}%'
    return Book.query.filter(
        Book.status == 'published',
        or_(
            Book.title.ilike(like),
            Book.subtitle.ilike(like),
            Book.author.ilike(like),
            Book.description.ilike(like),
            Book.search_keywords.ilike(like),
        ),
    )


@bp.route('/user/profile', methods=['GET'])
@login_required
def api_get_user_profile(current_user):
    user_data = current_user.to_dict()
    user_data['book_age_days'] = 1240
    return jsonify(user_data), 200


@bp.route('/notifications/unread-count', methods=['GET'])
@login_required
def api_get_unread_notifications_count(current_user):
    return jsonify({'unread_count': 3}), 200


@bp.route('/books/search', methods=['GET'])
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


@bp.route('/home/continue-reading', methods=['GET'])
@login_optional
def api_get_continue_reading(current_user):
    return jsonify({'item': _get_continue_reading(current_user)}), 200


@bp.route('/books/featured', methods=['GET'])
def api_get_featured_book():
    book = (
        Book.query.filter_by(status='published')
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
    if not book or (book.status or 'published') != 'published':
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
        Book.query.filter_by(status='published')
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

    query = Book.query.filter_by(status='published')
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
    if not book or (book.status or 'published') != 'published':
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
    rank_type = request.args.get('type', 'high_score')
    try:
        limit = int(request.args.get('limit', '10'))
    except ValueError:
        limit = 10

    latest_snapshot = (
        db.session.query(func.max(BookRanking.snapshot_date))
        .filter(BookRanking.type == rank_type)
        .scalar()
    )

    if latest_snapshot:
        rows = (
            db.session.query(BookRanking, Book)
            .join(Book, Book.id == BookRanking.book_id)
            .filter(
                BookRanking.type == rank_type,
                BookRanking.snapshot_date == latest_snapshot,
                Book.status == 'published',
            )
            .order_by(BookRanking.rank_no.asc())
            .limit(limit)
            .all()
        )
        items = []
        for ranking, book in rows:
            payload = _book_payload(book, recommend_reason='口碑榜稳定上榜')
            payload['rank'] = int(ranking.rank_no)
            items.append(payload)
        return jsonify({'type': rank_type, 'snapshot_date': latest_snapshot.isoformat(), 'items': items}), 200

    books = (
        Book.query.filter_by(status='published')
        .order_by(Book.rating.desc(), Book.rating_count.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    items = []
    for idx, book in enumerate(books, start=1):
        payload = _book_payload(book, recommend_reason='口碑榜高分推荐')
        payload['rank'] = idx
        items.append(payload)
    return jsonify({'type': rank_type, 'snapshot_date': date.today().isoformat(), 'items': items}), 200


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

    query = Book.query.filter_by(status='published')
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

    query = Book.query.filter_by(status='published')
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
