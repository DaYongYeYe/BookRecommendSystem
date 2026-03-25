from datetime import date

from flask import jsonify, request
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from app import db
from app.api import bp
from app.models import (
    UserShelf,
    Book,
    Category,
    Tag,
    BookTag,
    BookRanking,
)
from app.rbac.decorators import login_required


def _message(text: str, **extra):
    payload = {'message': text}
    payload.update(extra)
    return payload


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
    return jsonify(
        {
            'query': q,
            'items': [
                {
                    'id': 1,
                    'title': '阅读样章：漫长的余生',
                    'author': '罗新',
                    'cover': 'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',
                    'rating': 9.1,
                }
            ],
        }
    ), 200


@bp.route('/books/featured', methods=['GET'])
def api_get_featured_book():
    return jsonify(
        {
            'id': 1,
            'title': '阅读样章：漫长的余生',
            'subtitle': '在命运的褶皱里寻找互相照亮的时刻',
            'author': '罗新',
            'description': '一部带有纪实质感的文学样章，适合展示阅读器的交互体验。',
            'cover': 'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',
            'score': 9.4,
            'recent_reads': 128000,
        }
    ), 200


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
    return jsonify(
        {
            'preview_url': f'/reader/{book_id}',
            'chapters': [
                {'id': 1, 'title': '第一章 抵达旧港'},
                {'id': 2, 'title': '第二章 雨夜抄录'},
            ],
        }
    ), 200


@bp.route('/moods', methods=['GET'])
def api_get_moods():
    return jsonify(
        {
            'items': [
                {'id': 'healing', 'label': '寻求治愈', 'icon': 'hugeicons:cloud-01'},
                {'id': 'brainstorm', 'label': '脑力风暴', 'icon': 'hugeicons:flash'},
                {'id': 'focus', 'label': '深度专注', 'icon': 'hugeicons:target-02'},
            ]
        }
    ), 200


@bp.route('/recommendations/by-mood', methods=['GET'])
def api_get_recommendations_by_mood():
    mood_id = request.args.get('mood_id', 'healing')
    return jsonify(
        {
            'mood_id': mood_id,
            'books': [
                {
                    'id': 1,
                    'title': '阅读样章：漫长的余生',
                    'author': '罗新',
                    'cover': 'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',
                    'rating': 8.9,
                }
            ],
        }
    ), 200


@bp.route('/recommendations/personalized', methods=['GET'])
@login_required
def api_get_personalized_recommendations(current_user):
    try:
        limit = max(1, min(int(request.args.get('limit', 8)), 30))
    except ValueError:
        limit = 8

    books = (
        Book.query.filter_by(status='published')
        .order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    return jsonify({'items': [book.to_dict() for book in books]}), 200


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
            payload = book.to_dict()
            payload['rank'] = int(ranking.rank_no)
            items.append(payload)
        return jsonify({'type': rank_type, 'snapshot_date': latest_snapshot.isoformat(), 'items': items}), 200

    # Fallback when no ranking snapshots are configured.
    books = (
        Book.query.filter_by(status='published')
        .order_by(Book.rating.desc(), Book.rating_count.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    items = []
    for idx, book in enumerate(books, start=1):
        payload = book.to_dict()
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

    if category_id:
        try:
            category_id = int(category_id)
        except ValueError:
            return jsonify({'error': 'invalid category_id'}), 400
        query = query.filter(Book.category_id == category_id)

    if tag_id:
        try:
            tag_id = int(tag_id)
        except ValueError:
            return jsonify({'error': 'invalid tag_id'}), 400
        query = query.join(BookTag, BookTag.book_id == Book.id).filter(BookTag.tag_id == tag_id)

    books = (
        query.order_by(Book.is_featured.desc(), Book.rating.desc(), Book.recent_reads.desc(), Book.id.desc())
        .limit(30)
        .all()
    )
    return jsonify(
        {
            'category_id': category_id,
            'tag_id': tag_id,
            'items': [book.to_dict() for book in books],
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
            'items': [book.to_dict() for book in books],
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
                    'book': {'id': 1, 'title': '阅读样章：漫长的余生'},
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
