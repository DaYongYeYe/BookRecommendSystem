from datetime import date, datetime, timedelta

from flask import current_app, request, jsonify

from app import db
from app.models import (
    Book,
    BookAnalyticsEvent,
    ReaderBookmark,
    ReaderBookComment,
    ReaderHighlight,
    ReaderHighlightComment,
    ReaderUserPreference,
    User,
    UserAchievement,
    UserReadingProgress,
    UserShelf,
)
from app.rbac.decorators import login_required
from app.services.tencent_cos import upload_image
from app.logging_utils import business_log_aspect
from app.user import bp

ALLOWED_AVATAR_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}


def _display_names(user):
    names = {
        user.username or '',
        user.name or '',
        user.pen_name or '',
    }
    return {item.strip() for item in names if item and item.strip()}


def _start_of_week():
    today = date.today()
    return datetime.combine(today - timedelta(days=today.weekday()), datetime.min.time())


def _count_reading_streak(user_id: int) -> int:
    rows = (
        db.session.query(db.func.date(BookAnalyticsEvent.created_at))
        .filter(BookAnalyticsEvent.user_id == user_id)
        .group_by(db.func.date(BookAnalyticsEvent.created_at))
        .order_by(db.func.date(BookAnalyticsEvent.created_at).desc())
        .limit(60)
        .all()
    )
    day_values = []
    for row in rows:
        raw = row[0]
        if isinstance(raw, date):
            day_values.append(raw)
        elif raw:
            day_values.append(date.fromisoformat(str(raw)))

    if not day_values:
        progress = (
            UserReadingProgress.query.filter_by(user_id=user_id)
            .order_by(UserReadingProgress.updated_at.desc())
            .first()
        )
        if progress and progress.updated_at and progress.updated_at.date() == date.today():
            return 1
        return 0

    streak = 0
    cursor = date.today()
    day_set = set(day_values)
    if cursor not in day_set:
        cursor = cursor - timedelta(days=1)
    while cursor in day_set:
        streak += 1
        cursor = cursor - timedelta(days=1)
    return streak


def _sync_achievements(user, stats):
    definitions = [
        (
            'first_shelf',
            '第一次加入书架',
            '已经把第一本书放进自己的阅读清单。',
            stats['shelf_count'] >= 1,
        ),
        (
            'first_highlight',
            '第一次划线',
            '开始把有共鸣的句子沉淀成笔记。',
            stats['highlight_count'] >= 1,
        ),
        (
            'three_day_streak',
            '连续阅读 3 天',
            '保持了稳定的阅读节奏。',
            stats['reading_streak_days'] >= 3,
        ),
        (
            'chapter_finisher',
            '完成章节阅读',
            '至少读完过一个章节。',
            stats['completed_chapter_count'] >= 1,
        ),
        (
            'weekly_half_hour',
            '本周阅读 30 分钟',
            '本周已经有一段扎实的阅读时间。',
            stats['weekly_read_minutes'] >= 30,
        ),
    ]

    existing = {
        item.achievement_key: item
        for item in UserAchievement.query.filter_by(user_id=user.id).all()
    }
    for key, title, description, unlocked in definitions:
        if unlocked and key not in existing:
            db.session.add(
                UserAchievement(
                    user_id=user.id,
                    achievement_key=key,
                    title=title,
                    description=description,
                )
            )
    db.session.commit()

    refreshed = {
        item.achievement_key: item
        for item in UserAchievement.query.filter_by(user_id=user.id).all()
    }
    return [
        {
            'achievement_key': key,
            'title': title,
            'description': description,
            'unlocked': key in refreshed,
            'unlocked_at': refreshed[key].unlocked_at.isoformat() if key in refreshed and refreshed[key].unlocked_at else None,
        }
        for key, title, description, _unlocked in definitions
    ]


@bp.route('/profile', methods=['GET'])
@login_required
def get_profile(current_user):
    return jsonify({'user': current_user.to_self_dict(), 'meta': {}}), 200


@bp.route('/profile', methods=['PUT'])
@login_required
@business_log_aspect('user.profile_update', tags=['user', 'business', 'aop'])
def update_profile(current_user):
    data = request.get_json() or {}
    if not data:
        return jsonify({'error': '没有提供更新数据'}), 400

    if 'name' in data:
        current_user.name = (data.get('name') or '').strip() or None

    if 'pen_name' in data:
        pen_name = (data.get('pen_name') or '').strip()
        if pen_name and len(pen_name) > 80:
            return jsonify({'error': '笔名长度不能超过 80 个字符'}), 400
        current_user.pen_name = pen_name or None

    if 'avatar_url' in data:
        current_user.avatar_url = (data.get('avatar_url') or '').strip() or None

    if 'age' in data:
        raw_age = data.get('age')
        if raw_age in (None, ''):
            current_user.age = None
        else:
            try:
                parsed_age = int(raw_age)
            except (TypeError, ValueError):
                return jsonify({'error': '年龄必须是数字'}), 400
            if parsed_age < 1 or parsed_age > 120:
                return jsonify({'error': '年龄需在 1-120 之间'}), 400
            current_user.age = parsed_age

    if 'province' in data:
        current_user.province = (data.get('province') or '').strip() or None

    if 'city' in data:
        current_user.city = (data.get('city') or '').strip() or None

    if 'email' in data:
        email = (data.get('email') or '').strip()
        if not email:
            return jsonify({'error': '邮箱不能为空'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != current_user.id:
            return jsonify({'error': '邮箱已被其他用户使用'}), 400

        current_user.email = email

    db.session.commit()
    return jsonify({'message': '用户信息更新成功', 'user': current_user.to_self_dict(), 'meta': {}}), 200


@bp.route('/avatar/upload', methods=['POST'])
@login_required
@business_log_aspect('user.avatar_upload', tags=['user', 'business', 'avatar', 'aop'])
def upload_avatar(current_user):
    file_obj = request.files.get('avatar')
    max_size = int(current_app.config.get('MAX_AVATAR_UPLOAD_SIZE', 2 * 1024 * 1024))
    avatar_url, error = upload_image(
        file_obj,
        folder=f'avatars/{current_user.id}',
        allowed_extensions=ALLOWED_AVATAR_EXTENSIONS,
        max_size=max_size,
    )
    if error:
        status = 500 if error in ('cos not configured', 'invalid cos secret id', 'cos upload failed') else 400
        return jsonify({'error': error}), status

    current_user.avatar_url = avatar_url
    db.session.commit()
    return jsonify({'message': '头像上传成功', 'avatar_url': avatar_url, 'user': current_user.to_self_dict(), 'meta': {}}), 200


@bp.route('/change_password', methods=['POST'])
@login_required
@business_log_aspect('user.change_password', tags=['user', 'business', 'security', 'aop'])
def change_password(current_user):
    data = request.get_json() or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not old_password or not new_password:
        return jsonify({'error': '请提供旧密码和新密码'}), 400

    if not current_user.check_password(old_password):
        return jsonify({'error': '旧密码错误'}), 400

    current_user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': '密码修改成功'}), 200


@bp.route('/favorites', methods=['GET'])
@login_required
def get_favorites(current_user):
    records = (
        UserShelf.query.filter_by(user_id=current_user.id)
        .order_by(UserShelf.created_at.desc(), UserShelf.id.desc())
        .all()
    )
    book_ids = [record.book_id for record in records]
    books = (
        Book.query.filter(Book.id.in_(book_ids), Book.status == 'published', Book.shelf_status == 'up').all()
        if book_ids
        else []
    )
    books_map = {book.id: book for book in books}

    items = []
    for record in records:
        book = books_map.get(record.book_id)
        if not book:
            continue
        payload = book.to_dict()
        payload['favorited_at'] = record.created_at.isoformat() if record.created_at else None
        items.append(payload)

    return jsonify({'items': items}), 200


@bp.route('/history', methods=['GET'])
@login_required
def get_history(current_user):
    progress_items = (
        UserReadingProgress.query.filter_by(user_id=current_user.id)
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .all()
    )
    book_ids = [item.book_id for item in progress_items]
    books = (
        Book.query.filter(Book.id.in_(book_ids), Book.status == 'published', Book.shelf_status == 'up').all()
        if book_ids
        else []
    )
    books_map = {book.id: book for book in books}

    items = []
    for progress in progress_items:
        book = books_map.get(progress.book_id)
        if not book:
            continue
        payload = book.to_dict()
        payload['history'] = {
            'section_id': progress.section_id,
            'paragraph_id': progress.paragraph_id,
            'scroll_percent': float(progress.scroll_percent or 0),
            'updated_at': progress.updated_at.isoformat() if progress.updated_at else None,
        }
        items.append(payload)

    return jsonify({'items': items}), 200


@bp.route('/reading-stats', methods=['GET'])
@login_required
def get_reading_stats(current_user):
    week_start = _start_of_week()
    author_names = _display_names(current_user)

    weekly_seconds = (
        db.session.query(db.func.coalesce(db.func.sum(BookAnalyticsEvent.read_duration_seconds), 0))
        .filter(BookAnalyticsEvent.user_id == current_user.id, BookAnalyticsEvent.created_at >= week_start)
        .scalar()
        or 0
    )
    weekly_read_minutes = int(weekly_seconds // 60)
    weekly_reading_days = (
        db.session.query(db.func.count(db.func.distinct(db.func.date(BookAnalyticsEvent.created_at))))
        .filter(BookAnalyticsEvent.user_id == current_user.id, BookAnalyticsEvent.created_at >= week_start)
        .scalar()
        or 0
    )

    completed_chapter_count = (
        UserReadingProgress.query.filter(
            UserReadingProgress.user_id == current_user.id,
            UserReadingProgress.section_id.isnot(None),
            UserReadingProgress.scroll_percent >= 80,
        ).count()
    )
    shelf_count = UserShelf.query.filter_by(user_id=current_user.id).count()
    bookmark_count = ReaderBookmark.query.filter_by(user_id=current_user.id).count()
    highlight_count = ReaderHighlight.query.filter(ReaderHighlight.created_by.in_(author_names)).count()
    book_comment_count = ReaderBookComment.query.filter(ReaderBookComment.author.in_(author_names)).count()
    highlight_comment_count = ReaderHighlightComment.query.filter(ReaderHighlightComment.author.in_(author_names)).count()

    preference = ReaderUserPreference.query.filter_by(user_id=current_user.id).first()
    if not preference:
        preference = ReaderUserPreference(user_id=current_user.id)
        db.session.add(preference)
        db.session.commit()

    stats = {
        'weekly_read_minutes': weekly_read_minutes,
        'weekly_reading_days': int(weekly_reading_days or 0),
        'completed_chapter_count': int(completed_chapter_count or 0),
        'shelf_count': int(shelf_count or 0),
        'highlight_count': int(highlight_count or 0),
        'comment_count': int((book_comment_count or 0) + (highlight_comment_count or 0)),
        'bookmark_count': int(bookmark_count or 0),
        'reading_streak_days': _count_reading_streak(current_user.id),
    }
    achievements = _sync_achievements(current_user, stats)

    recent_books = []
    progress_items = (
        UserReadingProgress.query.filter_by(user_id=current_user.id)
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .limit(5)
        .all()
    )
    if progress_items:
        books = Book.query.filter(Book.id.in_([item.book_id for item in progress_items])).all()
        book_map = {book.id: book for book in books}
        for progress in progress_items:
            book = book_map.get(progress.book_id)
            if not book:
                continue
            recent_books.append(
                {
                    'id': book.id,
                    'title': book.title,
                    'author': book.author,
                    'cover': book.cover,
                    'section_id': progress.section_id,
                    'scroll_percent': float(progress.scroll_percent or 0),
                    'updated_at': progress.updated_at.isoformat() if progress.updated_at else None,
                }
            )

    return jsonify(
        {
            'stats': stats,
            'preferences': preference.to_dict(),
            'achievements': achievements,
            'recent_books': recent_books,
            'week_start': week_start.date().isoformat(),
        }
    ), 200
