from __future__ import annotations

from dataclasses import dataclass
from math import log1p

from sqlalchemy import func

from app import db
from app.models import (
    Book,
    BookAnalyticsEvent,
    BookTag,
    RecommendationFeedback,
    Tag,
    User,
    UserReadingProgress,
    UserSearchHistory,
    UserShelf,
)


POSITIVE_FEEDBACK = {'more_like_this', 'add_to_shelf', 'read_later'}


@dataclass(frozen=True)
class FeatureSpace:
    category_ids: list[int]
    tag_ids: list[int]

    @property
    def size(self) -> int:
        # category one-hot + tag weights + 5 dense behavior/book metrics
        return len(self.category_ids) + len(self.tag_ids) + 5


@dataclass(frozen=True)
class TrainingSample:
    user_id: int
    book_id: int
    label: float
    weight: float = 1.0


def build_feature_space() -> FeatureSpace:
    category_ids = [
        int(category_id)
        for category_id, in db.session.query(Book.category_id)
        .filter(Book.category_id.isnot(None))
        .distinct()
        .order_by(Book.category_id.asc())
        .all()
    ]
    tag_ids = [int(row.id) for row in Tag.query.order_by(Tag.id.asc()).all()]
    return FeatureSpace(category_ids=category_ids, tag_ids=tag_ids)


def visible_books_query():
    return Book.query.filter(Book.status == 'published', Book.shelf_status == 'up')


def _book_tag_map(book_ids: list[int] | None = None) -> dict[int, set[int]]:
    query = db.session.query(BookTag.book_id, BookTag.tag_id)
    if book_ids:
        query = query.filter(BookTag.book_id.in_(book_ids))
    result: dict[int, set[int]] = {}
    for book_id, tag_id in query.all():
        result.setdefault(int(book_id), set()).add(int(tag_id))
    return result


def _normalize(values: list[float]) -> list[float]:
    total = sum(abs(value) for value in values)
    if total <= 0:
        return values
    return [value / total for value in values]


def book_feature_vector(book: Book, space: FeatureSpace, tag_map: dict[int, set[int]] | None = None) -> list[float]:
    tags_by_book = tag_map or _book_tag_map([book.id])
    vector = [0.0] * space.size

    category_index = {category_id: idx for idx, category_id in enumerate(space.category_ids)}
    tag_index_offset = len(space.category_ids)
    tag_index = {tag_id: tag_index_offset + idx for idx, tag_id in enumerate(space.tag_ids)}

    if book.category_id in category_index:
        vector[category_index[int(book.category_id)]] = 1.0
    for tag_id in tags_by_book.get(int(book.id), set()):
        idx = tag_index.get(int(tag_id))
        if idx is not None:
            vector[idx] = 1.0

    dense_offset = len(space.category_ids) + len(space.tag_ids)
    vector[dense_offset] = min(float(book.rating or book.score or 0) / 10.0, 1.0)
    vector[dense_offset + 1] = min(log1p(float(book.rating_count or 0)) / 12.0, 1.0)
    vector[dense_offset + 2] = min(log1p(float(book.recent_reads or 0)) / 14.0, 1.0)
    vector[dense_offset + 3] = min(log1p(float(book.word_count or 0)) / 15.0, 1.0)
    vector[dense_offset + 4] = 1.0 if (book.completion_status or 'ongoing') == 'completed' else 0.0
    return vector


def user_feature_vector(user_id: int, space: FeatureSpace) -> list[float]:
    vector = [0.0] * space.size
    category_index = {category_id: idx for idx, category_id in enumerate(space.category_ids)}
    tag_index_offset = len(space.category_ids)
    tag_index = {tag_id: tag_index_offset + idx for idx, tag_id in enumerate(space.tag_ids)}

    category_scores: dict[int, float] = {}
    tag_scores: dict[int, float] = {}

    shelf_book_ids = [int(row.book_id) for row in UserShelf.query.filter_by(user_id=user_id).all()]
    progress_book_ids = [
        int(row.book_id)
        for row in UserReadingProgress.query.filter_by(user_id=user_id)
        .order_by(UserReadingProgress.updated_at.desc(), UserReadingProgress.id.desc())
        .limit(50)
        .all()
    ]
    feedback_rows = (
        RecommendationFeedback.query.filter_by(user_id=user_id)
        .order_by(RecommendationFeedback.created_at.desc(), RecommendationFeedback.id.desc())
        .limit(80)
        .all()
    )

    weighted_books: dict[int, float] = {}
    for book_id in shelf_book_ids:
        weighted_books[book_id] = weighted_books.get(book_id, 0.0) + 5.0
    for book_id in progress_book_ids:
        weighted_books[book_id] = weighted_books.get(book_id, 0.0) + 4.0
    for row in feedback_rows:
        if row.action == 'hide':
            weighted_books[int(row.book_id)] = weighted_books.get(int(row.book_id), 0.0) - 3.0
        elif row.action in POSITIVE_FEEDBACK:
            weighted_books[int(row.book_id)] = weighted_books.get(int(row.book_id), 0.0) + (6.0 if row.action == 'more_like_this' else 4.0)

    if weighted_books:
        books = Book.query.filter(Book.id.in_(list(weighted_books.keys()))).all()
        tags_by_book = _book_tag_map(list(weighted_books.keys()))
        for book in books:
            weight = weighted_books.get(int(book.id), 0.0)
            if book.category_id:
                category_scores[int(book.category_id)] = category_scores.get(int(book.category_id), 0.0) + weight
            for tag_id in tags_by_book.get(int(book.id), set()):
                tag_scores[int(tag_id)] = tag_scores.get(int(tag_id), 0.0) + weight

    search_rows = (
        UserSearchHistory.query.filter_by(user_id=user_id)
        .order_by(UserSearchHistory.last_searched_at.desc(), UserSearchHistory.id.desc())
        .limit(20)
        .all()
    )
    tags = Tag.query.all()
    for row in search_rows:
        keyword = (row.keyword or '').lower()
        if not keyword:
            continue
        points = min(8.0, max(1.0, float(row.search_count or 1)) * 1.5)
        for tag in tags:
            label = (tag.label or '').lower()
            code = (tag.code or '').lower()
            if keyword in label or label in keyword or keyword in code or code in keyword:
                tag_scores[int(tag.id)] = tag_scores.get(int(tag.id), 0.0) + points

    for category_id, score in category_scores.items():
        idx = category_index.get(category_id)
        if idx is not None:
            vector[idx] = score
    for tag_id, score in tag_scores.items():
        idx = tag_index.get(tag_id)
        if idx is not None:
            vector[idx] = score

    dense_offset = len(space.category_ids) + len(space.tag_ids)
    vector[dense_offset] = min(len(progress_book_ids) / 20.0, 1.0)
    vector[dense_offset + 1] = min(len(shelf_book_ids) / 20.0, 1.0)
    vector[dense_offset + 2] = min(len(feedback_rows) / 40.0, 1.0)
    vector[dense_offset + 3] = min(sum(1 for row in feedback_rows if row.action == 'more_like_this') / 10.0, 1.0)
    vector[dense_offset + 4] = min(len(search_rows) / 12.0, 1.0)

    sparse_len = len(space.category_ids) + len(space.tag_ids)
    vector[:sparse_len] = _normalize(vector[:sparse_len])
    return vector


def collect_training_samples(max_negative_per_user: int = 5) -> list[TrainingSample]:
    users = User.query.order_by(User.id.asc()).all()
    visible_books = visible_books_query().order_by(Book.rating.desc(), Book.recent_reads.desc(), Book.id.asc()).all()
    all_book_ids = [int(book.id) for book in visible_books]
    samples: list[TrainingSample] = []

    for user in users:
        positives: dict[int, float] = {}
        for row in UserShelf.query.filter_by(user_id=user.id).all():
            positives[int(row.book_id)] = max(positives.get(int(row.book_id), 0.0), 1.0)
        for row in UserReadingProgress.query.filter_by(user_id=user.id).all():
            positives[int(row.book_id)] = max(positives.get(int(row.book_id), 0.0), 1.0)
        for row in RecommendationFeedback.query.filter_by(user_id=user.id).all():
            if row.action in POSITIVE_FEEDBACK:
                positives[int(row.book_id)] = max(positives.get(int(row.book_id), 0.0), 1.0)
            elif row.action == 'hide':
                samples.append(TrainingSample(user_id=int(user.id), book_id=int(row.book_id), label=0.0, weight=1.5))

        for book_id in positives:
            samples.append(TrainingSample(user_id=int(user.id), book_id=book_id, label=1.0, weight=1.0))

        negative_count = 0
        for book_id in all_book_ids:
            if book_id in positives:
                continue
            samples.append(TrainingSample(user_id=int(user.id), book_id=book_id, label=0.0, weight=1.0))
            negative_count += 1
            if negative_count >= max_negative_per_user:
                break

    return samples


def user_ids_with_behavior() -> list[int]:
    ids = set()
    for query in (
        db.session.query(UserShelf.user_id),
        db.session.query(UserReadingProgress.user_id),
        db.session.query(RecommendationFeedback.user_id),
        db.session.query(UserSearchHistory.user_id),
        db.session.query(BookAnalyticsEvent.user_id).filter(BookAnalyticsEvent.user_id.isnot(None)),
    ):
        ids.update(int(user_id) for user_id, in query.distinct().all())
    return sorted(ids)


def popularity_book_ids(limit: int = 100) -> list[int]:
    rows = (
        visible_books_query()
        .order_by(Book.is_featured.desc(), Book.recent_reads.desc(), Book.rating.desc(), Book.id.desc())
        .limit(limit)
        .all()
    )
    return [int(book.id) for book in rows]
