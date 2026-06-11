from __future__ import annotations

import json
from dataclasses import dataclass

from app import redis_client
from app.models import Book, BookTag, RecommendationCandidate, RecommendationFeedback, RecommendationModelVersion, UserShelf


@dataclass(frozen=True)
class OnlineRecommendation:
    book_id: int
    score: float
    rank_no: int
    reason_type: str
    model_version: str


def active_model_version() -> str | None:
    row = RecommendationModelVersion.query.filter_by(is_active=True).order_by(RecommendationModelVersion.id.desc()).first()
    return row.version if row else None


def _feedback_state(user_id: int) -> dict[int, str]:
    rows = (
        RecommendationFeedback.query.filter_by(user_id=user_id)
        .order_by(RecommendationFeedback.created_at.desc(), RecommendationFeedback.id.desc())
        .all()
    )
    states: dict[int, str] = {}
    for row in rows:
        states.setdefault(int(row.book_id), row.action)
    return states


def _shelf_ids(user_id: int) -> set[int]:
    return {int(row.book_id) for row in UserShelf.query.filter_by(user_id=user_id).all()}


def _candidate_ids_for_positive_feedback(user_id: int) -> set[int]:
    rows = (
        RecommendationFeedback.query.filter_by(user_id=user_id, action='more_like_this')
        .order_by(RecommendationFeedback.created_at.desc(), RecommendationFeedback.id.desc())
        .limit(10)
        .all()
    )
    source_book_ids = [int(row.book_id) for row in rows]
    if not source_book_ids:
        return set()
    tag_ids = {
        int(tag_id)
        for tag_id, in BookTag.query.filter(BookTag.book_id.in_(source_book_ids)).with_entities(BookTag.tag_id).all()
    }
    if not tag_ids:
        return set(source_book_ids)
    return {
        int(book_id)
        for book_id, in BookTag.query.filter(BookTag.tag_id.in_(tag_ids)).with_entities(BookTag.book_id).all()
    }


def _redis_candidates(user_id: int, version: str) -> list[dict] | None:
    if not redis_client:
        return None
    try:
        raw = redis_client.get(f'recommendation:candidates:{version}:{user_id}')
    except Exception:
        return None
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8')
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, list) else None


def _db_candidates(user_id: int, version: str, candidate_limit: int) -> list[dict]:
    rows = (
        RecommendationCandidate.query.filter_by(user_id=user_id, model_version=version)
        .order_by(RecommendationCandidate.rank_no.asc(), RecommendationCandidate.score.desc(), RecommendationCandidate.id.asc())
        .limit(candidate_limit)
        .all()
    )
    return [row.to_dict() for row in rows]


def get_two_tower_recommendations(
    user_id: int | None,
    *,
    limit: int,
    hidden_ids: set[int] | None = None,
    used_ids: set[int] | None = None,
    exclude_shelf: bool = False,
    candidate_limit: int = 100,
) -> list[OnlineRecommendation]:
    if not user_id:
        return []
    version = active_model_version()
    if not version:
        return []

    hidden = set(hidden_ids or set())
    used = set(used_ids or set())
    feedback_states = _feedback_state(user_id)
    hidden.update(book_id for book_id, action in feedback_states.items() if action == 'hide')
    if exclude_shelf:
        hidden.update(_shelf_ids(user_id))

    boost_ids = _candidate_ids_for_positive_feedback(user_id)
    payload = _redis_candidates(user_id, version)
    if payload is None:
        payload = _db_candidates(user_id, version, candidate_limit)
    if not payload:
        return []

    book_ids = [int(item.get('book_id') or 0) for item in payload]
    visible_ids = {
        int(book.id)
        for book in Book.query.filter(
            Book.id.in_(book_ids),
            Book.status == 'published',
            Book.shelf_status == 'up',
        ).all()
    }

    ranked: list[OnlineRecommendation] = []
    for idx, item in enumerate(payload):
        book_id = int(item.get('book_id') or 0)
        if book_id not in visible_ids or book_id in hidden or book_id in used:
            continue
        score = float(item.get('score') or 0)
        if book_id in boost_ids:
            score += 0.08
        ranked.append(
            OnlineRecommendation(
                book_id=book_id,
                score=score,
                rank_no=int(item.get('rank_no') or idx + 1),
                reason_type=item.get('reason_type') or 'two_tower',
                model_version=version,
            )
        )

    ranked.sort(key=lambda item: (-item.score, item.rank_no, item.book_id))
    return ranked[: max(1, int(limit))]
