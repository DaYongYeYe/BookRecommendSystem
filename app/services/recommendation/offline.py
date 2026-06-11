from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from app import db
from app.models import Book, RecommendationCandidate, RecommendationModelVersion
from app.services.recommendation.features import (
    book_feature_vector,
    build_feature_space,
    collect_training_samples,
    popularity_book_ids,
    user_feature_vector,
    user_ids_with_behavior,
    visible_books_query,
)
from app.services.recommendation.two_tower import TwoTowerFactory


DEFAULT_ARTIFACT_ROOT = os.path.join('instance', 'recommendation_models')


def _lazy_numeric():
    import numpy as np
    import torch

    return np, torch


def _version_name() -> str:
    return datetime.utcnow().strftime('two_tower_%Y%m%d%H%M%S')


def _artifact_dir(version: str, artifact_root: str | None = None) -> str:
    return os.path.abspath(os.path.join(artifact_root or DEFAULT_ARTIFACT_ROOT, version))


def train_two_tower(epochs: int = 20, embedding_dim: int = 64, top_k: int = 100, activate: bool = False, artifact_root: str | None = None):
    np, torch = _lazy_numeric()
    space = build_feature_space()
    samples = collect_training_samples()
    if not samples:
        raise RuntimeError('not enough user behavior to train two-tower recommendations')

    books = visible_books_query().order_by(Book.id.asc()).all()
    book_by_id = {int(book.id): book for book in books}
    user_ids = sorted({sample.user_id for sample in samples})
    user_vectors = {user_id: user_feature_vector(user_id, space) for user_id in user_ids}
    book_vectors = {book_id: book_feature_vector(book, space) for book_id, book in book_by_id.items()}

    train_samples = [
        sample
        for sample in samples
        if sample.user_id in user_vectors and sample.book_id in book_vectors
    ]
    if not train_samples:
        raise RuntimeError('training samples did not match visible books')

    model = TwoTowerFactory.create(space.size, embedding_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = torch.nn.BCEWithLogitsLoss(reduction='none')

    user_tensor = torch.tensor([user_vectors[sample.user_id] for sample in train_samples], dtype=torch.float32)
    book_tensor = torch.tensor([book_vectors[sample.book_id] for sample in train_samples], dtype=torch.float32)
    labels = torch.tensor([sample.label for sample in train_samples], dtype=torch.float32)
    weights = torch.tensor([sample.weight for sample in train_samples], dtype=torch.float32)

    last_loss = 0.0
    for _ in range(max(1, int(epochs))):
        optimizer.zero_grad()
        logits = model(user_tensor, book_tensor)
        loss = (loss_fn(logits, labels) * weights).mean()
        loss.backward()
        optimizer.step()
        last_loss = float(loss.detach().cpu().item())

    with torch.no_grad():
        user_id_order = user_ids
        book_id_order = sorted(book_vectors)
        encoded_users = model.encode_user(torch.tensor([user_vectors[user_id] for user_id in user_id_order], dtype=torch.float32)).cpu().numpy()
        encoded_books = model.encode_book(torch.tensor([book_vectors[book_id] for book_id in book_id_order], dtype=torch.float32)).cpu().numpy()
        scores = encoded_users @ encoded_books.T

    version = _version_name()
    output_dir = _artifact_dir(version, artifact_root)
    os.makedirs(output_dir, exist_ok=True)
    np.save(os.path.join(output_dir, 'user_embeddings.npy'), encoded_users)
    np.save(os.path.join(output_dir, 'book_embeddings.npy'), encoded_books)

    candidate_cache = {}
    for row_index, user_id in enumerate(user_id_order):
        ranked_indices = np.argsort(-scores[row_index])[: max(1, int(top_k))]
        candidate_cache[str(user_id)] = [
            {
                'book_id': int(book_id_order[col_index]),
                'score': float(scores[row_index][col_index]),
                'rank_no': rank_no + 1,
                'reason_type': 'two_tower',
            }
            for rank_no, col_index in enumerate(ranked_indices)
        ]

    meta = {
        'version': version,
        'embedding_dim': int(embedding_dim),
        'feature_size': int(space.size),
        'epochs': int(epochs),
        'top_k': int(top_k),
        'sample_count': len(train_samples),
        'user_count': len(user_id_order),
        'book_count': len(book_id_order),
        'loss': last_loss,
        'trained_at': datetime.utcnow().isoformat(),
    }
    with open(os.path.join(output_dir, 'model_meta.json'), 'w', encoding='utf-8') as fp:
        json.dump(meta, fp, ensure_ascii=False, indent=2)
    with open(os.path.join(output_dir, 'candidate_cache.json'), 'w', encoding='utf-8') as fp:
        json.dump(candidate_cache, fp, ensure_ascii=False)

    model_version = RecommendationModelVersion(
        version=version,
        embedding_dim=int(embedding_dim),
        artifact_dir=output_dir,
        metrics_json=json.dumps({'loss': last_loss, 'sample_count': len(train_samples)}, ensure_ascii=False),
        trained_at=datetime.utcnow(),
        is_active=False,
    )
    db.session.add(model_version)
    db.session.flush()
    refresh_recommendation_candidates(version=version, top_k=top_k, candidate_cache=candidate_cache)
    if activate:
        activate_model_version(version)
    db.session.commit()
    return {'version': version, 'artifact_dir': output_dir, 'metrics': meta}


def activate_model_version(version: str):
    RecommendationModelVersion.query.update({RecommendationModelVersion.is_active: False}, synchronize_session=False)
    row = RecommendationModelVersion.query.filter_by(version=version).first()
    if not row:
        raise RuntimeError(f'model version not found: {version}')
    row.is_active = True
    db.session.flush()
    return row


def _load_candidate_cache(version: str) -> dict:
    row = RecommendationModelVersion.query.filter_by(version=version).first()
    if not row or not row.artifact_dir:
        raise RuntimeError(f'model artifact not found: {version}')
    path = os.path.join(row.artifact_dir, 'candidate_cache.json')
    with open(path, 'r', encoding='utf-8') as fp:
        return json.load(fp)


def refresh_recommendation_candidates(version: str = 'latest', top_k: int = 100, candidate_cache: dict | None = None):
    if version == 'latest':
        active = RecommendationModelVersion.query.filter_by(is_active=True).order_by(RecommendationModelVersion.id.desc()).first()
        latest = active or RecommendationModelVersion.query.order_by(RecommendationModelVersion.id.desc()).first()
        if not latest:
            raise RuntimeError('no recommendation model version available')
        version = latest.version

    cache = candidate_cache or _load_candidate_cache(version)
    RecommendationCandidate.query.filter_by(model_version=version).delete(synchronize_session=False)

    visible_ids = set(popularity_book_ids(limit=100000))
    rows = []
    for user_id_text, candidates in cache.items():
        try:
            user_id = int(user_id_text)
        except (TypeError, ValueError):
            continue
        for rank_no, item in enumerate(candidates[: max(1, int(top_k))], start=1):
            book_id = int(item.get('book_id') or 0)
            if book_id not in visible_ids:
                continue
            rows.append(
                RecommendationCandidate(
                    user_id=user_id,
                    model_version=version,
                    book_id=book_id,
                    rank_no=int(item.get('rank_no') or rank_no),
                    score=float(item.get('score') or 0),
                    reason_type=item.get('reason_type') or 'two_tower',
                )
            )

    db.session.bulk_save_objects(rows)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        raise
    return {'version': version, 'candidate_count': len(rows), 'user_count': len(cache)}


def refresh_candidates_from_current_features(version: str = 'latest', top_k: int = 100):
    # Lightweight fallback for demos where a trained artifact exists but user behavior has changed.
    if version == 'latest':
        active = RecommendationModelVersion.query.filter_by(is_active=True).order_by(RecommendationModelVersion.id.desc()).first()
        if not active:
            raise RuntimeError('no active recommendation model version available')
        version = active.version
    cache = {str(user_id): [{'book_id': book_id, 'score': 0.0, 'rank_no': rank_no + 1, 'reason_type': 'two_tower'} for rank_no, book_id in enumerate(popularity_book_ids(top_k))] for user_id in user_ids_with_behavior()}
    return refresh_recommendation_candidates(version=version, top_k=top_k, candidate_cache=cache)
