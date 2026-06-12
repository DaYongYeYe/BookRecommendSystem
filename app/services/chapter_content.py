from __future__ import annotations

import json
from hashlib import md5
from typing import Any

from flask import current_app

from app.services.cache_service import get_text, set_text
from app.services.tencent_cos import fetch_text, upload_text


class ContentStorageError(RuntimeError):
    pass


def _require_storage_result(result: dict[str, str] | None, error: str | None) -> dict[str, str]:
    if error or not result:
        raise ContentStorageError(error or 'content storage failed')
    return result


def store_text_on_record(record: Any, content: str | None, *, folder: str, clear_inline: bool = True) -> str:
    text = (content or '').strip()
    if not text:
        if clear_inline:
            record.content_text = None
        return ''

    result, error = upload_text(text, folder=folder)
    stored = _require_storage_result(result, error)
    record.content_url = stored['url']
    record.content_md5 = stored['md5']
    if clear_inline:
        record.content_text = None
    else:
        record.content_text = text
    return text


def _chapter_revision_cache_key(record: Any) -> str | None:
    if not record or record.__class__.__name__ != 'BookChapterRevision':
        return None
    record_id = getattr(record, 'id', None)
    if not record_id:
        return None

    inline_text = getattr(record, 'content_text', None)
    if inline_text:
        fingerprint = md5(inline_text.encode('utf-8')).hexdigest()
    else:
        fingerprint = (
            (getattr(record, 'content_md5', None) or '').strip()
            or (getattr(record, 'content_url', None) or '').strip()
            or str(getattr(record, 'updated_at', '') or '')
        )
        fingerprint = md5(fingerprint.encode('utf-8')).hexdigest()
    return f'book:chapter-content:v1:{record_id}:{fingerprint}'


def _chapter_content_cache_ttl() -> int:
    try:
        return int(current_app.config.get('CHAPTER_CONTENT_CACHE_TTL', 86400))
    except RuntimeError:
        return 86400


def get_record_text(record: Any) -> str:
    if not record:
        return ''

    cache_key = _chapter_revision_cache_key(record)
    if cache_key:
        cached_text = get_text(cache_key)
        if cached_text is not None:
            return cached_text

    inline_text = getattr(record, 'content_text', None)
    if inline_text:
        if cache_key:
            set_text(cache_key, inline_text, _chapter_content_cache_ttl())
        return inline_text

    content_url = (getattr(record, 'content_url', None) or '').strip()
    if not content_url:
        return ''
    text, error = fetch_text(content_url, getattr(record, 'content_md5', None))
    if error:
        raise ContentStorageError(error)
    text = text or ''
    if cache_key and text:
        set_text(cache_key, text, _chapter_content_cache_ttl())
    return text


def store_manuscript_chapters(manuscript: Any, chapters: list[dict] | None) -> None:
    if not chapters:
        manuscript.chapter_payload_url = None
        manuscript.chapter_payload_md5 = None
        manuscript.chapter_payload = None
        return
    payload = json.dumps(chapters, ensure_ascii=False)
    result, error = upload_text(payload, folder='book_manuscript_chapters')
    stored = _require_storage_result(result, error)
    manuscript.chapter_payload_url = stored['url']
    manuscript.chapter_payload_md5 = stored['md5']
    manuscript.chapter_payload = None


def get_manuscript_chapters(manuscript: Any) -> list[dict]:
    raw_payload = getattr(manuscript, 'chapter_payload', None)
    if not raw_payload:
        payload_url = (getattr(manuscript, 'chapter_payload_url', None) or '').strip()
        if payload_url:
            raw_payload, error = fetch_text(payload_url, getattr(manuscript, 'chapter_payload_md5', None))
            if error:
                raise ContentStorageError(error)

    if not raw_payload:
        return []
    try:
        data = json.loads(raw_payload)
    except (TypeError, ValueError) as exc:
        raise ContentStorageError('invalid chapters payload') from exc
    return data if isinstance(data, list) else []


def serialize_revision_with_content(revision: Any | None) -> dict | None:
    if not revision:
        return None
    payload = revision.to_dict()
    payload['content_text'] = get_record_text(revision)
    return payload


def serialize_manuscript_with_content(manuscript: Any | None) -> dict | None:
    if not manuscript:
        return None
    payload = manuscript.to_dict()
    payload['content_text'] = get_record_text(manuscript)
    payload['chapters'] = get_manuscript_chapters(manuscript)
    return payload


def serialize_version_with_content(version: Any | None) -> dict | None:
    if not version:
        return None
    payload = version.to_dict()
    payload['content_text'] = get_record_text(version)
    return payload
