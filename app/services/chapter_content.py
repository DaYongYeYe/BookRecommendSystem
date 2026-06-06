from __future__ import annotations

import json
from typing import Any

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


def get_record_text(record: Any) -> str:
    if not record:
        return ''
    inline_text = getattr(record, 'content_text', None)
    if inline_text:
        return inline_text

    content_url = (getattr(record, 'content_url', None) or '').strip()
    if not content_url:
        return ''
    text, error = fetch_text(content_url, getattr(record, 'content_md5', None))
    if error:
        raise ContentStorageError(error)
    return text or ''


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
