from __future__ import annotations

import json
from typing import Any

from flask import current_app

from app import redis_client


def _redis_configured() -> bool:
    try:
        return bool(current_app.config.get('REDIS_URL'))
    except RuntimeError:
        return False


def _log_cache_error(operation: str, key: str, exc: Exception) -> None:
    try:
        current_app.logger.debug('Redis cache %s failed for %s: %s', operation, key, exc)
    except RuntimeError:
        pass


def get_text(key: str) -> str | None:
    if not _redis_configured():
        return None
    try:
        value = redis_client.get(key)
    except Exception as exc:  # pragma: no cover - exact Redis errors vary by client/runtime.
        _log_cache_error('get', key, exc)
        return None
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode('utf-8')
    return str(value)


def set_text(key: str, value: str, ttl: int | None) -> None:
    if not _redis_configured() or value is None:
        return
    try:
        ttl_seconds = int(ttl or 0)
        if ttl_seconds > 0:
            redis_client.setex(key, ttl_seconds, value)
        else:
            redis_client.set(key, value)
    except Exception as exc:  # pragma: no cover - exact Redis errors vary by client/runtime.
        _log_cache_error('set', key, exc)


def get_json(key: str) -> Any | None:
    raw = get_text(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        _log_cache_error('decode', key, exc)
        return None


def set_json(key: str, value: Any, ttl: int | None) -> None:
    try:
        payload = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        _log_cache_error('encode', key, exc)
        return
    set_text(key, payload, ttl)
