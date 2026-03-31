import json
import threading
import time
from typing import Any

from flask import current_app

from app import redis_client

_local_store: dict[str, dict[str, Any]] = {}
_store_lock = threading.Lock()


class AuthThrottleError(Exception):
    def __init__(self, message: str, retry_after: int | None = None):
        self.retry_after = retry_after
        super().__init__(message)


def _now() -> int:
    return int(time.time())


def _cleanup_local_expired(now_ts: int):
    expired_keys = [key for key, value in _local_store.items() if int(value.get('expire_at', 0)) <= now_ts]
    for key in expired_keys:
        _local_store.pop(key, None)


def _window_key(prefix: str, identity: str, window_seconds: int) -> str:
    slot = _now() // window_seconds
    return f'auth_throttle:{prefix}:{identity}:{window_seconds}:{slot}'


def _increment_counter(key: str, window_seconds: int) -> tuple[int, int]:
    now_ts = _now()
    if current_app.config.get('REDIS_URL'):
        current = redis_client.incr(key)
        ttl = redis_client.ttl(key)
        if ttl in (-1, -2):
            redis_client.expire(key, window_seconds)
            ttl = window_seconds
        return int(current), max(1, int(ttl))

    with _store_lock:
        _cleanup_local_expired(now_ts)
        record = _local_store.get(key)
        if not record:
            expire_at = now_ts + window_seconds
            _local_store[key] = {'count': 1, 'expire_at': expire_at}
            return 1, window_seconds

        record['count'] = int(record.get('count', 0)) + 1
        ttl = max(1, int(record.get('expire_at', now_ts + window_seconds)) - now_ts)
        return int(record['count']), ttl


def enforce_email_code_send_limits(target: str, ip_address: str):
    normalized_target = (target or '').strip().lower()
    normalized_ip = (ip_address or 'unknown').strip().lower()

    rules = [
        ('ip', normalized_ip, int(current_app.config.get('AUTH_CODE_MAX_PER_IP_PER_HOUR', 10)), 3600, '当前 IP 发送过于频繁，请稍后再试'),
        ('ip', normalized_ip, int(current_app.config.get('AUTH_CODE_MAX_PER_IP_PER_DAY', 30)), 86400, '当前 IP 今日发送次数已达上限，请明天再试'),
        ('email', normalized_target, int(current_app.config.get('AUTH_CODE_MAX_PER_EMAIL_PER_HOUR', 5)), 3600, '该邮箱短时间内发送过于频繁，请稍后再试'),
        ('email', normalized_target, int(current_app.config.get('AUTH_CODE_MAX_PER_EMAIL_PER_DAY', 10)), 86400, '该邮箱今日发送次数已达上限，请明天再试'),
    ]

    for prefix, identity, limit, window_seconds, message in rules:
        if limit <= 0:
            continue
        key = _window_key(prefix, identity, window_seconds)
        current, retry_after = _increment_counter(key, window_seconds)
        if current > limit:
            raise AuthThrottleError(message, retry_after=retry_after)
