import json
import random
import threading
import time
from typing import Any

from flask import current_app

from app import redis_client
from app.logging_utils import log_business_event, log_dependency_call

_local_code_store: dict[str, dict[str, Any]] = {}
_store_lock = threading.Lock()
_CODE_PREFIX = 'auth_code:'
_COOLDOWN_PREFIX = 'auth_code_cooldown:'


class VerificationCodeError(Exception):
    pass


class VerificationCodeRateLimitError(VerificationCodeError):
    def __init__(self, retry_after: int):
        self.retry_after = max(1, int(retry_after))
        super().__init__(f'Please retry after {self.retry_after} seconds')


def _now() -> float:
    return time.time()


def _cleanup_local_expired(now_ts: float):
    expired_keys = [key for key, value in _local_code_store.items() if float(value.get('expire_at', 0)) <= now_ts]
    for key in expired_keys:
        _local_code_store.pop(key, None)


def _make_record_key(target: str, purpose: str) -> str:
    return f'{_CODE_PREFIX}{purpose}:{target.lower()}'


def _make_cooldown_key(target: str, purpose: str) -> str:
    return f'{_COOLDOWN_PREFIX}{purpose}:{target.lower()}'


def _redis_enabled() -> bool:
    return bool(current_app.config.get('REDIS_URL'))


def _redis_get_json(key: str) -> dict[str, Any] | None:
    raw = redis_client.get(key)
    if not raw:
        return None
    try:
        return json.loads(raw.decode('utf-8'))
    except (ValueError, AttributeError):
        return None


def _local_get_json(key: str) -> dict[str, Any] | None:
    with _store_lock:
        _cleanup_local_expired(_now())
        value = _local_code_store.get(key)
        return dict(value) if value else None


def _get_json(key: str) -> dict[str, Any] | None:
    started = time.perf_counter()
    if _redis_enabled():
        value = _redis_get_json(key)
        log_dependency_call(
            current_app.logger,
            'redis',
            'get_auth_code',
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=['dependency', 'redis', 'auth_code'],
            data={'key': key, 'hit': bool(value)},
        )
        return value

    value = _local_get_json(key)
    log_dependency_call(
        current_app.logger,
        'local_store',
        'get_auth_code',
        success=True,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        tags=['dependency', 'memory', 'auth_code'],
        data={'key': key, 'hit': bool(value)},
    )
    return value


def _set_json(key: str, payload: dict[str, Any], expires_in: int):
    started = time.perf_counter()
    if _redis_enabled():
        redis_client.setex(key, expires_in, json.dumps(payload))
        log_dependency_call(
            current_app.logger,
            'redis',
            'set_auth_code',
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=['dependency', 'redis', 'auth_code'],
            data={'key': key, 'expires_in': expires_in},
        )
        return

    expire_at = _now() + expires_in
    with _store_lock:
        _cleanup_local_expired(_now())
        _local_code_store[key] = {**payload, 'expire_at': expire_at}
    log_dependency_call(
        current_app.logger,
        'local_store',
        'set_auth_code',
        success=True,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        tags=['dependency', 'memory', 'auth_code'],
        data={'key': key, 'expires_in': expires_in},
    )


def _delete_key(key: str):
    started = time.perf_counter()
    if _redis_enabled():
        redis_client.delete(key)
        log_dependency_call(
            current_app.logger,
            'redis',
            'delete_auth_code',
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=['dependency', 'redis', 'auth_code'],
            data={'key': key},
        )
        return

    with _store_lock:
        _local_code_store.pop(key, None)
    log_dependency_call(
        current_app.logger,
        'local_store',
        'delete_auth_code',
        success=True,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        tags=['dependency', 'memory', 'auth_code'],
        data={'key': key},
    )


def _generate_code(length: int = 6) -> str:
    return ''.join(random.choice('0123456789') for _ in range(length))


def mask_email(email: str) -> str:
    normalized = (email or '').strip()
    if '@' not in normalized:
        return normalized
    local, domain = normalized.split('@', 1)
    if len(local) <= 2:
        masked_local = f'{local[:1]}*'
    else:
        masked_local = f'{local[:2]}***'
    return f'{masked_local}@{domain}'


def create_email_code(target: str, purpose: str) -> dict[str, Any]:
    normalized_target = (target or '').strip().lower()
    normalized_purpose = (purpose or '').strip().lower()
    if not normalized_target or not normalized_purpose:
        raise VerificationCodeError('target and purpose are required')

    expires_in = int(current_app.config.get('AUTH_CODE_EXPIRES_IN', 600))
    resend_seconds = int(current_app.config.get('AUTH_CODE_RESEND_SECONDS', 60))
    max_attempts = int(current_app.config.get('AUTH_CODE_MAX_ATTEMPTS', 5))
    cooldown_key = _make_cooldown_key(normalized_target, normalized_purpose)
    record_key = _make_record_key(normalized_target, normalized_purpose)

    cooldown_record = _get_json(cooldown_key)
    if cooldown_record:
        retry_after = int(float(cooldown_record.get('retry_after', 0)) - _now())
        if retry_after > 0:
            raise VerificationCodeRateLimitError(retry_after)

    code = _generate_code()
    record = {
        'code': code,
        'purpose': normalized_purpose,
        'target': normalized_target,
        'attempts_left': max_attempts,
        'created_at': int(_now()),
    }
    cooldown_payload = {'retry_after': _now() + resend_seconds}

    _set_json(record_key, record, expires_in)
    _set_json(cooldown_key, cooldown_payload, resend_seconds)

    log_business_event(
        current_app.logger,
        'auth.email_code_created',
        tags=['business', 'auth', 'verification_code'],
        data={
            'purpose': normalized_purpose,
            'target': mask_email(normalized_target),
            'expires_in': expires_in,
            'resend_seconds': resend_seconds,
        },
    )
    return {
        'code': code,
        'expires_in': expires_in,
        'resend_seconds': resend_seconds,
        'masked_target': mask_email(normalized_target),
    }


def verify_email_code(target: str, purpose: str, code: str) -> bool:
    normalized_target = (target or '').strip().lower()
    normalized_purpose = (purpose or '').strip().lower()
    normalized_code = (code or '').strip()
    if not normalized_target or not normalized_purpose or not normalized_code:
        return False

    record_key = _make_record_key(normalized_target, normalized_purpose)
    record = _get_json(record_key)
    if not record:
        return False

    saved_code = str(record.get('code', '')).strip()
    if saved_code == normalized_code:
        _delete_key(record_key)
        log_business_event(
            current_app.logger,
            'auth.email_code_verified',
            tags=['business', 'auth', 'verification_code'],
            data={'purpose': normalized_purpose, 'target': mask_email(normalized_target), 'success': True},
        )
        return True

    attempts_left = max(0, int(record.get('attempts_left', 1)) - 1)
    if attempts_left <= 0:
        _delete_key(record_key)
    else:
        record['attempts_left'] = attempts_left
        expires_in = int(current_app.config.get('AUTH_CODE_EXPIRES_IN', 600))
        _set_json(record_key, record, expires_in)

    log_business_event(
        current_app.logger,
        'auth.email_code_verified',
        tags=['business', 'auth', 'verification_code'],
        data={
            'purpose': normalized_purpose,
            'target': mask_email(normalized_target),
            'success': False,
            'attempts_left': attempts_left,
        },
    )
    return False
