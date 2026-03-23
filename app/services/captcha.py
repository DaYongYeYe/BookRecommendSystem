import base64
import random
import threading
import time
import uuid
from typing import Dict

from flask import current_app

from app import redis_client
from app.logging_utils import log_business_event, log_dependency_call

_local_captcha_store: Dict[str, Dict[str, float | str]] = {}
_store_lock = threading.Lock()
_CAPTCHA_PREFIX = "captcha:"


def _generate_code(length: int = 4) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(chars) for _ in range(length))


def _cleanup_local_expired(now_ts: float):
    expired_keys = [key for key, val in _local_captcha_store.items() if float(val.get("expire_at", 0)) <= now_ts]
    for key in expired_keys:
        _local_captcha_store.pop(key, None)


def _save_code(captcha_id: str, code: str, expires_in: int):
    started = time.perf_counter()
    if current_app.config.get("REDIS_URL"):
        redis_client.setex(f"{_CAPTCHA_PREFIX}{captcha_id}", expires_in, code)
        log_dependency_call(
            current_app.logger,
            "redis",
            "setex_captcha",
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=["dependency", "redis", "captcha"],
            data={"captcha_id": captcha_id, "expires_in": expires_in},
        )
        return

    expire_at = time.time() + expires_in
    with _store_lock:
        _cleanup_local_expired(time.time())
        _local_captcha_store[captcha_id] = {"code": code, "expire_at": expire_at}
    log_dependency_call(
        current_app.logger,
        "local_store",
        "save_captcha",
        success=True,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        tags=["dependency", "captcha", "memory"],
        data={"captcha_id": captcha_id, "expires_in": expires_in},
    )


def _get_code(captcha_id: str) -> str | None:
    started = time.perf_counter()
    if current_app.config.get("REDIS_URL"):
        val = redis_client.get(f"{_CAPTCHA_PREFIX}{captcha_id}")
        log_dependency_call(
            current_app.logger,
            "redis",
            "get_captcha",
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=["dependency", "redis", "captcha"],
            data={"captcha_id": captcha_id, "hit": bool(val)},
        )
        return val.decode("utf-8") if val else None

    now_ts = time.time()
    with _store_lock:
        _cleanup_local_expired(now_ts)
        val = _local_captcha_store.get(captcha_id)
        if not val:
            log_dependency_call(
                current_app.logger,
                "local_store",
                "get_captcha",
                success=True,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                tags=["dependency", "captcha", "memory"],
                data={"captcha_id": captcha_id, "hit": False},
            )
            return None
        log_dependency_call(
            current_app.logger,
            "local_store",
            "get_captcha",
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=["dependency", "captcha", "memory"],
            data={"captcha_id": captcha_id, "hit": True},
        )
        return str(val.get("code", ""))


def _delete_code(captcha_id: str):
    started = time.perf_counter()
    if current_app.config.get("REDIS_URL"):
        redis_client.delete(f"{_CAPTCHA_PREFIX}{captcha_id}")
        log_dependency_call(
            current_app.logger,
            "redis",
            "delete_captcha",
            success=True,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            tags=["dependency", "redis", "captcha"],
            data={"captcha_id": captcha_id},
        )
        return

    with _store_lock:
        _local_captcha_store.pop(captcha_id, None)
    log_dependency_call(
        current_app.logger,
        "local_store",
        "delete_captcha",
        success=True,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        tags=["dependency", "captcha", "memory"],
        data={"captcha_id": captcha_id},
    )


def _build_svg_data_url(code: str) -> str:
    width = 120
    height = 42
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
<rect width="100%" height="100%" fill="#f3f7ff"/>
<path d="M0 10 Q 30 20 60 10 T 120 10" stroke="#d8e3ff" fill="none" stroke-width="2"/>
<path d="M0 28 Q 30 38 60 28 T 120 28" stroke="#d8e3ff" fill="none" stroke-width="2"/>
<text x="14" y="30" font-size="24" fill="#2f54eb" font-family="Arial, sans-serif" letter-spacing="3">{code}</text>
</svg>"""
    encoded = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return f"data:image/svg+xml;base64,{encoded}"


def generate_captcha() -> dict:
    captcha_id = uuid.uuid4().hex
    code = _generate_code()
    expires_in = int(current_app.config.get("CAPTCHA_EXPIRES_IN", 300))
    _save_code(captcha_id, code, expires_in)
    log_business_event(
        current_app.logger,
        "captcha.generated",
        tags=["business", "captcha"],
        data={"captcha_id": captcha_id, "expires_in": expires_in},
    )
    return {
        "captcha_id": captcha_id,
        "captcha_image": _build_svg_data_url(code),
        "expires_in": expires_in,
    }


def verify_captcha(captcha_id: str, captcha_code: str) -> bool:
    normalized_id = (captcha_id or "").strip()
    normalized_code = (captcha_code or "").strip().upper()
    if not normalized_id or not normalized_code:
        log_business_event(current_app.logger, "captcha.verify_failed", tags=["business", "captcha"], data={"reason": "missing_input"})
        return False

    saved_code = _get_code(normalized_id)
    if not saved_code:
        log_business_event(
            current_app.logger,
            "captcha.verify_failed",
            tags=["business", "captcha"],
            data={"reason": "not_found_or_expired", "captcha_id": normalized_id},
        )
        return False

    _delete_code(normalized_id)
    success = saved_code.upper() == normalized_code
    log_business_event(
        current_app.logger,
        "captcha.verify_result",
        tags=["business", "captcha"],
        data={"captcha_id": normalized_id, "success": success},
    )
    return success
