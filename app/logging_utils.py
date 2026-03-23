import json
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Callable

import jwt
from flask import current_app, g, has_app_context, has_request_context, request
from werkzeug.exceptions import HTTPException


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _active_logger():
    if has_app_context():
        return current_app.logger
    return logging.getLogger("flask.app")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": _utc_now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "source": {
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
                "file": record.filename,
            },
        }

        # Search-friendly tags
        tags = getattr(record, "tags", None)
        if tags:
            payload["tags"] = tags if isinstance(tags, list) else [str(tags)]

        # Event metadata
        event = getattr(record, "event", None)
        if event:
            payload["event"] = event

        data = getattr(record, "data", None)
        if data is not None:
            payload["data"] = data

        dependency = getattr(record, "dependency", None)
        if dependency:
            payload["dependency"] = dependency

        if has_request_context():
            payload["request"] = {
                "request_id": getattr(g, "request_id", None),
                "method": request.method,
                "path": request.path,
                "query_string": request.query_string.decode("utf-8", errors="ignore"),
                "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
                "user_agent": request.user_agent.string,
            }
            payload["identity"] = {
                "user_id": getattr(g, "log_user_id", None),
                "username": getattr(g, "log_username", None),
                "role": getattr(g, "log_role", None),
                "is_admin": getattr(g, "log_is_admin", None),
                "auth_state": getattr(g, "log_auth_state", "anonymous"),
            }

        if record.exc_info:
            exc_type = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["error"] = {
                "type": exc_type,
                "detail": self.formatException(record.exc_info),
            }

        return json.dumps(payload, ensure_ascii=True, default=str)


def _build_timed_rotating_handler(log_path: str, level: int, backup_count: int) -> TimedRotatingFileHandler:
    handler = TimedRotatingFileHandler(
        filename=log_path,
        when="midnight",
        interval=1,
        backupCount=backup_count,
        encoding="utf-8",
        utc=True,
    )
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    return handler


def setup_logging(app) -> None:
    log_level_name = (app.config.get("LOG_LEVEL") or "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_dir = app.config.get("LOG_DIR") or os.path.join(app.instance_path, "logs")
    retention_days = int(app.config.get("LOG_RETENTION_DAYS", 14))

    os.makedirs(log_dir, exist_ok=True)

    app.logger.handlers.clear()
    app.logger.setLevel(log_level)
    app.logger.propagate = False

    app_log = _build_timed_rotating_handler(
        log_path=os.path.join(log_dir, "app.log"),
        level=log_level,
        backup_count=retention_days,
    )
    error_log = _build_timed_rotating_handler(
        log_path=os.path.join(log_dir, "error.log"),
        level=logging.ERROR,
        backup_count=retention_days,
    )
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(JsonFormatter())

    app.logger.addHandler(app_log)
    app.logger.addHandler(error_log)
    app.logger.addHandler(console)

    app.logger.info(
        "logging_initialized",
        extra={
            "event": "app.lifecycle.logging_initialized",
            "tags": ["lifecycle", "logging", "startup"],
            "data": {
                "log_level": log_level_name,
                "log_dir": log_dir,
                "retention_days": retention_days,
                "hostname": socket.gethostname(),
            },
        },
    )


def attach_request_hooks(app) -> None:
    @app.before_request
    def _before_request():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.request_start_ts = time.perf_counter()
        g.log_auth_state = "anonymous"
        _try_bind_identity_from_token(app)

    @app.after_request
    def _after_request(response):
        elapsed_ms = int((time.perf_counter() - getattr(g, "request_start_ts", time.perf_counter())) * 1000)
        app.logger.info(
            "request_completed",
            extra={
                "event": "http.request.completed",
                "tags": ["http", "request", "access"],
                "data": {
                    "status_code": response.status_code,
                    "elapsed_ms": elapsed_ms,
                    "response_content_type": response.content_type,
                },
            },
        )
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return response

    @app.teardown_request
    def _teardown_request(error):
        if error and not getattr(g, "_error_already_logged", False):
            app.logger.error(
                "request_teardown_with_error",
                exc_info=error,
                extra={
                    "event": "http.request.teardown_error",
                    "tags": ["http", "request", "error"],
                },
            )


def bind_identity(user=None, *, auth_state: str = "authenticated") -> None:
    if not has_request_context():
        return
    if user is None:
        g.log_auth_state = auth_state
        return
    g.log_user_id = getattr(user, "id", None)
    g.log_username = getattr(user, "username", None)
    g.log_role = getattr(user, "role", None)
    g.log_is_admin = bool(getattr(user, "is_admin", lambda: False)())
    g.log_auth_state = auth_state


def log_business_event(logger, event: str, *, level: int = logging.INFO, tags=None, data=None):
    logger.log(
        level,
        event,
        extra={
            "event": f"business.{event}",
            "tags": list(tags or ["business"]),
            "data": data or {},
        },
    )


def log_dependency_call(
    logger,
    dependency: str,
    operation: str,
    *,
    success: bool,
    elapsed_ms: int,
    tags=None,
    data=None,
    level: int | None = None,
):
    log_level = level if level is not None else (logging.INFO if success else logging.ERROR)
    logger.log(
        log_level,
        f"{dependency}.{operation}",
        extra={
            "event": "dependency.call",
            "dependency": {"name": dependency, "operation": operation},
            "tags": list(tags or ["dependency"]),
            "data": {"success": success, "elapsed_ms": elapsed_ms, **(data or {})},
        },
    )


def business_log_aspect(
    event: str,
    *,
    tags: list[str] | None = None,
    data_builder: Callable[[tuple, dict, Any, Exception | None], dict[str, Any]] | None = None,
):
    """
    AOP-like business logging decorator.
    Logs one success/failure event around the wrapped function call.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            err: Exception | None = None
            result: Any = None
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as exc:  # noqa: BLE001
                err = exc
                raise
            finally:
                level = logging.ERROR if err else logging.INFO
                payload = {"success": err is None}
                if err is not None:
                    payload["error"] = str(err)
                if data_builder:
                    try:
                        payload.update(data_builder(args, kwargs, result, err) or {})
                    except Exception:  # noqa: BLE001
                        payload["data_builder_error"] = True
                log_business_event(
                    _active_logger(),
                    event,
                    level=level,
                    tags=tags or ["business", "aop"],
                    data=payload,
                )

        return wrapper

    return decorator


def dependency_log_aspect(
    dependency: str,
    operation: str,
    *,
    tags: list[str] | None = None,
    data_builder: Callable[[tuple, dict, Any, Exception | None], dict[str, Any]] | None = None,
):
    """
    AOP-like dependency logging decorator.
    Logs dependency call result and elapsed time for the wrapped function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            err: Exception | None = None
            result: Any = None
            success = True
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as exc:  # noqa: BLE001
                err = exc
                success = False
                raise
            finally:
                payload: dict[str, Any] = {}
                # Convention: (data, error) or (..., error) and error is truthy means failure
                if err is None and isinstance(result, tuple) and result:
                    maybe_error = result[-1]
                    if isinstance(maybe_error, str) and maybe_error:
                        success = False
                        payload["error"] = maybe_error
                if err is not None:
                    payload["error"] = str(err)
                if data_builder:
                    try:
                        payload.update(data_builder(args, kwargs, result, err) or {})
                    except Exception:  # noqa: BLE001
                        payload["data_builder_error"] = True
                log_dependency_call(
                    _active_logger(),
                    dependency,
                    operation,
                    success=success,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    tags=tags or ["dependency", "aop"],
                    data=payload,
                )

        return wrapper

    return decorator


def register_error_handlers(app) -> None:
    @app.errorhandler(Exception)
    def _handle_unexpected_error(exc):
        if isinstance(exc, HTTPException):
            return exc
        g._error_already_logged = True
        app.logger.exception(
            "unhandled_exception",
            extra={
                "event": "app.error.unhandled_exception",
                "tags": ["error", "exception", "unhandled"],
            },
        )
        return {"error": "服务器内部错误", "request_id": getattr(g, "request_id", None)}, 500


def _try_bind_identity_from_token(app) -> None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return
    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET_KEY"],
            algorithms=[app.config.get("JWT_ALGORITHM", "HS256")],
        )
    except Exception:
        g.log_auth_state = "invalid_token"
        return
    g.log_user_id = payload.get("user_id")
    g.log_username = payload.get("username")
    g.log_role = payload.get("role")
    g.log_is_admin = bool(payload.get("is_admin"))
    g.log_auth_state = "token_verified"
