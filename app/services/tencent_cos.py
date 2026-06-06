from __future__ import annotations

from hashlib import md5
from io import BytesIO
from urllib.parse import urlparse
from urllib.request import urlopen
from uuid import uuid4

from flask import current_app
from qcloud_cos import CosConfig, CosS3Client
from app.logging_utils import dependency_log_aspect


@dependency_log_aspect('tencent_cos', 'build_client', tags=['dependency', 'cos', 'aop'])
def _build_cos_client():
    secret_id = (current_app.config.get('COS_SECRET_ID') or '').strip()
    secret_key = (current_app.config.get('COS_SECRET_KEY') or '').strip()
    region = (current_app.config.get('COS_REGION') or '').strip()
    bucket = (current_app.config.get('COS_BUCKET') or '').strip()

    if not all([secret_id, secret_key, region, bucket]):
        return None, None, 'cos not configured'
    if not secret_id.startswith('AKID'):
        return None, None, 'invalid cos secret id'

    config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key)
    client = CosS3Client(config)
    return client, bucket, None


def _object_url(bucket: str, region: str, object_key: str) -> str:
    custom_domain = (current_app.config.get('COS_DOMAIN') or '').strip()
    if custom_domain:
        base = custom_domain.rstrip('/')
        return f'{base}/{object_key}'
    return f'https://{bucket}.cos.{region}.myqcloud.com/{object_key}'


def _object_key_from_url(url: str, bucket: str, region: str) -> str | None:
    parsed = urlparse(url or '')
    path = parsed.path.lstrip('/')
    if not parsed.netloc or not path:
        return None

    custom_domain = (current_app.config.get('COS_DOMAIN') or '').strip()
    if custom_domain:
        custom = urlparse(custom_domain)
        if parsed.netloc == custom.netloc:
            custom_path = custom.path.strip('/')
            if custom_path and path.startswith(f'{custom_path}/'):
                return path[len(custom_path) + 1:]
            return path

    expected_host = f'{bucket}.cos.{region}.myqcloud.com'
    if parsed.netloc == expected_host:
        return path
    return None


@dependency_log_aspect('tencent_cos', 'upload_image', tags=['dependency', 'cos', 'upload', 'aop'])
def upload_image(file_obj, *, folder: str, allowed_extensions: set[str], max_size: int):
    if not file_obj:
        return None, 'file is required'

    filename = (file_obj.filename or '').strip()
    if '.' not in filename:
        return None, 'invalid file name'

    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in allowed_extensions:
        return None, 'file type not allowed'

    file_obj.stream.seek(0, 2)
    size = file_obj.stream.tell()
    file_obj.stream.seek(0)
    if size > max_size:
        return None, 'file too large'

    client, bucket, error = _build_cos_client()
    if error:
        return None, error

    region = (current_app.config.get('COS_REGION') or '').strip()
    object_key = f'{folder.rstrip("/")}/{uuid4().hex}.{ext}'
    try:
        client.put_object(
            Bucket=bucket,
            Body=file_obj.stream,
            Key=object_key,
            ContentType=file_obj.mimetype or 'application/octet-stream',
        )
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception(
            'cos_upload_exception',
            extra={
                'event': 'dependency.tencent_cos.upload.exception',
                'tags': ['dependency', 'cos', 'upload', 'exception'],
                'data': {
                    'bucket': bucket,
                    'region': region,
                    'object_key': object_key,
                    'error': str(exc),
                },
            },
        )
        return None, 'cos upload failed'

    return _object_url(bucket, region, object_key), None


@dependency_log_aspect('tencent_cos', 'upload_image_bytes', tags=['dependency', 'cos', 'upload', 'aop'])
def upload_image_bytes(
    content: bytes,
    *,
    filename: str,
    mimetype: str,
    folder: str,
    allowed_extensions: set[str],
    max_size: int,
):
    if not content:
        return None, 'file is required'

    filename = (filename or '').strip()
    if '.' not in filename:
        return None, 'invalid file name'

    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in allowed_extensions:
        return None, 'file type not allowed'

    if len(content) > max_size:
        return None, 'file too large'

    client, bucket, error = _build_cos_client()
    if error:
        return None, error

    region = (current_app.config.get('COS_REGION') or '').strip()
    object_key = f'{folder.rstrip("/")}/{uuid4().hex}.{ext}'
    try:
        client.put_object(
            Bucket=bucket,
            Body=BytesIO(content),
            Key=object_key,
            ContentType=mimetype or 'application/octet-stream',
        )
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception(
            'cos_upload_exception',
            extra={
                'event': 'dependency.tencent_cos.upload.exception',
                'tags': ['dependency', 'cos', 'upload', 'exception'],
                'data': {
                    'bucket': bucket,
                    'region': region,
                    'object_key': object_key,
                    'error': str(exc),
                },
            },
        )
        return None, 'cos upload failed'

    return _object_url(bucket, region, object_key), None


@dependency_log_aspect('tencent_cos', 'upload_text', tags=['dependency', 'cos', 'upload', 'text', 'aop'])
def upload_text(content: str, *, folder: str = 'book_chapters'):
    text = content or ''
    payload = text.encode('utf-8')
    if not payload:
        return None, 'content is required'

    client, bucket, error = _build_cos_client()
    if error:
        return None, error

    region = (current_app.config.get('COS_REGION') or '').strip()
    digest = md5(payload).hexdigest()
    object_key = f'{folder.rstrip("/")}/{digest[:2]}/{uuid4().hex}.txt'
    try:
        client.put_object(
            Bucket=bucket,
            Body=BytesIO(payload),
            Key=object_key,
            ContentType='text/plain; charset=utf-8',
        )
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception(
            'cos_text_upload_exception',
            extra={
                'event': 'dependency.tencent_cos.text_upload.exception',
                'tags': ['dependency', 'cos', 'upload', 'text', 'exception'],
                'data': {
                    'bucket': bucket,
                    'region': region,
                    'object_key': object_key,
                    'error': str(exc),
                },
            },
        )
        return None, 'cos upload failed'

    return {'url': _object_url(bucket, region, object_key), 'md5': digest}, None


@dependency_log_aspect('tencent_cos', 'fetch_text', tags=['dependency', 'cos', 'download', 'text', 'aop'])
def fetch_text(url: str, expected_md5: str | None = None):
    target_url = (url or '').strip()
    if not target_url:
        return None, 'content url is required'

    client, bucket, cos_error = _build_cos_client()
    region = (current_app.config.get('COS_REGION') or '').strip()
    content: bytes | None = None

    object_key = _object_key_from_url(target_url, bucket or '', region) if bucket and region else None
    if client and bucket and object_key:
        try:
            response = client.get_object(Bucket=bucket, Key=object_key)
            content = response['Body'].get_raw_stream().read()
        except Exception as exc:  # noqa: BLE001
            current_app.logger.exception(
                'cos_text_fetch_exception',
                extra={
                    'event': 'dependency.tencent_cos.text_fetch.exception',
                    'tags': ['dependency', 'cos', 'download', 'text', 'exception'],
                    'data': {
                        'bucket': bucket,
                        'region': region,
                        'object_key': object_key,
                        'error': str(exc),
                    },
                },
            )
            return None, 'cos fetch failed'
    else:
        if cos_error and not target_url.lower().startswith(('http://', 'https://')):
            return None, cos_error
        try:
            with urlopen(target_url, timeout=15) as response:  # noqa: S310 - configured content URL.
                content = response.read()
        except Exception as exc:  # noqa: BLE001
            current_app.logger.exception(
                'cos_text_url_fetch_exception',
                extra={
                    'event': 'dependency.tencent_cos.text_url_fetch.exception',
                    'tags': ['dependency', 'cos', 'download', 'text', 'exception'],
                    'data': {'url': target_url, 'error': str(exc)},
                },
            )
            return None, 'content fetch failed'

    digest = md5(content or b'').hexdigest()
    if expected_md5 and digest.lower() != expected_md5.lower():
        return None, 'content md5 mismatch'
    return (content or b'').decode('utf-8', errors='replace'), None
