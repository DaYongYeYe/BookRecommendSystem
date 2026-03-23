from __future__ import annotations

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
