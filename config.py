import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ.get('REDIS_URL')

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRES_IN = int(os.environ.get('JWT_EXPIRES_IN', 7200))
    CAPTCHA_EXPIRES_IN = int(os.environ.get('CAPTCHA_EXPIRES_IN', 300))

    AUTH_CODE_EXPIRES_IN = int(os.environ.get('AUTH_CODE_EXPIRES_IN', 600))
    AUTH_CODE_RESEND_SECONDS = int(os.environ.get('AUTH_CODE_RESEND_SECONDS', 60))
    AUTH_CODE_MAX_ATTEMPTS = int(os.environ.get('AUTH_CODE_MAX_ATTEMPTS', 5))
    AUTH_CODE_REQUIRE_CAPTCHA = os.environ.get('AUTH_CODE_REQUIRE_CAPTCHA', '1').lower() in ('1', 'true', 'yes', 'on')
    AUTH_CODE_MAX_PER_IP_PER_HOUR = int(os.environ.get('AUTH_CODE_MAX_PER_IP_PER_HOUR', 10))
    AUTH_CODE_MAX_PER_IP_PER_DAY = int(os.environ.get('AUTH_CODE_MAX_PER_IP_PER_DAY', 30))
    AUTH_CODE_MAX_PER_EMAIL_PER_HOUR = int(os.environ.get('AUTH_CODE_MAX_PER_EMAIL_PER_HOUR', 5))
    AUTH_CODE_MAX_PER_EMAIL_PER_DAY = int(os.environ.get('AUTH_CODE_MAX_PER_EMAIL_PER_DAY', 10))

    AUTH_NOTIFICATION_PROVIDER = os.environ.get('AUTH_NOTIFICATION_PROVIDER', 'smtp')
    SMTP_HOST = os.environ.get('SMTP_HOST', '')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 465))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    SMTP_FROM_EMAIL = os.environ.get('SMTP_FROM_EMAIL', '')
    SMTP_FROM_NAME = os.environ.get('SMTP_FROM_NAME', 'Book Recommend')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', '0').lower() in ('1', 'true', 'yes', 'on')
    SMTP_USE_SSL = os.environ.get('SMTP_USE_SSL', '1').lower() in ('1', 'true', 'yes', 'on')

    ADMIN_REGISTER_CODE = os.environ.get('ADMIN_REGISTER_CODE', '')
    DEFAULT_TENANT_ID = int(os.environ.get('DEFAULT_TENANT_ID', 1))
    UPLOAD_DIR = os.environ.get('UPLOAD_DIR') or os.path.join('instance', 'uploads')
    COVER_UPLOAD_SUBDIR = os.environ.get('COVER_UPLOAD_SUBDIR', 'book_covers')
    MAX_COVER_UPLOAD_SIZE = int(os.environ.get('MAX_COVER_UPLOAD_SIZE', 5 * 1024 * 1024))
    MAX_AVATAR_UPLOAD_SIZE = int(os.environ.get('MAX_AVATAR_UPLOAD_SIZE', 2 * 1024 * 1024))

    COS_SECRET_ID = os.environ.get('COS_SECRET_ID')
    COS_SECRET_KEY = os.environ.get('COS_SECRET_KEY')
    COS_REGION = os.environ.get('COS_REGION')
    COS_BUCKET = os.environ.get('COS_BUCKET')
    COS_DOMAIN = os.environ.get('COS_DOMAIN')

    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_DIR = os.environ.get('LOG_DIR') or os.path.join('instance', 'logs')
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 14))
