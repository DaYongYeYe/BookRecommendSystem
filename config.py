import os

from dotenv import load_dotenv
load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    # 优先使用环境变量中的数据库连接；未配置时回退到本地 SQLite，便于本机快速启动
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
 
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Redis 可选：未配置时不初始化 Redis
    REDIS_URL = os.environ.get('REDIS_URL')

    # JWT 配置
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRES_IN = int(os.environ.get('JWT_EXPIRES_IN', 7200))  # 单位：秒，默认2小时
    # 管理员注册码（为空时禁止管理员自行注册）
    ADMIN_REGISTER_CODE = os.environ.get('ADMIN_REGISTER_CODE', '')
    UPLOAD_DIR = os.environ.get('UPLOAD_DIR') or os.path.join('instance', 'uploads')
    COVER_UPLOAD_SUBDIR = os.environ.get('COVER_UPLOAD_SUBDIR', 'book_covers')
    MAX_COVER_UPLOAD_SIZE = int(os.environ.get('MAX_COVER_UPLOAD_SIZE', 5 * 1024 * 1024))
