import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    # 更新数据库URI以使用MySQL
    SQLALCHEMY_DATABASE_URI = (os.environ.get('DATABASE_URL') or
                              'mysql+pymysql://book_user:book_password@localhost/book_recommend_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # 更新Redis URI以匹配本地Docker实例
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'