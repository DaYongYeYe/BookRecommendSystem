from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from config import Config

db = SQLAlchemy()
redis_client = FlaskRedis()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    db.init_app(app)
    redis_client.init_app(app)
    
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    from app.user import bp as user_bp
    app.register_blueprint(user_bp, url_prefix='/user')
    
    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    from app.rbac import bp as rbac_bp
    app.register_blueprint(rbac_bp, url_prefix='/rbac')
    
    @app.before_first_request
    def create_tables():
        db.create_all()
    
    return app