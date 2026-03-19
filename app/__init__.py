from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from config import Config

db = SQLAlchemy()
redis_client = FlaskRedis()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Allow local frontend dev server to call backend APIs.
    CORS(
        app,
        resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}},
        supports_credentials=True,
    )
    
    db.init_app(app)
    if app.config.get('REDIS_URL'):
        redis_client.init_app(app)
    
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    from app.user import bp as user_bp
    app.register_blueprint(user_bp, url_prefix='/user')
    
    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    from app.rbac import bp as rbac_bp
    app.register_blueprint(rbac_bp, url_prefix='/rbac')

    from app.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    @app.cli.command('init-db')
    def init_db_command():
        """Initialize database tables."""
        with app.app_context():
            db.create_all()
        print('Database tables initialized.')
    
    return app