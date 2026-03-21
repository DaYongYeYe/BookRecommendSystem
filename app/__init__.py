from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from sqlalchemy import inspect, text
from config import Config

db = SQLAlchemy()
redis_client = FlaskRedis()


def _apply_schema_compatibility_patches(app: Flask):
    """
    Apply lightweight compatibility patches for legacy databases.
    This keeps old local DBs usable after model evolution.
    """
    with app.app_context():
        inspector = inspect(db.engine)
        table_names = set(inspector.get_table_names())
        if 'users' not in table_names:
            return

        user_columns = {col['name'] for col in inspector.get_columns('users')}
        patches = []

        if 'name' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN name VARCHAR(80) NULL")
        if 'avatar_url' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500) NULL")

        if 'reader_user_preferences' not in table_names:
            user_id_type = 'INT'
            users_id_column = next((col for col in inspector.get_columns('users') if col.get('name') == 'id'), None)
            if users_id_column:
                raw_type = str(users_id_column.get('type', '')).upper()
                if 'BIGINT' in raw_type:
                    user_id_type = 'BIGINT'
                if 'UNSIGNED' in raw_type:
                    user_id_type = f'{user_id_type} UNSIGNED'
            patches.append(
                """
                CREATE TABLE reader_user_preferences (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id {user_id_type} NOT NULL UNIQUE,
                    theme VARCHAR(16) NOT NULL DEFAULT 'light',
                    font_size INT NOT NULL DEFAULT 20,
                    show_highlights TINYINT(1) NOT NULL DEFAULT 1,
                    show_comments TINYINT(1) NOT NULL DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
                """
                .replace('{user_id_type}', user_id_type)
            )

        if not patches:
            return

        applied = []
        for sql in patches:
            try:
                db.session.execute(text(sql))
                applied.append(sql.strip().split('\n')[0][:80])
            except Exception as exc:
                db.session.rollback()
                app.logger.warning("Skip compatibility patch due to error: %s", exc)
        if applied:
            db.session.commit()
            app.logger.info("Applied schema compatibility patches: %s", ", ".join(applied))


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Allow local frontend dev server to call backend APIs.
    CORS(
        app,
        resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"]}},
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    )
    
    db.init_app(app)
    if app.config.get('REDIS_URL'):
        redis_client.init_app(app)

    _apply_schema_compatibility_patches(app)
    
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
