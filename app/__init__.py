import os

from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from sqlalchemy import inspect, text
from config import Config
from app.logging_utils import attach_request_hooks, register_error_handlers, setup_logging

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

        if 'books' in table_names:
            book_columns = {col['name'] for col in inspector.get_columns('books')}
            if 'status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'published'")
            if 'creator_id' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN creator_id BIGINT NULL")
            if 'published_at' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN published_at DATETIME NULL")

        users_id_type = 'BIGINT'
        users_id_column = next((col for col in inspector.get_columns('users') if col.get('name') == 'id'), None)
        if users_id_column:
            raw_type = str(users_id_column.get('type', '')).upper()
            if 'INT' in raw_type and 'BIGINT' not in raw_type:
                users_id_type = 'INT'
            if 'UNSIGNED' in raw_type:
                users_id_type = f'{users_id_type} UNSIGNED'

        books_id_type = 'BIGINT'
        if 'books' in table_names:
            books_id_column = next((col for col in inspector.get_columns('books') if col.get('name') == 'id'), None)
            if books_id_column:
                raw_type = str(books_id_column.get('type', '')).upper()
                if 'INT' in raw_type and 'BIGINT' not in raw_type:
                    books_id_type = 'INT'
                if 'UNSIGNED' in raw_type:
                    books_id_type = f'{books_id_type} UNSIGNED'

        if 'book_manuscripts' not in table_names:
            patches.append(
                f"""
                CREATE TABLE book_manuscripts (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    book_id {books_id_type} NOT NULL,
                    creator_id {users_id_type} NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    cover VARCHAR(500) NULL,
                    description TEXT NULL,
                    content_text LONGTEXT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'draft',
                    review_comment TEXT NULL,
                    submitted_at DATETIME NULL,
                    reviewed_at DATETIME NULL,
                    reviewed_by {users_id_type} NULL,
                    published_at DATETIME NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_book_manuscripts_book (book_id),
                    KEY idx_book_manuscripts_creator (creator_id)
                )
                """
            )

        if 'book_versions' not in table_names:
            patches.append(
                f"""
                CREATE TABLE book_versions (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    book_id {books_id_type} NOT NULL,
                    manuscript_id BIGINT UNSIGNED NULL,
                    version_no INT NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    cover VARCHAR(500) NULL,
                    description TEXT NULL,
                    content_text LONGTEXT NULL,
                    created_by {users_id_type} NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_book_version_no (book_id, version_no),
                    KEY idx_book_versions_book (book_id)
                )
                """
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
    setup_logging(app)

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

    from app.creator import bp as creator_bp
    app.register_blueprint(creator_bp, url_prefix='/creator')
    
    from app.rbac import bp as rbac_bp
    app.register_blueprint(rbac_bp, url_prefix='/rbac')

    from app.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    @app.route('/uploads/<path:filename>', methods=['GET'])
    def uploaded_files(filename):
        upload_root = app.config.get('UPLOAD_DIR') or os.path.join(app.instance_path, 'uploads')
        return send_from_directory(upload_root, filename)

    attach_request_hooks(app)
    register_error_handlers(app)

    @app.cli.command('init-db')
    def init_db_command():
        """Initialize database tables."""
        with app.app_context():
            db.create_all()
        print('Database tables initialized.')
    
    return app
