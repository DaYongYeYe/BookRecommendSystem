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
        if 'age' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN age INT NULL")
        if 'province' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN province VARCHAR(64) NULL")
        if 'city' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN city VARCHAR(64) NULL")
        if 'is_super_admin' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN is_super_admin TINYINT(1) NOT NULL DEFAULT 0")
        if 'tenant_id' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")
        if 'created_at' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP")
        if 'updated_at' not in user_columns:
            patches.append(
                "ALTER TABLE users ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
            )

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
            if 'score' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN score DOUBLE NULL")
            if 'rating' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN rating DOUBLE NULL")
            if 'rating_count' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN rating_count BIGINT NOT NULL DEFAULT 0")
            if 'recent_reads' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN recent_reads BIGINT NOT NULL DEFAULT 0")
            if 'home_recommendation_reason' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN home_recommendation_reason VARCHAR(255) NULL")
            if 'search_keywords' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN search_keywords VARCHAR(255) NULL")
            if 'is_featured' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN is_featured TINYINT(1) NOT NULL DEFAULT 0")
            if 'category_id' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN category_id INT NULL")
            if 'word_count' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN word_count INT NOT NULL DEFAULT 0")
            if 'completion_status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN completion_status VARCHAR(20) NOT NULL DEFAULT 'ongoing'")
            if 'suitable_audience' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN suitable_audience VARCHAR(255) NULL")
            if 'status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'published'")
            if 'creator_id' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN creator_id BIGINT NULL")
            if 'published_at' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN published_at DATETIME NULL")
            if 'tenant_id' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")

        if 'reader_book_comments' in table_names:
            rbc_columns = {col['name'] for col in inspector.get_columns('reader_book_comments')}
            if 'is_violation' not in rbc_columns:
                patches.append("ALTER TABLE reader_book_comments ADD COLUMN is_violation TINYINT(1) NOT NULL DEFAULT 0")
            if 'violation_reason' not in rbc_columns:
                patches.append("ALTER TABLE reader_book_comments ADD COLUMN violation_reason VARCHAR(255) NULL")
            if 'moderated_at' not in rbc_columns:
                patches.append("ALTER TABLE reader_book_comments ADD COLUMN moderated_at DATETIME NULL")
            if 'moderated_by' not in rbc_columns:
                patches.append("ALTER TABLE reader_book_comments ADD COLUMN moderated_by BIGINT NULL")
            if 'tenant_id' not in rbc_columns:
                patches.append("ALTER TABLE reader_book_comments ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")

        if 'reader_highlight_comments' in table_names:
            rhc_columns = {col['name'] for col in inspector.get_columns('reader_highlight_comments')}
            if 'is_violation' not in rhc_columns:
                patches.append("ALTER TABLE reader_highlight_comments ADD COLUMN is_violation TINYINT(1) NOT NULL DEFAULT 0")
            if 'violation_reason' not in rhc_columns:
                patches.append("ALTER TABLE reader_highlight_comments ADD COLUMN violation_reason VARCHAR(255) NULL")
            if 'moderated_at' not in rhc_columns:
                patches.append("ALTER TABLE reader_highlight_comments ADD COLUMN moderated_at DATETIME NULL")
            if 'moderated_by' not in rhc_columns:
                patches.append("ALTER TABLE reader_highlight_comments ADD COLUMN moderated_by BIGINT NULL")
            if 'tenant_id' not in rhc_columns:
                patches.append("ALTER TABLE reader_highlight_comments ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")

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
                    tenant_id INT NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_book_manuscripts_book (book_id),
                    KEY idx_book_manuscripts_creator (creator_id)
                )
                """
            )
        else:
            manuscript_columns = {col['name'] for col in inspector.get_columns('book_manuscripts')}
            if 'tenant_id' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")

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

        if 'categories' not in table_names:
            patches.append(
                """
                CREATE TABLE categories (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    code VARCHAR(64) NOT NULL UNIQUE,
                    name VARCHAR(100) NOT NULL,
                    en_name VARCHAR(100) NULL,
                    description VARCHAR(255) NULL,
                    cover VARCHAR(500) NULL,
                    is_highlighted TINYINT(1) NOT NULL DEFAULT 0
                )
                """
            )

        if 'tags' not in table_names:
            patches.append(
                """
                CREATE TABLE tags (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    code VARCHAR(64) NOT NULL UNIQUE,
                    label VARCHAR(100) NOT NULL
                )
                """
            )

        if 'book_tags' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE book_tags (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    book_id {books_id_type} NOT NULL,
                    tag_id BIGINT UNSIGNED NOT NULL,
                    UNIQUE KEY uniq_book_tag (book_id, tag_id),
                    KEY idx_bt_tag (tag_id)
                )
                """
            )

        if 'book_rankings' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE book_rankings (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    type VARCHAR(64) NOT NULL,
                    rank_no INT NOT NULL,
                    book_id {books_id_type} NOT NULL,
                    snapshot_date DATE NOT NULL,
                    UNIQUE KEY uniq_type_date_rank (type, snapshot_date, rank_no),
                    KEY idx_br_book (book_id)
                )
                """
            )

        if 'book_analytics_events' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE book_analytics_events (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    book_id {books_id_type} NOT NULL,
                    user_id {users_id_type} NULL,
                    event_type VARCHAR(32) NOT NULL,
                    session_id VARCHAR(64) NULL,
                    read_duration_seconds INT NOT NULL DEFAULT 0,
                    geo_label VARCHAR(100) NULL,
                    age_group VARCHAR(32) NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_bae_book (book_id),
                    KEY idx_bae_user (user_id),
                    KEY idx_bae_event (event_type),
                    KEY idx_bae_session (session_id),
                    KEY idx_bae_created_at (created_at)
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

        # Safety bootstrap: ensure at least one super admin exists for default tenant.
        try:
            super_admin_count = db.session.execute(
                text("SELECT COUNT(1) AS c FROM users WHERE role='admin' AND is_super_admin=1")
            ).scalar() or 0
            if super_admin_count == 0:
                first_admin_id = db.session.execute(
                    text("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1")
                ).scalar()
                if first_admin_id:
                    db.session.execute(
                        text("UPDATE users SET is_super_admin=1 WHERE id=:uid"),
                        {'uid': int(first_admin_id)},
                    )
                    db.session.commit()
                    app.logger.info("Promoted first admin user to super admin: user_id=%s", first_admin_id)
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Skip super admin bootstrap due to error: %s", exc)


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
