import os

import click
from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from sqlalchemy import inspect, text
from config import Config
from app.logging_utils import attach_request_hooks, register_error_handlers, setup_logging
from app.services.work_catalog import WORK_CATEGORY_TAXONOMY, WORK_TAG_LIBRARY

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
        users_id_column = next((col for col in inspector.get_columns('users') if col.get('name') == 'id'), None)
        users_id_type = 'INT'
        if users_id_column:
            raw_type = str(users_id_column.get('type', '')).upper()
            if 'BIGINT' in raw_type:
                users_id_type = 'BIGINT'
            if 'UNSIGNED' in raw_type:
                users_id_type = f'{users_id_type} UNSIGNED'
        patches = []

        if 'name' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN name VARCHAR(80) NULL")
        if 'pen_name' not in user_columns:
            patches.append("ALTER TABLE users ADD COLUMN pen_name VARCHAR(80) NULL")
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

        if 'creator_profiles' not in table_names:
            patches.append(
                f"""
                CREATE TABLE creator_profiles (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    tenant_id INT NOT NULL DEFAULT 1,
                    status VARCHAR(20) NOT NULL DEFAULT 'active',
                    activated_by {users_id_type} NULL,
                    activated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    deactivated_at DATETIME NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_creator_profile_user_tenant (user_id, tenant_id),
                    KEY idx_creator_profiles_user (user_id),
                    KEY idx_creator_profiles_tenant (tenant_id),
                    KEY idx_creator_profiles_status (status)
                )
                """
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
                    line_height FLOAT NOT NULL DEFAULT 2.0,
                    margin VARCHAR(16) NOT NULL DEFAULT 'medium',
                    show_highlights TINYINT(1) NOT NULL DEFAULT 1,
                    show_comments TINYINT(1) NOT NULL DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
                """
                .replace('{user_id_type}', user_id_type)
            )
        else:
            rup_columns = {col['name'] for col in inspector.get_columns('reader_user_preferences')}
            if 'line_height' not in rup_columns:
                patches.append("ALTER TABLE reader_user_preferences ADD COLUMN line_height FLOAT NOT NULL DEFAULT 2.0")
            if 'margin' not in rup_columns:
                patches.append("ALTER TABLE reader_user_preferences ADD COLUMN margin VARCHAR(16) NOT NULL DEFAULT 'medium'")

        if 'user_search_history' not in table_names:
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
                CREATE TABLE user_search_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id {user_id_type} NOT NULL,
                    keyword VARCHAR(100) NOT NULL,
                    search_count INT NOT NULL DEFAULT 1,
                    last_searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_user_search_keyword (user_id, keyword),
                    KEY idx_ush_user (user_id),
                    KEY idx_ush_last_searched_at (last_searched_at)
                )
                """
                .replace('{user_id_type}', user_id_type)
            )

        if 'user_achievements' not in table_names:
            achievement_user_id_type = 'INT'
            users_id_column = next((col for col in inspector.get_columns('users') if col.get('name') == 'id'), None)
            if users_id_column:
                raw_type = str(users_id_column.get('type', '')).upper()
                if 'BIGINT' in raw_type:
                    achievement_user_id_type = 'BIGINT'
                if 'UNSIGNED' in raw_type:
                    achievement_user_id_type = f'{achievement_user_id_type} UNSIGNED'
            patches.append(
                f"""
                CREATE TABLE user_achievements (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {achievement_user_id_type} NOT NULL,
                    achievement_key VARCHAR(64) NOT NULL,
                    title VARCHAR(100) NOT NULL,
                    description VARCHAR(255) NULL,
                    unlocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_user_achievement_key (user_id, achievement_key),
                    KEY idx_user_achievements_user (user_id),
                    KEY idx_user_achievements_unlocked_at (unlocked_at)
                )
                """
            )

        if 'books' in table_names:
            book_columns = {col['name'] for col in inspector.get_columns('books')}
            if 'subtitle' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN subtitle VARCHAR(255) NULL")
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
            if 'subcategory_code' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN subcategory_code VARCHAR(64) NULL")
            if 'word_count' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN word_count INT NOT NULL DEFAULT 0")
            if 'completion_status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN completion_status VARCHAR(20) NOT NULL DEFAULT 'ongoing'")
            if 'suitable_audience' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN suitable_audience VARCHAR(255) NULL")
            if 'price_type' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN price_type VARCHAR(20) NOT NULL DEFAULT 'free'")
            if 'creation_type' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN creation_type VARCHAR(20) NOT NULL DEFAULT 'original'")
            if 'protagonist' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN protagonist TEXT NULL")
            if 'worldview' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN worldview TEXT NULL")
            if 'author_message' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN author_message TEXT NULL")
            if 'author_notice' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN author_notice TEXT NULL")
            if 'copyright_notice' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN copyright_notice TEXT NULL")
            if 'update_note' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN update_note TEXT NULL")
            if 'audit_status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN audit_status VARCHAR(20) NOT NULL DEFAULT 'draft'")
            if 'audit_comment' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN audit_comment TEXT NULL")
            if 'shelf_status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN shelf_status VARCHAR(20) NOT NULL DEFAULT 'down'")
            if 'off_shelf_reason' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN off_shelf_reason VARCHAR(255) NULL")
            if 'audit_submitted_at' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN audit_submitted_at DATETIME NULL")
            if 'status' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'published'")
            if 'creator_id' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN creator_id BIGINT NULL")
            if 'published_at' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN published_at DATETIME NULL")
            if 'updated_at' not in book_columns:
                patches.append(
                    "ALTER TABLE books ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
                )
            if 'tenant_id' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")
            if 'is_deleted' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0")
            if 'deleted_at' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN deleted_at DATETIME NULL")
            if 'deleted_by' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN deleted_by BIGINT NULL")
            if 'delete_snapshot' not in book_columns:
                patches.append("ALTER TABLE books ADD COLUMN delete_snapshot LONGTEXT NULL")

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
                    content_url VARCHAR(1000) NULL,
                    content_md5 CHAR(32) NULL,
                    chapter_payload LONGTEXT NULL,
                    chapter_payload_url VARCHAR(1000) NULL,
                    chapter_payload_md5 CHAR(32) NULL,
                    update_mode VARCHAR(20) NOT NULL DEFAULT 'create',
                    status VARCHAR(20) NOT NULL DEFAULT 'draft',
                    review_comment TEXT NULL,
                    submitted_at DATETIME NULL,
                    reviewed_at DATETIME NULL,
                    reviewed_by {users_id_type} NULL,
                    published_at DATETIME NULL,
                    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
                    deleted_at DATETIME NULL,
                    deleted_by {users_id_type} NULL,
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
            if 'chapter_payload' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN chapter_payload LONGTEXT NULL")
            if 'content_url' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN content_url VARCHAR(1000) NULL")
            if 'content_md5' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN content_md5 CHAR(32) NULL")
            if 'chapter_payload_url' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN chapter_payload_url VARCHAR(1000) NULL")
            if 'chapter_payload_md5' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN chapter_payload_md5 CHAR(32) NULL")
            if 'update_mode' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN update_mode VARCHAR(20) NOT NULL DEFAULT 'create'")
            if 'is_deleted' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0")
            if 'deleted_at' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN deleted_at DATETIME NULL")
            if 'deleted_by' not in manuscript_columns:
                patches.append("ALTER TABLE book_manuscripts ADD COLUMN deleted_by BIGINT NULL")

        if 'creator_applications' not in table_names:
            patches.append(
                f"""
                CREATE TABLE creator_applications (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    tenant_id INT NOT NULL DEFAULT 1,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    apply_reason TEXT NULL,
                    review_comment TEXT NULL,
                    reviewed_by {users_id_type} NULL,
                    reviewed_at DATETIME NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_creator_app_user (user_id),
                    KEY idx_creator_app_status (status),
                    KEY idx_creator_app_tenant (tenant_id)
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
                    content_url VARCHAR(1000) NULL,
                    content_md5 CHAR(32) NULL,
                    created_by {users_id_type} NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_book_version_no (book_id, version_no),
                    KEY idx_book_versions_book (book_id)
                )
                """
            )
        else:
            version_columns = {col['name'] for col in inspector.get_columns('book_versions')}
            if 'content_url' not in version_columns:
                patches.append("ALTER TABLE book_versions ADD COLUMN content_url VARCHAR(1000) NULL")
            if 'content_md5' not in version_columns:
                patches.append("ALTER TABLE book_versions ADD COLUMN content_md5 CHAR(32) NULL")

        if 'book_chapters' not in table_names:
            patches.append(
                f"""
                CREATE TABLE book_chapters (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    book_id {books_id_type} NOT NULL,
                    chapter_key VARCHAR(64) NOT NULL,
                    chapter_no INT NOT NULL DEFAULT 1,
                    title VARCHAR(255) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'draft',
                    published_revision_id BIGINT UNSIGNED NULL,
                    tenant_id INT NOT NULL DEFAULT 1,
                    created_by {users_id_type} NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_book_chapter_key (book_id, chapter_key),
                    UNIQUE KEY uniq_book_chapter_no (book_id, chapter_no),
                    KEY idx_book_chapters_tenant (tenant_id)
                )
                """
            )
        else:
            chapter_columns = {col['name'] for col in inspector.get_columns('book_chapters')}
            needs_chapter_key_backfill = 'chapter_key' not in chapter_columns
            needs_chapter_no_backfill = 'chapter_no' not in chapter_columns
            if 'chapter_key' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN chapter_key VARCHAR(64) NULL")
            if 'chapter_no' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN chapter_no INT NOT NULL DEFAULT 1")
            if 'published_revision_id' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN published_revision_id BIGINT UNSIGNED NULL")
            if 'tenant_id' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")
            if 'created_by' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN created_by BIGINT NULL")
            if 'status' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'draft'")
            if 'created_at' not in chapter_columns:
                patches.append("ALTER TABLE book_chapters ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP")
            if 'updated_at' not in chapter_columns:
                patches.append(
                    "ALTER TABLE book_chapters ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
                )
            if (needs_chapter_key_backfill or needs_chapter_no_backfill) and 'order_no' in chapter_columns:
                patches.append(
                    """
                    UPDATE book_chapters
                    SET chapter_key = CONCAT('chapter-', COALESCE(order_no, id))
                    WHERE chapter_key IS NULL OR chapter_key = ''
                    """
                )
                patches.append("UPDATE book_chapters SET chapter_no = COALESCE(order_no, chapter_no, id, 1)")
            elif needs_chapter_key_backfill or needs_chapter_no_backfill:
                patches.append(
                    """
                    UPDATE book_chapters
                    SET chapter_key = CONCAT('chapter-', id)
                    WHERE chapter_key IS NULL OR chapter_key = ''
                    """
                )
                patches.append("UPDATE book_chapters SET chapter_no = COALESCE(chapter_no, id, 1)")

        if 'book_chapter_revisions' not in table_names:
            patches.append(
                f"""
                CREATE TABLE book_chapter_revisions (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    chapter_id BIGINT UNSIGNED NOT NULL,
                    version_no INT NOT NULL DEFAULT 1,
                    title VARCHAR(255) NOT NULL,
                    content_text LONGTEXT NULL,
                    content_url VARCHAR(1000) NULL,
                    content_md5 CHAR(32) NULL,
                    summary TEXT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'draft',
                    review_comment TEXT NULL,
                    submitted_at DATETIME NULL,
                    reviewed_at DATETIME NULL,
                    reviewed_by {users_id_type} NULL,
                    published_at DATETIME NULL,
                    created_by {users_id_type} NULL,
                    tenant_id INT NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_chapter_revision_no (chapter_id, version_no),
                    KEY idx_chapter_revisions_tenant (tenant_id)
                )
                """
            )
        else:
            revision_columns = {col['name'] for col in inspector.get_columns('book_chapter_revisions')}
            if 'tenant_id' not in revision_columns:
                patches.append("ALTER TABLE book_chapter_revisions ADD COLUMN tenant_id INT NOT NULL DEFAULT 1")
            if 'created_by' not in revision_columns:
                patches.append("ALTER TABLE book_chapter_revisions ADD COLUMN created_by BIGINT NULL")
            if 'status' not in revision_columns:
                patches.append("ALTER TABLE book_chapter_revisions ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'draft'")
            if 'review_comment' not in revision_columns:
                patches.append("ALTER TABLE book_chapter_revisions ADD COLUMN review_comment TEXT NULL")
            if 'content_url' not in revision_columns:
                patches.append("ALTER TABLE book_chapter_revisions ADD COLUMN content_url VARCHAR(1000) NULL")
            if 'content_md5' not in revision_columns:
                patches.append("ALTER TABLE book_chapter_revisions ADD COLUMN content_md5 CHAR(32) NULL")

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

        if 'recommendation_feedback' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE recommendation_feedback (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    book_id {books_id_type} NOT NULL,
                    action VARCHAR(32) NOT NULL,
                    source_section VARCHAR(64) NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_rf_user_book (user_id, book_id),
                    KEY idx_rf_action (action),
                    KEY idx_rf_created_at (created_at)
                )
                """
            )
        else:
            feedback_columns = {col['name'] for col in inspector.get_columns('recommendation_feedback')} if 'recommendation_feedback' in table_names else set()
            if feedback_columns and 'source_section' not in feedback_columns:
                patches.append("ALTER TABLE recommendation_feedback ADD COLUMN source_section VARCHAR(64) NULL")

        if 'recommendation_placements' not in table_names:
            patches.append(
                """
                CREATE TABLE recommendation_placements (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    code VARCHAR(64) NOT NULL UNIQUE,
                    name VARCHAR(100) NOT NULL,
                    description VARCHAR(255) NULL,
                    scene VARCHAR(64) NOT NULL DEFAULT 'home',
                    strategy VARCHAR(64) NOT NULL DEFAULT 'manual',
                    max_items INT NOT NULL DEFAULT 6,
                    is_active TINYINT(1) NOT NULL DEFAULT 1,
                    sort_order INT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_recommendation_placements_scene (scene),
                    KEY idx_recommendation_placements_active (is_active),
                    KEY idx_recommendation_placements_sort (sort_order)
                )
                """
            )

        if 'recommendation_model_versions' not in table_names:
            patches.append(
                """
                CREATE TABLE recommendation_model_versions (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    version VARCHAR(64) NOT NULL UNIQUE,
                    embedding_dim INT NOT NULL DEFAULT 64,
                    artifact_dir VARCHAR(500) NULL,
                    metrics_json TEXT NULL,
                    is_active TINYINT(1) NOT NULL DEFAULT 0,
                    trained_at DATETIME NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_recommendation_model_versions_version (version),
                    KEY idx_recommendation_model_versions_active (is_active)
                )
                """
            )

        if 'recommendation_candidates' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE recommendation_candidates (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    model_version VARCHAR(64) NOT NULL,
                    book_id {books_id_type} NOT NULL,
                    rank_no INT NOT NULL DEFAULT 0,
                    score DOUBLE NOT NULL DEFAULT 0,
                    reason_type VARCHAR(64) NOT NULL DEFAULT 'two_tower',
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_recommendation_candidate_user_model_book (user_id, model_version, book_id),
                    KEY idx_recommendation_candidates_user (user_id),
                    KEY idx_recommendation_candidates_model (model_version),
                    KEY idx_recommendation_candidates_book (book_id),
                    KEY idx_recommendation_candidates_updated_at (updated_at)
                )
                """
            )

        if 'book_lists' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE book_lists (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    title VARCHAR(120) NOT NULL,
                    description VARCHAR(500) NULL,
                    visibility VARCHAR(20) NOT NULL DEFAULT 'public',
                    cover VARCHAR(500) NULL,
                    likes_count INT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_book_lists_user (user_id),
                    KEY idx_book_lists_visibility (visibility),
                    KEY idx_book_lists_created_at (created_at)
                )
                """
            )

        if 'book_list_items' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE book_list_items (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    list_id BIGINT UNSIGNED NOT NULL,
                    book_id {books_id_type} NOT NULL,
                    note VARCHAR(255) NULL,
                    sort_order INT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_book_list_book (list_id, book_id),
                    KEY idx_book_list_items_list (list_id),
                    KEY idx_book_list_items_book (book_id)
                )
                """
            )

        if 'community_book_reviews' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE community_book_reviews (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    book_id {books_id_type} NOT NULL,
                    title VARCHAR(120) NOT NULL,
                    content TEXT NOT NULL,
                    rating INT NULL,
                    visibility VARCHAR(20) NOT NULL DEFAULT 'public',
                    likes_count INT NOT NULL DEFAULT 0,
                    comments_count INT NOT NULL DEFAULT 0,
                    is_violation TINYINT(1) NOT NULL DEFAULT 0,
                    violation_reason VARCHAR(255) NULL,
                    moderated_at DATETIME NULL,
                    moderated_by {users_id_type} NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_community_reviews_user (user_id),
                    KEY idx_community_reviews_book (book_id),
                    KEY idx_community_reviews_visibility (visibility),
                    KEY idx_community_reviews_created_at (created_at)
                )
                """
            )

        if 'community_book_review_reactions' not in table_names:
            patches.append(
                f"""
                CREATE TABLE community_book_review_reactions (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    review_id BIGINT UNSIGNED NOT NULL,
                    user_id {users_id_type} NOT NULL,
                    reaction VARCHAR(20) NOT NULL DEFAULT 'like',
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_review_reaction_user (review_id, user_id),
                    KEY idx_community_review_reactions_review (review_id),
                    KEY idx_community_review_reactions_user (user_id)
                )
                """
            )

        if 'user_interest_tags' not in table_names:
            patches.append(
                f"""
                CREATE TABLE user_interest_tags (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    tag_id BIGINT UNSIGNED NOT NULL,
                    weight INT NOT NULL DEFAULT 0,
                    source_summary VARCHAR(255) NULL,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_user_interest_tag (user_id, tag_id),
                    KEY idx_user_interest_tags_user (user_id),
                    KEY idx_user_interest_tags_tag (tag_id),
                    KEY idx_user_interest_tags_updated_at (updated_at)
                )
                """
            )

        if 'reader_bookmarks' not in table_names and 'books' in table_names:
            patches.append(
                f"""
                CREATE TABLE reader_bookmarks (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    user_id {users_id_type} NOT NULL,
                    book_id {books_id_type} NOT NULL,
                    section_id VARCHAR(64) NOT NULL,
                    paragraph_id VARCHAR(64) NULL,
                    note VARCHAR(255) NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_reader_bookmark_position (user_id, book_id, section_id, paragraph_id),
                    KEY idx_rb_user_book (user_id, book_id),
                    KEY idx_rb_created_at (created_at)
                )
                """
            )

        if patches:
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

        try:
            refreshed_table_names = set(inspect(db.engine).get_table_names())
            if 'creator_profiles' in refreshed_table_names:
                db.session.execute(
                    text(
                        """
                        INSERT INTO creator_profiles (user_id, tenant_id, status, activated_at, created_at, updated_at)
                        SELECT u.id, COALESCE(u.tenant_id, 1), 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                        FROM users u
                        LEFT JOIN creator_profiles cp
                            ON cp.user_id = u.id AND cp.tenant_id = COALESCE(u.tenant_id, 1)
                        WHERE u.role = 'creator' AND cp.id IS NULL
                        """
                    )
                )
                db.session.execute(text("UPDATE users SET role='user' WHERE role='creator'"))
                db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Skip creator profile migration due to error: %s", exc)

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

        try:
            refreshed_table_names = set(inspect(db.engine).get_table_names())
            category_rows = (
                db.session.execute(text("SELECT code FROM categories")).fetchall() if 'categories' in refreshed_table_names else []
            )
            existing_category_codes = {str(row[0]) for row in category_rows}
            for item in WORK_CATEGORY_TAXONOMY:
                if item['code'] in existing_category_codes:
                    continue
                db.session.execute(
                    text(
                        """
                        INSERT INTO categories (code, name, description, is_highlighted)
                        VALUES (:code, :name, :description, :is_highlighted)
                        """
                    ),
                    {
                        'code': item['code'],
                        'name': item['name'],
                        'description': f"{item['name']}频道",
                        'is_highlighted': 1,
                    },
                )

            tag_rows = db.session.execute(text("SELECT code FROM tags")).fetchall() if 'tags' in refreshed_table_names else []
            existing_tag_codes = {str(row[0]) for row in tag_rows}
            for item in WORK_TAG_LIBRARY:
                if item['code'] in existing_tag_codes:
                    continue
                db.session.execute(
                    text("INSERT INTO tags (code, label) VALUES (:code, :label)"),
                    {'code': item['code'], 'label': item['label']},
                )

            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Skip taxonomy bootstrap due to error: %s", exc)


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

    @app.cli.command('migrate-chapters')
    def migrate_chapters_command():
        """Backfill chapter workflow tables from reader sections."""
        from app.services.chapter_migration import migrate_reader_sections_to_chapter_revisions

        with app.app_context():
            result = migrate_reader_sections_to_chapter_revisions()
        print(f"Chapter migration finished: {result}")

    @app.cli.command('rollback-chapter-migration')
    def rollback_chapter_migration_command():
        """Rollback chapter workflow records (keeps reader content)."""
        from app.services.chapter_migration import rollback_chapter_migration

        with app.app_context():
            result = rollback_chapter_migration()
        print(f"Chapter migration rollback finished: {result}")

    @app.cli.command('train-two-tower')
    @click.option('--epochs', default=20, show_default=True, help='Training epochs.')
    @click.option('--dim', 'embedding_dim', default=64, show_default=True, help='Embedding dimension.')
    @click.option('--top-k', default=100, show_default=True, help='Candidates to export per user.')
    @click.option('--activate', is_flag=True, help='Activate this model version after training.')
    def train_two_tower_command(epochs, embedding_dim, top_k, activate):
        """Train and export the two-tower recommendation model."""
        from app.services.recommendation.offline import train_two_tower

        with app.app_context():
            result = train_two_tower(
                epochs=epochs,
                embedding_dim=embedding_dim,
                top_k=top_k,
                activate=activate,
            )
        print(
            'Two-tower training finished: '
            f"version={result['version']}, artifact_dir={result['artifact_dir']}, "
            f"loss={result['metrics'].get('loss')}"
        )

    @app.cli.command('refresh-recommendation-candidates')
    @click.option('--model-version', default='latest', show_default=True, help='Model version to refresh; latest uses active/latest.')
    @click.option('--top-k', default=100, show_default=True, help='Candidates to persist per user.')
    def refresh_recommendation_candidates_command(model_version, top_k):
        """Refresh persisted recommendation candidates from a trained model artifact."""
        from app.services.recommendation.offline import refresh_recommendation_candidates

        with app.app_context():
            result = refresh_recommendation_candidates(version=model_version, top_k=top_k)
            db.session.commit()
        print(
            'Recommendation candidates refreshed: '
            f"version={result['version']}, users={result['user_count']}, candidates={result['candidate_count']}"
        )

    @app.cli.command('import-book-source')
    @click.option('--source', 'source_location', default=None, help='Book source JSON URL, source page URL, local JSON file, or comma-separated locations.')
    @click.option('--limit', default=1000, show_default=True, help='Maximum number of hot books to import.')
    @click.option('--max-pages', default=60, show_default=True, help='Maximum list pages to scan per source category.')
    @click.option('--include-toc', is_flag=True, help='Also import chapter titles into the reader outline.')
    @click.option('--include-content', is_flag=True, help='Fetch chapter content. Use with a small --max-chapters-per-book first.')
    @click.option('--max-chapters-per-book', default=0, show_default=True, help='Limit chapters fetched per book; 0 means all when chapter import is enabled.')
    @click.option('--cookie', default=None, help='Optional Cookie header for sources protected by browser verification.')
    @click.option('--timeout', default=20, show_default=True, help='Request timeout in seconds.')
    @click.option('--retries', default=2, show_default=True, help='Retry count per request.')
    @click.option('--delay', default=0.2, show_default=True, help='Delay between retries/requests in seconds.')
    @click.option('--dry-run', is_flag=True, help='Parse and fetch candidates without writing database rows.')
    @click.option('--overwrite-content', is_flag=True, help='Create a new published revision even when a chapter already has content.')
    @click.option('--random-sample', is_flag=True, help='Shuffle source categories and list candidates before importing.')
    def import_book_source_command(
        source_location,
        limit,
        max_pages,
        include_toc,
        include_content,
        max_chapters_per_book,
        cookie,
        timeout,
        retries,
        delay,
        dry_run,
        overwrite_content,
        random_sample,
    ):
        """Import authorized books from a Yuedu book source into the local catalog."""
        from app.services.book_source_importer import DEFAULT_SOURCE_JSON_URL, import_book_source

        source_location = source_location or DEFAULT_SOURCE_JSON_URL
        stats = import_book_source(
            source_location=source_location,
            limit=limit,
            max_pages=max_pages,
            include_toc=include_toc or include_content,
            include_content=include_content,
            max_chapters_per_book=max_chapters_per_book,
            cookie=cookie or os.environ.get('BOOK_SOURCE_COOKIE'),
            timeout=timeout,
            retries=retries,
            delay=delay,
            dry_run=dry_run,
            overwrite_content=overwrite_content,
            random_sample=random_sample,
        )
        print(
            'Book source import finished: '
            f'candidates={stats.candidates}, created={stats.created}, updated={stats.updated}, '
            f'skipped={stats.skipped}, failed={stats.failed}, chapters={stats.chapters}, '
            f'paragraphs={stats.paragraphs}, failed_chapters={stats.failed_chapters}, '
            f'skipped_chapters={stats.skipped_chapters}'
        )
        if stats.errors:
            print('Errors:')
            for item in stats.errors[:20]:
                print(f'- {item}')
            if len(stats.errors) > 20:
                print(f'- ... {len(stats.errors) - 20} more')
    
    return app
