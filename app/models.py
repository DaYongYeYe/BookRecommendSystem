from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True, nullable=False)
    avatar_url = db.Column(db.String(500))
    age = db.Column(db.Integer)
    province = db.Column(db.String(64))
    city = db.Column(db.String(64))
    # Werkzeug scrypt hashes are longer than legacy pbkdf2 hashes.
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # user or admin
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        # Some historical/imported records may contain invalid hash strings.
        # Treat them as authentication failures instead of raising 500.
        try:
            return check_password_hash(self.password_hash, password)
        except (ValueError, TypeError):
            return False
    
    def is_admin(self):
        return self.role == 'admin'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'name': self.name,
            'email': self.email,
            'avatar_url': self.avatar_url,
            'age': self.age,
            'province': self.province,
            'city': self.city,
            'role': self.role
        }

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }

class Permission(db.Model):
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }

class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), nullable=False)
    
    # 复合唯一约束，确保同一角色不会重复拥有相同权限
    __table_args__ = (db.UniqueConstraint('role_id', 'permission_id'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'role_id': self.role_id,
            'permission_id': self.permission_id
        }

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    
    # 复合唯一约束，确保同一用户不会被重复分配相同角色
    __table_args__ = (db.UniqueConstraint('user_id', 'role_id'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'role_id': self.role_id
        }


class Book(db.Model):
    __tablename__ = 'books'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    subtitle = db.Column(db.String(255))
    author = db.Column(db.String(255))
    description = db.Column(db.Text)
    cover = db.Column(db.String(500))
    score = db.Column(db.Float)
    rating = db.Column(db.Float)
    rating_count = db.Column(db.BigInteger, default=0)
    recent_reads = db.Column(db.BigInteger, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    category_id = db.Column(db.Integer)
    status = db.Column(db.String(20), nullable=False, default='published')
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    published_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'subtitle': self.subtitle,
            'author': self.author,
            'description': self.description,
            'cover': self.cover,
            'score': self.score,
            'rating': self.rating,
            'rating_count': int(self.rating_count or 0),
            'recent_reads': int(self.recent_reads or 0),
            'is_featured': bool(self.is_featured),
            'category_id': self.category_id,
            'status': self.status or 'published',
            'creator_id': self.creator_id,
            'published_at': self.published_at.isoformat() if self.published_at else None,
        }


class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    en_name = db.Column(db.String(100))
    description = db.Column(db.String(255))
    cover = db.Column(db.String(500))
    is_highlighted = db.Column(db.Boolean, nullable=False, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'en_name': self.en_name,
            'description': self.description,
            'cover': self.cover,
            'is_highlighted': bool(self.is_highlighted),
        }


class Tag(db.Model):
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'label': self.label,
        }


class BookTag(db.Model):
    __tablename__ = 'book_tags'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'), nullable=False, index=True)

    __table_args__ = (db.UniqueConstraint('book_id', 'tag_id', name='uniq_book_tag'),)


class BookRanking(db.Model):
    __tablename__ = 'book_rankings'

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(64), nullable=False, index=True)
    rank_no = db.Column(db.Integer, nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    snapshot_date = db.Column(db.Date, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('type', 'snapshot_date', 'rank_no', name='uniq_type_date_rank'),
    )


class UserReadingProgress(db.Model):
    __tablename__ = 'user_reading_progress'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    section_id = db.Column(db.String(64))
    paragraph_id = db.Column(db.String(64))
    scroll_percent = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    __table_args__ = (db.UniqueConstraint('user_id', 'book_id', name='uniq_user_book_progress'),)

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'book_id': self.book_id,
            'section_id': self.section_id,
            'paragraph_id': self.paragraph_id,
            'scroll_percent': float(self.scroll_percent or 0),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class UserShelf(db.Model):
    __tablename__ = 'user_shelf'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (db.UniqueConstraint('user_id', 'book_id', name='uniq_user_book'),)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'book_id': self.book_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ReaderUserPreference(db.Model):
    __tablename__ = 'reader_user_preferences'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True, index=True)
    theme = db.Column(db.String(16), nullable=False, default='light')
    font_size = db.Column(db.Integer, nullable=False, default=20)
    show_highlights = db.Column(db.Boolean, nullable=False, default=True)
    show_comments = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def to_dict(self):
        return {
            'theme': self.theme or 'light',
            'font_size': int(self.font_size or 20),
            'show_highlights': bool(self.show_highlights),
            'show_comments': bool(self.show_comments),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class ReaderSection(db.Model):
    __tablename__ = 'reader_sections'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    section_key = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text)
    level = db.Column(db.Integer, default=1)
    order_no = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (db.UniqueConstraint('book_id', 'section_key', name='uniq_reader_section_key'),)


class ReaderParagraph(db.Model):
    __tablename__ = 'reader_paragraphs'

    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(db.Integer, db.ForeignKey('reader_sections.id'), nullable=False, index=True)
    paragraph_key = db.Column(db.String(64), nullable=False)
    text = db.Column(db.Text, nullable=False)
    order_no = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (db.UniqueConstraint('section_id', 'paragraph_key', name='uniq_reader_paragraph_key'),)


class ReaderHighlight(db.Model):
    __tablename__ = 'reader_highlights'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    paragraph_key = db.Column(db.String(64), nullable=False, index=True)
    start_offset = db.Column(db.Integer, nullable=False)
    end_offset = db.Column(db.Integer, nullable=False)
    selected_text = db.Column(db.Text, nullable=False)
    color = db.Column(db.String(32), nullable=False, default='amber')
    note = db.Column(db.Text)
    created_by = db.Column(db.String(64), nullable=False, default='当前读者')
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class ReaderHighlightComment(db.Model):
    __tablename__ = 'reader_highlight_comments'

    id = db.Column(db.Integer, primary_key=True)
    highlight_id = db.Column(db.Integer, db.ForeignKey('reader_highlights.id'), nullable=False, index=True)
    author = db.Column(db.String(64), nullable=False, default='当前读者')
    content = db.Column(db.Text, nullable=False)
    is_violation = db.Column(db.Boolean, nullable=False, default=False)
    violation_reason = db.Column(db.String(255))
    moderated_at = db.Column(db.DateTime)
    moderated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class ReaderBookComment(db.Model):
    __tablename__ = 'reader_book_comments'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    author = db.Column(db.String(64), nullable=False, default='当前读者')
    content = db.Column(db.Text, nullable=False)
    is_violation = db.Column(db.Boolean, nullable=False, default=False)
    violation_reason = db.Column(db.String(255))
    moderated_at = db.Column(db.DateTime)
    moderated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class BookManuscript(db.Model):
    __tablename__ = 'book_manuscripts'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    cover = db.Column(db.String(500))
    description = db.Column(db.Text)
    content_text = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False, default='draft')
    review_comment = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    published_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def to_dict(self):
        return {
            'id': self.id,
            'book_id': self.book_id,
            'creator_id': self.creator_id,
            'title': self.title,
            'cover': self.cover,
            'description': self.description,
            'content_text': self.content_text,
            'status': self.status,
            'review_comment': self.review_comment,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'reviewed_by': self.reviewed_by,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class BookVersion(db.Model):
    __tablename__ = 'book_versions'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    manuscript_id = db.Column(db.Integer, db.ForeignKey('book_manuscripts.id'))
    version_no = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    cover = db.Column(db.String(500))
    description = db.Column(db.Text)
    content_text = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (db.UniqueConstraint('book_id', 'version_no', name='uniq_book_version_no'),)

    def to_dict(self):
        return {
            'id': self.id,
            'book_id': self.book_id,
            'manuscript_id': self.manuscript_id,
            'version_no': self.version_no,
            'title': self.title,
            'cover': self.cover,
            'description': self.description,
            'content_text': self.content_text,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class BookAnalyticsEvent(db.Model):
    __tablename__ = 'book_analytics_events'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    event_type = db.Column(db.String(32), nullable=False, index=True)
    session_id = db.Column(db.String(64), index=True)
    read_duration_seconds = db.Column(db.Integer, nullable=False, default=0)
    geo_label = db.Column(db.String(100))
    age_group = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)
