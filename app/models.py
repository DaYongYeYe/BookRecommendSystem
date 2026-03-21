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
    # Werkzeug scrypt hashes are longer than legacy pbkdf2 hashes.
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # user or admin
    
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
            'category_id': self.category_id
        }


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
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class ReaderBookComment(db.Model):
    __tablename__ = 'reader_book_comments'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False, index=True)
    author = db.Column(db.String(64), nullable=False, default='当前读者')
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
