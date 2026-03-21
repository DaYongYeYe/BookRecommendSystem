-- 图书推荐系统数据库表结构
-- 初始化：库若已存在则删除后重建；创建库使用 IF NOT EXISTS，便于在「未建库」时单独执行建库语句

-- 若已存在则删除（清空整库，便于重复初始化）
DROP DATABASE IF EXISTS book_recommend_db;

-- 不存在则创建（整库删除后必然不存在；若只执行本行则不会覆盖已有库）
CREATE DATABASE IF NOT EXISTS book_recommend_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 使用数据库
USE book_recommend_db;

-- 用户表
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    name VARCHAR(80),
    email VARCHAR(120) NOT NULL UNIQUE,
    avatar_url VARCHAR(500),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 角色表
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(80) NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- 权限表
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- 角色权限关联表
CREATE TABLE role_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE KEY unique_role_permission (role_id, permission_id)
);

-- 用户角色关联表
CREATE TABLE user_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_role (user_id, role_id)
);

-- 图书表（预留）
CREATE TABLE books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    isbn VARCHAR(20) UNIQUE,
    publication_date DATE,
    publisher VARCHAR(255),
    genre VARCHAR(100),
    description TEXT,
    cover_image_url VARCHAR(500),
    average_rating DECIMAL(3,2) DEFAULT 0.00,
    rating_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 用户图书评分表（预留）
CREATE TABLE user_ratings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    book_id INT NOT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    review TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_book (user_id, book_id)
);

-- 用户阅读历史表（预留）
CREATE TABLE reading_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    book_id INT NOT NULL,
    status ENUM('want_to_read', 'reading', 'read') DEFAULT 'want_to_read',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_book_status (user_id, book_id)
);

-- 用户阅读进度（用于从首页直接续读）
CREATE TABLE user_reading_progress (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    book_id INT NOT NULL,
    section_id VARCHAR(64),
    paragraph_id VARCHAR(64),
    scroll_percent DECIMAL(5,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_user_book_progress (user_id, book_id)
);

CREATE TABLE reader_user_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    theme VARCHAR(16) NOT NULL DEFAULT 'light',
    font_size INT NOT NULL DEFAULT 20,
    show_highlights TINYINT(1) NOT NULL DEFAULT 1,
    show_comments TINYINT(1) NOT NULL DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 阅读正文结构（章节、段落）
CREATE TABLE reader_sections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_id INT NOT NULL,
    section_key VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    level INT NOT NULL DEFAULT 1,
    order_no INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_reader_section_key (book_id, section_key)
);

CREATE TABLE reader_paragraphs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    section_id INT NOT NULL,
    paragraph_key VARCHAR(64) NOT NULL,
    text TEXT NOT NULL,
    order_no INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (section_id) REFERENCES reader_sections(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_reader_paragraph_key (section_id, paragraph_key)
);

-- 阅读划线与评论
CREATE TABLE reader_highlights (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_id INT NOT NULL,
    paragraph_key VARCHAR(64) NOT NULL,
    start_offset INT NOT NULL,
    end_offset INT NOT NULL,
    selected_text TEXT NOT NULL,
    color VARCHAR(32) NOT NULL DEFAULT 'amber',
    note TEXT,
    created_by VARCHAR(64) NOT NULL DEFAULT 'Current Reader',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
);

CREATE TABLE reader_highlight_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    highlight_id INT NOT NULL,
    author VARCHAR(64) NOT NULL DEFAULT 'Current Reader',
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (highlight_id) REFERENCES reader_highlights(id) ON DELETE CASCADE
);

CREATE TABLE reader_book_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_id INT NOT NULL,
    author VARCHAR(64) NOT NULL DEFAULT 'Current Reader',
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
);

-- 创建索引以提升查询性能
CREATE INDEX idx_books_title ON books(title);
CREATE INDEX idx_books_author ON books(author);
CREATE INDEX idx_books_genre ON books(genre);
CREATE INDEX idx_user_ratings_user_id ON user_ratings(user_id);
CREATE INDEX idx_user_ratings_book_id ON user_ratings(book_id);
CREATE INDEX idx_reading_history_user_id ON reading_history(user_id);
CREATE INDEX idx_reading_history_book_id ON reading_history(book_id);
CREATE INDEX idx_reading_progress_user_id ON user_reading_progress(user_id);
CREATE INDEX idx_reading_progress_book_id ON user_reading_progress(book_id);
CREATE INDEX idx_reader_pref_user_id ON reader_user_preferences(user_id);
CREATE INDEX idx_reader_sections_book ON reader_sections(book_id, order_no);
CREATE INDEX idx_reader_paragraphs_section ON reader_paragraphs(section_id, order_no);
CREATE INDEX idx_reader_highlights_book ON reader_highlights(book_id, paragraph_key);
CREATE INDEX idx_reader_hc_highlight ON reader_highlight_comments(highlight_id);
CREATE INDEX idx_reader_book_comments_book ON reader_book_comments(book_id);

-- 插入默认角色
INSERT INTO roles (name, description) VALUES
('admin', '系统管理员'),
('user', '普通用户'),
('moderator', '版主');

-- 插入默认权限
INSERT INTO permissions (name, description) VALUES
('user_create', '创建用户'),
('user_read', '查看用户'),
('user_update', '更新用户'),
('user_delete', '删除用户'),
('book_create', '创建图书'),
('book_read', '查看图书'),
('book_update', '更新图书'),
('book_delete', '删除图书'),
('rating_create', '创建评分'),
('rating_read', '查看评分'),
('rating_update', '更新评分'),
('rating_delete', '删除评分');

-- 为管理员角色分配所有权限
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin';

-- 为普通用户分配基本权限
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'user'
AND p.name IN ('book_read', 'rating_create', 'rating_read', 'rating_update');

-- 插入默认管理员用户（密码为 "admin123" 的 bcrypt 哈希）
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.PZvO.S', 'admin');

-- 将默认用户分配给管理员角色
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'admin';

-- 授权 book_user 用户访问数据库
GRANT ALL PRIVILEGES ON book_recommend_db.* TO 'book_user'@'%';
FLUSH PRIVILEGES;
