-- 鍥句功鎺ㄨ崘绯荤粺鏁版嵁搴撹〃缁撴瀯

-- 鍒犻櫎宸插瓨鍦ㄧ殑鏁版嵁搴擄紙濡傛灉瀛樺湪锛?
DROP DATABASE IF EXISTS book_recommend_db;

-- 鍒涘缓鏁版嵁搴?
CREATE DATABASE book_recommend_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 浣跨敤鏁版嵁搴?
USE book_recommend_db;

-- 鐢ㄦ埛琛?
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 瑙掕壊琛?
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(80) NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- 鏉冮檺琛?
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- 瑙掕壊鏉冮檺鍏宠仈琛?
CREATE TABLE role_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE KEY unique_role_permission (role_id, permission_id)
);

-- 鐢ㄦ埛瑙掕壊鍏宠仈琛?
CREATE TABLE user_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_role (user_id, role_id)
);

-- 鍥句功琛紙棰勭暀锛?
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

-- 鐢ㄦ埛鍥句功璇勫垎琛紙棰勭暀锛?
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

-- 鐢ㄦ埛闃呰鍘嗗彶琛紙棰勭暀锛?
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

-- 鐢ㄦ埛闃呰杩涘害锛堢敤浜庝粠棣栭〉鐩存帴缁锛?
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

-- 闃呰姝ｆ枃缁撴瀯锛堢珷鑺?娈佃惤锛?
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

-- 闃呰鍒掔嚎涓庤瘎璁?
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

-- 鍒涘缓绱㈠紩浠ユ彁楂樻煡璇㈡€ц兘
CREATE INDEX idx_books_title ON books(title);
CREATE INDEX idx_books_author ON books(author);
CREATE INDEX idx_books_genre ON books(genre);
CREATE INDEX idx_user_ratings_user_id ON user_ratings(user_id);
CREATE INDEX idx_user_ratings_book_id ON user_ratings(book_id);
CREATE INDEX idx_reading_history_user_id ON reading_history(user_id);
CREATE INDEX idx_reading_history_book_id ON reading_history(book_id);
CREATE INDEX idx_reading_progress_user_id ON user_reading_progress(user_id);
CREATE INDEX idx_reading_progress_book_id ON user_reading_progress(book_id);
CREATE INDEX idx_reader_sections_book ON reader_sections(book_id, order_no);
CREATE INDEX idx_reader_paragraphs_section ON reader_paragraphs(section_id, order_no);
CREATE INDEX idx_reader_highlights_book ON reader_highlights(book_id, paragraph_key);
CREATE INDEX idx_reader_hc_highlight ON reader_highlight_comments(highlight_id);
CREATE INDEX idx_reader_book_comments_book ON reader_book_comments(book_id);

-- 鎻掑叆榛樿瑙掕壊
INSERT INTO roles (name, description) VALUES 
('admin', '绯荤粺绠＄悊鍛?),
('user', '鏅€氱敤鎴?),
('moderator', '鐗堜富');

-- 鎻掑叆榛樿鏉冮檺
INSERT INTO permissions (name, description) VALUES 
('user_create', '鍒涘缓鐢ㄦ埛'),
('user_read', '鏌ョ湅鐢ㄦ埛'),
('user_update', '鏇存柊鐢ㄦ埛'),
('user_delete', '鍒犻櫎鐢ㄦ埛'),
('book_create', '鍒涘缓鍥句功'),
('book_read', '鏌ョ湅鍥句功'),
('book_update', '鏇存柊鍥句功'),
('book_delete', '鍒犻櫎鍥句功'),
('rating_create', '鍒涘缓璇勫垎'),
('rating_read', '鏌ョ湅璇勫垎'),
('rating_update', '鏇存柊璇勫垎'),
('rating_delete', '鍒犻櫎璇勫垎');

-- 涓虹鐞嗗憳瑙掕壊鍒嗛厤鎵€鏈夋潈闄?
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'admin';

-- 涓烘櫘閫氱敤鎴峰垎閰嶅熀鏈潈闄?
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'user' 
AND p.name IN ('book_read', 'rating_create', 'rating_read', 'rating_update');

-- 鎻掑叆榛樿绠＄悊鍛樼敤鎴凤紙瀵嗙爜涓?admin123"鐨勫搱甯屽€硷級
INSERT INTO users (username, email, password_hash, role) VALUES 
('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.PZvO.S', 'admin');

-- 灏嗛粯璁ょ敤鎴峰垎閰嶇粰绠＄悊鍛樿鑹?
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id 
FROM users u, roles r 
WHERE u.username = 'admin' AND r.name = 'admin';

-- 鎺堟潈book_user鐢ㄦ埛璁块棶鏁版嵁搴?
GRANT ALL PRIVILEGES ON book_recommend_db.* TO 'book_user'@'%';
FLUSH PRIVILEGES;

