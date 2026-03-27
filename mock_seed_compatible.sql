-- Mock seed data (compatible with current DB tables)
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
START TRANSACTION;

-- RBAC
INSERT INTO roles (id, name, description) VALUES
  (1, 'admin', 'System administrator'),
  (2, 'user', 'Normal user')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT INTO permissions (id, name, description) VALUES
  (1, 'book.read', 'Read books'),
  (2, 'book.comment', 'Comment on books'),
  (3, 'book.manage', 'Manage books'),
  (4, 'user.manage', 'Manage users')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT INTO role_permissions (id, role_id, permission_id) VALUES
  (1,1,1),(2,1,2),(3,1,3),(4,1,4),
  (5,2,1),(6,2,2)
ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), permission_id = VALUES(permission_id);

-- Users (password: 123456)
INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at) VALUES
  (1, 'admin', 'admin@book.local', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'admin', NOW(), NOW()),
  (2, 'reader_alice', 'alice@book.local', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'user', NOW(), NOW()),
  (3, 'reader_bob', 'bob@book.local', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'user', NOW(), NOW()),
  (4, 'reader_cindy', 'cindy@book.local', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'user', NOW(), NOW())
ON DUPLICATE KEY UPDATE
  email = VALUES(email), password_hash = VALUES(password_hash), role = VALUES(role), updated_at = NOW();

INSERT INTO user_roles (id, user_id, role_id) VALUES
  (1,1,1),(2,2,2),(3,3,2),(4,4,2)
ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), role_id = VALUES(role_id);

INSERT INTO notifications (id, user_id, title, content, is_read, created_at) VALUES
  (1,2,'Weekly reading reminder','You are 60% to your weekly goal.',0,NOW()),
  (2,2,'New highlight reply','Someone replied to your highlight.',0,NOW()),
  (3,3,'Fresh recommendations','Mood-based recommendations are ready.',0,NOW()),
  (4,4,'Reading streak','You have read for 7 days in a row.',1,NOW())
ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),title=VALUES(title),content=VALUES(content),is_read=VALUES(is_read);

-- Catalog
INSERT INTO categories (id, code, name, en_name, description, cover, is_highlighted) VALUES
  (1,'literature','Literature Narrative','Literature','Human stories and memory.','https://images.unsplash.com/photo-1507842217343-583bb7270b66?auto=format&fit=crop&w=900&q=80',1),
  (2,'psychology','Psychology','Psychology','Emotion and behavior insights.','https://images.unsplash.com/photo-1455885666463-9f41fdef8c86?auto=format&fit=crop&w=900&q=80',1),
  (3,'history','History','History','Civilization and social change.','https://images.unsplash.com/photo-1461360370896-922624d12aa1?auto=format&fit=crop&w=900&q=80',1)
ON DUPLICATE KEY UPDATE
  name=VALUES(name),en_name=VALUES(en_name),description=VALUES(description),cover=VALUES(cover),is_highlighted=VALUES(is_highlighted);

INSERT INTO tags (id, code, label) VALUES
  (1,'memory','Memory'),
  (2,'harbor','Harbor Story'),
  (3,'growth','Growth'),
  (4,'healing','Healing')
ON DUPLICATE KEY UPDATE label=VALUES(label);

INSERT INTO books (id, title, subtitle, author, description, cover, score, rating, rating_count, recent_reads, is_featured, category_id, created_at) VALUES
  (1,'Reading Sample: Long Remaining Life','Find each other in fate','Luo Xin','A warm narrative suitable for reader experience.','https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',9.4,9.1,12000,128000,1,1,NOW()),
  (2,'Night Dive Film','Silence and tide','Chen Chunguang','A reflective novel around city and loneliness.','https://images.unsplash.com/photo-1481627834876-b7833e8f5570?auto=format&fit=crop&w=900&q=80',9.1,9.0,9800,86000,0,1,NOW()),
  (3,'Klara and the Sun','A machine and love','Kazuo Ishiguro','Stories about care, replacement and hope.','https://images.unsplash.com/photo-1495446815901-a7297e633e8d?auto=format&fit=crop&w=900&q=80',9.0,8.9,15000,112000,0,2,NOW()),
  (4,'Inside the Story','Details of ordinary life','Lan Xiaohuan','Small events with deep emotional waves.','https://images.unsplash.com/photo-1474932430478-367dbb6832c1?auto=format&fit=crop&w=900&q=80',8.8,8.7,7200,53000,0,1,NOW()),
  (5,'Deep Focus','Work with calm mind','Lina Zhou','Build focus routines through practical methods.','https://images.unsplash.com/photo-1497633762265-9d179a990aa6?auto=format&fit=crop&w=900&q=80',8.7,8.8,5400,41000,0,2,NOW()),
  (6,'Archive of Rainy Night','Letters and weather','Ming Li','A collection of letters and emotional records.','https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?auto=format&fit=crop&w=900&q=80',8.9,8.6,4600,37000,0,3,NOW())
ON DUPLICATE KEY UPDATE
  title=VALUES(title),subtitle=VALUES(subtitle),author=VALUES(author),description=VALUES(description),
  cover=VALUES(cover),score=VALUES(score),rating=VALUES(rating),rating_count=VALUES(rating_count),
  recent_reads=VALUES(recent_reads),is_featured=VALUES(is_featured),category_id=VALUES(category_id);

INSERT INTO book_tags (id, book_id, tag_id) VALUES
  (1,1,1),(2,1,2),(3,1,4),
  (4,2,2),(5,2,4),
  (6,3,1),(7,3,3),
  (8,4,3),(9,4,4),
  (10,5,3),
  (11,6,1),(12,6,2)
ON DUPLICATE KEY UPDATE book_id=VALUES(book_id),tag_id=VALUES(tag_id);

INSERT INTO book_chapters (id, book_id, title, order_no, preview_url) VALUES
  (1,1,'Chapter 1: Arrival at Old Harbor',1,'/reader/1'),
  (2,1,'Chapter 2: Notes on Rainy Night',2,'/reader/1'),
  (3,2,'Chapter 1: Tide Sound',1,'/reader/2'),
  (4,3,'Chapter 1: Artificial Heartbeat',1,'/reader/3')
ON DUPLICATE KEY UPDATE book_id=VALUES(book_id),title=VALUES(title),order_no=VALUES(order_no),preview_url=VALUES(preview_url);

-- Reader content
INSERT INTO reader_sections (id, book_id, section_key, title, summary, level, order_no, created_at) VALUES
  (101,1,'chapter-1','第一章 抵达旧港','她在潮湿的海港小城重新落脚，也重新面对那些还没来得及解释的过去。',1,1,NOW()),
  (102,1,'chapter-1-1','1.1 海雾中的来信','一封没有署名的信，把她带回了那段始终没能讲完的关系。',2,2,NOW()),
  (103,1,'chapter-1-2','1.2 灯塔下的谈话','守塔人的一句话，让她第一次意识到，等待未必只是徒劳。',2,3,NOW()),
  (104,1,'chapter-2','第二章 雨夜摘录','在深夜整理旧笔记时，她终于理解，有些答案并不是为了原谅别人，而是为了安放自己。',1,4,NOW())
ON DUPLICATE KEY UPDATE
  title=VALUES(title),summary=VALUES(summary),level=VALUES(level),order_no=VALUES(order_no);

INSERT INTO reader_paragraphs (id, section_id, paragraph_key, text, order_no, created_at) VALUES
  (1001,101,'p1','黄昏压低在港口上空，潮水拍打着木栈桥。她拖着行李走下最后一级台阶，空气里混着海盐、铁锈和雨前石板的气味。',1,NOW()),
  (1002,101,'p2','旅馆老板递来钥匙，又朝远处灯塔抬了抬下巴，说今夜风会很大。她点头，却还是在门口站了几秒，像在等一个迟到了很多年的信号。',2,NOW()),
  (1003,102,'p3','信纸边角被海风吹得卷起，字迹却比记忆里的任何一次都更安稳。上面只写着一句话：有些人要绕很远的路，才能回到最初想靠近的光。',1,NOW()),
  (1004,102,'p4','窗外的海雾越积越厚，路灯一盏接一盏地模糊开来。她把那封信放在桌上，忽然觉得多年压住的话，也许并没有真正沉到底。',2,NOW()),
  (1005,103,'p5','守塔人说，船不会因为灯塔沉默就停下，但只要那束光还在，迷路的人就会知道自己并不是被彻底遗忘。',1,NOW()),
  (1006,103,'p6','风穿过栏杆，海面一片碎银般的冷意。她忽然很想把这些年没寄出的句子，都讲给潮声听，哪怕它不会回答。',2,NOW()),
  (1007,104,'p7','夜色完全沉下去以后，雨终于落了。她重翻旧笔记，把那些曾经匆匆读过的句子一行一行抄下来，像在替过去的自己补一场迟到的停顿。',1,NOW()),
  (1008,104,'p8','理解并不是原谅的附录，而是留给自己的那盏小灯。它未必能照亮所有回忆，却足够让人不再害怕回头。',2,NOW())
ON DUPLICATE KEY UPDATE text=VALUES(text),order_no=VALUES(order_no);

INSERT INTO reader_highlights (id, book_id, paragraph_key, start_offset, end_offset, selected_text, color, note, created_by, created_at) VALUES
  (201,1,'p3',33,57,'有些人要绕很远的路，才能回到最初想靠近的光。','amber','这句像是整本书的情感核心，关于迟到、绕路和重新靠近。','Alice Lin',NOW()),
  (202,1,'p5',24,53,'只要那束光还在，迷路的人就会知道自己并不是被彻底遗忘。','sky','灯塔的比喻很克制，但很有力量。','Bob Chen',NOW()),
  (203,1,'p8',0,27,'理解并不是原谅的附录，而是留给自己的那盏小灯。','rose','这一句很温柔，像给整章收了个口。','Cindy Wu',NOW())
ON DUPLICATE KEY UPDATE
  paragraph_key=VALUES(paragraph_key),start_offset=VALUES(start_offset),end_offset=VALUES(end_offset),
  selected_text=VALUES(selected_text),color=VALUES(color),note=VALUES(note),created_by=VALUES(created_by);

INSERT INTO reader_highlight_comments (id, highlight_id, author, content, created_at) VALUES
  (1,201,'Bob Chen','这句和开头的港口意象连得特别好。',NOW()),
  (2,201,'Cindy Wu','读到这里时一下就记住了这本书。',NOW()),
  (3,202,'Alice Lin','很适合放进阅读摘录。',NOW())
ON DUPLICATE KEY UPDATE highlight_id=VALUES(highlight_id),author=VALUES(author),content=VALUES(content),created_at=VALUES(created_at);

INSERT INTO reader_book_comments (id, book_id, author, content, created_at) VALUES
  (1,1,'Alice Lin','节奏很稳，适合晚上安静读一会儿。',NOW()),
  (2,1,'Bob Chen','灯塔那一节特别有画面感。',NOW()),
  (3,1,'Cindy Wu','不是那种很吵闹的故事，但情绪会慢慢进来。',NOW())
ON DUPLICATE KEY UPDATE book_id=VALUES(book_id),author=VALUES(author),content=VALUES(content),created_at=VALUES(created_at);

INSERT INTO user_reading_progress (id, user_id, book_id, section_id, paragraph_id, scroll_percent, created_at, updated_at) VALUES
  (1,2,1,'chapter-1-2','p5',68.50,NOW(),NOW()),
  (2,2,3,'chapter-1','p1',22.00,NOW(),NOW()),
  (3,3,1,'chapter-2','p7',84.00,NOW(),NOW()),
  (4,4,6,'chapter-1','p1',31.50,NOW(),NOW())
ON DUPLICATE KEY UPDATE
  user_id=VALUES(user_id),book_id=VALUES(book_id),section_id=VALUES(section_id),paragraph_id=VALUES(paragraph_id),
  scroll_percent=VALUES(scroll_percent),updated_at=NOW();

INSERT INTO reader_user_preferences (id, user_id, theme, font_size, show_highlights, show_comments, updated_at) VALUES
  (1,2,'light',20,1,1,NOW()),
  (2,3,'dark',22,1,1,NOW()),
  (3,4,'light',18,1,0,NOW())
ON DUPLICATE KEY UPDATE
  user_id=VALUES(user_id),theme=VALUES(theme),font_size=VALUES(font_size),
  show_highlights=VALUES(show_highlights),show_comments=VALUES(show_comments),updated_at=VALUES(updated_at);

-- Mood recommendations
INSERT INTO moods (id, label, icon) VALUES
  ('healing','Seeking Healing','hugeicons:cloud-01'),
  ('brainstorm','Brainstorm','hugeicons:flash'),
  ('focus','Deep Focus','hugeicons:target-02')
ON DUPLICATE KEY UPDATE label=VALUES(label),icon=VALUES(icon);

INSERT INTO mood_book_recommendations (id, mood_id, book_id, weight) VALUES
  (1,'healing',1,100),(2,'healing',2,90),(3,'healing',6,82),
  (4,'brainstorm',3,95),(5,'brainstorm',5,88),
  (6,'focus',5,99),(7,'focus',3,86)
ON DUPLICATE KEY UPDATE mood_id=VALUES(mood_id),book_id=VALUES(book_id),weight=VALUES(weight);

-- Shelf + feedback
INSERT INTO user_shelf (id, user_id, book_id, created_at) VALUES
  (1,2,1,NOW()),(2,2,3,NOW()),
  (3,3,1,NOW()),(4,3,2,NOW()),
  (5,4,1,NOW()),(6,4,6,NOW())
ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),book_id=VALUES(book_id),created_at=VALUES(created_at);

INSERT INTO recommendation_feedback (id, user_id, book_id, action, created_at) VALUES
  (1,2,1,'click',NOW()),
  (2,2,3,'add_shelf',NOW()),
  (3,3,2,'dismiss',NOW()),
  (4,4,6,'like',NOW())
ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),book_id=VALUES(book_id),action=VALUES(action),created_at=VALUES(created_at);

-- Rankings and weekly tasks
INSERT INTO book_rankings (id, type, rank_no, book_id, snapshot_date) VALUES
  (1,'high_score',1,1,'2026-03-21'),
  (2,'high_score',2,2,'2026-03-21'),
  (3,'high_score',3,3,'2026-03-21'),
  (4,'word_of_mouth',1,3,'2026-03-21'),
  (5,'word_of_mouth',2,1,'2026-03-21'),
  (6,'word_of_mouth',3,6,'2026-03-21')
ON DUPLICATE KEY UPDATE type=VALUES(type),rank_no=VALUES(rank_no),book_id=VALUES(book_id),snapshot_date=VALUES(snapshot_date);

INSERT INTO weekly_reading_tasks (id, user_id, week_start_date, target_books, finished_books, reward_desc, created_at, updated_at) VALUES
  (1,2,'2026-03-16',5,3,'Unlock spring limited bookmark',NOW(),NOW()),
  (2,3,'2026-03-16',4,2,'Unlock profile frame',NOW(),NOW()),
  (3,4,'2026-03-16',3,3,'Unlock reading badge',NOW(),NOW())
ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),week_start_date=VALUES(week_start_date),target_books=VALUES(target_books),finished_books=VALUES(finished_books),reward_desc=VALUES(reward_desc),updated_at=NOW();

-- Reviews
INSERT INTO reviews (id, user_id, book_id, content, likes_count, comments_count, created_at) VALUES
  (701,2,1,'The story is calm but emotionally strong. Great for slow reading.',12,2,NOW()),
  (702,3,3,'A thoughtful book about care and replacement.',9,1,NOW()),
  (703,4,2,'Very visual writing. Feels like watching a silent film.',6,1,NOW())
ON DUPLICATE KEY UPDATE
  user_id=VALUES(user_id),book_id=VALUES(book_id),content=VALUES(content),likes_count=VALUES(likes_count),comments_count=VALUES(comments_count);

INSERT INTO review_likes (id, review_id, user_id, is_like, created_at) VALUES
  (1,701,3,1,NOW()),
  (2,701,4,1,NOW()),
  (3,702,2,1,NOW()),
  (4,703,2,1,NOW())
ON DUPLICATE KEY UPDATE review_id=VALUES(review_id),user_id=VALUES(user_id),is_like=VALUES(is_like),created_at=VALUES(created_at);

INSERT INTO review_comments (id, review_id, user_id, content, created_at) VALUES
  (1,701,3,'I had the same feeling around chapter 1.',NOW()),
  (2,701,4,'The wording is clean and vivid.',NOW()),
  (3,702,2,'Totally agree with this review.',NOW())
ON DUPLICATE KEY UPDATE review_id=VALUES(review_id),user_id=VALUES(user_id),content=VALUES(content),created_at=VALUES(created_at);

COMMIT;
SET FOREIGN_KEY_CHECKS = 1;
