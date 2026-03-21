-- Mock seed data for BookRecommendSystem
-- Safe to run repeatedly (uses ON DUPLICATE KEY UPDATE)

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

START TRANSACTION;

-- ========== RBAC ==========
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

INSERT INTO role_permissions (role_id, permission_id) VALUES
  (1,1),(1,2),(1,3),(1,4),
  (2,1),(2,2)
ON DUPLICATE KEY UPDATE permission_id = VALUES(permission_id);

-- ========== Users ==========
-- Password for all users: 123456
INSERT INTO users (id, username, name, email, avatar_url, password_hash, role, created_at, updated_at) VALUES
  (1, 'admin', 'System Admin', 'admin@book.local', 'https://images.unsplash.com/photo-1568602471122-7832951cc4c5?auto=format&fit=crop&w=200&q=80', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'admin', NOW(), NOW()),
  (2, 'reader_alice', 'Alice Lin', 'alice@book.local', 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&w=200&q=80', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'user', NOW(), NOW()),
  (3, 'reader_bob', 'Bob Chen', 'bob@book.local', 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?auto=format&fit=crop&w=200&q=80', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'user', NOW(), NOW()),
  (4, 'reader_cindy', 'Cindy Wu', 'cindy@book.local', 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?auto=format&fit=crop&w=200&q=80', 'scrypt:32768:8:1$e9e6mB37s8IIQuF7$dded5db1c212477442cc1c6f52ce7af1c32fa1e14ce5a95deed8f0813183836da3cf724565e83b91b563713525f261ebf1691b3e9c6e933aa9bc072ca0e6859e', 'user', NOW(), NOW())
ON DUPLICATE KEY UPDATE
  name = VALUES(name), email = VALUES(email), avatar_url = VALUES(avatar_url), role = VALUES(role), updated_at = NOW();

INSERT INTO user_roles (user_id, role_id) VALUES
  (1,1),(2,2),(3,2),(4,2)
ON DUPLICATE KEY UPDATE role_id = VALUES(role_id);

INSERT INTO notifications (user_id, title, content, is_read, created_at) VALUES
  (2, 'Weekly reading reminder', 'You are 60% to your weekly goal.', 0, NOW()),
  (2, 'New highlight reply', 'Someone replied to your highlight.', 0, NOW()),
  (3, 'Fresh recommendations', 'Mood-based recommendations are ready.', 0, NOW()),
  (4, 'Reading streak', 'You have read for 7 days in a row.', 1, NOW())
ON DUPLICATE KEY UPDATE is_read = VALUES(is_read), content = VALUES(content);

-- ========== Catalog ==========
INSERT INTO categories (id, code, name, en_name, description, cover, is_highlighted) VALUES
  (1, 'literature', 'Literature Narrative', 'Literature', 'Human stories and memory.', 'https://images.unsplash.com/photo-1507842217343-583bb7270b66?auto=format&fit=crop&w=900&q=80', 1),
  (2, 'psychology', 'Psychology', 'Psychology', 'Emotion and behavior insights.', 'https://images.unsplash.com/photo-1455885666463-9f41fdef8c86?auto=format&fit=crop&w=900&q=80', 1),
  (3, 'history', 'History', 'History', 'Civilization and social change.', 'https://images.unsplash.com/photo-1461360370896-922624d12aa1?auto=format&fit=crop&w=900&q=80', 1)
ON DUPLICATE KEY UPDATE
  name = VALUES(name), en_name = VALUES(en_name), description = VALUES(description), cover = VALUES(cover), is_highlighted = VALUES(is_highlighted);

INSERT INTO tags (id, code, label) VALUES
  (1, 'memory', 'Memory'),
  (2, 'harbor', 'Harbor Story'),
  (3, 'growth', 'Growth'),
  (4, 'healing', 'Healing')
ON DUPLICATE KEY UPDATE label = VALUES(label);

INSERT INTO books (id, title, subtitle, author, description, cover, score, rating, rating_count, recent_reads, is_featured, category_id, created_at) VALUES
  (1, 'Reading Sample: Long Remaining Life', 'Find each other in fate', 'Luo Xin', 'A warm narrative suitable for reader experience.', 'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80', 9.4, 9.1, 12000, 128000, 1, 1, NOW()),
  (2, 'Night Dive Film', 'Silence and tide', 'Chen Chunguang', 'A reflective novel around city and loneliness.', 'https://images.unsplash.com/photo-1481627834876-b7833e8f5570?auto=format&fit=crop&w=900&q=80', 9.1, 9.0, 9800, 86000, 0, 1, NOW()),
  (3, 'Klara and the Sun', 'A machine and love', 'Kazuo Ishiguro', 'Stories about care, replacement and hope.', 'https://images.unsplash.com/photo-1495446815901-a7297e633e8d?auto=format&fit=crop&w=900&q=80', 9.0, 8.9, 15000, 112000, 0, 2, NOW()),
  (4, 'Inside the Story', 'Details of ordinary life', 'Lan Xiaohuan', 'Small events with deep emotional waves.', 'https://images.unsplash.com/photo-1474932430478-367dbb6832c1?auto=format&fit=crop&w=900&q=80', 8.8, 8.7, 7200, 53000, 0, 1, NOW()),
  (5, 'Deep Focus', 'Work with calm mind', 'Lina Zhou', 'Build focus routines through practical methods.', 'https://images.unsplash.com/photo-1497633762265-9d179a990aa6?auto=format&fit=crop&w=900&q=80', 8.7, 8.8, 5400, 41000, 0, 2, NOW()),
  (6, 'Archive of Rainy Night', 'Letters and weather', 'Ming Li', 'A collection of letters and emotional records.', 'https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?auto=format&fit=crop&w=900&q=80', 8.9, 8.6, 4600, 37000, 0, 3, NOW())
ON DUPLICATE KEY UPDATE
  title = VALUES(title), subtitle = VALUES(subtitle), author = VALUES(author), description = VALUES(description),
  cover = VALUES(cover), score = VALUES(score), rating = VALUES(rating), rating_count = VALUES(rating_count),
  recent_reads = VALUES(recent_reads), is_featured = VALUES(is_featured), category_id = VALUES(category_id);

INSERT INTO book_tags (book_id, tag_id) VALUES
  (1,1),(1,2),(1,4),
  (2,2),(2,4),
  (3,1),(3,3),
  (4,3),(4,4),
  (5,3),
  (6,1),(6,2)
ON DUPLICATE KEY UPDATE tag_id = VALUES(tag_id);

INSERT INTO book_chapters (book_id, title, order_no, preview_url) VALUES
  (1, 'Chapter 1: Arrival at Old Harbor', 1, '/reader/1'),
  (1, 'Chapter 2: Notes on Rainy Night', 2, '/reader/1'),
  (2, 'Chapter 1: Tide Sound', 1, '/reader/2'),
  (3, 'Chapter 1: Artificial Heartbeat', 1, '/reader/3')
ON DUPLICATE KEY UPDATE title = VALUES(title), preview_url = VALUES(preview_url);

-- ========== Reader Content (book_id=1) ==========
INSERT INTO reader_sections (id, book_id, section_key, title, summary, level, order_no, created_at) VALUES
  (101, 1, 'chapter-1', 'Chapter 1: Arrival at Old Harbor', 'The traveler arrives in a humid harbor city.', 1, 1, NOW()),
  (102, 1, 'chapter-1-1', '1.1 Letter in Sea Fog', 'An unsigned letter triggers old memories.', 2, 2, NOW()),
  (103, 1, 'chapter-1-2', '1.2 Conversation under Lighthouse', 'She talks with a lighthouse keeper.', 2, 3, NOW()),
  (104, 1, 'chapter-2', 'Chapter 2: Rainy Night Notes', 'She reorganizes old notes and emotions.', 1, 4, NOW())
ON DUPLICATE KEY UPDATE
  title = VALUES(title), summary = VALUES(summary), level = VALUES(level), order_no = VALUES(order_no);

INSERT INTO reader_paragraphs (id, section_id, paragraph_key, text, order_no, created_at) VALUES
  (1001, 101, 'p1', 'Dusk pressed over the harbor and the wet boardwalk echoed softly under the tide.', 1, NOW()),
  (1002, 101, 'p2', 'She stood at the door for a few seconds, unsure if she came to hide from rain or to recover a paused life.', 2, NOW()),
  (1003, 102, 'p3', 'The letter did not explain why he left. It only said some people circle for years to return to the first light they trusted.', 1, NOW()),
  (1004, 102, 'p4', 'Outside the window, fog thickened and every street lamp became a blurred circle.', 2, NOW()),
  (1005, 103, 'p5', 'The keeper said ships do not stop because the tower is silent, but they steer better when one steady light remains.', 1, NOW()),
  (1006, 103, 'p6', 'Wind crossed the railings and she wanted to tell the sea all the unsent sentences from those years.', 2, NOW()),
  (1007, 104, 'p7', 'At night she reopened old notes and copied lines she once rushed through.', 1, NOW()),
  (1008, 104, 'p8', 'Understanding is not an appendix of forgiveness, but a small lamp left for oneself.', 2, NOW())
ON DUPLICATE KEY UPDATE text = VALUES(text), order_no = VALUES(order_no);

INSERT INTO reader_highlights (id, book_id, paragraph_key, start_offset, end_offset, selected_text, color, note, created_by, created_at) VALUES
  (201, 1, 'p3', 53, 118, 'some people circle for years to return to the first light they trusted', 'amber', 'This sentence feels like the core theme of the story.', 'Alice Lin', NOW()),
  (202, 1, 'p5', 55, 103, 'one steady light remains', 'sky', 'Great metaphor for emotional stability.', 'Bob Chen', NOW()),
  (203, 1, 'p8', 0, 85, 'Understanding is not an appendix of forgiveness, but a small lamp left for oneself.', 'rose', 'This line is a gentle ending.', 'Cindy Wu', NOW())
ON DUPLICATE KEY UPDATE
  selected_text = VALUES(selected_text), color = VALUES(color), note = VALUES(note), created_by = VALUES(created_by);

INSERT INTO reader_highlight_comments (highlight_id, author, content, created_at) VALUES
  (201, 'Bob Chen', 'Agree. This line connects the opening and ending very well.', NOW()),
  (201, 'Cindy Wu', 'I bookmarked this too.', NOW()),
  (202, 'Alice Lin', 'Simple line but very powerful.', NOW())
ON DUPLICATE KEY UPDATE content = VALUES(content);

INSERT INTO reader_book_comments (book_id, author, content, created_at) VALUES
  (1, 'Alice Lin', 'Steady pace and very immersive reading experience.', NOW()),
  (1, 'Bob Chen', 'Good for night reading with tea.', NOW()),
  (1, 'Cindy Wu', 'Loved the lighthouse metaphor in chapter 1.2.', NOW())
ON DUPLICATE KEY UPDATE content = VALUES(content);

-- ========== Mood + Recommendation ==========
INSERT INTO moods (id, label, icon) VALUES
  ('healing', 'Seeking Healing', 'hugeicons:cloud-01'),
  ('brainstorm', 'Brainstorm', 'hugeicons:flash'),
  ('focus', 'Deep Focus', 'hugeicons:target-02')
ON DUPLICATE KEY UPDATE label = VALUES(label), icon = VALUES(icon);

INSERT INTO mood_book_recommendations (mood_id, book_id, weight) VALUES
  ('healing', 1, 100), ('healing', 2, 90), ('healing', 6, 82),
  ('brainstorm', 3, 95), ('brainstorm', 5, 88),
  ('focus', 5, 99), ('focus', 3, 86)
ON DUPLICATE KEY UPDATE weight = VALUES(weight);

-- ========== User shelf + progress ==========
INSERT INTO user_shelf (user_id, book_id, created_at) VALUES
  (2, 1, NOW()), (2, 3, NOW()),
  (3, 1, NOW()), (3, 2, NOW()),
  (4, 1, NOW()), (4, 6, NOW())
ON DUPLICATE KEY UPDATE created_at = VALUES(created_at);

INSERT INTO user_reading_progress (user_id, book_id, section_id, paragraph_id, scroll_percent, created_at, updated_at) VALUES
  (2, 1, 'chapter-1-2', 'p5', 68.50, NOW(), NOW()),
  (2, 3, 'chapter-1', 'p1', 22.00, NOW(), NOW()),
  (3, 1, 'chapter-2', 'p7', 84.00, NOW(), NOW()),
  (4, 6, 'chapter-1', 'p1', 31.50, NOW(), NOW())
ON DUPLICATE KEY UPDATE
  section_id = VALUES(section_id), paragraph_id = VALUES(paragraph_id), scroll_percent = VALUES(scroll_percent), updated_at = NOW();

INSERT INTO recommendation_feedback (user_id, book_id, action, created_at) VALUES
  (2, 1, 'click', NOW()),
  (2, 3, 'add_shelf', NOW()),
  (3, 2, 'dismiss', NOW()),
  (4, 6, 'like', NOW())
ON DUPLICATE KEY UPDATE action = VALUES(action);

-- ========== Ranking + tasks ==========
INSERT INTO book_rankings (type, rank_no, book_id, snapshot_date) VALUES
  ('high_score', 1, 1, '2026-03-21'),
  ('high_score', 2, 2, '2026-03-21'),
  ('high_score', 3, 3, '2026-03-21'),
  ('word_of_mouth', 1, 3, '2026-03-21'),
  ('word_of_mouth', 2, 1, '2026-03-21'),
  ('word_of_mouth', 3, 6, '2026-03-21')
ON DUPLICATE KEY UPDATE book_id = VALUES(book_id);

INSERT INTO weekly_reading_tasks (user_id, week_start_date, target_books, finished_books, reward_desc, created_at, updated_at) VALUES
  (2, '2026-03-16', 5, 3, 'Unlock spring limited bookmark', NOW(), NOW()),
  (3, '2026-03-16', 4, 2, 'Unlock profile frame', NOW(), NOW()),
  (4, '2026-03-16', 3, 3, 'Unlock reading badge', NOW(), NOW())
ON DUPLICATE KEY UPDATE
  target_books = VALUES(target_books), finished_books = VALUES(finished_books), reward_desc = VALUES(reward_desc), updated_at = NOW();

-- ========== Reviews ==========
INSERT INTO reviews (id, user_id, book_id, content, likes_count, comments_count, created_at) VALUES
  (701, 2, 1, 'The story is calm but emotionally strong. Great for slow reading.', 12, 2, NOW()),
  (702, 3, 3, 'A thoughtful book about care and replacement.', 9, 1, NOW()),
  (703, 4, 2, 'Very visual writing. Feels like watching a silent film.', 6, 1, NOW())
ON DUPLICATE KEY UPDATE
  content = VALUES(content), likes_count = VALUES(likes_count), comments_count = VALUES(comments_count);

INSERT INTO review_likes (review_id, user_id, is_like, created_at) VALUES
  (701, 3, 1, NOW()),
  (701, 4, 1, NOW()),
  (702, 2, 1, NOW()),
  (703, 2, 1, NOW())
ON DUPLICATE KEY UPDATE is_like = VALUES(is_like);

INSERT INTO review_comments (review_id, user_id, content, created_at) VALUES
  (701, 3, 'I had the same feeling around chapter 1.', NOW()),
  (701, 4, 'The wording is clean and vivid.', NOW()),
  (702, 2, 'Totally agree with this review.', NOW())
ON DUPLICATE KEY UPDATE content = VALUES(content);

COMMIT;
SET FOREIGN_KEY_CHECKS = 1;
