-- MySQL schema for BookRecommendSystem homepage-related features
-- Charset: utf8mb4, Engine: InnoDB
--
-- 初始化：已存在的表先删除再创建（DROP IF EXISTS + CREATE）。
-- 临时关闭外键检查，避免删除顺序受依赖约束。

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `book_chapters`;
DROP TABLE IF EXISTS `book_analytics_events`;
DROP TABLE IF EXISTS `book_versions`;
DROP TABLE IF EXISTS `book_manuscripts`;
DROP TABLE IF EXISTS `book_rankings`;
DROP TABLE IF EXISTS `book_tags`;
DROP TABLE IF EXISTS `books`;
DROP TABLE IF EXISTS `categories`;
DROP TABLE IF EXISTS `mood_book_recommendations`;
DROP TABLE IF EXISTS `moods`;
DROP TABLE IF EXISTS `notifications`;
DROP TABLE IF EXISTS `permissions`;
DROP TABLE IF EXISTS `reader_book_comments`;
DROP TABLE IF EXISTS `reader_highlight_comments`;
DROP TABLE IF EXISTS `reader_highlights`;
DROP TABLE IF EXISTS `reader_paragraphs`;
DROP TABLE IF EXISTS `reader_sections`;
DROP TABLE IF EXISTS `recommendation_feedback`;
DROP TABLE IF EXISTS `review_comments`;
DROP TABLE IF EXISTS `review_likes`;
DROP TABLE IF EXISTS `reviews`;
DROP TABLE IF EXISTS `role_permissions`;
DROP TABLE IF EXISTS `roles`;
DROP TABLE IF EXISTS `tags`;
DROP TABLE IF EXISTS `user_reading_progress`;
DROP TABLE IF EXISTS `user_roles`;
DROP TABLE IF EXISTS `user_shelf`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `weekly_reading_tasks`;

SET FOREIGN_KEY_CHECKS = 1;

-- ======================
-- 用户 & 权限体系（对应现有 models）
-- ======================

CREATE TABLE `users` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(80) NOT NULL UNIQUE,
  `name`          VARCHAR(80) DEFAULT NULL,
  `email`         VARCHAR(120) NOT NULL UNIQUE,
  `avatar_url`    VARCHAR(500) DEFAULT NULL,
  `age`           INT DEFAULT NULL,
  `province`      VARCHAR(64) DEFAULT NULL,
  `city`          VARCHAR(64) DEFAULT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `role`          VARCHAR(20)  NOT NULL DEFAULT 'user',
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `roles` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`        VARCHAR(80) NOT NULL UNIQUE,
  `description` VARCHAR(255),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `permissions` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`        VARCHAR(100) NOT NULL UNIQUE,
  `description` VARCHAR(255),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `role_permissions` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `role_id`       BIGINT UNSIGNED NOT NULL,
  `permission_id` BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_role_permission` (`role_id`, `permission_id`),
  CONSTRAINT `fk_rp_role`       FOREIGN KEY (`role_id`)       REFERENCES `roles`(`id`)       ON DELETE CASCADE,
  CONSTRAINT `fk_rp_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `user_roles` (
  `id`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `role_id` BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_user_role` (`user_id`, `role_id`),
  CONSTRAINT `fk_ur_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ur_role` FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 通知（未读数量）
-- ======================

CREATE TABLE `notifications` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `title`      VARCHAR(255) NOT NULL,
  `content`    TEXT,
  `is_read`    TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_notifications_user` (`user_id`, `is_read`),
  CONSTRAINT `fk_notifications_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 图书主体（书籍、分类、标签）
-- ======================

CREATE TABLE `categories` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`          VARCHAR(64) NOT NULL UNIQUE,
  `name`          VARCHAR(100) NOT NULL,
  `en_name`       VARCHAR(100),
  `description`   VARCHAR(255),
  `cover`         VARCHAR(500),
  `is_highlighted` TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `tags` (
  `id`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`    VARCHAR(64) NOT NULL UNIQUE,
  `label`   VARCHAR(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `books` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `title`         VARCHAR(255) NOT NULL,
  `subtitle`      VARCHAR(255),
  `author`        VARCHAR(255),
  `description`   TEXT,
  `cover`         VARCHAR(500),
  `score`         DECIMAL(3,1) DEFAULT NULL,
  `rating`        DECIMAL(3,1) DEFAULT NULL,
  `rating_count`  BIGINT UNSIGNED DEFAULT 0,
  `recent_reads`  BIGINT UNSIGNED DEFAULT 0,
  `is_featured`   TINYINT(1) NOT NULL DEFAULT 0,
  `category_id`   BIGINT UNSIGNED DEFAULT NULL,
  `status`        VARCHAR(20) NOT NULL DEFAULT 'published',
  `creator_id`    BIGINT UNSIGNED DEFAULT NULL,
  `published_at`  DATETIME DEFAULT NULL,
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_books_category` (`category_id`),
  CONSTRAINT `fk_books_category` FOREIGN KEY (`category_id`) REFERENCES `categories`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `book_manuscripts` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`       BIGINT UNSIGNED NOT NULL,
  `creator_id`    BIGINT UNSIGNED NOT NULL,
  `title`         VARCHAR(255) NOT NULL,
  `cover`         VARCHAR(500) DEFAULT NULL,
  `description`   TEXT,
  `content_text`  LONGTEXT,
  `status`        VARCHAR(20) NOT NULL DEFAULT 'draft',
  `review_comment` TEXT,
  `submitted_at`  DATETIME DEFAULT NULL,
  `reviewed_at`   DATETIME DEFAULT NULL,
  `reviewed_by`   BIGINT UNSIGNED DEFAULT NULL,
  `published_at`  DATETIME DEFAULT NULL,
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_bm_book` (`book_id`),
  KEY `idx_bm_creator` (`creator_id`),
  KEY `idx_bm_status` (`status`),
  CONSTRAINT `fk_bm_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_bm_creator` FOREIGN KEY (`creator_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `book_versions` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`       BIGINT UNSIGNED NOT NULL,
  `manuscript_id` BIGINT UNSIGNED DEFAULT NULL,
  `version_no`    INT NOT NULL,
  `title`         VARCHAR(255) NOT NULL,
  `cover`         VARCHAR(500) DEFAULT NULL,
  `description`   TEXT,
  `content_text`  LONGTEXT,
  `created_by`    BIGINT UNSIGNED DEFAULT NULL,
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_book_version_no` (`book_id`, `version_no`),
  KEY `idx_bv_book` (`book_id`),
  CONSTRAINT `fk_bv_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_bv_manuscript` FOREIGN KEY (`manuscript_id`) REFERENCES `book_manuscripts`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `book_tags` (
  `id`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id` BIGINT UNSIGNED NOT NULL,
  `tag_id`  BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_book_tag` (`book_id`, `tag_id`),
  KEY `idx_bt_tag` (`tag_id`),
  CONSTRAINT `fk_bt_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_bt_tag`  FOREIGN KEY (`tag_id`)  REFERENCES `tags`(`id`)  ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 试读 / 章节
-- ======================

CREATE TABLE `book_chapters` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`     BIGINT UNSIGNED NOT NULL,
  `title`       VARCHAR(255) NOT NULL,
  `order_no`    INT NOT NULL DEFAULT 1,
  `preview_url` VARCHAR(500) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_chapters_book` (`book_id`, `order_no`),
  CONSTRAINT `fk_chapters_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 用户阅读进度（首页续读）
-- ======================

CREATE TABLE `user_reading_progress` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`       BIGINT UNSIGNED NOT NULL,
  `book_id`       BIGINT UNSIGNED NOT NULL,
  `section_id`    VARCHAR(64) DEFAULT NULL,
  `paragraph_id`  VARCHAR(64) DEFAULT NULL,
  `scroll_percent` DECIMAL(5,2) NOT NULL DEFAULT 0.00,
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_user_book_progress` (`user_id`, `book_id`),
  KEY `idx_urp_user` (`user_id`),
  KEY `idx_urp_book` (`book_id`),
  CONSTRAINT `fk_urp_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_urp_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `book_analytics_events` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`               BIGINT UNSIGNED NOT NULL,
  `user_id`               BIGINT UNSIGNED DEFAULT NULL,
  `event_type`            VARCHAR(32) NOT NULL,
  `session_id`            VARCHAR(64) DEFAULT NULL,
  `read_duration_seconds` INT NOT NULL DEFAULT 0,
  `geo_label`             VARCHAR(100) DEFAULT NULL,
  `age_group`             VARCHAR(32) DEFAULT NULL,
  `created_at`            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_bae_book` (`book_id`),
  KEY `idx_bae_user` (`user_id`),
  KEY `idx_bae_event_type` (`event_type`),
  KEY `idx_bae_session` (`session_id`),
  KEY `idx_bae_created_at` (`created_at`),
  CONSTRAINT `fk_bae_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_bae_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `reader_user_preferences` (
  `id`               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`          BIGINT UNSIGNED NOT NULL,
  `theme`            VARCHAR(16) NOT NULL DEFAULT 'light',
  `font_size`        INT NOT NULL DEFAULT 20,
  `show_highlights`  TINYINT(1) NOT NULL DEFAULT 1,
  `show_comments`    TINYINT(1) NOT NULL DEFAULT 1,
  `updated_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_reader_pref_user` (`user_id`),
  CONSTRAINT `fk_reader_pref_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `reader_sections` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`     BIGINT UNSIGNED NOT NULL,
  `section_key` VARCHAR(64) NOT NULL,
  `title`       VARCHAR(255) NOT NULL,
  `summary`     TEXT,
  `level`       INT NOT NULL DEFAULT 1,
  `order_no`    INT NOT NULL DEFAULT 1,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_reader_section_key` (`book_id`, `section_key`),
  KEY `idx_reader_sections_book` (`book_id`, `order_no`),
  CONSTRAINT `fk_reader_sections_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `reader_paragraphs` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `section_id`    BIGINT UNSIGNED NOT NULL,
  `paragraph_key` VARCHAR(64) NOT NULL,
  `text`          TEXT NOT NULL,
  `order_no`      INT NOT NULL DEFAULT 1,
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_reader_paragraph_key` (`section_id`, `paragraph_key`),
  KEY `idx_reader_paragraphs_section` (`section_id`, `order_no`),
  CONSTRAINT `fk_reader_paragraphs_section` FOREIGN KEY (`section_id`) REFERENCES `reader_sections`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `reader_highlights` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`       BIGINT UNSIGNED NOT NULL,
  `paragraph_key` VARCHAR(64) NOT NULL,
  `start_offset`  INT NOT NULL,
  `end_offset`    INT NOT NULL,
  `selected_text` TEXT NOT NULL,
  `color`         VARCHAR(32) NOT NULL DEFAULT 'amber',
  `note`          TEXT,
  `created_by`    VARCHAR(64) NOT NULL DEFAULT '当前读者',
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_reader_highlights_book` (`book_id`, `paragraph_key`),
  CONSTRAINT `fk_reader_highlights_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `reader_highlight_comments` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `highlight_id` BIGINT UNSIGNED NOT NULL,
  `author`       VARCHAR(64) NOT NULL DEFAULT '当前读者',
  `content`      TEXT NOT NULL,
  `is_violation` TINYINT(1) NOT NULL DEFAULT 0,
  `violation_reason` VARCHAR(255) DEFAULT NULL,
  `moderated_at` DATETIME DEFAULT NULL,
  `moderated_by` BIGINT UNSIGNED DEFAULT NULL,
  `created_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_reader_hc_highlight` (`highlight_id`),
  CONSTRAINT `fk_reader_hc_highlight` FOREIGN KEY (`highlight_id`) REFERENCES `reader_highlights`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `reader_book_comments` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `book_id`    BIGINT UNSIGNED NOT NULL,
  `author`     VARCHAR(64) NOT NULL DEFAULT '当前读者',
  `content`    TEXT NOT NULL,
  `is_violation` TINYINT(1) NOT NULL DEFAULT 0,
  `violation_reason` VARCHAR(255) DEFAULT NULL,
  `moderated_at` DATETIME DEFAULT NULL,
  `moderated_by` BIGINT UNSIGNED DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_reader_book_comments_book` (`book_id`),
  CONSTRAINT `fk_reader_book_comments_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 心境（moods） & 基于心境的推荐
-- ======================

CREATE TABLE `moods` (
  `id`     VARCHAR(64) NOT NULL,
  `label`  VARCHAR(100) NOT NULL,
  `icon`   VARCHAR(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `mood_book_recommendations` (
  `id`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `mood_id` VARCHAR(64) NOT NULL,
  `book_id` BIGINT UNSIGNED NOT NULL,
  `weight`  INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_mood_book` (`mood_id`, `book_id`),
  KEY `idx_mbr_book` (`book_id`),
  CONSTRAINT `fk_mbr_mood` FOREIGN KEY (`mood_id`) REFERENCES `moods`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_mbr_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 用户书架 & 个性化推荐反馈
-- ======================

CREATE TABLE `user_shelf` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `book_id`    BIGINT UNSIGNED NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_user_book` (`user_id`, `book_id`),
  KEY `idx_shelf_book` (`book_id`),
  CONSTRAINT `fk_shelf_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_shelf_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `recommendation_feedback` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `book_id`    BIGINT UNSIGNED NOT NULL,
  `action`     VARCHAR(32) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rf_user_book` (`user_id`, `book_id`),
  CONSTRAINT `fk_rf_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_rf_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 榜单（高分口碑榜等）
-- ======================

CREATE TABLE `book_rankings` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `type`         VARCHAR(64) NOT NULL,
  `rank_no`      INT NOT NULL,
  `book_id`      BIGINT UNSIGNED NOT NULL,
  `snapshot_date` DATE NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_type_date_rank` (`type`, `snapshot_date`, `rank_no`),
  KEY `idx_br_book` (`book_id`),
  CONSTRAINT `fk_br_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 本周读书任务
-- ======================

CREATE TABLE `weekly_reading_tasks` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`         BIGINT UNSIGNED NOT NULL,
  `week_start_date` DATE NOT NULL,
  `target_books`    INT NOT NULL DEFAULT 0,
  `finished_books`  INT NOT NULL DEFAULT 0,
  `reward_desc`     VARCHAR(255),
  `created_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_user_week` (`user_id`, `week_start_date`),
  CONSTRAINT `fk_wrt_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======================
-- 书评 & 点赞 & 评论
-- ======================

CREATE TABLE `reviews` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `book_id`        BIGINT UNSIGNED NOT NULL,
  `content`        TEXT NOT NULL,
  `likes_count`    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `comments_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_reviews_book` (`book_id`),
  KEY `idx_reviews_user` (`user_id`),
  CONSTRAINT `fk_reviews_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_reviews_book` FOREIGN KEY (`book_id`) REFERENCES `books`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `review_likes` (
  `id`        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `review_id` BIGINT UNSIGNED NOT NULL,
  `user_id`   BIGINT UNSIGNED NOT NULL,
  `is_like`   TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_review_like` (`review_id`, `user_id`),
  CONSTRAINT `fk_rl_review` FOREIGN KEY (`review_id`) REFERENCES `reviews`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_rl_user`   FOREIGN KEY (`user_id`)   REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `review_comments` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `review_id`  BIGINT UNSIGNED NOT NULL,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `content`    TEXT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rc_review` (`review_id`),
  KEY `idx_rc_user`   (`user_id`),
  CONSTRAINT `fk_rc_review` FOREIGN KEY (`review_id`) REFERENCES `reviews`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_rc_user`   FOREIGN KEY (`user_id`)   REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

