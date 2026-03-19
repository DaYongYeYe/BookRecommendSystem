-- MySQL schema for BookRecommendSystem homepage-related features
-- Charset: utf8mb4, Engine: InnoDB

-- ======================
-- 用户 & 权限体系（对应现有 models）
-- ======================

CREATE TABLE `users` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(80) NOT NULL UNIQUE,
  `email`         VARCHAR(120) NOT NULL UNIQUE,
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
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_books_category` (`category_id`),
  CONSTRAINT `fk_books_category` FOREIGN KEY (`category_id`) REFERENCES `categories`(`id`) ON DELETE SET NULL
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

