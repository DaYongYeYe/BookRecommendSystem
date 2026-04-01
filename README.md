# BookRecommendSystem

一个围绕“阅读发现 + 在线阅读 + 创作投稿 + 后台审核”实现的全栈项目。

当前仓库由两部分组成：

- 后端：`Flask + SQLAlchemy + MySQL + JWT`
- 前端：`Vue 3 + TypeScript + Vite + Element Plus`

项目已经不是单一的“图书推荐页”，而是包含读者端、创作者端、管理端和 RBAC 权限管理的完整业务原型。

## 当前已实现的功能

### 读者端

- 首页推荐：
  - 个性化推荐
  - 热门标签与精选分类
  - 榜单卡片
  - 继续阅读入口
- 搜索与发现：
  - 关键词搜索
  - 热搜词
  - 搜索历史
  - 分类页按分类、标签、连载状态筛选
  - 更多推荐分页浏览
- 榜单：
  - 支持多种榜单类型切换
  - 展示榜单元数据、更新时间和完整列表
- 书籍详情：
  - 书籍基础信息
  - 分类、标签、字数、评分、在读人数
  - 阅读进度提示
  - 加入 / 移出书架
  - 相关推荐
- 在线阅读器：
  - 章节大纲与正文阅读
  - 阅读进度自动同步
  - 阅读偏好设置（主题、字号、评论可见性）
  - 文本划线
  - 划线评论
  - 书籍评论
- 用户中心：
  - 个人资料查看与编辑
  - 头像上传
  - 修改密码
  - 我的收藏
  - 浏览 / 阅读历史

### 认证与账号能力

- 普通用户图形验证码登录
- 用户注册支持邮箱验证码
- 忘记密码支持邮箱验证码重置
- 登录态检查与 JWT 鉴权
- 管理员独立登录 / 注册入口
- 管理员注册码控制后台账号开通

### 创作者端

- 创作者入口页，和阅读端做角色分流
- 创作数据看板：
  - 总曝光量
  - 总阅读量
  - 阅读用户数
  - 每本作品的阅读表现
  - 地域 / 年龄分布摘要
- 作品管理：
  - 新建作品
  - 编辑作品基础资料
  - 设置分类、子分类、标签
  - 上传封面
  - 设置连载状态、收费模式、创作属性
  - 提交作品资料审核
  - 上下架操作
- 稿件管理：
  - 新建新书稿件
  - 维护已有书籍稿件
  - 章节新增、排序、覆盖更新
  - 保存草稿
  - 提交审核
- 创作者前置约束：
  - 进入创作者后台前需要先设置笔名
  - 需要账号具备 `creator` 角色

### 管理端

- 仪表盘：
  - 待审核稿件数
  - 今日新增用户
  - 违规评论统计
  - 今日发布图书
  - 用户总量
  - 近 14 天趋势
- 用户管理：
  - 分页查询
  - 新增用户
  - 编辑用户
  - 删除用户
  - 重置密码
  - 管理 `creator` / `admin` / `editor` / `user` 角色字段
- 图书管理：
  - 新增 / 编辑 / 删除图书
  - 封面上传
  - 分类与标签维护
  - 推荐位开关
  - 批量状态更新
  - 批量分类 / 标签 / 推荐设置
- 作品资料审核：
  - 查看作品资料
  - 审核通过 / 驳回
- 稿件审核与发布：
  - 查看稿件列表
  - 稿件审核
  - 稿件发布为正式内容
- 评论管理：
  - 图书评论与划线评论统一管理
  - 删除评论
  - 标记 / 取消违规

### RBAC 权限管理

RBAC 页面仅允许超级管理员访问，当前已实现：

- 角色管理
- 权限管理
- 角色绑定权限
- 用户绑定角色
- 查询用户最终权限

## 技术栈

### 前端

- Vue 3
- TypeScript
- Vue Router
- Vite
- Element Plus
- Axios
- Tailwind CSS 4

### 后端

- Flask
- Flask-SQLAlchemy
- Flask-CORS
- Flask-Redis
- PyMySQL
- PyJWT
- python-dotenv
- 腾讯云 COS SDK

## 项目结构

```text
BookRecommendSystem/
├─ app/
│  ├─ __init__.py              # create_app、蓝图注册、兼容性补丁、分类/标签初始化
│  ├─ models.py                # 用户、图书、稿件、阅读器、RBAC 等模型
│  ├─ auth/                    # /auth 普通用户认证
│  ├─ user/                    # /user 用户中心
│  ├─ api/                     # /api 阅读端接口与阅读器接口
│  ├─ creator/                 # /creator 创作者接口
│  ├─ admin/                   # /admin 管理后台接口
│  ├─ rbac/                    # /rbac 超级管理员权限管理
│  └─ services/                # 验证码、邮件发送、发布、阅读器服务等
├─ frontend/
│  ├─ src/
│  │  ├─ api/                  # 前端接口封装
│  │  ├─ router/               # 路由与守卫
│  │  ├─ views/                # 读者端 / 管理端 / 创作者端页面
│  │  ├─ components/           # 组件
│  │  ├─ composables/          # 阅读偏好、阅读进度、创作者资料等
│  │  └─ constants/            # 榜单、分类导航等常量
│  ├─ package.json
│  └─ vite.config.ts
├─ schema.sql                  # 推荐使用的完整数据库初始化脚本
├─ mock_seed_compatible.sql    # 与当前代码兼容的示例数据
├─ database_schema.sql         # 历史数据库脚本
├─ requirements.txt
├─ docker-compose.yml
├─ restart-backend.ps1
└─ .env.example
```

## 运行环境

- Python 3.11+
- Node.js 18+
- MySQL 8.0+
- Redis 7+（可选）

## 快速开始

### 1. 进入项目目录

```powershell
cd BookRecommendSystem
```

### 2. 配置后端环境

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

然后编辑 `.env`，至少补齐：

- `DATABASE_URL`
- `SECRET_KEY`
- `JWT_SECRET_KEY`

如果要启用邮箱验证码，再补齐：

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`

### 3. 准备数据库

推荐顺序：

1. 创建数据库
2. 执行 [`schema.sql`](./schema.sql)
3. 按需执行 [`mock_seed_compatible.sql`](./mock_seed_compatible.sql)

示例：

```sql
CREATE DATABASE book_recommend_db DEFAULT CHARACTER SET utf8mb4;
USE book_recommend_db;
SOURCE schema.sql;
SOURCE mock_seed_compatible.sql;
```

说明：

- `schema.sql` 才覆盖当前首页、搜索、榜单、阅读器、评论、创作者、管理端所需表结构。
- `flask init-db` 只会按 SQLAlchemy 模型创建表，更适合做最小化本地调试，不替代完整 SQL 初始化。

### 4. 安装前端依赖

```powershell
cd frontend
npm install
cd ..
```

## 启动项目

完整联调需要两个独立进程。

### 启动后端 Flask

在仓库根目录执行：

```powershell
$env:FLASK_APP = "app:create_app"
$env:FLASK_ENV = "development"
flask run --host 127.0.0.1 --port 5000
```

也可以使用仓库脚本：

```powershell
.\restart-backend.ps1
```

### 启动前端 Vite

```powershell
cd frontend
npm run dev
```

默认地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:5000`

Vite 已代理这些后端前缀到 Flask：

- `/auth`
- `/user`
- `/admin`
- `/creator`
- `/rbac`
- `/api`

## Docker 辅助依赖

仓库提供了 MySQL 和 Redis 的 `docker-compose.yml`：

```powershell
docker compose up -d
```

默认映射：

- MySQL：`13306 -> 3306`
- Redis：`6379 -> 6379`

如果你直接使用该容器配置，`.env` 中数据库连接可按容器账号改成类似：

```env
DATABASE_URL=mysql+pymysql://book_user:book_password@127.0.0.1:13306/book_recommend_db
REDIS_URL=redis://127.0.0.1:6379/0
```

## 示例数据

执行 [`mock_seed_compatible.sql`](./mock_seed_compatible.sql) 后，默认会生成示例用户。

已写入的账号包括：

- 管理员：`admin`
- 普通读者：`reader_alice`
- 普通读者：`reader_bob`
- 普通读者：`reader_cindy`

默认密码均为：

```text
123456
```

注意：

- 示例数据里默认没有创作者账号。
- 如需测试创作者后台，可先用管理员在后台把某个用户角色改为 `creator`。

## 关键环境变量

### 基础与鉴权

- `DATABASE_URL`
- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `JWT_EXPIRES_IN`
- `CAPTCHA_EXPIRES_IN`
- `ADMIN_REGISTER_CODE`
- `DEFAULT_TENANT_ID`

### 邮箱验证码

- `AUTH_NOTIFICATION_PROVIDER`
- `AUTH_CODE_EXPIRES_IN`
- `AUTH_CODE_RESEND_SECONDS`
- `AUTH_CODE_MAX_ATTEMPTS`
- `AUTH_CODE_REQUIRE_CAPTCHA`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`
- `SMTP_FROM_NAME`
- `SMTP_USE_SSL`
- `SMTP_USE_TLS`

### Redis 与上传

- `REDIS_URL`
- `UPLOAD_DIR`
- `COVER_UPLOAD_SUBDIR`
- `MAX_COVER_UPLOAD_SIZE`
- `MAX_AVATAR_UPLOAD_SIZE`

### 腾讯云 COS

- `COS_SECRET_ID`
- `COS_SECRET_KEY`
- `COS_REGION`
- `COS_BUCKET`
- `COS_DOMAIN`

### 日志

- `LOG_LEVEL`
- `LOG_DIR`
- `LOG_RETENTION_DAYS`

## 主要前端页面

### 读者端

- `/`
- `/search`
- `/categories`
- `/recommendations`
- `/rankings`
- `/books/:bookId`
- `/reader/:bookId`
- `/user/profile`
- `/user/library`

### 认证

- `/login`
- `/register`

### 创作者端

- `/creator-center`
- `/creator/dashboard`
- `/creator/works`
- `/creator/manuscripts`

### 管理端

- `/manage/login`
- `/manage/register`
- `/manage/dashboard`
- `/manage/users`
- `/manage/books`
- `/manage/comments`
- `/manage/works/review`
- `/manage/manuscripts/review`
- `/manage/rbac/roles`
- `/manage/rbac/permissions`
- `/manage/rbac/role-permissions`
- `/manage/rbac/user-roles`

## 后端接口概览

### `/auth`

- `GET /auth/captcha`
- `POST /auth/email-code`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/password-reset`
- `POST /auth/logout`
- `GET /auth/check`

### `/user`

- `GET /user/profile`
- `PUT /user/profile`
- `POST /user/avatar/upload`
- `POST /user/change_password`
- `GET /user/favorites`
- `GET /user/history`

### `/api`

- 搜索与发现：
  - `GET /api/search/hot-terms`
  - `GET /api/search/history`
  - `DELETE /api/search/history`
  - `GET /api/books/search`
  - `GET /api/categories`
  - `GET /api/categories/highlighted`
  - `GET /api/tags/hot`
  - `GET /api/books/by-category`
  - `GET /api/recommendations/more`
- 首页与推荐：
  - `GET /api/home/continue-reading`
  - `GET /api/books/featured`
  - `GET /api/moods`
  - `GET /api/recommendations/by-mood`
  - `GET /api/recommendations/personalized`
  - `POST /api/recommendations/feedback`
  - `GET /api/books/rankings`
- 阅读任务与互动：
  - `GET /api/user/weekly-reading-task`
  - `POST /api/user/weekly-reading-task/progress`
  - `GET /api/reviews/highlighted`
  - `POST /api/reviews/:id/like`
  - `POST /api/reviews/:id/comments`
  - `GET /api/notifications/unread-count`
- 阅读器：
  - `GET /api/books/:bookId/landing`
  - `GET /api/books/:bookId/reader`
  - `GET /api/books/:bookId/preview`
  - `POST /api/books/:bookId/highlights`
  - `POST /api/books/:bookId/highlights/:highlightId/comments`
  - `POST /api/books/:bookId/comments`
  - `GET /api/books/:bookId/progress`
  - `POST /api/books/:bookId/progress`
  - `POST /api/shelf`
  - `POST /api/shelf/toggle`
  - `GET /api/reader/preferences`
  - `POST /api/reader/preferences`

### `/creator`

- `GET /creator/books`
- `GET /creator/books/:bookId/chapters`
- `GET /creator/books/analytics`
- `GET /creator/work-options`
- `GET /creator/works`
- `GET /creator/works/:bookId`
- `POST /creator/works`
- `PUT /creator/works/:bookId`
- `POST /creator/works/:bookId/submit-audit`
- `POST /creator/works/:bookId/shelf`
- `POST /creator/works/:bookId/completion-status`
- `GET /creator/manuscripts`
- `POST /creator/manuscripts`
- `PUT /creator/manuscripts/:manuscriptId`
- `POST /creator/manuscripts/:manuscriptId/submit`

### `/admin`

- 认证：
  - `GET /admin/auth/captcha`
  - `POST /admin/auth/register`
  - `POST /admin/auth/login`
- 仪表盘：
  - `GET /admin/dashboard/overview`
- 用户管理：
  - `GET /admin/users`
  - `POST /admin/users`
  - `GET /admin/users/:id`
  - `PUT /admin/users/:id`
  - `DELETE /admin/users/:id`
  - `POST /admin/users/:id/reset_password`
- 图书管理：
  - `GET /admin/books`
  - `POST /admin/books`
  - `PUT /admin/books/:id`
  - `DELETE /admin/books/:id`
  - `GET /admin/books/options`
  - `POST /admin/books/cover/upload`
  - `POST /admin/books/batch`
- 作品与稿件审核：
  - `GET /admin/works/reviews`
  - `POST /admin/works/:bookId/review`
  - `GET /admin/manuscripts`
  - `POST /admin/manuscripts/:manuscriptId/review`
  - `POST /admin/manuscripts/:manuscriptId/publish`
- 评论管理：
  - `GET /admin/comments`
  - `DELETE /admin/comments/:type/:id`
  - `POST /admin/comments/:type/:id/violation`

### `/rbac`

- `GET /rbac/roles`
- `POST /rbac/roles`
- `PUT /rbac/roles/:roleId`
- `DELETE /rbac/roles/:roleId`
- `GET /rbac/permissions`
- `POST /rbac/permissions`
- `GET /rbac/roles/:roleId/permissions`
- `POST /rbac/roles/:roleId/permissions`
- `DELETE /rbac/roles/:roleId/permissions/:permissionId`
- `GET /rbac/users/:userId/roles`
- `POST /rbac/users/:userId/roles`
- `DELETE /rbac/users/:userId/roles/:roleId`
- `GET /rbac/users/:userId/permissions`

## 代码层面的实现说明

- 应用入口为 `app:create_app`。
- 启动时会自动注册全部蓝图，并执行轻量级数据库兼容补丁：
  - 缺失字段自动补齐
  - 缺失表自动创建
  - 分类与标签基础数据自动补种
- 如果数据库中已经存在管理员，但还没有超级管理员，系统会自动把第一个管理员提升为超级管理员。
- 验证码和邮箱验证码优先使用 Redis；如果未配置 Redis，会退回到进程内存存储。
- 邮件发送当前实际实现的是 SMTP；阿里云 / 腾讯云发送器只预留了扩展位置，还没有接好。
- 上传文件默认落在 `instance/uploads`，并通过 `/uploads/<path>` 暴露访问。
- 配置了腾讯云 COS 时，头像 / 封面上传可走对象存储。

## 开发说明

- 修改后端接口后，建议至少联调这些页面：
  - 登录 / 注册
  - 首页 / 搜索 / 阅读页
  - 创作者稿件页
  - 管理后台对应页面
- 修改前端页面后，建议同时打开读者端与后台验证路由守卫和鉴权逻辑。
- 当前前端没有配置真正的 `lint` 流程，`npm run lint` 只会输出占位信息。
- 仓库中没有现成的自动化测试套件，主要依赖手动联调验证。

## 常见问题

### 1. 登录或注册收不到邮箱验证码

检查：

- `.env` 中 SMTP 配置是否完整
- `AUTH_NOTIFICATION_PROVIDER` 是否为 `smtp`
- 是否有网络权限连接邮件服务器

### 2. 图形验证码总是失效

检查：

- 前后端是否请求到了同一后端实例
- 是否配置了 Redis
- 如果未配置 Redis，是否频繁重启了 Flask 进程

### 3. 创作者后台进不去

检查：

- 当前用户是否已登录
- 当前用户角色是否为 `creator`
- 是否已设置笔名

### 4. RBAC 页面被拦截到 403

这是正常行为，只有超级管理员可访问 RBAC 页面。

### 5. 只有执行了 `flask init-db`，但很多页面没数据

这是因为完整功能依赖 [`schema.sql`](./schema.sql) 和示例数据脚本，不要只依赖 `flask init-db`。
