# BookRecommendSystem

图书推荐与在线阅读系统，包含以下三类端到端能力：

- 读者端：推荐首页、图书搜索、书籍详情、阅读器、书架、个人中心
- 创作者端：创建/编辑投稿，提交审核
- 管理端：管理员登录注册、用户管理、图书管理、稿件审核与发布

前端使用 `Vue 3 + TypeScript + Vite + Element Plus`，后端使用 `Flask + SQLAlchemy + MySQL + JWT`。

## 当前功能概览

### 前端页面（`frontend/src/views`）

- 读者端：`Home`、`BookDetail`、`BookEntry`、`Reader`、`UserProfile`、`UserLibrary`
- 认证页：`Login`、`Register`
- 管理端：`AdminLogin`、`AdminRegister`、`AdminDashboard`、`AdminUsers`、`AdminBooks`、`AdminComments`、`AdminManuscriptsReview`
- 创作者端：`CreatorManuscripts`

### 后端模块（`app/`）

- `auth`：用户验证码、注册、登录、登出、登录态检查
- `user`：个人资料、头像上传、密码修改、收藏与历史
- `api`：首页推荐/搜索/书架、阅读任务、榜单、书评互动、阅读器相关接口
- `creator`：创作者稿件管理与提审
- `admin`：管理员认证、用户管理、图书管理、稿件审核发布
- `rbac`：角色、权限、用户角色分配与权限查询

## 技术栈

### 前端

- Vue 3
- TypeScript
- Vue Router
- Vite
- Element Plus
- Axios

### 后端

- Flask
- Flask-SQLAlchemy
- Flask-CORS
- Flask-Redis（可选）
- PyMySQL
- PyJWT
- cos-python-sdk-v5（腾讯云 COS 上传）

## 项目结构

```text
BookRecommendSystem/
├─ app/
│  ├─ __init__.py           # create_app、蓝图注册、CORS、兼容性补丁
│  ├─ models.py             # 用户/图书/阅读器/稿件等模型
│  ├─ auth/                 # /auth
│  ├─ user/                 # /user
│  ├─ api/                  # /api（含 reader_views）
│  ├─ creator/              # /creator
│  ├─ admin/                # /admin
│  └─ rbac/                 # /rbac
├─ frontend/
│  ├─ src/router/index.ts   # 路由与鉴权守卫
│  └─ src/views/            # 各端页面
├─ config.py
├─ schema.sql
├─ requirements.txt
└─ .env.example
```

## 快速开始

### 1) 后端（Flask）

在仓库根目录执行：

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

启动后端：

```powershell
$env:FLASK_APP="app:create_app"
$env:FLASK_ENV="development"
flask run --host 127.0.0.1 --port 5000
```

可选初始化表：

```powershell
$env:FLASK_APP="app:create_app"
flask init-db
```

### 2) 前端（Vite）

```powershell
cd frontend
npm install
npm run dev
```

默认地址：`http://127.0.0.1:5173`  
开发代理已配置到后端 `http://localhost:5000`，包含 `/auth`、`/user`、`/admin`、`/creator`、`/rbac`、`/api`。

## 关键环境变量

以 `.env.example` 为准，常用项如下：

- `DATABASE_URL`：MySQL 连接串（示例：`mysql+pymysql://user:pass@localhost:3306/db`）
- `SECRET_KEY`、`JWT_SECRET_KEY`、`JWT_EXPIRES_IN`
- `CAPTCHA_EXPIRES_IN`
- `ADMIN_REGISTER_CODE`（为空时禁用管理员自助注册）
- `REDIS_URL`（可留空）
- `MAX_AVATAR_UPLOAD_SIZE`
- `COS_SECRET_ID`、`COS_SECRET_KEY`、`COS_REGION`、`COS_BUCKET`、`COS_DOMAIN`

## 接口概览（按蓝图）

### `/auth`

- `GET /auth/captcha`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/check`

### `/user`

- `GET /user/profile`
- `PUT /user/profile`
- `POST /user/avatar/upload`
- `POST /user/change_password`
- `GET /user/favorites`
- `GET /user/history`

### `/api`（读者侧）

- 首页/推荐：`/books/featured`、`/books/rankings`、`/recommendations/personalized`、`/recommendations/by-mood`
- 检索/分类：`/books/search`、`/books/by-category`、`/categories/highlighted`、`/tags/hot`
- 书架与反馈：`/shelf`、`/shelf/toggle`、`/recommendations/feedback`
- 互动：`/reviews/highlighted`、`/reviews/<id>/like`、`/reviews/<id>/comments`
- 阅读任务：`/user/weekly-reading-task`、`/user/weekly-reading-task/progress`
- 阅读器：`/books/<book_id>/reader`、`/books/<book_id>/landing`、`/books/<book_id>/highlights`、`/books/<book_id>/comments`、`/books/<book_id>/progress`、`/reader/preferences`

### `/creator`

- `GET /creator/manuscripts`
- `POST /creator/manuscripts`
- `PUT /creator/manuscripts/<manuscript_id>`
- `POST /creator/manuscripts/<manuscript_id>/submit`

### `/admin`

- 认证：`/admin/auth/captcha`、`/admin/auth/register`、`/admin/auth/login`
- 用户管理：`/admin/users`、`/admin/users/<user_id>`、`/admin/users/<user_id>/reset_password`
- 图书管理：`/admin/books`、`/admin/books/<book_id>`
- 稿件审核：`/admin/manuscripts`、`/admin/manuscripts/<manuscript_id>/review`、`/admin/manuscripts/<manuscript_id>/publish`

### `/rbac`

- 角色管理：`/rbac/roles`、`/rbac/roles/<role_id>`
- 权限管理：`/rbac/permissions`
- 角色权限绑定：`/rbac/roles/<role_id>/permissions`
- 用户角色绑定：`/rbac/users/<user_id>/roles`
- 用户权限查询：`/rbac/users/<user_id>/permissions`

## 开发说明

- 后端入口是 `app:create_app`，在创建应用时会注册所有蓝图并尝试执行数据库兼容性补丁（缺列补齐、阅读器偏好表/稿件表/版本表自动创建）。
- 上传文件默认走 `instance/uploads`，可通过 `UPLOAD_DIR` 覆盖；访问路径为 `/uploads/<path>`.
- 前端路由包含读者、管理员、创作者三套鉴权逻辑（普通登录、管理员 Token、创作者 Token）。

## 常见问题排查

- 启动失败：确认已激活虚拟环境并安装 `requirements.txt`
- 接口 401：检查 token 是否过期，以及前端是否在请求头带 `Authorization`
- 数据库错误：确认 `DATABASE_URL` 可连通，且已执行 `schema.sql`（或至少运行过 `flask init-db`）
- 上传失败：检查 `MAX_AVATAR_UPLOAD_SIZE` 与 COS 相关环境变量是否配置完整
