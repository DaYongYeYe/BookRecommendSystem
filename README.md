# BookRecommendSystem

BookRecommendSystem 是一个围绕“阅读发现、在线阅读、创作投稿、后台审核”构建的全栈图书推荐与阅读平台。项目包含读者端、创作者入口、管理端与 RBAC 权限模型，适合作为课程设计、毕业设计或全栈业务原型继续扩展。

- 后端：`Flask + SQLAlchemy + MySQL + JWT`
- 前端：`Vue 3 + TypeScript + Vite + Element Plus + Tailwind CSS`
- 数据能力：推荐流、分类/标签、榜单、阅读进度、评论、创作者作品与后台审核

## 在线演示

演示地址：[http://43.155.215.208:8080](http://43.155.215.208:8080)

## 核心能力

### 读者端

- 首页推荐：个性化推荐、热门标签、精选分类、榜单入口和继续阅读入口。
- 搜索发现：支持按书名、作者、标签、简介关键词检索，并展示热搜词与历史记录。
- 分类与榜单：分类页支持按题材发现作品，榜单支持热门榜、新书榜、飙升榜、完结榜、收藏榜和追更榜。
- 书籍详情：展示封面、作者、评分、字数、完结状态、阅读决策点、目录、评论和相关推荐。
- 在线阅读器：支持章节阅读、目录面板、阅读偏好、划线、评论、书签和阅读进度同步。
- 用户中心：包含个人资料、头像上传、密码修改、我的收藏和阅读历史。

### 创作者端

- 创作者入口：通过“登录账号、提交申请、开始创作”三步引导完成角色分流。
- 创作看板：展示曝光量、阅读量、读者画像、作品排行和创作建议。
- 作品管理：支持创建/编辑作品资料、封面上传、分类标签维护、上架准备度检查和审核提交。
- 章节工作台：支持章节新增、编辑、排序、提审、自动保存、字数统计和版本记录。
- 稿件管理：支持新书稿件、已有作品稿件、草稿保存和提交审核。

### 管理端与权限

- 管理后台：包含仪表盘、用户管理、图书管理、评论管理、作品审核、稿件审核与章节审核。
- RBAC：支持角色管理、权限管理、角色绑定权限、用户绑定角色和用户最终权限查询。
- 账号体系：普通用户登录/注册、邮箱验证码、忘记密码、管理员独立登录和管理员注册码注册。

## 截图预览

以下截图来自本地 MySQL 数据库联调环境，前端通过 Vite 访问 Flask API。截图覆盖读者端的发现、搜索、阅读链路，也补充了创作者端的作品管理、章节维护和数据看板。

### 1. 首页推荐

![首页推荐](docs/screenshots/01-home.png)

首页聚合了搜索入口、今日推荐、推荐理由、榜单和分类内容，是读者进入系统后的核心发现页。

### 2. 搜索与热搜发现

![搜索与热搜发现](docs/screenshots/02-search.png)

搜索页支持按书名、作者、标签和剧情关键词检索，同时保留热门搜索和搜索历史入口。

### 3. 分类发现

![分类发现](docs/screenshots/03-categories.png)

分类页按题材聚合图书内容，适合从玄幻、言情、都市、历史、悬疑、科幻等频道进入发现流程。

### 4. 榜单页

![榜单页](docs/screenshots/04-rankings.png)

榜单页根据阅读热度、收藏人数、评分、增长趋势等指标展示不同类型的作品排行。

### 5. 更多推荐

![更多推荐](docs/screenshots/05-recommendations.png)

更多推荐页提供可分页浏览的推荐池，并支持结合分类、标签、连载状态和关键词做筛选。

### 6. 书籍详情

![书籍详情](docs/screenshots/06-book-detail.png)

书籍详情页展示作品基础信息、阅读决策点、目录、评论与相关推荐，承接“开始阅读”和“加入书架”等行为。

### 7. 在线阅读器

![在线阅读器](docs/screenshots/07-reader.png)

阅读器提供章节正文、目录、阅读偏好、划线评论、书签和阅读统计，是项目中最重要的沉浸式阅读页面。

### 8. 创作者入口

![创作者入口](docs/screenshots/08-creator-entry.png)

创作者入口页负责将普通读者引导到创作者申请流程，并说明从登录到开始创作的完整路径。

### 9. 创作者作品管理

![创作者作品管理](docs/screenshots/09-creator-home.png)

创作者工作台展示作品总数、上架状态、审核状态、完结数量和作品列表，支持搜索、筛选、编辑、提审、上下架与进入章节管理。

### 10. 章节工作台

![章节工作台](docs/screenshots/010-creator-chapters.png)

章节工作台围绕单本作品组织章节，提供新建章节、章节排序、编辑、提审、审核时间线和版本记录等写作流程能力。

### 11. 创作数据看板

![创作数据看板](docs/screenshots/011-creator-data.png)

数据看板用图表展示作品阅读排行、读者地域分布、读者年龄分布和每本作品的阅读表现，并给出创作优化建议。

## 技术栈

### 前端

- Vue 3
- TypeScript
- Vue Router
- Vite
- Element Plus
- Axios
- Tailwind CSS
- ECharts / vue-echarts

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
│  ├─ __init__.py              # create_app、蓝图注册、兼容性补丁
│  ├─ models.py                # 用户、图书、稿件、阅读器、通知、RBAC 等模型
│  ├─ auth/                    # /auth 普通用户认证
│  ├─ user/                    # /user 用户中心
│  ├─ api/                     # /api 阅读端、推荐、搜索、榜单、阅读器接口
│  ├─ creator/                 # /creator 创作者接口
│  ├─ admin/                   # /admin 管理后台接口
│  ├─ rbac/                    # /rbac 权限管理接口
│  └─ services/                # 验证码、邮件、发布、阅读器、通知等服务
├─ frontend/
│  ├─ src/
│  │  ├─ api/                  # 前端接口封装
│  │  ├─ router/               # 路由与守卫
│  │  ├─ views/                # 读者端、创作者端、管理端页面
│  │  ├─ components/           # 通用组件与业务组件
│  │  ├─ composables/          # 阅读偏好、阅读进度、创作者资料等逻辑
│  │  └─ constants/            # 榜单、分类、路由常量
│  ├─ package.json
│  └─ vite.config.ts
├─ docs/
│  └─ screenshots/             # README 页面截图
├─ schema.sql                  # 推荐使用的完整数据库初始化脚本
├─ mock_seed_compatible.sql    # 示例数据
├─ database_schema.sql         # 历史数据库脚本
├─ requirements.txt
├─ docker-compose.yml
├─ restart-backend.ps1
└─ .env.example
```

## 环境准备

### 运行环境

- Python 3.11+
- Node.js 18+
- MySQL 8.0+
- Redis 7+（可选）

### 1. 后端依赖

在仓库根目录执行：

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

然后编辑 `.env`，至少配置：

```env
DATABASE_URL=mysql+pymysql://用户名:密码@127.0.0.1:3306/数据库名
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
```

如需启用 Redis、邮箱验证码或 COS 上传，再按 `.env.example` 补充对应配置。

### 2. 数据库初始化

推荐使用完整 SQL 初始化：

```sql
CREATE DATABASE book_recommend_db DEFAULT CHARACTER SET utf8mb4;
USE book_recommend_db;
SOURCE schema.sql;
SOURCE mock_seed_compatible.sql;
```

说明：

- `schema.sql` 覆盖首页、搜索、榜单、阅读器、评论、创作者和管理端所需表结构。
- `mock_seed_compatible.sql` 提供可直接登录和演示的基础示例数据。
- `flask init-db` 更适合最小化本地调试，不替代完整 SQL 初始化。

### 3. 前端依赖

```powershell
cd frontend
npm install
cd ..
```

## 启动项目

完整联调需要两个独立长期运行进程：一个 Flask 后端进程，一个 Vite 前端进程。

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

后端默认地址：

```text
http://127.0.0.1:5000
```

### 启动前端 Vite

在 `frontend/` 目录执行：

```powershell
npm run dev
```

前端默认地址：

```text
http://127.0.0.1:5173
```

如果 5173 已被占用，Vite 会自动选择下一个可用端口，例如 `5174` 或 `5175`。

### Vite 代理

开发模式下，前端会把以下路径代理到 Flask：

- `/auth`
- `/user`
- `/admin`
- `/creator`
- `/rbac`
- `/api`

## Docker 辅助依赖

仓库提供 MySQL 和 Redis 的 `docker-compose.yml`：

```powershell
docker compose up -d
```

默认映射：

- MySQL：`13306 -> 3306`
- Redis：`6379 -> 6379`

如果使用该容器配置，`.env` 中的数据库连接可以按实际账号改成：

```env
DATABASE_URL=mysql+pymysql://book_user:book_password@127.0.0.1:13306/book_recommend_db
REDIS_URL=redis://127.0.0.1:6379/0
```

## 示例账号

执行 `mock_seed_compatible.sql` 后，默认会生成以下示例账号：

| 类型 | 用户名 | 默认密码 |
| --- | --- | --- |
| 管理员 | `admin` | `123456` |
| 普通读者 | `reader_alice` | `123456` |
| 普通读者 | `reader_bob` | `123456` |
| 普通读者 | `reader_cindy` | `123456` |

如果需要测试创作者后台，可使用管理员账号在后台给用户开通 `creator` 角色或创建创作者资料。

## 主要页面路由

### 读者端

- `/`
- `/search`
- `/categories`
- `/recommendations`
- `/rankings`
- `/books/:bookId`
- `/reader/:bookId`
- `/user/profile-hub`
- `/user/profile`
- `/user/library`

### 认证

- `/login`
- `/register`

### 创作者端

- `/creator-center`
- `/creator/works`
- `/creator/dashboard`
- `/creator/manuscripts`
- `/creator/books/:bookId/chapters`

### 管理端

- `/manage/login`
- `/manage/register`
- `/manage/dashboard`
- `/manage/users`
- `/manage/books`
- `/manage/comments`
- `/manage/works/review`
- `/manage/manuscripts/review`
- `/manage/chapters/review`
- `/manage/rbac/roles`
- `/manage/rbac/permissions`
- `/manage/rbac/role-permissions`
- `/manage/rbac/user-roles`

## 后端接口模块

- `/auth`：用户登录、注册、验证码、忘记密码、登录态检查。
- `/user`：用户资料、头像、密码、收藏、阅读历史。
- `/api`：首页推荐、搜索、分类、标签、榜单、书籍详情、阅读器、评论、书架和推荐反馈。
- `/creator`：创作者申请、作品管理、稿件管理、章节工作台、创作看板和通知。
- `/admin`：后台仪表盘、用户、图书、评论、作品审核、稿件审核和章节审核。
- `/rbac`：角色、权限、角色权限绑定、用户角色绑定和权限查询。

## 常用验证命令

### 前端生产构建

```powershell
cd frontend
npm run build
```

### 预览前端构建产物

```powershell
cd frontend
npm run preview
```

### 后端接口快速检查

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5000/api/categories
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5000/api/books/rankings
```

## 后续扩展方向

- 接入更完整的推荐算法：结合阅读行为、收藏、标签权重和内容相似度。
- 完善创作者审核流：增加审核记录、操作日志和消息推送。
- 强化管理端可观测性：补充趋势图、异常告警和导出报表。
- 增加自动化测试：覆盖认证、推荐、阅读器、后台审核和 RBAC 权限。
- 优化部署链路：完善生产 Docker Compose、Nginx 配置和环境变量模板。
