# P0/P1 实施进度记录

本文记录 `docs/competitor-gap-analysis.md` 中 P0/P1 的实际落地情况。为避免一次性改动过大，每批只完成 1-2 个功能点。

## 本轮完成范围

### P0：文档与产品表达

已完成：

- 在 `README.md` 增加“项目定位与路线图”入口，明确项目是学习型/课程设计/毕设级阅读平台原型。
- 在 `README.md` 增加竞品差异分析、截图索引、产品能力地图链接。
- 新增 `docs/screenshot-index.md`，按读者端、创作者端、管理端整理截图与能力说明。
- 新增 `docs/product-capability-map.md`，用 Mermaid 展示“发现 -> 阅读 -> 互动 -> 创作 -> 审核 -> 权限”的主链路。
- 明确边界：当前示例内容、阅读数据、作者数据和运营数据均为原型演示数据，不承诺真实版权、真实收益或真实商业运营。

对应文件：

- `README.md`
- `docs/screenshot-index.md`
- `docs/product-capability-map.md`

### P1：阅读统计、偏好展示与阅读成就

已完成：

- 新增读者端页面 `/user/reading-stats`。
- 页面展示本周阅读时长、阅读天数、完成章节数、收藏数、划线数、评论数、书签数、连续阅读天数。
- 页面展示阅读器同步偏好：主题、字号、行高、版心、划线/评论显示开关。
- 页面展示轻量阅读成就：第一次加入书架、第一次划线、连续阅读 3 天、完成章节、本周阅读 30 分钟。
- 页面展示最近阅读书籍，支持跳转到书籍详情。
- 个人中心新增“阅读统计”入口。
- 我的阅读页新增“阅读统计”入口。

对应文件：

- `frontend/src/views/UserReadingStats.vue`
- `frontend/src/router/index.ts`
- `frontend/src/api/user.ts`
- `frontend/src/views/UserProfileHub.vue`
- `frontend/src/views/UserLibrary.vue`

## 后端与数据层

### 新增/修改的数据表

新增表：`user_achievements`

用途：记录用户已解锁的阅读成就，避免每次只靠前端临时计算。

关键字段：

- `user_id`：用户 ID。
- `achievement_key`：成就唯一键。
- `title`：成就标题。
- `description`：成就说明。
- `unlocked_at`：解锁时间。

已更新：

- `app/models.py`：新增 `UserAchievement` 模型。
- `schema.sql`：新增 `user_achievements` 表结构。
- `app/__init__.py`：补充旧数据库兼容创建逻辑。
- `mock_seed_compatible.sql`：补充阅读行为、书签和成就种子数据。

### 新增接口

新增接口：`GET /user/reading-stats`

鉴权：需要普通用户登录态。

返回内容：

- `stats`：阅读统计汇总。
- `preferences`：当前阅读偏好。
- `achievements`：成就列表与解锁状态。
- `recent_books`：最近阅读书籍。
- `week_start`：本周起始日期。

接口实现文件：

- `app/user/views.py`

## 测试与验证

新增测试：

- `tests/test_reading_stats.py`

覆盖内容：

- 阅读统计接口可用。
- 书架数、书签数、划线数、完成章节数可正确聚合。
- 本周阅读时长可从 `book_analytics_events` 聚合。
- 阅读偏好可返回后端保存值。
- 成就会根据真实数据解锁。
- 最近阅读书籍可返回。

已执行命令：

```powershell
.\venv\Scripts\python.exe -m unittest tests.test_reading_stats
```

结果：通过，`Ran 1 test ... OK`。

已执行前端构建：

```powershell
cd frontend
npm.cmd run build
```

结果：通过，Vite 构建成功。构建输出中存在 chunk 体积提示，这是构建警告，不影响本轮功能验收。

补充说明：

- 系统 Python 环境未安装 Flask，因此后端测试使用项目虚拟环境 `.\venv\Scripts\python.exe` 执行。
- PowerShell 阻止直接执行 `npm.ps1`，因此前端构建使用 `npm.cmd run build` 执行。
- 当前项目未安装 `pytest`，本轮使用标准库 `unittest` 增加最小关键接口测试。

## 未完成的 P1 项

按用户要求“一次最多只修改 1-2 点”，以下 P1 功能尚未在本轮实现：

- 书单/书评广场：创建书单、添加书籍、发布书评、基础互动。
- 章节/段落评论：按章节查看和发布讨论。
- 推荐与搜索增强：兴趣标签、榜单筛选、热搜趋势、推荐位配置预留。

建议下一批优先做：

- 章节/段落评论。
- 或书单/书评广场 + 用户兴趣标签。

## 第二批完成范围

### P1：书单 / 书评广场

已完成：

- 新增读者端页面 `/community`，展示公开书单、公开书评和兴趣标签。
- 首页新增“书评广场”入口，并在热门标签区域增加社区广场跳转卡片。
- 支持登录用户创建公开书单。
- 支持登录用户把推荐池中的图书加入自己的书单，并填写推荐语。
- 支持登录用户发布书评，包含书籍、标题、正文和 1-5 星评分。
- 支持登录用户对书评做“赞同/取消赞同”基础互动。
- 列表页具备加载、空状态、错误提示和登录跳转。

对应文件：

- `frontend/src/views/CommunityPlaza.vue`
- `frontend/src/api/community.ts`
- `frontend/src/router/index.ts`
- `frontend/src/views/Home.vue`
- `app/api/views.py`
- `app/models.py`

### P1：推荐兴趣标签

已完成：

- 新增 `GET /api/recommendations/interest-tags`。
- 登录用户会从阅读历史、书架、搜索历史、推荐反馈中计算兴趣标签。
- 接口会把最新计算结果写入 `user_interest_tags`，作为可追踪的兴趣标签快照。
- 未登录用户返回热门标签兜底，保证页面仍可浏览。
- 社区广场右侧展示兴趣标签、权重和来源摘要，标签可跳转搜索。

对应文件：

- `app/api/views.py`
- `app/models.py`
- `frontend/src/views/CommunityPlaza.vue`
- `frontend/src/api/community.ts`

## 第二批后端与数据层

新增表：

- `book_lists`：用户创建的书单，包含标题、描述、可见性、封面、点赞数和时间字段。
- `book_list_items`：书单与图书关联，包含推荐语和排序字段。
- `community_book_reviews`：社区书评，包含书籍、用户、标题、正文、评分、可见性、互动数和治理预留字段。
- `community_book_review_reactions`：书评互动，当前支持 `like`。
- `user_interest_tags`：用户兴趣标签快照，记录标签权重和来源摘要。

新增接口：

- `GET /api/community/booklists`
- `POST /api/community/booklists`
- `POST /api/community/booklists/<list_id>/books`
- `GET /api/community/reviews`
- `POST /api/community/reviews`
- `POST /api/community/reviews/<review_id>/reaction`
- `GET /api/recommendations/interest-tags`

已更新：

- `schema.sql`：新增上述表结构。
- `app/__init__.py`：补充旧数据库兼容建表逻辑。
- `mock_seed_compatible.sql`：补充社区书单、书单图书、社区书评、书评互动和兴趣标签种子数据。

## 第二批测试与验证

新增测试：

- `tests/test_community_interest.py`

覆盖内容：

- 创建书单、查询书单、向书单加入图书。
- 发布书评、查询书评、赞同书评。
- 根据书架、阅读历史、搜索历史和推荐反馈生成兴趣标签，并落库到 `user_interest_tags`。

已执行命令：

```powershell
.\venv\Scripts\python.exe -m unittest tests.test_reading_stats tests.test_community_interest
```

结果：通过，`Ran 4 tests ... OK`。

已执行前端构建：

```powershell
cd frontend
npm.cmd run build
```

结果：通过，Vite 构建成功。构建输出中存在 chunk 体积提示，这是构建警告，不影响本批功能验收。

## 第三批完成范围

### P1：听书入口与连续朗读

已完成：

- 书籍详情页提供“听书”入口，进入阅读器时带上 `listen=1` 查询参数，可从当前阅读进度继续朗读。
- 阅读器顶部提供听书、暂停/继续、上一章、下一章和停止控制。
- 阅读器使用浏览器 `SpeechSynthesis API` 朗读当前章节正文。
- 当前浏览器不支持语音朗读时会展示不支持提示。
- 本章朗读结束后，如果还有下一章，会自动切换并继续朗读。
- 手动切换上一章/下一章时，会等待目标章节加载并滚动到位后再开始朗读。
- 停止朗读或切换任务时会使旧朗读回调失效，避免旧回调错误更新播放状态。

对应文件：

- `frontend/src/views/BookDetail.vue`
- `frontend/src/views/Reader.vue`

### 第三批测试与验证

已执行前端构建：

```powershell
cd frontend
npm.cmd run build
```

结果：通过，Vite 构建成功。构建输出中仍存在 chunk 体积提示，这是构建警告，不影响本批功能验收。
