# P0/P1 实施进度记录

本文记录 `docs/competitor-gap-analysis.md` 中 P0/P1 的实际落地情况。为避免一次性改动过大，本轮只完成 2 个点：P0 文档与产品表达、P1 阅读统计/偏好/成就页。

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

- 听书入口：书籍详情页和阅读器的 SpeechSynthesis 播放 UI。
- 书单/书评广场：创建书单、添加书籍、发布书评、基础互动。
- 章节/段落评论：按章节查看和发布讨论。
- 推荐与搜索增强：兴趣标签、榜单筛选、热搜趋势、推荐位配置预留。

建议下一批优先做：

- 听书入口 + 章节/段落评论。
- 或书单/书评广场 + 用户兴趣标签。
