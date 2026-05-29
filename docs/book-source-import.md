# 授权书源导入

本项目提供 `flask import-book-source` 命令，用于把已获授权的阅读书源导入本地数据库。当前默认书源为：

```text
https://www.yckceo.com/yuedu/shuyuan/json/id/7283.json
```

默认导入逻辑：

- 从书源 JSON 读取目标站点、请求头和分类入口。
- 按 `/sort/` 热门列表顺序抓取作品链接，默认最多导入 1000 本。
- 抓取作品详情并写入 `books` 表，设置为已审核、已上架、已发布。
- 用列表排名生成本地热度字段，使现有首页推荐、搜索和榜单接口可以直接展示。
- 默认只导入作品元数据，不抓正文；目录和正文需要显式开启。

## 常用命令

在项目根目录执行：

```powershell
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --limit 1000
```

## 定时拉取

长驻进程方式，默认每轮间隔 360 分钟，每次请求间隔不少于 3 秒：

```powershell
$env:BOOK_SOURCE_COOKIE = "cf_clearance=...; other_cookie=..."
.\venv\Scripts\python.exe .\scripts\scheduled_book_source_import.py --limit 1000 --request-delay 3 --interval-minutes 360
```

如果要周期性补前 50 章正文：

```powershell
$env:BOOK_SOURCE_COOKIE = "cf_clearance=...; other_cookie=..."
.\venv\Scripts\python.exe .\scripts\scheduled_book_source_import.py --limit 1000 --include-content --max-chapters-per-book 50 --request-delay 3 --interval-minutes 360
```

Windows 任务计划方式：

```powershell
.\scripts\register-book-source-import-task.ps1 -IntervalMinutes 360 -Limit 1000 -RequestDelaySeconds 3
```

带正文导入的 Windows 任务计划：

```powershell
.\scripts\register-book-source-import-task.ps1 -IntervalMinutes 360 -Limit 1000 -RequestDelaySeconds 3 -IncludeContent -MaxChaptersPerBook 50
```

如果不想依赖系统环境变量，也可以注册任务时直接传 Cookie：

```powershell
.\scripts\register-book-source-import-task.ps1 -IntervalMinutes 360 -Limit 1000 -RequestDelaySeconds 3 -IncludeContent -MaxChaptersPerBook 50 -Cookie "cf_clearance=...; other_cookie=..."
```

任务日志会写入：

```text
instance\logs\book-source-import-task.log
```

定时导入器自身创建 Flask app 时，会把应用日志写到独立目录，避免和本地后端开发服务抢占同一个日志文件：

```text
instance\logs\book_source_importer\
```

先小批量试跑：

```powershell
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --limit 20 --max-pages 2
```

只验证抓取候选，不写数据库：

```powershell
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --limit 20 --dry-run
```

导入章节目录标题：

```powershell
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --limit 20 --include-toc
```

导入章节正文建议先限制范围：

```powershell
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --limit 3 --include-content --max-chapters-per-book 5
```

如果目标站点需要浏览器验证，可以把浏览器里已经授权的 Cookie 传入：

```powershell
$env:BOOK_SOURCE_COOKIE = "cf_clearance=...; other_cookie=..."
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --limit 1000
```

也可以直接传本地书源 JSON 文件：

```powershell
$env:FLASK_APP = "app:create_app"
.\venv\Scripts\flask.exe import-book-source --source .\my-book-source.json --limit 1000
```

## 注意事项

- 目标书源页面说明该站点可能需要网络代理或 Cloudflare 验证；命令支持 Cookie，但不会自动绕过浏览器验证。
- 1000 本全量正文通常会非常大，建议先导入元数据或目录，再按需分批导入正文。
- 命令会按书名、作者和来源 URL 做 upsert，重复执行会更新已有作品，而不是无限新增。
