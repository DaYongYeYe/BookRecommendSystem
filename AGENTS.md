# BookRecommendSystem — Codex / 代理说明

全栈项目：**Flask 后端**（仓库根目录）+ **Vue 3 + Vite 前端**（`frontend/`）。完整联调需要两个长期运行的进程（两个终端）。

## 首次环境准备

1. **后端（Python）**
   - 在项目根目录：`python -m venv venv`
   - Windows PowerShell 激活：`.\venv\Scripts\Activate.ps1`
   - 安装依赖：`pip install -r requirements.txt`
   - 复制环境变量：将 `.env.example` 复制为 `.env`，按本地 MySQL 填写 `DATABASE_URL`（并按需设置 `REDIS_URL`、JWT 等）。
   - 数据库：按 `README.md` 与 `schema.sql` 初始化 MySQL。

2. **前端（Node）**
   - `cd frontend`
   - `npm install`

## 运行命令（开发）

在**项目根目录**（`BookRecommendSystem/`，与 `app/`、`config.py` 同级）执行后端；在 `frontend/` 执行前端。

### 后端 — Flask（默认 `http://127.0.0.1:5000`）

**PowerShell（推荐，与仓库内脚本一致）：**

```powershell
$env:FLASK_APP = "app:create_app"
$env:FLASK_ENV = "development"
flask run --host 127.0.0.1 --port 5000
```

或直接使用根目录脚本（会先尝试激活 `venv`、并可释放占用端口）：

```powershell
.\restart-backend.ps1
```

**cmd.exe：**

```bat
set FLASK_APP=app:create_app
set FLASK_ENV=development
flask run --host 127.0.0.1 --port 5000
```

**可选 — 初始化数据库表（Flask CLI）：**

```powershell
$env:FLASK_APP = "app:create_app"
flask init-db
```

### 前端 — Vite（默认 `http://127.0.0.1:5173`）

```powershell
cd frontend
npm run dev
```

开发模式下，Vite 将 `/auth`、`/user`、`/admin`、`/rbac` 代理到 `http://localhost:5000`（见 `frontend/vite.config.ts`）。

## 其他常用命令

- 前端生产构建：`cd frontend` → `npm run build` → `npm run preview`（预览构建结果）
- 后端无 `package.json`；所有 Python 脚本与 Flask 命令均在仓库根目录执行。

## 给 Codex 的约定

- 修改 API 后，用上述方式启动 Flask 验证；修改 UI 后用 `npm run dev` 验证。
- 需要同时跑前后端时，使用**两个独立进程**（两个 shell），不要假设单条命令能阻塞启动两个服务（除非用户显式要求并已安装进程编排工具）。
