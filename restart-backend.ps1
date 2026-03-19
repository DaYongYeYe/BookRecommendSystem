param(
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

# 切到脚本所在目录（项目根目录）
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "Project root: $ProjectRoot" -ForegroundColor Cyan

# 如果存在虚拟环境则自动激活
$VenvActivate = Join-Path $ProjectRoot "venv\Scripts\Activate.ps1"
if (Test-Path $VenvActivate) {
    Write-Host "Activating venv..." -ForegroundColor Yellow
    . $VenvActivate
} else {
    Write-Host "venv not found, use current Python environment." -ForegroundColor DarkYellow
}

# 查找并停止占用目标端口的进程
try {
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conns) {
        $processIds = $conns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($procId in $processIds) {
            try {
                Write-Host "Stopping process on port $Port (PID: $procId)..." -ForegroundColor Yellow
                Stop-Process -Id $procId -Force -ErrorAction Stop
            } catch {
                Write-Host "Failed to stop PID ${procId}: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No listening process found on port $Port." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "Port check skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# 设置 Flask 环境变量
$env:FLASK_APP = "app:create_app"
$env:FLASK_ENV = "development"

Write-Host "Starting Flask on 127.0.0.1:$Port ..." -ForegroundColor Green
flask run --host 127.0.0.1 --port $Port
