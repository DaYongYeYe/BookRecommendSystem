param(
    [string]$TaskName = "BookRecommendSourceImport",
    [int]$IntervalMinutes = 360,
    [int]$Limit = 1000,
    [int]$MaxPages = 60,
    [double]$RequestDelaySeconds = 3,
    [switch]$IncludeContent,
    [switch]$OverwriteContent,
    [switch]$ExistingOnly,
    [string]$BookIds = "",
    [int]$MaxChaptersPerBook = 0,
    [string]$Cookie = ""
)

if ($RequestDelaySeconds -lt 3) {
    throw "RequestDelaySeconds must be at least 3."
}

$projectRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$pythonExe = Join-Path $projectRoot "venv\Scripts\python.exe"
$scriptPath = Join-Path $projectRoot "scripts\scheduled_book_source_import.py"
$logDir = Join-Path $projectRoot "instance\logs"
$logPath = Join-Path $logDir "book-source-import-task.log"

if (!(Test-Path -LiteralPath $pythonExe)) {
    throw "Python virtualenv not found: $pythonExe"
}

if (!(Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

$arguments = @(
    "`"$scriptPath`"",
    "--run-once",
    "--limit", $Limit,
    "--max-pages", $MaxPages,
    "--request-delay", $RequestDelaySeconds
)

if ($IncludeContent) {
    $arguments += "--include-content"
    $arguments += "--max-chapters-per-book"
    $arguments += $MaxChaptersPerBook
}

if ($OverwriteContent) {
    $arguments += "--overwrite-content"
}

if ($ExistingOnly) {
    $arguments += "--existing-only"
}

if ($BookIds) {
    $arguments += "--book-ids"
    $arguments += $BookIds
}

$envPrefix = ""
if ($Cookie) {
    $escapedCookie = $Cookie.Replace("'", "''")
    $envPrefix = "`$env:BOOK_SOURCE_COOKIE='$escapedCookie'; "
}

$command = "$envPrefix& `"$pythonExe`" $($arguments -join ' ') >> `"$logPath`" 2>&1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command $command" -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null

Write-Output "Registered task: $TaskName"
Write-Output "Project root: $projectRoot"
Write-Output "Every: $IntervalMinutes minutes"
Write-Output "Request delay: $RequestDelaySeconds seconds"
Write-Output "Log: $logPath"
