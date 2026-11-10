@echo off
setlocal enabledelayedexpansion

echo === Building server for Linux AMD64 ===
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0

set "PROJECT_ROOT=%~dp0..\"
cd /d "%PROJECT_ROOT%app\src\main\assets\linux-server"
go build -ldflags="-s -w" -o "%PROJECT_ROOT%app\src\main\assets\server" .

if %errorlevel% neq 0 (
    echo FAILED: server
    pause
    exit /b 1
)
echo OK: server built in app\src\main\assets
pause
