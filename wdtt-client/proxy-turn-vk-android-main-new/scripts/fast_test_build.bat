@echo off
setlocal enabledelayedexpansion

echo === Fast Test Build (arm64-v8a only) ===
echo.

set "ROOT_DIR=%~dp0..\"
set "GO_CLIENT_DIR=%ROOT_DIR%app\src\main\assets\android-client"
set "ANDROID_JNILIBS=%ROOT_DIR%app\src\main\jniLibs"

:: Find Android SDK/NDK
call "%ROOT_DIR%scripts\find_android_sdk_ndk.bat"
if %errorlevel% neq 0 (
    exit /b 1
)
set "ANDROID_HOME=%SDK_PATH%"

set "CC_PATH_ARM64=%TOOLCHAIN%\aarch64-linux-android28-clang.cmd"
if not exist "%CC_PATH_ARM64%" (
    set "CC_PATH_ARM64=%TOOLCHAIN%\aarch64-linux-android29-clang.cmd"
)
if not exist "%CC_PATH_ARM64%" (
    set "CC_PATH_ARM64=%TOOLCHAIN%\aarch64-linux-android30-clang.cmd"
)

if not exist "%CC_PATH_ARM64%" (
    echo Error: Clang compiler for arm64 not found in %TOOLCHAIN%
    pause
    exit /b 1
)

:: 1. Verify or build arm64-v8a .so
if not exist "%ANDROID_JNILIBS%\arm64-v8a" mkdir "%ANDROID_JNILIBS%\arm64-v8a"

echo.
echo [1/2] Building arm64-v8a Go .so client...
cd /d "%GO_CLIENT_DIR%"

set "GOOS=android"
set "CGO_ENABLED=1"
set "GOARCH=arm64"
set "GOARM="
set "CC=%CC_PATH_ARM64%"

go build -ldflags="-s -w -checklinkname=0" -trimpath -o "%ANDROID_JNILIBS%\arm64-v8a\libclient.so" .

if %errorlevel% neq 0 (
    echo BUILD FAILED for arm64-v8a Go client!
    pause
    exit /b 1
)
echo arm64-v8a .so: OK

:: 2. Build release APKs (same as buld_apk.bat, full assembleRelease)
echo.
echo [2/2] Building release APKs...
cd /d "%ROOT_DIR%"
call gradlew assembleRelease --no-daemon

if %errorlevel% neq 0 (
    echo.
    echo BUILD FAILED for APK!
    pause
    exit /b 1
)

:: 3. Read versionName from app/build.gradle.kts
set "VERSION="
for /f "usebackq tokens=3" %%a in (`findstr "versionName" app\build.gradle.kts`) do (
    set "VERSION=%%a"
)
set "VERSION=!VERSION:"=!"

if "!VERSION!"=="" (
    echo   [WARN] Could not read versionName, falling back to 1.2.4
    set "VERSION=1.2.4"
)

:: 4. Copy only arm64-v8a APK to release folder
if not exist "app\release" mkdir "app\release"

set "APK_DIR=app\build\outputs\apk\release"
set "OUT_APK=app\release\v!VERSION!-android-v8a-fast-test.apk"

if exist "%APK_DIR%\app-arm64-v8a-release.apk" (
    copy /Y "%APK_DIR%\app-arm64-v8a-release.apk" "!OUT_APK!" >nul
    echo.
    echo === SUCCESS ===
    for %%F in ("!OUT_APK!") do echo   [OK] %%~nxF  [%%~zF bytes]
) else (
    echo.
    echo   [ERROR] arm64-v8a APK not found in %APK_DIR%
)

echo.
pause
