#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "=== WDTT APK Build Script ==="
echo "=== Output: 4 APKs (universal, arm64-v8a, armeabi-v7a, x86_64) ==="
echo ""

# 1. Verify .so files exist for all architectures
MISSING=0
if [[ ! -f "app/src/main/jniLibs/arm64-v8a/libclient.so" ]]; then
    echo "ERROR: arm64-v8a .so not found!"
    MISSING=1
fi
if [[ ! -f "app/src/main/jniLibs/armeabi-v7a/libclient.so" ]]; then
    echo "ERROR: armeabi-v7a .so not found!"
    MISSING=1
fi
if [[ ! -f "app/src/main/jniLibs/x86_64/libclient.so" ]]; then
    echo "ERROR: x86_64 .so not found!"
    MISSING=1
fi

if [[ "$MISSING" == "1" ]]; then
    echo ""
    echo "Run build_client.sh first to build all native libraries!"
    exit 1
fi

echo "Incremental build..."
echo "Building release APKs..."

# Find Android SDK for Gradle (so it works even with a stale local.properties)
SDK_DIR=""
if [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME" ]]; then
  SDK_DIR="$ANDROID_HOME"
elif [[ -n "${ANDROID_SDK_ROOT:-}" && -d "$ANDROID_SDK_ROOT" ]]; then
  SDK_DIR="$ANDROID_SDK_ROOT"
elif [[ -f "local.properties" ]]; then
  SDK_DIR="$(grep -E '^sdk\.dir=' local.properties | head -n1 | cut -d= -f2- || true)"
  SDK_DIR="${SDK_DIR//\\:/:}"
  if [[ -n "$SDK_DIR" && ! -d "$SDK_DIR" ]]; then
    SDK_DIR=""
  fi
fi

if [[ -z "$SDK_DIR" ]]; then
  for cand in \
    "$HOME/AppData/Local/Android/Sdk" \
    "$HOME/Library/Android/sdk" \
    "/opt/android-sdk" \
    "/usr/lib/android-sdk"; do
    if [[ -d "$cand" ]]; then
      SDK_DIR="$cand"
      break
    fi
  done
fi

if [[ -n "$SDK_DIR" ]]; then
  export ANDROID_HOME="$SDK_DIR"
  echo "Using SDK: $SDK_DIR"
fi

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    ./gradlew.bat assembleRelease --no-daemon
else
    ./gradlew assembleRelease --no-daemon
fi

mkdir -p app/release

echo ""
echo "Copying APKs to release folder..."

APK_DIR="app/build/outputs/apk/release"

if [[ -f "$APK_DIR/app-universal-release.apk" ]]; then
    cp "$APK_DIR/app-universal-release.apk" "app/release/WDTT-universal.apk"
    echo "  [OK] WDTT-universal.apk"
else
    echo "  [!!] Universal APK not found"
fi

if [[ -f "$APK_DIR/app-arm64-v8a-release.apk" ]]; then
    cp "$APK_DIR/app-arm64-v8a-release.apk" "app/release/WDTT-arm64-v8a.apk"
    echo "  [OK] WDTT-arm64-v8a.apk"
else
    echo "  [!!] arm64-v8a APK not found"
fi

if [[ -f "$APK_DIR/app-armeabi-v7a-release.apk" ]]; then
    cp "$APK_DIR/app-armeabi-v7a-release.apk" "app/release/WDTT-armeabi-v7a.apk"
    echo "  [OK] WDTT-armeabi-v7a.apk"
else
    echo "  [!!] armeabi-v7a APK not found"
fi

if [[ -f "$APK_DIR/app-x86_64-release.apk" ]]; then
    cp "$APK_DIR/app-x86_64-release.apk" "app/release/WDTT-x86_64.apk"
    echo "  [OK] WDTT-x86_64.apk"
else
    echo "  [!!] x86_64 APK not found"
fi

echo ""
echo "=== DONE ==="
echo "Output directory: app/release/"
echo ""
echo "  WDTT-universal.apk    - all architectures in one APK"
echo "  WDTT-arm64-v8a.apk    - 64-bit ARM only"
echo "  WDTT-armeabi-v7a.apk  - 32-bit ARM only"
echo "  WDTT-x86_64.apk       - x86_64 only"
echo ""
