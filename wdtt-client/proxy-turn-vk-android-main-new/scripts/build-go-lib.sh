#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_DIR="$ROOT_DIR/app/src/main/assets/android-client"
ABI="${1:-arm64-v8a}"
API_LEVEL="${ANDROID_NATIVE_API_LEVEL:-28}"
NDK_DIR="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
GO_VERSION="$(go version | awk '{print $3}' | sed 's/^go//')"

needs_checklinkname_flag() {
  local major minor
  major="${GO_VERSION%%.*}"
  minor="${GO_VERSION#*.}"
  minor="${minor%%.*}"

  if [[ "$major" -gt 1 ]]; then
    return 0
  fi
  if [[ "$major" -eq 1 && "$minor" -ge 23 ]]; then
    return 0
  fi
  return 1
}

case "$ABI" in
  arm64-v8a)
    GOARCH="arm64"
    GOARM=""
    CLANG_PREFIX="aarch64-linux-android"
    ;;
  armeabi-v7a)
    GOARCH="arm"
    GOARM="7"
    CLANG_PREFIX="armv7a-linux-androideabi"
    ;;
  x86_64)
    GOARCH="amd64"
    GOARM=""
    CLANG_PREFIX="x86_64-linux-android"
    ;;
  *)
    echo "Unsupported ABI: $ABI" >&2
    exit 1
    ;;
esac

if [[ -n "$NDK_DIR" && ! -d "$NDK_DIR/toolchains/llvm/prebuilt" ]]; then
  NDK_DIR=""
fi

SDK_DIR=""

if [[ -z "$NDK_DIR" ]]; then
  if [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME" ]]; then
    SDK_DIR="$ANDROID_HOME"
  elif [[ -n "${ANDROID_SDK_ROOT:-}" && -d "$ANDROID_SDK_ROOT" ]]; then
    SDK_DIR="$ANDROID_SDK_ROOT"
  elif [[ -f "$ROOT_DIR/local.properties" ]]; then
    SDK_DIR="$(grep -E '^sdk\.dir=' "$ROOT_DIR/local.properties" | head -n1 | cut -d= -f2- || true)"
    # Android Studio may escape colons in local.properties (C\:/...)
    SDK_DIR="${SDK_DIR//\\:/:}"
    if [[ -n "$SDK_DIR" && ! -d "$SDK_DIR" ]]; then
      SDK_DIR=""
    fi
  fi
fi

# Fallback to common Android Studio install locations
if [[ -z "$NDK_DIR" && -z "$SDK_DIR" ]]; then
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

if [[ -z "$NDK_DIR" && -n "$SDK_DIR" && -d "$SDK_DIR/ndk" ]]; then
  NDK_DIR="$(find "$SDK_DIR/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -n1 || true)"
fi

# Fallback to common standalone NDK locations
if [[ -z "$NDK_DIR" ]]; then
  for cand in \
    "$HOME/Downloads/android-ndk-r29" \
    "$HOME/Downloads/android-ndk-r28" \
    "$HOME/Downloads/android-ndk-r27" \
    "/opt/android-ndk"; do
    if [[ -d "$cand/toolchains/llvm/prebuilt" ]]; then
      NDK_DIR="$cand"
      break
    fi
  done
fi

if [[ -z "$NDK_DIR" ]]; then
  echo "NDK not found. Set ANDROID_NDK_HOME or install NDK via Android Studio." >&2
  exit 1
fi

HOST_TAG="linux-x86_64"
if [[ "$OSTYPE" == "darwin"* ]]; then
  HOST_TAG="darwin-x86_64"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
  HOST_TAG="windows-x86_64"
fi

CC="$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG/bin/${CLANG_PREFIX}${API_LEVEL}-clang"
if [[ ! -x "$CC" && -x "${CC}.cmd" ]]; then
  CC="${CC}.cmd"
fi

if [[ ! -x "$CC" ]]; then
  CC29="$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG/bin/${CLANG_PREFIX}29-clang"
  CC30="$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG/bin/${CLANG_PREFIX}30-clang"
  if [[ -x "$CC29" ]]; then CC="$CC29";
  elif [[ -x "${CC29}.cmd" ]]; then CC="${CC29}.cmd";
  elif [[ -x "$CC30" ]]; then CC="$CC30";
  elif [[ -x "${CC30}.cmd" ]]; then CC="${CC30}.cmd";
  else
    echo "Compiler not found: $CC" >&2
    exit 1
  fi
fi

echo "Refreshing Go checksums"
(
  cd "$GO_DIR"
  go mod tidy -e
)

OUT_DIR="$ROOT_DIR/app/src/main/jniLibs/$ABI"
mkdir -p "$OUT_DIR"

echo "Building $ABI -> $OUT_DIR/libclient.so"
(
  cd "$GO_DIR"
  if needs_checklinkname_flag; then
    GOOS=android GOARCH="$GOARCH" GOARM="$GOARM" CGO_ENABLED=1 CC="$CC" \
      go build -trimpath -ldflags="-s -w -checklinkname=0" -o "$OUT_DIR/libclient.so" .
  else
    GOOS=android GOARCH="$GOARCH" GOARM="$GOARM" CGO_ENABLED=1 CC="$CC" \
      go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/libclient.so" .
  fi
)

echo "Done: $OUT_DIR/libclient.so"
