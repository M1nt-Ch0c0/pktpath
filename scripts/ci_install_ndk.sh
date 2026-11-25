#!/usr/bin/env bash
# Install the official Android NDK r28b (28.1.13356709) for compile-only
# collector builds in CI and Release. This does not run on-device or
# kernel tests and must not be treated as a device-support matrix.
set -euo pipefail

NDK_URL="${NDK_URL:-https://dl.google.com/android/repository/android-ndk-r28b-linux.zip}"
# SHA-256 of android-ndk-r28b-linux.zip, computed 2026-11-25 after verifying
# official repository2-3.xml SHA-1 f574d3165405bd59ffc5edaadac02689075a729f
# (display-name "NDK (Side by side) 28.1.13356709", size 722264879).
NDK_SHA256="${NDK_SHA256:-e9f2759862cecfd48c20bbb7d8cfedbb020f4d91b5f78d9a2fc106f7db3c27ed}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "usage: $0 [install-dir]" >&2
  exit 0
fi

DEST="${1:-${PKTPATH_NDK_ROOT:-}}"
if [[ -z "$DEST" ]]; then
  DEST="${HOME}/.cache/pktpath-ci/android-ndk-r28b"
fi

CLANG="$DEST/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang"
if [[ -x "$CLANG" && -f "$DEST/source.properties" ]] \
    && grep -q 'Pkg.Revision = 28.1.13356709' "$DEST/source.properties"; then
  echo "NDK already present at $DEST"
else
  parent="$(dirname "$DEST")"
  mkdir -p "$parent"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/pktpath-ndk.XXXXXX")"
  cleanup() { rm -rf "$tmp"; }
  trap cleanup EXIT
  zip="$tmp/android-ndk-r28b-linux.zip"
  curl -fL --retry 3 --retry-delay 2 -o "$zip" "$NDK_URL"
  echo "$NDK_SHA256  $zip" | sha256sum -c -
  unzip -q "$zip" -d "$tmp"
  if [[ ! -d "$tmp/android-ndk-r28b" ]]; then
    echo "unexpected zip layout: android-ndk-r28b/ missing" >&2
    exit 1
  fi
  rm -rf "$DEST"
  mv "$tmp/android-ndk-r28b" "$DEST"
fi

test -x "$CLANG"
grep -q 'Pkg.Revision = 28.1.13356709' "$DEST/source.properties"
echo "ANDROID_NDK_HOME=$DEST"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "ANDROID_NDK_HOME=$DEST" >> "$GITHUB_ENV"
  echo "ANDROID_NDK_ROOT=$DEST" >> "$GITHUB_ENV"
fi
