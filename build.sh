#!/bin/sh
# Builds warp-chain into ./build. Usage:
#   ./build.sh               # linux amd64
#   ./build.sh win android   # one or more of: win, linux, arm64, android
set -e
mkdir -p build

# git tag wins, otherwise "dev"
VERSION=$(git describe --tags 2>/dev/null || true)
[ -n "$VERSION" ] || VERSION=dev
echo "version: $VERSION"

build() {
    out="build/warp-chain-$1-$2$3"
    GOOS="$1" GOARCH="$2" CGO_ENABLED=0 \
        go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$out" .
    echo "OK  $out"
}

if [ $# -eq 0 ]; then
    set -- linux
fi

for t in "$@"; do
    case "$t" in
        win)     build windows amd64 .exe ;;
        linux)   build linux   amd64 ""   ;;
        arm64)   build linux   arm64 ""   ;;
        android) build android arm64 ""   ;;
        *) echo "unknown target '$t' — use win, linux, arm64, android" >&2; exit 1 ;;
    esac
done
