#!/usr/bin/env bash
# Cross-platform build script for ipv4Bypass.
#
# Usage:
#   ./build.sh                  build all release targets into dist/
#   ./build.sh native           build only for the current platform
#   ./build.sh linux/arm64 windows/amd64 ...   build selected os/arch targets
#
# Output: dist/ipv4Bypass-<os>-<arch>[.exe] + SHA256SUMS
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUTDIR="${OUTDIR:-dist}"
LDFLAGS="-s -w -X main.version=${VERSION}"

# Default release matrix. Add/remove freely.
ALL_TARGETS=(
    linux/amd64
    linux/arm64
    linux/arm      # 32-bit: Raspberry Pi and friends
    darwin/amd64
    darwin/arm64   # Apple Silicon
    windows/amd64
    windows/arm64
)

if [[ "${1:-}" == "native" ]]; then
    TARGETS=("$(go env GOOS)/$(go env GOARCH)")
elif [[ $# -gt 0 ]]; then
    TARGETS=("$@")
else
    TARGETS=("${ALL_TARGETS[@]}")
fi

mkdir -p "$OUTDIR"
rm -f "${OUTDIR}"/ipv4Bypass-* "${OUTDIR}/SHA256SUMS"

echo "==> ipv4Bypass ${VERSION}"
fail=0
for target in "${TARGETS[@]}"; do
    os="${target%%/*}"
    arch="${target##*/}"
    out="ipv4Bypass-${os}-${arch}"
    [[ "$os" == "windows" ]] && out+=".exe"

    echo "--> building ${target}"
    if ! GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "${LDFLAGS}" -o "${OUTDIR}/${out}" .; then
        echo "!!  failed: ${target}" >&2
        fail=1
        continue
    fi
done

if [[ $fail -ne 0 ]]; then
    echo "==> some builds FAILED (see above)" >&2
    exit 1
fi

# Checksums over successfully built artifacts only.
( cd "$OUTDIR" && sha256sum ipv4Bypass-* > SHA256SUMS )

echo "==> done: ${#TARGETS[@]} target(s) in ${OUTDIR}/"
ls -lh "${OUTDIR}"
