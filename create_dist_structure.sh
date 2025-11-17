#!/bin/bash
set -e

VERSION="0.2.0"
BASE_DIR="dist/v${VERSION}"

# Clean structure: dist/v0.2.0/{platform-arch}/
platforms=(
    "linux-x86_64"
    "linux-aarch64"
    "darwin-x86_64"
    "darwin-arm64"
    "windows-x86_64"
)

echo "Creating clean dist structure for v${VERSION}..."

for platform in "${platforms[@]}"; do
    mkdir -p "${BASE_DIR}/${platform}"
    echo "✓ ${BASE_DIR}/${platform}"
done

echo ""
echo "Clean structure created. Tree view:"
tree dist/ 2>/dev/null || find dist -type d | sort
