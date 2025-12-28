#!/bin/bash
# Version Consistency Check
# Validates that all package files have matching versions

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Extract version from Cargo.toml
CARGO_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo -e "${YELLOW}Checking version consistency...${NC}"
echo "Cargo.toml version: $CARGO_VERSION"

# Check npm package.json
if [ -f "npm/package.json" ]; then
    NPM_VERSION=$(jq -r .version npm/package.json)
    echo "npm/package.json version: $NPM_VERSION"
    if [ "$NPM_VERSION" != "$CARGO_VERSION" ]; then
        echo -e "${RED}ERROR: npm version ($NPM_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
        exit 1
    fi

    # Check optional dependencies versions
    for dep in darwin-x64 darwin-arm64 linux-x64 win32-x64; do
        DEP_VERSION=$(jq -r ".optionalDependencies[\"@narsil-mcp/$dep\"]" npm/package.json)
        if [ "$DEP_VERSION" != "null" ] && [ "$DEP_VERSION" != "$CARGO_VERSION" ]; then
            echo -e "${RED}ERROR: npm optional dep @narsil-mcp/$dep version ($DEP_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
            exit 1
        fi
    done
fi

# Check AUR PKGBUILD files
for aur_dir in ../aur-narsil-mcp ../aur-narsil-mcp-bin; do
    if [ -f "$aur_dir/PKGBUILD" ]; then
        AUR_VERSION=$(grep '^pkgver=' "$aur_dir/PKGBUILD" | sed 's/pkgver=\(.*\)/\1/')
        echo "$aur_dir version: $AUR_VERSION"
        if [ "$AUR_VERSION" != "$CARGO_VERSION" ]; then
            echo -e "${RED}ERROR: AUR version ($AUR_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
            exit 1
        fi
    fi
done

# Check Homebrew formula
if [ -f "../homebrew-narsil/Formula/narsil-mcp.rb" ]; then
    BREW_VERSION=$(grep 'version "' ../homebrew-narsil/Formula/narsil-mcp.rb | sed 's/.*version "\(.*\)".*/\1/')
    echo "Homebrew formula version: $BREW_VERSION"
    if [ "$BREW_VERSION" != "$CARGO_VERSION" ]; then
        echo -e "${RED}ERROR: Homebrew version ($BREW_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
        exit 1
    fi
fi

# Check Scoop manifest
if [ -f "../scoop-narsil/bucket/narsil-mcp.json" ]; then
    SCOOP_VERSION=$(jq -r .version ../scoop-narsil/bucket/narsil-mcp.json)
    echo "Scoop manifest version: $SCOOP_VERSION"
    if [ "$SCOOP_VERSION" != "$CARGO_VERSION" ]; then
        echo -e "${RED}ERROR: Scoop version ($SCOOP_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
        exit 1
    fi
fi

# If binary exists, check its --version output
if [ -f "target/release/narsil-mcp" ]; then
    BINARY_VERSION=$(./target/release/narsil-mcp --version 2>/dev/null | sed 's/narsil-mcp //')
    echo "Binary --version output: $BINARY_VERSION"
    if [ "$BINARY_VERSION" != "$CARGO_VERSION" ]; then
        echo -e "${RED}ERROR: Binary version ($BINARY_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All versions consistent: $CARGO_VERSION${NC}"
exit 0
