#!/usr/bin/env bash
#
# TxGate Release Script
#
# This script automates local release preparation:
# - Validates the codebase is ready for release
# - Bumps version numbers across all crates
# - Updates CHANGELOG.md
# - Creates and pushes the release tag
#
# Usage:
#   ./scripts/release.sh <version>
#   ./scripts/release.sh 0.2.0
#
# The GitHub Actions workflow will handle building and publishing.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Validate arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.2.0"
    exit 1
fi

VERSION="$1"
TAG="v$VERSION"

# Validate version format (semver)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    error "Invalid version format: $VERSION (expected semver like 0.2.0 or 0.2.0-rc.1)"
fi

info "Preparing release $TAG"

# Check we're on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    warn "Not on main branch (currently on $BRANCH)"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    error "Working directory has uncommitted changes. Please commit or stash them first."
fi

# Check that we're up to date with remote
git fetch origin
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main 2>/dev/null || echo "")
if [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
    error "Local branch is not up to date with origin/main. Please pull first."
fi

# Check that tag doesn't already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
    error "Tag $TAG already exists"
fi

info "Running pre-release checks..."

# Run tests
info "Running tests..."
cargo test --all-features || error "Tests failed"

# Run clippy
info "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings || error "Clippy failed"

# Run fmt check
info "Checking formatting..."
cargo fmt --all -- --check || error "Formatting check failed"

# Run audit
info "Running security audit..."
cargo audit || warn "Security audit found issues (continuing anyway)"

# Build release binaries to ensure they compile
info "Building release binaries..."
cargo build --release || error "Release build failed"

info "All checks passed!"

# Update version in all Cargo.toml files
info "Updating version to $VERSION in all crates..."

CRATES=(
    "Cargo.toml"
    "crates/txgate-core/Cargo.toml"
    "crates/txgate-crypto/Cargo.toml"
    "crates/txgate-chain/Cargo.toml"
    "crates/txgate-policy/Cargo.toml"
    "crates/txgate/Cargo.toml"
)

for CRATE in "${CRATES[@]}"; do
    if [ -f "$CRATE" ]; then
        # Update version = "x.y.z" line
        sed -i.bak "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*.*\"/version = \"$VERSION\"/" "$CRATE"
        rm -f "$CRATE.bak"
        info "  Updated $CRATE"
    fi
done

# Check if CHANGELOG.md has an entry for this version
if ! grep -q "\[$VERSION\]" CHANGELOG.md 2>/dev/null; then
    warn "CHANGELOG.md doesn't have an entry for $VERSION"
    warn "Please update CHANGELOG.md before continuing"
    read -p "Open CHANGELOG.md in editor? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        ${EDITOR:-vim} CHANGELOG.md
    fi
fi

# Show what will be committed
info "Changes to be committed:"
git diff --stat

echo
read -p "Commit these changes and create tag $TAG? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Reverting version changes..."
    git checkout -- .
    exit 1
fi

# Commit version bump
git add -A
git commit -m "chore: bump version to $VERSION

Prepare for release $TAG

Generated with [Claude Code](https://claude.ai/code)
via [Happy](https://happy.engineering)

Co-Authored-By: Claude <noreply@anthropic.com>
Co-Authored-By: Happy <yesreply@happy.engineering>"

# Create annotated tag
git tag -a "$TAG" -m "Release $VERSION"

info "Created commit and tag $TAG"

echo
read -p "Push to origin (this will trigger the release workflow)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push origin main
    git push origin "$TAG"
    info "Pushed to origin. Release workflow will start automatically."
    info "Monitor at: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
else
    info "Tag created locally. Push when ready with:"
    echo "  git push origin main"
    echo "  git push origin $TAG"
fi

info "Release preparation complete!"
