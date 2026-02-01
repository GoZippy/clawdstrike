#!/usr/bin/env bash
set -euo pipefail

# Version bumping script for hushclaw
# Usage: ./scripts/bump-version.sh <version>
# Example: ./scripts/bump-version.sh 0.2.0

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.2.0"
    exit 1
fi

# Validate version format (semver)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "Error: Invalid version format. Use semver (e.g., 0.2.0 or 0.2.0-alpha.1)"
    exit 1
fi

echo "Bumping version to $VERSION..."

# Update root Cargo.toml workspace version
sed -i.bak "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak

# Update all crate Cargo.toml files that use workspace version inheritance
# (They inherit from workspace, so we only need to update root)

# Update package.json files
if [[ -f "packages/hushclaw-openclaw/package.json" ]]; then
    # Use node/npm if available, otherwise sed
    if command -v npm &> /dev/null; then
        (cd packages/hushclaw-openclaw && npm version "$VERSION" --no-git-tag-version --allow-same-version)
    else
        sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" packages/hushclaw-openclaw/package.json
        rm -f packages/hushclaw-openclaw/package.json.bak
    fi
    echo "  Updated packages/hushclaw-openclaw/package.json"
fi

# Update pyproject.toml if it exists
if [[ -f "packages/hush-py/pyproject.toml" ]]; then
    sed -i.bak "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/hush-py/pyproject.toml
    rm -f packages/hush-py/pyproject.toml.bak
    echo "  Updated packages/hush-py/pyproject.toml"
fi

# Update Homebrew formula URL (placeholder - actual SHA will be updated after release)
if [[ -f "HomebrewFormula/hush.rb" ]]; then
    sed -i.bak "s|/v[0-9]*\.[0-9]*\.[0-9]*[^/]*/|/v$VERSION/|g" HomebrewFormula/hush.rb
    rm -f HomebrewFormula/hush.rb.bak
    echo "  Updated HomebrewFormula/hush.rb (SHA256 must be updated after release)"
fi

echo ""
echo "Version bumped to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Update CHANGELOG.md"
echo "  3. Commit: git commit -am 'chore: bump version to $VERSION'"
echo "  4. Tag: git tag -a v$VERSION -m 'Release v$VERSION'"
echo "  5. Push: git push origin main --tags"
