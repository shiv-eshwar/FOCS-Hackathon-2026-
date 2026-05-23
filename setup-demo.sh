#!/usr/bin/env bash
set -euo pipefail

current_branch="$(git rev-parse --abbrev-ref HEAD)"

if ! git show-ref --verify --quiet refs/heads/main; then
  git checkout -b main
else
  git checkout main
fi

git checkout -B vulnerable
cp Dockerfile.vulnerable Dockerfile
git add Dockerfile
git commit -m "demo: use vulnerable nginx base image for security gate demo"

git checkout main

echo "Demo branches prepared."
echo "Current branch: ${current_branch}"
echo ""
echo "Run these commands to publish demo branches:"
echo "  git checkout main"
echo "  git push -u origin main"
echo "  git checkout vulnerable"
echo "  git push -u origin vulnerable"
echo "  git checkout main"
