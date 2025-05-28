#!/usr/bin/env bash
#
set -o errexit

if [[ ! -f "docs/index.md" ]]; then
  echo "Missing files in docs/, check symlink."
  exit 1
fi

git pull
cp -Rv docs/* ./
git add .
git commit -a -m "Mirror update $(date +%Y%m%d)"
git push
