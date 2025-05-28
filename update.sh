set -o errexit

test -f docs/indexx.md || (
  echo "Missing files in docs/, check symlink."
  exit
)
git pull
cp -Rv docs/* ./
git add .
git commit -a -m "Mirror update $(date +%Y%m%d)"
