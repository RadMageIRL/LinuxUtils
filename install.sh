#!/usr/bin/env bash
# Symlink every tool in this repo into ~/.local/bin, stripping the extension.
# Symlinks point back at the clone, so `git pull` updates the tools in place.
#
#   ./install.sh              install
#   ./install.sh --uninstall  remove only the symlinks this script created
#
# Nothing is installed system-wide and nothing is copied.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
UNINSTALL=0

case "${1:-}" in
  --uninstall) UNINSTALL=1 ;;
  --help|-h)   sed -n '2,10p' "$0" | sed 's/^# \?//'; exit 0 ;;
  "")          ;;
  *)           echo "unknown option: $1" >&2; exit 2 ;;
esac

# Discover tools: any executable-ish script one level down whose basename
# (minus extension) matches its parent directory.
mapfile -t TOOLS < <(
  find "$REPO" -mindepth 2 -maxdepth 2 -type f \( -name '*.py' -o -name '*.sh' \) \
    | while read -r f; do
        dir="$(basename "$(dirname "$f")")"
        base="$(basename "$f")"
        [[ "${base%.*}" == "$dir" ]] && echo "$f"
      done | sort
)

if [[ ${#TOOLS[@]} -eq 0 ]]; then
  echo "No tools found under $REPO" >&2
  exit 1
fi

if [[ $UNINSTALL -eq 1 ]]; then
  removed=0
  for src in "${TOOLS[@]}"; do
    name="$(basename "$(dirname "$src")")"
    link="$BIN/$name"
    # Only remove symlinks that actually point into this repo.
    if [[ -L "$link" && "$(readlink -f "$link")" == "$(readlink -f "$src")" ]]; then
      rm "$link"
      echo "  removed  $link"
      removed=$((removed + 1))
    elif [[ -e "$link" ]]; then
      echo "  skipped  $link (not ours)"
    fi
  done
  echo "Removed $removed symlink(s)."
  exit 0
fi

mkdir -p "$BIN"

for src in "${TOOLS[@]}"; do
  name="$(basename "$(dirname "$src")")"
  link="$BIN/$name"

  chmod +x "$src"

  if [[ -L "$link" ]]; then
    if [[ "$(readlink -f "$link")" == "$(readlink -f "$src")" ]]; then
      echo "  ok       $name (already linked)"
      continue
    fi
    ln -sfn "$src" "$link"
    echo "  relinked $name -> $src"
  elif [[ -e "$link" ]]; then
    # Refuse to clobber a real file we did not create.
    echo "  SKIP     $name: $link exists and is not a symlink" >&2
    continue
  else
    ln -s "$src" "$link"
    echo "  linked   $name -> $src"
  fi
done

echo
case ":$PATH:" in
  *":$BIN:"*) echo "$BIN is on your PATH." ;;
  *)
    echo "WARNING: $BIN is not on your PATH. Add it:"
    echo "  echo 'export PATH=\"\$PATH:$BIN\"' >> ~/.bashrc && exec bash"
    ;;
esac
