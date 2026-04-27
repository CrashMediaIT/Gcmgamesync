#!/usr/bin/env bash
# Crash Crafts Game Sync — Decky Loader plugin installer.
#
# Installs the Game-Mode helper into Decky Loader's plugins directory on any
# Linux distribution that runs Decky Loader (SteamOS 3 / Holo, Arch, Debian,
# Ubuntu, Fedora, Nobara, openSUSE, AppImage-only setups, etc.).
#
# Strategy:
#   1. Locate Decky Loader's plugin root (XDG-aware, with the SteamOS default
#      as a fallback).
#   2. Copy this directory into ${PLUGINS}/Crash Crafts Game Sync/.
#   3. If the desktop daemon (crash-crafts-game-sync-gui) is not on PATH,
#      print a hint pointing at the README's per-distro install instructions.
#
# The script is intentionally POSIX-portable Bash with no SteamOS-only
# assumptions so it works on every Linux install type the daemon supports.

set -euo pipefail

PLUGIN_NAME="Crash Crafts Game Sync"

candidate_dirs=(
  "${DECKY_PLUGIN_ROOT:-}"
  "${HOME}/homebrew/plugins"
  "${HOME}/.local/share/decky-loader/plugins"
  "${XDG_DATA_HOME:-$HOME/.local/share}/decky-loader/plugins"
  "/home/deck/homebrew/plugins"
)

target=""
for candidate in "${candidate_dirs[@]}"; do
  if [ -n "${candidate}" ] && [ -d "${candidate}" ]; then
    target="${candidate}"
    break
  fi
done

if [ -z "${target}" ]; then
  echo "error: could not find a Decky Loader plugins directory." >&2
  echo "       Set DECKY_PLUGIN_ROOT to the absolute path and re-run." >&2
  exit 1
fi

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
dest="${target}/${PLUGIN_NAME}"
mkdir -p "${dest}"
cp -R "${source_dir}/." "${dest}/"
echo "installed Decky helper to: ${dest}"

if ! command -v crash-crafts-game-sync-gui >/dev/null 2>&1; then
  cat <<'EOF' >&2
note: crash-crafts-game-sync-gui was not found on PATH. The Decky helper
      will only display data once the desktop GUI is running. Install the
      desktop binary using one of:

        Debian / Ubuntu / Pop!_OS : sudo apt install ./crash-crafts-game-sync_*.deb
        Fedora / openSUSE         : sudo dnf install ./crash-crafts-game-sync-*.rpm
        Arch / Manjaro / SteamOS  : makepkg -si  (in packaging/linux/aur)
        AppImage-only / Flatpak   : copy the binary into ~/.local/bin/

      then run `crash-crafts-game-sync-gui` once to register the local port.
EOF
fi
