"""Crash Crafts Game Sync — Decky Loader plugin backend.

This Python module is loaded by Decky Loader inside Steam Deck's Game Mode and
exposes a small RPC surface to the JavaScript front-end (``main.js``). The
backend's only job is to talk to the *local* desktop GUI process
(``crash-crafts-game-sync-gui``) over its ``127.0.0.1`` HTTP port, so it works
identically on every Linux install type that can run the daemon:

* SteamOS 3 (Steam Deck) — the daemon is shipped under
  ``~/.local/share/crash-crafts-game-sync/`` because ``/usr`` is read-only.
* Arch / Manjaro — daemon installed via the AUR ``PKGBUILD``.
* Debian / Ubuntu / Pop!_OS — daemon installed via the ``.deb`` package.
* Fedora / openSUSE — daemon installed via the ``.rpm`` package.
* AppImage or Flatpak users — daemon launched from the user's own bin dir.

We auto-discover the local GUI port from
``$XDG_STATE_HOME/crash-crafts-game-sync/gui-port`` (the GUI writes its bound
port there on startup), with a fallback to common defaults.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


PORT_HINT_FILES = [
    Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    / "crash-crafts-game-sync"
    / "gui-port",
    Path.home() / ".config" / "crash-crafts-game-sync" / "gui-port",
]

DEFAULT_PORTS = [17835, 18765, 8765]


def _candidate_ports() -> List[int]:
    ports: List[int] = []
    for path in PORT_HINT_FILES:
        try:
            value = int(path.read_text().strip())
            if 1 <= value <= 65535:
                ports.append(value)
        except (OSError, ValueError):
            pass
    for port in DEFAULT_PORTS:
        if port not in ports:
            ports.append(port)
    return ports


def _request(path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    last_error: Optional[str] = None
    for port in _candidate_ports():
        url = f"http://127.0.0.1:{port}{path}"
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=2.5) as response:
                payload = response.read().decode("utf-8") or "{}"
                parsed = json.loads(payload)
                parsed["_port"] = port
                return parsed
        except urllib.error.URLError as error:
            last_error = str(error)
            continue
        except json.JSONDecodeError as error:
            last_error = f"invalid JSON from {url}: {error}"
            continue
    return {
        "ok": False,
        "error": last_error or "no local Crash Crafts Game Sync GUI process found",
    }


class Plugin:
    """RPC surface exposed to the Decky front-end."""

    async def status(self) -> Dict[str, Any]:
        return _request("/api/local/status")

    async def emulators(self) -> Dict[str, Any]:
        return _request("/api/local/emulators")

    async def sync_now(self) -> Dict[str, Any]:
        return _request("/api/local/sync-now", method="POST", body={})

    async def pause(self) -> Dict[str, Any]:
        return _request("/api/local/pause", method="POST", body={})

    async def folders(self) -> Dict[str, Any]:
        return _request("/api/local/folders")

    async def _main(self) -> None:  # noqa: D401
        """Decky lifecycle hook — nothing to set up at boot."""
        return None

    async def _unload(self) -> None:
        return None
