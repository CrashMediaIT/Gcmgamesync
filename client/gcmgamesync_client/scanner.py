from __future__ import annotations

import fnmatch
import json
import platform
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "shared" / "emulators.json").read_text(encoding="utf-8"))


def current_os() -> str:
    name = platform.system().lower()
    if name.startswith("win"):
        return "windows"
    if name == "linux":
        return "linux"
    return name


def detect_emulators(root: Path) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for emulator in MANIFEST["emulators"]:
        for candidate in emulator.get("detect_paths", []):
            path = root / candidate
            if path.exists():
                found.append({
                    "id": emulator["id"],
                    "name": emulator["name"],
                    "path": str(path),
                    "portable": any((path / marker).exists() for marker in emulator.get("portable_markers", [])),
                    "update_policy": emulator.get("updates", {}).get(current_os(), {"source": "unsupported"}),
                })
                break
    return found


def should_sync(relative_path: str, emulator: dict[str, Any]) -> bool:
    includes = emulator.get("sync_include", [])
    excludes = emulator.get("sync_exclude", [])
    normalized = relative_path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pat) for pat in includes) and not any(fnmatch.fnmatch(normalized, pat) for pat in excludes)
