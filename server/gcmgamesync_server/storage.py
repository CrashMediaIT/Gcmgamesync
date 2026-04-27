from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "shared" / "emulators.json").read_text(encoding="utf-8"))
VERSIONS_TO_KEEP = int(MANIFEST["policy"]["file_versions_to_keep"])


class JsonStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.write({"users": {}, "invites": {}, "sessions": {}, "logs": []})

    def read(self) -> dict[str, Any]:
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name, text=True)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp, self.path)


def safe_relative_path(path: str) -> Path:
    clean = Path(path)
    if clean.is_absolute() or ".." in clean.parts:
        raise ValueError("unsafe path")
    return clean


def write_versioned_file(root: Path, owner: str, rel_path: str, content: bytes) -> dict[str, Any]:
    relative = safe_relative_path(rel_path)
    base = root / "files" / owner / relative
    versions = root / "versions" / owner / relative.parent / relative.name
    base.parent.mkdir(parents=True, exist_ok=True)
    versions.mkdir(parents=True, exist_ok=True)

    changed = not base.exists() or base.read_bytes() != content
    if changed and base.exists():
        version_name = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
        shutil.copy2(base, versions / version_name)
        existing = sorted(versions.iterdir(), key=lambda p: p.name)
        max_old_versions = max(VERSIONS_TO_KEEP - 1, 0)
        delete_count = max(len(existing) - max_old_versions, 0)
        for old in existing[:delete_count]:
            old.unlink()
    if changed:
        base.write_bytes(content)
    return {"path": str(relative), "changed": changed, "versions_kept": len(list(versions.iterdir()))}
