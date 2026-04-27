from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .scanner import MANIFEST, detect_emulators


def post_json(url: str, payload: dict, token: str | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - user-configured server URL
        return json.loads(response.read().decode("utf-8"))


def cmd_scan(args: argparse.Namespace) -> int:
    print(json.dumps({"root": str(args.root), "emulators": detect_emulators(args.root)}, indent=2))
    return 0


def cmd_manifest(_: argparse.Namespace) -> int:
    print(json.dumps(MANIFEST, indent=2))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    detected = detect_emulators(args.root)
    portable_missing = [item for item in detected if not item["portable"]]
    print(json.dumps({"detected": detected, "errors": [], "portable_mode_required": portable_missing}, indent=2))
    return 1 if portable_missing else 0


def cmd_log(args: argparse.Namespace) -> int:
    try:
        result = post_json(f"{args.server.rstrip('/')}/api/logs", {"level": args.level, "message": args.message, "context": {"client": "gcmgamesync-cli"}}, args.token)
    except urllib.error.URLError as exc:
        print(f"failed to upload log: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gcmgamesync desktop client MVP")
    sub = parser.add_subparsers(required=True)
    scan = sub.add_parser("scan", help="detect configured emulators under a folder")
    scan.add_argument("--root", type=Path, required=True)
    scan.set_defaults(func=cmd_scan)
    manifest = sub.add_parser("manifest", help="print emulator sync manifest")
    manifest.set_defaults(func=cmd_manifest)
    status = sub.add_parser("status", help="show sync readiness and portable-mode status")
    status.add_argument("--root", type=Path, required=True)
    status.set_defaults(func=cmd_status)
    log = sub.add_parser("upload-log", help="upload a client log entry to the server")
    log.add_argument("--server", required=True)
    log.add_argument("--token", required=True)
    log.add_argument("--level", default="info")
    log.add_argument("message")
    log.set_defaults(func=cmd_log)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
