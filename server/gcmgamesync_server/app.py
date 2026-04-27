from __future__ import annotations

import json
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .auth import hash_password, new_token, new_totp_secret, otpauth_uri, verify_password, verify_totp
from .storage import JsonStore, write_versioned_file

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "shared" / "emulators.json").read_text(encoding="utf-8"))


def bootstrap_store(data_dir: Path) -> JsonStore:
    store = JsonStore(data_dir / "state.json")
    data = store.read()
    admin_email = os.environ.get("GCM_ADMIN_EMAIL")
    admin_password = os.environ.get("GCM_ADMIN_PASSWORD")
    if admin_email and admin_password and admin_email not in data["users"]:
        secret = new_totp_secret()
        data["users"][admin_email] = {
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "totp_secret": secret,
            "is_admin": True,
            "registered": True,
        }
        data["bootstrap_admin_otpauth"] = otpauth_uri(admin_email, secret)
        store.write(data)
    return store


class GcmHandler(BaseHTTPRequestHandler):
    server_version = "Gcmgamesync/0.1"

    @property
    def store(self) -> JsonStore:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def data_dir(self) -> Path:
        return self.server.data_dir  # type: ignore[attr-defined]

    def _send(self, status: int, body: object, content_type: str = "application/json") -> None:
        payload = body if isinstance(body, bytes) else json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _current_user(self) -> dict | None:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header.removeprefix("Bearer ")
        data = self.store.read()
        session = data["sessions"].get(token)
        if not session:
            return None
        return data["users"].get(session["email"])

    def _require_user(self) -> dict | None:
        user = self._current_user()
        if not user:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid bearer token"})
            return None
        return user

    def _require_admin(self) -> dict | None:
        user = self._require_user()
        if user and not user.get("is_admin"):
            self._send(HTTPStatus.FORBIDDEN, {"error": "admin required"})
            return None
        return user

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            html = """<!doctype html><title>Gcmgamesync</title><h1>Gcmgamesync</h1><p>Docker-hosted emulator save sync MVP.</p><ul><li><a href='/api/emulators'>Emulator manifest</a></li><li><a href='/api/health'>Health</a></li></ul>""".encode()
            self._send(HTTPStatus.OK, html, "text/html; charset=utf-8")
        elif parsed.path == "/api/health":
            self._send(HTTPStatus.OK, {"ok": True})
        elif parsed.path == "/api/emulators":
            self._send(HTTPStatus.OK, MANIFEST)
        elif parsed.path == "/api/users":
            if self._require_admin():
                users = list(self.store.read()["users"].values())
                for user in users:
                    user.pop("password_hash", None)
                    user.pop("totp_secret", None)
                self._send(HTTPStatus.OK, {"users": users})
        else:
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        body = self._json_body()
        data = self.store.read()
        if parsed.path == "/api/invites":
            if not self._require_admin():
                return
            email = body.get("email", "").strip().lower()
            if not email:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "email required"})
                return
            token = secrets.token_urlsafe(24)
            data["invites"][token] = {"email": email}
            store_note = "Configure SMTP later; this invite token is returned for manual delivery."
            self.store.write(data)
            self._send(HTTPStatus.CREATED, {"email": email, "invite_token": token, "email_status": store_note})
        elif parsed.path == "/api/register":
            token = body.get("invite_token", "")
            invite = data["invites"].get(token)
            if not invite:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid invite"})
                return
            email = invite["email"]
            password = body.get("password", "")
            if len(password) < 12:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "password must be at least 12 characters"})
                return
            secret = new_totp_secret()
            data["users"][email] = {"email": email, "password_hash": hash_password(password), "totp_secret": secret, "is_admin": False, "registered": True}
            del data["invites"][token]
            self.store.write(data)
            self._send(HTTPStatus.CREATED, {"email": email, "totp_secret": secret, "otpauth_uri": otpauth_uri(email, secret)})
        elif parsed.path == "/api/login":
            email = body.get("email", "").strip().lower()
            user = data["users"].get(email)
            if not user or not verify_password(body.get("password", ""), user.get("password_hash", "")) or not verify_totp(user.get("totp_secret", ""), body.get("totp_code", "")):
                self._send(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials or 2fa code"})
                return
            token = new_token()
            data["sessions"][token] = {"email": email}
            self.store.write(data)
            self._send(HTTPStatus.OK, {"token": token, "is_admin": user.get("is_admin", False)})
        elif parsed.path == "/api/logs":
            user = self._require_user()
            if not user:
                return
            data["logs"].append({"email": user["email"], "level": body.get("level", "info"), "message": body.get("message", ""), "context": body.get("context", {})})
            data["logs"] = data["logs"][-1000:]
            self.store.write(data)
            self._send(HTTPStatus.CREATED, {"ok": True})
        else:
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/files/"):
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        user = self._require_user()
        if not user:
            return
        rel_path = parsed.path.removeprefix("/api/files/")
        length = int(self.headers.get("Content-Length", "0"))
        result = write_versioned_file(self.data_dir, user["email"], rel_path, self.rfile.read(length))
        self._send(HTTPStatus.OK, result)


def run() -> None:
    data_dir = Path(os.environ.get("GCM_DATA_DIR", "/data"))
    host = os.environ.get("GCM_HOST", "0.0.0.0")
    port = int(os.environ.get("GCM_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), GcmHandler)
    server.data_dir = data_dir  # type: ignore[attr-defined]
    server.store = bootstrap_store(data_dir)  # type: ignore[attr-defined]
    print(f"Gcmgamesync server listening on http://{host}:{port}")
    server.serve_forever()
