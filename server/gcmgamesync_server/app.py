from __future__ import annotations

import json
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .auth import hash_password, new_token, new_totp_secret, otpauth_uri, verify_password, verify_totp
from .storage import JsonStore, write_versioned_file

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "shared" / "emulators.json").read_text(encoding="utf-8"))
DUMMY_PASSWORD_HASH = hash_password("invalid-password-placeholder")

UI_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gcmgamesync</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #070a12;
      --panel: rgba(17, 24, 39, 0.82);
      --panel-strong: rgba(12, 18, 31, 0.94);
      --text: #f8fafc;
      --muted: #aab7cf;
      --brand: #ff7a1a;
      --brand-2: #22d3ee;
      --good: #7ee787;
      --warn: #fbbf24;
      --border: rgba(255, 255, 255, 0.12);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(circle at 18% 12%, rgba(255, 122, 26, 0.23), transparent 32rem),
        radial-gradient(circle at 82% 4%, rgba(34, 211, 238, 0.20), transparent 30rem),
        linear-gradient(135deg, #070a12 0%, #101827 48%, #070a12 100%);
    }
    .shell { width: min(1160px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 56px; }
    nav, .card, .stat, .feature {
      border: 1px solid var(--border);
      background: var(--panel);
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
      backdrop-filter: blur(18px);
      border-radius: 24px;
    }
    nav { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; }
    .logo { display: flex; gap: 12px; align-items: center; font-weight: 800; letter-spacing: -0.04em; }
    .mark { width: 38px; height: 38px; border-radius: 12px; background: linear-gradient(135deg, var(--brand), var(--brand-2)); box-shadow: 0 0 32px rgba(255, 122, 26, 0.45); }
    .pill { color: var(--muted); border: 1px solid var(--border); border-radius: 999px; padding: 8px 12px; font-size: 0.85rem; }
    .hero { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 24px; align-items: stretch; margin-top: 28px; }
    .card { padding: clamp(28px, 5vw, 56px); }
    h1 { font-size: clamp(2.4rem, 7vw, 5.7rem); line-height: 0.94; margin: 0 0 20px; letter-spacing: -0.08em; }
    h2 { margin: 0 0 12px; font-size: 1.25rem; }
    p { color: var(--muted); line-height: 1.7; }
    .accent { background: linear-gradient(90deg, var(--brand), var(--brand-2)); -webkit-background-clip: text; color: transparent; }
    .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px; }
    a.button { text-decoration: none; color: #071019; background: linear-gradient(135deg, var(--brand), #ffd166); padding: 13px 18px; border-radius: 14px; font-weight: 800; }
    a.secondary { color: var(--text); background: rgba(255,255,255,0.08); border: 1px solid var(--border); }
    .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; height: 100%; }
    .stat { padding: 22px; }
    .value { display: block; font-size: 2rem; font-weight: 900; color: var(--good); }
    .label { color: var(--muted); font-size: 0.95rem; }
    .features { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 20px; }
    .feature { padding: 22px; background: var(--panel-strong); }
    code { color: var(--brand-2); }
    @media (max-width: 820px) { .hero, .features { grid-template-columns: 1fr; } .stats { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
  <main class="shell">
    <nav>
      <div class="logo"><span class="mark"></span><span>Gcmgamesync</span></div>
      <span class="pill">CrashCrafts-inspired dark neon theme</span>
    </nav>
    <section class="hero">
      <div class="card">
        <h1>Save sync for <span class="accent">every emulator rig.</span></h1>
        <p>Docker-hosted backup, five-copy version retention, TOTP-protected accounts, client logs, and device-local emulator configuration protection for Windows, Linux, and Steam Deck workflows.</p>
        <div class="actions">
          <a class="button" href="/api/emulators">View emulator manifest</a>
          <a class="button secondary" href="/api/health">Check server health</a>
        </div>
      </div>
      <div class="stats">
        <div class="stat"><span class="value">{{emulator_count}}</span><span class="label">emulator profiles including Dolphin dev</span></div>
        <div class="stat"><span class="value">{{versions_to_keep}}</span><span class="label">total copies retained per changed file</span></div>
        <div class="stat"><span class="value">2FA</span><span class="label">required registration/login model</span></div>
        <div class="stat"><span class="value">OS</span><span class="label">aware update metadata</span></div>
      </div>
    </section>
    <section class="features">
      <div class="feature"><h2>Portable-first</h2><p>Client detection checks portable markers before sync so each emulator can keep saves isolated and predictable.</p></div>
      <div class="feature"><h2>Config-safe</h2><p>Manifest exclusions keep controllers, paths, graphics, and other user configuration local to each device.</p></div>
      <div class="feature"><h2>Admin-ready</h2><p>Admin APIs bootstrap invites, users, logs, and future server-managed emulator updates.</p></div>
    </section>
  </main>
</body>
</html>"""


def render_ui() -> str:
    return (
        UI_HTML.replace("{{emulator_count}}", str(len(MANIFEST["emulators"])))
        .replace("{{versions_to_keep}}", str(MANIFEST["policy"]["file_versions_to_keep"]))
    )


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
            self._send(HTTPStatus.OK, render_ui().encode(), "text/html; charset=utf-8")
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
            email_delivery_note = "Configure SMTP later; this invite token is returned for manual delivery."
            self.store.write(data)
            self._send(HTTPStatus.CREATED, {"email": email, "invite_token": token, "email_status": email_delivery_note})
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
            password_hash = user.get("password_hash", DUMMY_PASSWORD_HASH) if user else DUMMY_PASSWORD_HASH
            password_ok = verify_password(body.get("password", ""), password_hash)
            totp_ok = bool(user) and verify_totp(user.get("totp_secret", ""), body.get("totp_code", ""))
            if not user or not password_ok or not totp_ok:
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
        rel_path = unquote(parsed.path.removeprefix("/api/files/"))
        length = int(self.headers.get("Content-Length", "0"))
        result = write_versioned_file(self.data_dir, user["email"], rel_path, self.rfile.read(length))
        self._send(HTTPStatus.OK, result)


def run() -> None:
    data_dir = Path(os.environ.get("GCM_DATA_DIR", "/data"))
    host = os.environ.get("GCM_HOST", "127.0.0.1")
    port = int(os.environ.get("GCM_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), GcmHandler)
    server.data_dir = data_dir  # type: ignore[attr-defined]
    server.store = bootstrap_store(data_dir)  # type: ignore[attr-defined]
    print(f"Gcmgamesync server listening on http://{host}:{port}")
    server.serve_forever()
