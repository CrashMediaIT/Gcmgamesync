# Gcmgamesync

Gcmgamesync is an emulator save backup and synchronization platform. The MVP in this repository is now implemented in Rust and provides a Docker-hosted server, a cross-platform CLI client scaffold for Windows/Linux, and a shared emulator manifest that defines save-data sync rules while excluding device-local configuration.

## Screenshots

![Gcmgamesync web UI](docs/screenshots/server-ui.svg)

![Gcmgamesync CLI status output](docs/screenshots/cli-status.svg)

## Goals

- Synchronize emulator saves across devices.
- Preserve five total copies of changed files, including the current copy.
- Keep gamepad, path, graphics, and other user/device configuration local to each device.
- Support admin-managed users, registration, required TOTP 2FA, server-side client logs, and emulator update metadata.
- Track DuckStation, PCSX2 nightly, RPCS3 nightly, Xenia Canary, xemu, Cemu, RetroArch, Eden nightly, and Dolphin dev builds.

## Run the server with Docker

```bash
GCM_ADMIN_EMAIL=admin@example.com GCM_ADMIN_PASSWORD='replace-with-a-long-random-password' docker compose up --build
```

The server listens on <http://localhost:8080>. Set `GCM_ADMIN_EMAIL` and `GCM_ADMIN_PASSWORD`; the compose file refuses to start without them. On first boot, the server stores an admin TOTP provisioning URI in `/data/state.json` under `bootstrap_admin_otpauth`.

## Web UI theme

The server root (`/`) includes a modern dark, glass-style UI with orange and cyan neon accents. I could not fetch `crashcrafts.com` from this sandbox to verify exact brand tokens, so the MVP uses a CrashCrafts-style high-contrast gaming palette that can be adjusted once official colors are available.

## Run without Docker

```bash
GCM_DATA_DIR=/tmp/gcmgamesync-data GCM_ADMIN_EMAIL=admin@example.com GCM_ADMIN_PASSWORD='change-this-admin-password' cargo run -- server
```

## Client MVP

```bash
cargo run -- manifest
cargo run -- scan --root /path/to/emulators
cargo run -- status --root /path/to/emulators
```

## HTTP API MVP

- `GET /api/health` health check.
- `GET /api/emulators` shared emulator manifest.
- `POST /api/login` with `email`, `password`, and `totp_code`.
- `POST /api/invites` admin-only invite creation.
- `POST /api/register` invite-based registration that returns a TOTP secret/provisioning URI.
- `PUT /api/files/{relative-path}` authenticated file upload with version retention.
- `POST /api/logs` authenticated client log upload.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md).
