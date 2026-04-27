# Crash Crafts Game Sync

Crash Crafts Game Sync is an emulator save backup and synchronization platform. This PR focuses on the Docker-hosted Web UI setup flow, persistent server configuration, and secure-by-default container settings.

## Screenshots

![Crash Crafts Game Sync web UI](docs/screenshots/server-ui.svg)

![Crash Crafts Game Sync CLI status output](docs/screenshots/cli-status.svg)

## Goals

- Synchronize emulator saves across devices.
- Preserve five total copies of changed files, including the current copy.
- Keep gamepad, path, graphics, and other user/device configuration local to each device.
- Support admin-managed users, registration, required TOTP 2FA, server-side client logs, and emulator update metadata.
- Track DuckStation, PCSX2 nightly, RPCS3 nightly, Xenia Canary, xemu, Cemu, RetroArch, Eden nightly, and Dolphin dev builds.

## Run with Docker

```bash
docker compose up --build
```

Open <http://localhost:8080> and complete the first-run setup page. The initial admin account, TOTP secret, Office365 OAuth SMTP metadata, and uploaded logo are stored in the Docker volume at `/data`; no Docker environment variables are required.

The image includes a built-in healthcheck that calls `/api/health`, and the Docker build context excludes local build outputs and repository metadata.

For transit security, run the container behind an HTTPS reverse proxy before exposing it beyond localhost. At-rest state and uploaded synchronized files are written with restrictive file permissions on Unix-like hosts. A separate Postgres service is not required for the current Docker setup because the app stores its small setup/configuration state and versioned file metadata in the mounted `/data` volume.

## Web UI theme

The server root (`/`) includes a modern dark, glass-style UI with orange and cyan neon accents. I could not fetch `crashcrafts.com` from this sandbox to verify exact brand tokens, so the MVP uses a CrashCrafts-style high-contrast gaming palette that can be adjusted once official colors are available.

## Run without Docker

```bash
cargo run -- server
```

## Client MVP

```bash
cargo run -- manifest
cargo run -- scan --root /path/to/emulators
cargo run -- status --root /path/to/emulators
```

## HTTP API MVP

- `GET /api/health` health check.
- `GET /api/config` public Web UI setup/branding configuration.
- `GET /api/emulators` shared emulator manifest.
- `POST /api/setup` first-run Docker setup for initial admin and Office365 OAuth SMTP metadata.
- `POST /api/login` with `email`, `password`, and `totp_code`.
- `POST /api/admin/logo` admin-only logo upload using a PNG, JPEG, or SVG data URL.
- `POST /api/invites` admin-only invite creation.
- `POST /api/register` invite-based registration that returns a TOTP secret/provisioning URI.
- `PUT /api/files/{relative-path}` authenticated file upload with version retention.
- `POST /api/logs` authenticated client log upload.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md).
