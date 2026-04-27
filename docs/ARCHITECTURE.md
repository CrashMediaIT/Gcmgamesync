# Architecture

## Server

The server is a Docker-friendly Rust HTTP service with a first-run Web UI setup. It stores users, sessions, invites, Office365 OAuth SMTP metadata, uploaded branding, and recent logs in a JSON state file under `/data`, and stores synchronized files under `/data/files/{user}`. When a changed file is replaced, the previous copy is moved to `/data/versions/{user}` and pruned so each file has at most five total copies including the current copy.

## Client

The desktop foundation is a Rust CLI/daemon companion for the Docker server using a shared JSON config. The default desktop entry point reports companion setup status instead of starting another server. The `setup-desktop` command writes server/auth, ROM roots, emulator roots, service preferences, and Steam ROM Manager settings. The `daemon` command can run once or continuously, scans configured emulator folders with the shared manifest, uploads save-compatible files to the Docker server, and pulls explicit remote paths into local folders. A later GUI can wrap these commands without replacing the Rust daemon.

Desktop packaging is intentionally native: Windows uses an MSI/Windows Service, Linux publishes Debian, RPM, and AUR companion packages with a systemd user service, and Steam Deck game mode uses a Decky Loader companion plugin that reports status/control while the user service performs sync. Flatpak is deferred because sandboxing conflicts with broad folder monitoring and service installation.

## Sync policy

The shared `shared/emulators.json` manifest is the source of truth for emulator detection, portable markers, save-data include rules, device-local configuration exclusions, and OS-specific update channels. Device-local configuration is intentionally excluded to avoid breaking gamepad bindings, ROM paths, graphics settings, and per-device filesystem layout.
