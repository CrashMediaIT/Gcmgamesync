# Architecture

## Server

The server is a Docker-friendly Rust HTTP service with a first-run Web UI setup. It stores users, sessions, invites, Office365 OAuth SMTP metadata, uploaded branding, and recent logs in a JSON state file under `/data`, and stores synchronized files under `/data/files/{user}`. When a changed file is replaced, the previous copy is moved to `/data/versions/{user}` and pruned so each file has at most five total copies including the current copy.

## Client

The current PR scope is Docker configuration and Web UI setup. Desktop app work can later wrap the existing manifest detection and sync APIs with a dedicated GUI.

## Sync policy

The shared `shared/emulators.json` manifest is the source of truth for emulator detection, portable markers, save-data include rules, device-local configuration exclusions, and OS-specific update channels. Device-local configuration is intentionally excluded to avoid breaking gamepad bindings, ROM paths, graphics settings, and per-device filesystem layout.
