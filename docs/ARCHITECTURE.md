# Architecture

## Server

The server is a Docker-friendly Python HTTP service. It stores users, sessions, invites, and recent logs in a JSON state file and stores synchronized files under `/data/files/{user}`. When a changed file is replaced, the previous copy is moved to `/data/versions/{user}` and pruned so each file has at most five total copies including the current copy.

## Client

The client is currently a cross-platform Python CLI scaffold. It detects emulator folders under a user-selected root, checks portable-mode markers, evaluates OS-specific update policy metadata, and can upload logs to the server. This can later be wrapped by a Windows GUI, Linux Flatpak, and Decky Loader plugin.

## Sync policy

The shared `shared/emulators.json` manifest is the source of truth for emulator detection, portable markers, save-data include rules, device-local configuration exclusions, and OS-specific update channels. Device-local configuration is intentionally excluded to avoid breaking gamepad bindings, ROM paths, graphics settings, and per-device filesystem layout.
