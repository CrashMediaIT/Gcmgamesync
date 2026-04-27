# Gcmgamesync roadmap

## MVP foundation
- Docker-hosted server with web UI, user invitation, registration, 2FA, file storage, five-total-copy retention, and client log ingestion.
- Windows/Linux client that detects supported emulators, reports sync status, preserves device-local configuration, and uploads errors.
- Emulator manifest for DuckStation, PCSX2 nightly, RPCS3 nightly, Xenia Canary, xemu, Cemu, RetroArch, Eden nightly, and Dolphin dev builds.
- SMTP-backed invitation email delivery instead of manual invite-token delivery.

## Next feature: EmuDeck replacement mode
- Add an optional install checkbox to the Windows/Linux client.
- Let the user choose emulator install and ROM library locations.
- Download/install supported emulators in portable mode per OS.
- Install Steam ROM Manager and generate parser presets so imported Steam shortcuts launch correctly.
- Add Linux game-mode background sync through a Decky Loader plugin.
- Keep emulator user configuration device-local while syncing save-compatible data between Windows and Linux builds.
