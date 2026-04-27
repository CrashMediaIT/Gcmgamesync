# Crash Crafts Game Sync roadmap

## MVP foundation
- Rust Docker-hosted server with Web UI setup, user invitation, registration, 2FA, file storage, five-total-copy retention, and client log ingestion.
- Future Windows/Linux GUI clients that detect supported emulators, report sync status, preserve device-local configuration, and upload errors.
- Emulator manifest for DuckStation, PCSX2 nightly, RPCS3 nightly, Xenia Canary, xemu, Cemu, RetroArch, Eden nightly, and Dolphin dev builds.
- SMTP-backed invitation email delivery instead of manual invite-token delivery.

## Next feature: EmuDeck replacement mode
- Add an optional install checkbox to the Windows/Linux client.
- Let the user choose emulator install and ROM library locations.
- Download/install supported emulators in portable mode per OS.
- Install Steam ROM Manager and generate parser presets so imported Steam shortcuts launch correctly.
- Add Linux game-mode background sync through a Decky Loader plugin.
- Keep emulator user configuration device-local while syncing save-compatible data between Windows and Linux builds.
