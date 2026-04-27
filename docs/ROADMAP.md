# Crash Crafts Game Sync roadmap

## MVP foundation
- Rust Docker-hosted server with Web UI setup, user invitation, registration, 2FA, file storage, five-total-copy retention, and client log ingestion.
- Future Windows/Linux GUI clients that detect supported emulators, report sync status, preserve device-local configuration, and upload errors.
- Emulator manifest for DuckStation, PCSX2 nightly, RPCS3 nightly, Xenia Canary, xemu, Cemu, RetroArch, Eden nightly, and Dolphin dev builds.
- SMTP-backed invitation email delivery instead of manual invite-token delivery.

## Next feature: EmuDeck replacement mode
- Add an optional install checkbox to the Windows/Linux client.
- Let the user choose emulator install and ROM library locations. The Rust `setup-desktop` command now stores these paths in the shared desktop config.
- Download/install supported emulators in portable mode per OS.
- Install Steam ROM Manager and generate parser presets so imported Steam shortcuts launch correctly. The Rust `generate-srm` command now writes initial parser presets from configured sync roots.
- Add Linux game-mode background sync through a Decky Loader plugin. Packaging now includes a Decky companion manifest while sync remains in the Rust user service.
- Keep emulator user configuration device-local while syncing save-compatible data between Windows and Linux builds.

## Desktop packaging foundation
- Build Windows as MSI with Windows Service registration.
- Build Linux as native packages using a systemd user service before considering Flatpak.
- Keep the Steam Deck plugin as a game-mode companion for status/control rather than the sync engine.
