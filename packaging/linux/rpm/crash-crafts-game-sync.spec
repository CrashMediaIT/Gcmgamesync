Name: crash-crafts-game-sync
Version: %{version}
Release: 1%{?dist}
Summary: Desktop GUI and sync daemon for Crash Crafts Game Sync
License: NOASSERTION
URL: https://github.com/CrashMediaIT/Gcmgamesync
Source0: crash-crafts-game-sync
Source1: crash-crafts-game-sync.desktop
Source2: crash-crafts-game-sync.service
Source3: crash-crafts-game-sync-gui
Source4: crash-crafts-game-sync.png
Requires: ca-certificates, xdg-utils

%description
Crash Crafts Game Sync ships two binaries:

  * crash-crafts-game-sync-gui — the per-user desktop application that
    configures emulator + ROM library roots, installs portable emulator
    builds, generates Steam ROM Manager parsers, and shows live sync status.
  * crash-crafts-game-sync — the headless sync daemon used by the systemd
    user unit to push emulator save files to the Crash Crafts Game Sync
    Docker server and pull updates back. Controller and emulator
    configuration files are intentionally NOT synchronised so per-device
    settings stay device-local.

%prep

%build

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_bindir}/crash-crafts-game-sync
install -Dm0755 %{SOURCE3} %{buildroot}%{_bindir}/crash-crafts-game-sync-gui
install -Dm0644 %{SOURCE1} %{buildroot}%{_datadir}/applications/crash-crafts-game-sync.desktop
install -Dm0644 %{SOURCE2} %{buildroot}/usr/lib/systemd/user/crash-crafts-game-sync.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/crash-crafts-game-sync.png

%files
%{_bindir}/crash-crafts-game-sync
%{_bindir}/crash-crafts-game-sync-gui
%{_datadir}/applications/crash-crafts-game-sync.desktop
%{_datadir}/icons/hicolor/256x256/apps/crash-crafts-game-sync.png
/usr/lib/systemd/user/crash-crafts-game-sync.service

%changelog
* Mon Apr 27 2026 CrashMediaIT <support@crashmediait.com> - 0.1.0-1
- Package both the desktop GUI and the headless sync daemon for RPM-based
  distributions; install hicolor icon and .desktop entry so the GUI shows up
  in standard application menus.
