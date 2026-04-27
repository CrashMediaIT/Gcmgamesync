Name: crash-crafts-game-sync
Version: %{version}
Release: 1%{?dist}
Summary: Desktop companion for Crash Crafts Game Sync
License: NOASSERTION
URL: https://github.com/CrashMediaIT/Gcmgamesync
Source0: crash-crafts-game-sync
Source1: crash-crafts-game-sync.desktop
Source2: crash-crafts-game-sync.service
Requires: ca-certificates

%description
Crash Crafts Game Sync is a desktop companion daemon for the Docker-hosted sync
server. It configures local emulator paths, runs background save sync, and
generates Steam ROM Manager presets while server administration remains in the
Docker Web UI.

%prep

%build

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_bindir}/crash-crafts-game-sync
install -Dm0644 %{SOURCE1} %{buildroot}%{_datadir}/applications/crash-crafts-game-sync.desktop
install -Dm0644 %{SOURCE2} %{buildroot}/usr/lib/systemd/user/crash-crafts-game-sync.service

%files
%{_bindir}/crash-crafts-game-sync
%{_datadir}/applications/crash-crafts-game-sync.desktop
/usr/lib/systemd/user/crash-crafts-game-sync.service

%changelog
* Mon Apr 27 2026 CrashMediaIT <support@crashmediait.com> - 0.1.0-1
- Package the desktop companion for RPM-based distributions.
