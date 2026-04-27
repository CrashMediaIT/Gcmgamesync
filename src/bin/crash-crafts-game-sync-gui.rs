//! Desktop GUI binary for Crash Crafts Game Sync.
//!
//! Launches a local-only HTTP server (bound to 127.0.0.1) that serves the
//! desktop management SPA, and opens it in the user's default browser. The
//! same approach is used by Plex, qBittorrent, Sonarr, Radarr, NZBGet, Pi-hole
//! and other "desktop" apps that ship with a real per-user UI without pulling
//! in the system webview / GTK / native toolkit at build time.
//!
//! All command-line flags from `crash-crafts-game-sync gui` are accepted.

fn main() -> crash_crafts_game_sync::AppResult<()> {
    let mut args: Vec<String> = std::env::args().collect();
    // Inject the `gui` subcommand so this binary always launches the GUI even
    // when the user passes additional flags like `--config` or `--port`.
    if args.get(1).map(String::as_str) != Some("gui") {
        args.insert(1, "gui".to_owned());
    }
    crash_crafts_game_sync::run_desktop_gui(&args[1..])
}
