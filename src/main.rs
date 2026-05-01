fn main() {
    // Emit a startup banner on stderr (which is line-buffered, unlike the
    // block-buffered stdout used by `println!`) before doing any work. This
    // guarantees that `docker logs` shows *something* even if the process
    // crashes very early — for example because the `/data` volume is owned
    // by the wrong UID, the configured port is already in use, or a shared
    // library is missing. Previously a silent crash here produced an empty
    // log stream and made the failure impossible to diagnose remotely.
    eprintln!(
        "{} v{} starting (pid {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );
    let result = crash_crafts_game_sync::run_cli();
    // Flush stdout so any buffered `println!` output (server banners, JSON
    // responses, etc.) is visible before the process exits — without this
    // the buffered lines are dropped when we exit non-zero below.
    let _ = std::io::Write::flush(&mut std::io::stdout());
    if let Err(err) = result {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
