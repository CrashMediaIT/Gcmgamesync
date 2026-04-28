fn main() {
    if let Err(err) = crash_crafts_game_sync::run_cli() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
