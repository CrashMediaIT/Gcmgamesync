//! Core library for Crash Crafts Game Sync.
//!
//! This crate exposes the server, sync daemon, and configuration logic that is
//! shared between the headless `crash-crafts-game-sync` binary and the
//! desktop GUI binary `crash-crafts-game-sync-gui`.

use base64::{Engine, engine::general_purpose};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

pub const MANIFEST_JSON: &str = include_str!("../shared/emulators.json");
pub const APP_NAME: &str = "Crash Crafts Game Sync";
const PASSWORD_ITERATIONS: u32 = 240_000;
const MAX_LOGO_BYTES: usize = 262_144;
const MAX_LOGO_BASE64_SIZE: usize = 349_528;
const STATIC_APP_JS: &str = include_str!("../shared/web/app.js");
const MAX_LOG_ENTRIES: usize = 1000;
const MAX_DEVICE_HEARTBEATS: usize = 256;

pub type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn manifest() -> Value {
    serde_json::from_str(MANIFEST_JSON).expect("embedded manifest is valid JSON")
}

/// Apply admin-published emulator update overrides to the bundled manifest.
/// Admins use `POST /api/admin/emulators` to publish per-OS portable download
/// URLs and SHA-256 checksums; this overlay is what every desktop client sees
/// when it calls `GET /api/emulators` or runs the GUI's "Install" buttons, so
/// emulator updates land for all users at once without redeploying the Docker
/// image.
pub fn live_manifest(state: &Value) -> Value {
    let mut manifest = manifest();
    let updates = state
        .get("emulator_updates")
        .cloned()
        .unwrap_or(Value::Null);
    let Some(emulators) = manifest["emulators"].as_array_mut() else {
        return manifest;
    };
    for emulator in emulators {
        let Some(id) = emulator["id"].as_str().map(str::to_owned) else {
            continue;
        };
        let Some(per_os) = updates.get(&id).and_then(|v| v.as_object()) else {
            continue;
        };
        if !emulator["downloads"].is_object() {
            emulator["downloads"] = json!({});
        }
        for (os, override_value) in per_os {
            let url = override_value
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if url.is_empty() {
                continue;
            }
            emulator["downloads"][os] = override_value.clone();
        }
    }
    manifest
}

pub fn current_os() -> &'static str {
    match env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    }
}

pub fn detect_emulators(root: &Path) -> Vec<Value> {
    let os = current_os();
    manifest()["emulators"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|emulator| {
            let install_dir = locate_emulator_install(root, emulator)?;
            let portable = emulator["portable_markers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|marker| install_dir.join(marker).exists());
            let update_policy = emulator["updates"]
                .get(os)
                .cloned()
                .unwrap_or_else(|| json!({"source": "unsupported"}));
            let save_paths: Vec<String> = emulator["save_paths"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|sub| install_dir.join(sub).to_string_lossy().into_owned())
                .collect();
            Some(json!({
                "id": emulator["id"],
                "name": emulator["name"],
                "path": install_dir.to_string_lossy(),
                "portable": portable,
                "update_policy": update_policy,
                "save_paths": save_paths
            }))
        })
        .collect()
}

/// Resolve which directory inside (or equal to) `root` is the install dir for
/// `emulator`. The lookup is more forgiving than a literal `root.join(name)`
/// existence check so we still match the real-world install folders that
/// upstream produces — versioned (`pcsx2-v1.7.5945-windows-x64-Qt`),
/// case-mismatched on Linux (`Xenia_Canary` vs the manifest's
/// `xenia-canary`), or the install dir the user pointed `--emulator-root`
/// directly at instead of its parent (`~/games/Dolphin-x86_64.AppImage`).
///
/// Resolution order, returning the first match:
///   1. `root.join(candidate)` for every literal `detect_paths` entry
///      (preserves the original exact-match behaviour and the related tests).
///   2. Any immediate child directory of `root` whose name matches a
///      `detect_paths` entry as a case-insensitive glob.
///   3. `root` itself when its basename matches a `detect_paths` glob, or
///      when it directly contains one of the manifest's `detect_executables`.
///   4. Any immediate child directory of `root` that contains one of the
///      manifest's `detect_executables` (last-resort fallback for fully
///      renamed install folders).
fn locate_emulator_install(root: &Path, emulator: &Value) -> Option<PathBuf> {
    let detect_paths: Vec<&str> = emulator["detect_paths"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let detect_execs: Vec<String> = emulator
        .get("detect_executables")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(|s| s.to_lowercase())
                .collect()
        })
        .unwrap_or_default();

    // 1. Exact-name match inside the root.
    for candidate in &detect_paths {
        let direct = root.join(candidate);
        if direct.exists() {
            return Some(direct);
        }
    }

    // Snapshot the immediate children of `root` once for the glob /
    // case-insensitive / executable-presence passes.
    let entries: Vec<(PathBuf, bool)> = fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            let path = entry.path();
            let is_dir = path.is_dir();
            (path, is_dir)
        })
        .collect();

    // 2. Glob / case-insensitive match against immediate child directories.
    for (path, is_dir) in &entries {
        if !*is_dir {
            continue;
        }
        let Some(name) = path.file_name() else {
            continue;
        };
        let name_str = name.to_string_lossy();
        if matches_any_detect_pattern(&name_str, &detect_paths) {
            return Some(path.clone());
        }
    }

    // 3. The configured root might be the install dir itself.
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !root_name.is_empty() && matches_any_detect_pattern(&root_name, &detect_paths) {
        return Some(root.to_path_buf());
    }
    if !detect_execs.is_empty() && dir_contains_any_executable(root, &detect_execs) {
        return Some(root.to_path_buf());
    }

    // 4. Executable fallback for immediate child directories.
    if !detect_execs.is_empty() {
        for (path, is_dir) in &entries {
            if !*is_dir {
                continue;
            }
            if dir_contains_any_executable(path, &detect_execs) {
                return Some(path.clone());
            }
        }
    }

    None
}

fn matches_any_detect_pattern(name: &str, patterns: &[&str]) -> bool {
    let lower_name = name.to_lowercase();
    patterns.iter().any(|pattern| {
        let lower_pattern = pattern.to_lowercase();
        if lower_pattern == lower_name {
            return true;
        }
        if lower_pattern.contains('*')
            || lower_pattern.contains('?')
            || lower_pattern.contains('[')
        {
            glob::Pattern::new(&lower_pattern)
                .map(|pat| pat.matches(&lower_name))
                .unwrap_or(false)
        } else {
            false
        }
    })
}

fn dir_contains_any_executable(dir: &Path, lowercased_executables: &[String]) -> bool {
    let Ok(read) = fs::read_dir(dir) else {
        return false;
    };
    for entry in read.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if lowercased_executables.iter().any(|exe| exe == &name) {
            return true;
        }
    }
    false
}

/// Create the per-emulator portable-mode marker file inside `install_dir` so
/// the next time the emulator launches it stores all save data, configuration,
/// and states under its own folder (instead of leaking to the user's home dir).
///
/// Each manifest entry declares which file or directory-marker to create via
/// `portable_marker_to_create`. To avoid clobbering device-specific emulator
/// configuration files (e.g. RPCS3's `config.yml`, which holds GPU backend
/// and controller bindings), the marker is *only* allowed to be:
///
///   * a file the emulator treats as a pure presence-marker (DuckStation
///     `portable.txt`, PCSX2 `portable.ini`, Xenia `portable.txt`, Dolphin
///     `portable.txt`); or
///   * a `*/.keep` placeholder inside a directory-shaped marker (RPCS3
///     `GuiConfigs/.keep`, Eden `user/.keep`); or
///   * an entry that does not collide with any path listed in the
///     emulator's own `sync_exclude` / `portable_markers` config-file set.
///
/// If the manifest's `portable_marker_to_create` would touch a real
/// configuration file, this function refuses and returns an error so the
/// caller can surface it to the user instead of silently rewriting their
/// emulator settings.
///
/// Idempotent: if the marker already exists this is a no-op so we do not
/// clobber a config the user may have hand-edited.
pub fn enable_portable_mode(emulator: &Value, install_dir: &Path) -> AppResult<Option<PathBuf>> {
    if !manifest()["policy"]["auto_enable_portable_mode"]
        .as_bool()
        .unwrap_or(true)
    {
        return Ok(None);
    }
    let Some(marker) = emulator["portable_marker_to_create"].as_str() else {
        return Ok(None);
    };
    if marker.is_empty() {
        return Ok(None);
    }

    // Refuse to (re)write any file that matches the emulator's own
    // device-local exclude patterns. This protects RPCS3's config.yml and
    // similar emulator settings from being clobbered by automated portable
    // setup.
    let normalized = marker.replace('\\', "/");
    let touches_config = emulator["sync_exclude"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|pattern| {
            glob::Pattern::new(pattern)
                .map(|pat| pat.matches(&normalized))
                .unwrap_or(false)
        });
    if touches_config {
        return Err(format!(
            "refusing to auto-create portable marker '{marker}': it overlaps the emulator's device-local config files"
        )
        .into());
    }

    let target = install_dir.join(marker);
    if target.exists() {
        return Ok(Some(target));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::File::create(&target)?;
    Ok(Some(target))
}

/// Information about the latest upstream release of a given emulator,
/// returned by `latest_release`. `version` is the tag name as the upstream
/// publishes it, `published_at` is the upstream timestamp, `download_url` is
/// the per-OS asset URL when one matches the conventional asset-name pattern.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LatestRelease {
    pub version: String,
    pub published_at: String,
    pub download_url: Option<String>,
    pub source_url: String,
}

/// Return the effective release source for `emulator` on `os`. When the
/// manifest declares a per-OS override under `release_source_overrides.{os}`
/// it takes precedence (this is how Dolphin pulls Windows builds from the
/// official dev website but Linux AppImages from the pkgforge mirror). When
/// no override is present the top-level `release_source` is used.
fn effective_release_source<'a>(emulator: &'a Value, os: &str) -> Option<&'a Value> {
    if let Some(override_for_os) = emulator
        .get("release_source_overrides")
        .and_then(|v| v.get(os))
        .filter(|v| v.is_object())
    {
        return Some(override_for_os);
    }
    emulator.get("release_source")
}

/// Discover the latest upstream release for an emulator.
///
/// Supports three release sources:
///   * `github_release` — uses the public GitHub API (`/repos/{owner}/{repo}/releases/latest`,
///     falling back to `/releases?per_page=1` when only prereleases exist).
///   * `gitea_release` — used by Eden Nightly (`https://git.eden-emu.dev`).
///     Hits the same `/api/v1/repos/{owner}/{repo}/releases?limit=1` shape
///     that Gitea has used since 1.x.
///   * `dolphin_dev_website` — scrapes `https://dolphin-emu.org/download/`
///     to grab the bleeding-edge "Development Versions" Windows build.
///     Dolphin does not publish dev builds via the GitHub release feed, so
///     this is the only way to keep Windows clients on the dev channel.
///
/// All emulators in `shared/emulators.json` are covered: DuckStation, PCSX2
/// Nightly, RPCS3 Nightly (binaries-win), Xenia Canary, xemu, Cemu,
/// RetroArch, Eden Nightly, and Dolphin Dev. The per-OS override map
/// (`release_source_overrides`) lets a single emulator pick a different
/// source for Windows vs. Linux — Dolphin uses this to stay on the dev
/// channel for both platforms.
pub fn latest_release(emulator: &Value) -> AppResult<LatestRelease> {
    let os = current_os();
    let source = effective_release_source(emulator, os)
        .ok_or("emulator manifest is missing release_source")?;
    latest_release_from_source(source, os)
}

/// In-memory TTL cache for `latest_release_from_source` results so a single
/// GUI listing doesn't make one upstream request per emulator on every poll.
/// Unauthenticated GitHub API is capped at 60 requests/hr per IP — without
/// caching, a few page reloads exhaust the quota and every emulator's
/// "latest version" silently becomes "unknown" (Eden was unaffected because
/// it uses a separate Gitea host with its own quota). Successful results are
/// cached for `RELEASE_CACHE_TTL_SECS`; failures aren't cached so transient
/// errors get retried immediately.
const RELEASE_CACHE_TTL_SECS: u64 = 600;

fn release_cache() -> &'static Mutex<HashMap<String, (u64, LatestRelease)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (u64, LatestRelease)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn release_cache_key(source: &Value, os: &str) -> String {
    // Stable, source-shape-aware cache key. Using the JSON form means any
    // additional source parameters automatically participate in the key.
    let kind = source["type"].as_str().unwrap_or("");
    let canonical = serde_json::to_string(source).unwrap_or_default();
    format!("{kind}|{os}|{canonical}")
}

fn latest_release_from_source(source: &Value, os: &str) -> AppResult<LatestRelease> {
    let key = release_cache_key(source, os);
    let now = unix_time();
    if let Ok(cache) = release_cache().lock()
        && let Some((fetched_at, cached)) = cache.get(&key)
        && now.saturating_sub(*fetched_at) < RELEASE_CACHE_TTL_SECS
    {
        return Ok(cached.clone());
    }
    let release = fetch_latest_release_uncached(source, os)?;
    if let Ok(mut cache) = release_cache().lock() {
        cache.insert(key, (now, release.clone()));
    }
    Ok(release)
}

fn fetch_latest_release_uncached(source: &Value, os: &str) -> AppResult<LatestRelease> {
    let kind = source["type"].as_str().unwrap_or("");
    match kind {
        "github_release" => {
            let repo = source["repo"]
                .as_str()
                .ok_or("github_release.repo is required")?;
            let prerelease = source["prerelease"].as_bool().unwrap_or(false);
            let url = if prerelease {
                format!("https://api.github.com/repos/{repo}/releases?per_page=1")
            } else {
                format!("https://api.github.com/repos/{repo}/releases/latest")
            };
            let mut response = ureq::get(&url)
                .header("User-Agent", "crash-crafts-game-sync")
                .header("Accept", "application/vnd.github+json")
                .call()?
                .into_body();
            let body: Value = response.read_json()?;
            let release = if prerelease {
                body.as_array()
                    .and_then(|arr| arr.first().cloned())
                    .ok_or("no GitHub releases returned")?
            } else {
                body
            };
            Ok(LatestRelease {
                version: release["tag_name"].as_str().unwrap_or("").to_owned(),
                published_at: release["published_at"].as_str().unwrap_or("").to_owned(),
                download_url: pick_asset(&release["assets"], os),
                source_url: release["html_url"].as_str().unwrap_or(&url).to_owned(),
            })
        }
        "gitea_release" => {
            let base = source["base"]
                .as_str()
                .ok_or("gitea_release.base is required")?
                .trim_end_matches('/');
            let repo = source["repo"]
                .as_str()
                .ok_or("gitea_release.repo is required")?;
            let url = format!("{base}/api/v1/repos/{repo}/releases?limit=1");
            let mut response = ureq::get(&url)
                .header("User-Agent", "crash-crafts-game-sync")
                .header("Accept", "application/json")
                .call()?
                .into_body();
            let body: Value = response.read_json()?;
            let release = body
                .as_array()
                .and_then(|arr| arr.first().cloned())
                .ok_or("no Gitea releases returned")?;
            Ok(LatestRelease {
                version: release["tag_name"].as_str().unwrap_or("").to_owned(),
                published_at: release["published_at"].as_str().unwrap_or("").to_owned(),
                download_url: pick_asset(&release["assets"], os),
                source_url: release["html_url"].as_str().unwrap_or(&url).to_owned(),
            })
        }
        "dolphin_dev_website" => fetch_dolphin_dev_release(os),
        other => Err(format!("unsupported release source type: {other}").into()),
    }
}

/// Re-fetch the upstream release assets array for a specific OS so callers
/// can run `pick_asset` against an OS other than the host's. Used by the
/// admin "apply update" endpoint to publish both the Windows and Linux
/// bundles from a single button click. Honors `release_source_overrides`
/// so emulators with different feeds per OS (e.g. Dolphin) work correctly.
fn release_assets_for_os(emulator: &Value, os: &str) -> AppResult<Value> {
    let source = effective_release_source(emulator, os)
        .ok_or("emulator manifest is missing release_source")?;
    let kind = source["type"].as_str().unwrap_or("");
    match kind {
        "github_release" => {
            let repo = source["repo"]
                .as_str()
                .ok_or("github_release.repo is required")?;
            let prerelease = source["prerelease"].as_bool().unwrap_or(false);
            let url = if prerelease {
                format!("https://api.github.com/repos/{repo}/releases?per_page=1")
            } else {
                format!("https://api.github.com/repos/{repo}/releases/latest")
            };
            let mut response = ureq::get(&url)
                .header("User-Agent", "crash-crafts-game-sync")
                .header("Accept", "application/vnd.github+json")
                .call()?
                .into_body();
            let body: Value = response.read_json()?;
            let release = if prerelease {
                body.as_array()
                    .and_then(|arr| arr.first().cloned())
                    .ok_or("no GitHub releases returned")?
            } else {
                body
            };
            Ok(release["assets"].clone())
        }
        "gitea_release" => {
            let base = source["base"]
                .as_str()
                .ok_or("gitea_release.base is required")?
                .trim_end_matches('/');
            let repo = source["repo"]
                .as_str()
                .ok_or("gitea_release.repo is required")?;
            let url = format!("{base}/api/v1/repos/{repo}/releases?limit=1");
            let mut response = ureq::get(&url)
                .header("User-Agent", "crash-crafts-game-sync")
                .header("Accept", "application/json")
                .call()?
                .into_body();
            let body: Value = response.read_json()?;
            let release = body
                .as_array()
                .and_then(|arr| arr.first().cloned())
                .ok_or("no Gitea releases returned")?;
            Ok(release["assets"].clone())
        }
        "dolphin_dev_website" => {
            // Synthesize a single-asset list so `pick_asset` can match the
            // Windows download by `.7z` substring just like a GitHub release.
            let release = fetch_dolphin_dev_release(os)?;
            let url = release.download_url.unwrap_or_default();
            let name = url.rsplit('/').next().unwrap_or("dolphin-dev").to_owned();
            Ok(json!([{ "name": name, "browser_download_url": url }]))
        }
        other => Err(format!("unsupported release source type: {other}").into()),
    }
}

/// Scrape `https://dolphin-emu.org/download/` for the latest
/// "Development Versions" build. Dolphin does not publish a JSON feed for
/// dev builds, so we parse the HTML for the first `dl.dolphin-emu.org`
/// download link of the appropriate type and the dev version number that
/// labels its row.
fn fetch_dolphin_dev_release(os: &str) -> AppResult<LatestRelease> {
    let page_url = "https://dolphin-emu.org/download/";
    let mut response = ureq::get(page_url)
        .header("User-Agent", "crash-crafts-game-sync")
        .header("Accept", "text/html")
        .call()?
        .into_body();
    let html = response.read_to_string()?;
    let download_url = pick_dolphin_dev_url(&html, os);
    let version = parse_dolphin_dev_version(&html).unwrap_or_default();
    Ok(LatestRelease {
        version,
        published_at: String::new(),
        download_url,
        source_url: page_url.to_owned(),
    })
}

/// Find the first `dl.dolphin-emu.org` build URL on the Dolphin downloads
/// page that matches the requested OS. Windows uses `.7z`, Linux uses
/// AppImages (Dolphin does not currently host Linux AppImages, so this
/// returns `None` and callers fall back to the per-OS override).
fn pick_dolphin_dev_url(html: &str, os: &str) -> Option<String> {
    // Walk all https URLs that look like a build artifact on dl.dolphin-emu.org.
    let needle = "https://dl.dolphin-emu.org/builds/";
    let mut search = html;
    while let Some(idx) = search.find(needle) {
        let tail = &search[idx..];
        let end = tail.find(['"', '\'', ' ', '<', '>']).unwrap_or(tail.len());
        let url = &tail[..end];
        let lower = url.to_lowercase();
        let matches = match os {
            "windows" => lower.ends_with(".7z") && lower.contains("x64"),
            "linux" => lower.ends_with(".appimage"),
            "macos" => lower.ends_with(".dmg"),
            _ => false,
        };
        if matches {
            return Some(url.to_owned());
        }
        search = &tail[end..];
    }
    None
}

/// Pull the dev build version (e.g. `2603`) out of the downloads page so
/// the GUI can show it as `latest_version`.
fn parse_dolphin_dev_version(html: &str) -> Option<String> {
    // Dev rows label the build like `dolphin-master-2603-x64.7z` — extract the
    // version segment between `dolphin-master-` and the next `-`.
    let marker = "dolphin-master-";
    let after = html.find(marker).map(|i| &html[i + marker.len()..])?;
    let end = after.find(['-', '.', '"', '<'])?;
    let version = &after[..end];
    if version.is_empty() {
        None
    } else {
        Some(version.to_owned())
    }
}

fn pick_asset(assets: &Value, os: &str) -> Option<String> {
    let needles: &[&str] = if os == "windows" {
        &[
            "windows",
            "win64",
            "win-x64",
            "win_x64",
            ".exe",
            ".7z",
            "x86_64-pc-windows",
        ]
    } else {
        &[
            "linux",
            ".AppImage",
            ".appimage",
            "x86_64-linux",
            "ubuntu",
            "x86_64-unknown-linux",
        ]
    };
    let assets = assets.as_array()?;
    for asset in assets {
        let name = asset["name"].as_str().unwrap_or("").to_lowercase();
        if needles
            .iter()
            .any(|needle| name.contains(&needle.to_lowercase()))
            && let Some(url) = asset["browser_download_url"].as_str()
        {
            return Some(url.to_owned());
        }
    }
    None
}

pub fn should_sync(relative_path: &str, emulator: &Value) -> bool {
    use glob::Pattern;
    let normalized = relative_path.replace('\\', "/");
    let matches = |key: &str| {
        emulator[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|pattern| Pattern::new(pattern).ok())
            .any(|pattern| pattern.matches(&normalized))
    };
    matches("sync_include") && !matches("sync_exclude")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DesktopConfig {
    pub server_url: String,
    pub auth_token: String,
    pub rom_roots: Vec<String>,
    pub emulator_roots: Vec<String>,
    pub sync_roots: Vec<SyncRoot>,
    pub srm: SrmConfig,
    pub service: ServiceConfig,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SyncRoot {
    pub emulator_id: String,
    pub path: String,
    #[serde(default)]
    pub emulator_executable: String,
    pub remote_prefix: String,
    pub pull_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SrmConfig {
    pub install: bool,
    pub roms_directory: String,
    pub steam_directory: String,
    pub parsers_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServiceConfig {
    pub install_on_setup: bool,
    pub windows_service_name: String,
    pub linux_systemd_user_unit: String,
    pub steam_deck_decky_plugin: String,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            server_url: "https://sync.example.com".to_owned(),
            auth_token: String::new(),
            rom_roots: Vec::new(),
            emulator_roots: Vec::new(),
            sync_roots: Vec::new(),
            srm: SrmConfig {
                install: true,
                roms_directory: String::new(),
                steam_directory: String::new(),
                parsers_path: "steam-rom-manager/parsers/crash-crafts-game-sync.json".to_owned(),
            },
            service: ServiceConfig {
                install_on_setup: true,
                windows_service_name: "CrashCraftsGameSync".to_owned(),
                linux_systemd_user_unit: "crash-crafts-game-sync.service".to_owned(),
                steam_deck_decky_plugin: "crash-crafts-game-sync-decky".to_owned(),
            },
            device_id: String::new(),
            device_name: String::new(),
        }
    }
}

pub fn default_desktop_config_path() -> AppResult<PathBuf> {
    if cfg!(windows) {
        let base = env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("USERPROFILE")
                    .map(|home| PathBuf::from(home).join("AppData").join("Roaming"))
            })
            .ok_or("APPDATA or USERPROFILE is required to choose a desktop config path")?;
        Ok(base
            .join("CrashCrafts")
            .join("GameSync")
            .join("desktop-config.json"))
    } else {
        let base = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok_or("XDG_CONFIG_HOME or HOME is required to choose a desktop config path")?;
        Ok(base
            .join("crash-crafts-game-sync")
            .join("desktop-config.json"))
    }
}

pub fn read_desktop_config(path: &Path) -> AppResult<DesktopConfig> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn write_desktop_config(path: &Path, config: &DesktopConfig) -> AppResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        secure_create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    secure_file(path, &file)?;
    file.write_all(&serde_json::to_vec_pretty(config)?)?;
    Ok(())
}

pub fn emulator_by_id(id: &str) -> Option<Value> {
    manifest()["emulators"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|emulator| emulator["id"].as_str() == Some(id))
        .cloned()
}

pub fn collect_sync_files(root: &Path, emulator: &Value) -> AppResult<Vec<PathBuf>> {
    fn visit(
        base: &Path,
        path: &Path,
        emulator: &Value,
        files: &mut Vec<PathBuf>,
    ) -> AppResult<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit(base, &path, emulator, files)?;
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(base)?
                    .to_string_lossy()
                    .replace('\\', "/");
                if should_sync(&relative, emulator) {
                    files.push(path);
                }
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    if root.exists() {
        visit(root, root, emulator, &mut files)?;
    }
    files.sort();
    Ok(files)
}

pub fn remote_file_path(prefix: &str, relative: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        relative.trim_start_matches('/').to_owned()
    } else {
        format!("{prefix}/{}", relative.trim_start_matches('/'))
    }
}

pub fn upload_sync_file(
    server: &str,
    token: &str,
    remote_path: &str,
    path: &Path,
) -> AppResult<Value> {
    let url = format!(
        "{}/api/files/{}",
        server.trim_end_matches('/'),
        urlencoding::encode(remote_path)
    );
    let mut response = ureq::put(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send(fs::read(path)?)?
        .into_body();
    Ok(response.read_json()?)
}

pub fn pull_sync_file(
    server: &str,
    token: &str,
    remote_path: &str,
    destination: &Path,
) -> AppResult<()> {
    let url = format!(
        "{}/api/files/{}",
        server.trim_end_matches('/'),
        urlencoding::encode(remote_path)
    );
    let mut response = ureq::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .call()?
        .into_body();
    let bytes = response.read_to_vec()?;
    if let Some(parent) = destination.parent() {
        secure_create_dir_all(parent)?;
    }
    let mut file = fs::File::create(destination)?;
    secure_file(destination, &file)?;
    file.write_all(&bytes)?;
    Ok(())
}

pub fn run_desktop_sync_once(config: &DesktopConfig) -> AppResult<Value> {
    let server = validate_server_url(&config.server_url)?
        .trim_end_matches('/')
        .to_owned();
    if config.auth_token.trim().is_empty() {
        return Err("auth_token is required for desktop daemon sync".into());
    }

    let mut pushed = Vec::new();
    let mut pulled = Vec::new();
    let mut errors = Vec::new();
    for sync_root in &config.sync_roots {
        let Some(emulator) = emulator_by_id(&sync_root.emulator_id) else {
            errors.push(json!({"emulator_id": sync_root.emulator_id, "error": "unknown emulator"}));
            continue;
        };
        let root = PathBuf::from(&sync_root.path);
        for file in collect_sync_files(&root, &emulator)? {
            let relative = file
                .strip_prefix(&root)?
                .to_string_lossy()
                .replace('\\', "/");
            let remote = remote_file_path(&sync_root.remote_prefix, &relative);
            match upload_sync_file(&server, &config.auth_token, &remote, &file) {
                Ok(result) => {
                    pushed.push(json!({"local": file, "remote": remote, "result": result}))
                }
                Err(error) => errors
                    .push(json!({"local": file, "remote": remote, "error": error.to_string()})),
            }
        }
        for pull_path in &sync_root.pull_paths {
            let safe = match safe_relative_path(pull_path) {
                Ok(path) => path,
                Err(error) => {
                    errors.push(json!({"remote": pull_path, "error": error.to_string()}));
                    continue;
                }
            };
            let destination = root.join(&safe);
            let remote = remote_file_path(&sync_root.remote_prefix, pull_path);
            match pull_sync_file(&server, &config.auth_token, &remote, &destination) {
                Ok(()) => pulled.push(json!({"local": destination, "remote": remote})),
                Err(error) => errors.push(
                    json!({"local": destination, "remote": remote, "error": error.to_string()}),
                ),
            }
        }
    }

    Ok(json!({"pushed": pushed, "pulled": pulled, "errors": errors}))
}

/// Build the JSON body for a `/api/devices/heartbeat` request describing the
/// current device, its configured sync roots, and the result of the last sync
/// pass.
pub fn heartbeat_payload(config: &DesktopConfig, last_sync: &Value) -> Value {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|s| s.trim().to_owned())
        })
        .unwrap_or_default();
    let pushed = last_sync["pushed"].as_array().map_or(0, Vec::len);
    let pulled = last_sync["pulled"].as_array().map_or(0, Vec::len);
    let errors = last_sync["errors"].as_array().map_or(0, Vec::len);
    let state = if errors > 0 { "error" } else { "idle" };
    let last_error = last_sync["errors"]
        .as_array()
        .and_then(|errs| errs.first())
        .and_then(|err| err["error"].as_str())
        .unwrap_or("")
        .to_owned();
    json!({
        "device_id": config.device_id,
        "device_name": config.device_name,
        "hostname": hostname,
        "os": current_os(),
        "rom_roots": config.rom_roots,
        "emulator_roots": config.emulator_roots,
        "state": state,
        "files_pushed": pushed,
        "files_pulled": pulled,
        "last_sync": {
            "pushed": pushed,
            "pulled": pulled,
            "errors": errors,
            "timestamp": unix_time()
        },
        "last_error": last_error
    })
}

/// Send a heartbeat to the configured Docker server, returning the response
/// body. Errors are returned to the caller so the daemon can keep going even
/// when the server is briefly unavailable.
pub fn send_heartbeat(config: &DesktopConfig, last_sync: &Value) -> AppResult<Value> {
    let server = validate_server_url(&config.server_url)?
        .trim_end_matches('/')
        .to_owned();
    if config.auth_token.trim().is_empty() {
        return Err("auth_token is required to send heartbeat".into());
    }
    let payload = heartbeat_payload(config, last_sync);
    let mut response = ureq::post(&format!("{server}/api/devices/heartbeat"))
        .header("Authorization", &format!("Bearer {}", config.auth_token))
        .send_json(payload)?
        .into_body();
    Ok(response.read_json()?)
}

pub fn srm_parser_presets(config: &DesktopConfig) -> Value {
    let parsers = config
        .sync_roots
        .iter()
        .filter_map(|sync_root| {
            let emulator = emulator_by_id(&sync_root.emulator_id)?;
            Some(json!({
                "parserType": "Glob",
                "configTitle": format!("Crash Crafts - {}", emulator["name"].as_str().unwrap_or(&sync_root.emulator_id)),
                "steamCategory": format!("Crash Crafts/{}", emulator["name"].as_str().unwrap_or(&sync_root.emulator_id)),
                "romDirectory": if config.srm.roms_directory.is_empty() { &sync_root.path } else { &config.srm.roms_directory },
                "executable": sync_root.emulator_executable,
                "requiresExecutableSelection": sync_root.emulator_executable.is_empty(),
                "startInDirectory": sync_root.path,
                "titleModifier": "${fuzzyTitle}",
                "imageProviders": ["SteamGridDB"],
                "excludedSyncPatterns": emulator["sync_exclude"].clone()
            }))
        })
        .collect::<Vec<_>>();
    json!({
        "generated_by": APP_NAME,
        "steam_directory": config.srm.steam_directory,
        "parsers": parsers
    })
}

pub fn write_srm_parsers(config: &DesktopConfig) -> AppResult<PathBuf> {
    if config.srm.parsers_path.trim().is_empty() {
        return Err("srm.parsers_path is required".into());
    }
    let path = PathBuf::from(&config.srm.parsers_path);
    if let Some(parent) = path.parent() {
        secure_create_dir_all(parent)?;
    }
    let mut file = fs::File::create(&path)?;
    secure_file(&path, &file)?;
    file.write_all(&serde_json::to_vec_pretty(&srm_parser_presets(config))?)?;
    Ok(path)
}

/// Description of where to download an emulator/SRM portable build for the
/// current OS. Built from the optional `downloads.<os>` entry of an emulator
/// manifest entry; returns `None` when the manifest doesn't ship a download
/// URL for this OS (the GUI then falls back to opening the homepage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadSpec {
    pub url: String,
    pub sha256: Option<String>,
    pub archive: String,
    pub strip_components: usize,
}

pub fn emulator_download_spec(emulator: &Value, os: &str) -> Option<DownloadSpec> {
    let entry = emulator["downloads"][os].as_object()?;
    let url = entry.get("url")?.as_str()?.to_owned();
    if url.trim().is_empty() {
        return None;
    }
    Some(DownloadSpec {
        url,
        sha256: entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        archive: entry
            .get("archive")
            .and_then(|v| v.as_str())
            .unwrap_or("zip")
            .to_owned(),
        strip_components: entry
            .get("strip_components")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
    })
}

/// True when an emulator either ships a static `downloads.<os>.url` in the
/// manifest or has a `release_source` we can resolve at install time. This
/// is what the GUI listing uses to enable/disable the "Install" button —
/// keeping it cheap (no network) while still reporting installability for
/// every emulator with a configured release feed (Windows + Linux + Docker).
pub fn emulator_installable(emulator: &Value, os: &str) -> bool {
    if emulator_download_spec(emulator, os).is_some() {
        return true;
    }
    effective_release_source(emulator, os).is_some()
}

/// Resolve the actual download spec to use for an install, preferring the
/// admin-curated static `downloads.<os>` entry and falling back to the live
/// `release_source` feed when the static URL is empty. This is what makes
/// every emulator with a known release feed installable without the admin
/// having to paste URLs into the manifest.
fn resolve_install_spec(emulator: &Value, os: &str) -> AppResult<DownloadSpec> {
    if let Some(spec) = emulator_download_spec(emulator, os) {
        return Ok(spec);
    }
    let archive_default = emulator["downloads"][os]["archive"]
        .as_str()
        .unwrap_or("zip")
        .to_owned();
    let release = latest_release_for_os(emulator, os)?;
    let url = release.download_url.ok_or_else(|| {
        format!(
            "no portable download URL for {} on {os}; the upstream release feed had no matching asset",
            emulator["id"].as_str().unwrap_or("emulator")
        )
    })?;
    Ok(DownloadSpec {
        url,
        sha256: None,
        archive: archive_default,
        strip_components: 0,
    })
}

fn latest_release_for_os(emulator: &Value, os: &str) -> AppResult<LatestRelease> {
    let source = effective_release_source(emulator, os)
        .ok_or("emulator manifest is missing release_source")?;
    latest_release_from_source(source, os)
}

/// Download a portable emulator build (or any other file) over HTTPS, write it
/// to `destination`, and verify the SHA-256 checksum when one was supplied.
/// Returns the number of bytes written.
///
/// This is the primitive used by the GUI's "Install" buttons. Extraction of
/// archives is intentionally left to the platform's built-in tooling so we do
/// not pull a zip/tar dependency into the headless server build.
pub fn download_with_checksum(spec: &DownloadSpec, destination: &Path) -> AppResult<u64> {
    if !spec.url.starts_with("https://") {
        return Err("emulator download URL must use HTTPS".into());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut response = ureq::get(&spec.url).call()?.into_body();
    let bytes = response.read_to_vec()?;
    if let Some(expected) = &spec.sha256 {
        use sha2::Digest;
        let actual = hex_lower(&sha2::Sha256::digest(&bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "checksum mismatch for {}: expected {expected}, got {actual}",
                spec.url
            )
            .into());
        }
    }
    let mut file = fs::File::create(destination)?;
    secure_file(destination, &file)?;
    file.write_all(&bytes)?;
    Ok(bytes.len() as u64)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Install or update an emulator into the user's configured emulator root,
/// preferring a server-curated portable bundle and falling back to the
/// upstream URL only when no bundle is available.
///
/// The flow:
///
///   1. Ask the Docker server for `GET /api/emulator-bundle/{id}/{os}`. The
///      server returns a single zip whose top level is the portable
///      directory the admin tested (RPCS3 with its `GuiConfigs/`, Cemu
///      with `settings.xml`, etc.). Because the admin already enabled
///      portable mode on the bundle, the desktop never has to invent
///      portable markers — there is nothing to break per-device.
///   2. Extract the bundle into `{emulator_root}/{id}`.
///        * On a *first* install (no `.crash-crafts-managed.json` marker
///          present) every file is written, including the bundle's
///          working baseline config so the emulator launches with sane
///          defaults.
///        * On a subsequent install / update, files matching the
///          emulator's `sync_exclude` patterns (controller bindings,
///          RPCS3 `config.yml`, Cemu `settings.xml`, RetroArch
///          `retroarch.cfg`, etc.) are *skipped* so the user's
///          per-device settings survive the update.
///   3. If the server has no bundle for this emulator/OS, fall back to
///      the upstream `downloads.{os}.url` from the live manifest. This
///      preserves the original "download portable build directly from
///      the vendor" path for setups where the admin has not curated a
///      bundle yet.
///
/// Returns the install directory on success.
pub fn install_emulator(config: &DesktopConfig, emulator_id: &str) -> AppResult<PathBuf> {
    let manifest = fetch_live_manifest(config).unwrap_or_else(|_| manifest());
    let emulator = manifest["emulators"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|em| em["id"].as_str() == Some(emulator_id))
        .cloned()
        .ok_or_else(|| format!("unknown emulator id: {emulator_id}"))?;
    let root = config
        .emulator_roots
        .first()
        .cloned()
        .ok_or("emulator_roots is empty; pick an emulator install directory first")?;
    let dir = PathBuf::from(root).join(emulator_id);
    fs::create_dir_all(&dir)?;

    // Preferred path: server-curated portable bundle.
    match download_emulator_bundle(config, emulator_id) {
        Ok(bundle_bytes) => {
            let is_update = managed_marker_path(&dir).exists();
            extract_bundle_into(&bundle_bytes, &dir, &emulator, is_update)?;
            write_managed_marker(&dir, &emulator)?;
            return Ok(dir);
        }
        Err(BundleError::NotFound) => {
            // Fall through to the upstream URL fallback.
        }
        Err(BundleError::Other(error)) => {
            return Err(error);
        }
    }

    // Fallback: upstream vendor URL from the manifest, falling back to the
    // live release feed (Windows + Linux + Docker all benefit so admins don't
    // need to keep static URLs in sync with every dev/nightly release).
    let spec = resolve_install_spec(&emulator, current_os()).map_err(|err| {
        format!(
            "no portable download URL for {emulator_id} on {} and the server has no bundle for it: {err}",
            current_os()
        )
    })?;
    let filename = spec
        .url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("emulator.bin");
    let destination = dir.join(filename);
    download_with_checksum(&spec, &destination)?;
    Ok(dir)
}

enum BundleError {
    NotFound,
    Other(Box<dyn std::error::Error + Send + Sync>),
}

fn managed_marker_path(install_dir: &Path) -> PathBuf {
    install_dir.join(".crash-crafts-managed.json")
}

fn write_managed_marker(install_dir: &Path, emulator: &Value) -> AppResult<()> {
    let payload = json!({
        "emulator_id": emulator["id"],
        "managed_by": APP_NAME,
        "installed_at": unix_time(),
        "schema_version": 1
    });
    let path = managed_marker_path(install_dir);
    let serialized = serde_json::to_vec_pretty(&payload)?;
    fs::write(path, serialized)?;
    Ok(())
}

fn download_emulator_bundle(
    config: &DesktopConfig,
    emulator_id: &str,
) -> Result<Vec<u8>, BundleError> {
    let server = match validate_server_url(&config.server_url) {
        Ok(url) => url.trim_end_matches('/').to_owned(),
        Err(error) => return Err(BundleError::Other(error)),
    };
    let url = format!(
        "{server}/api/emulator-bundle/{}/{}",
        urlencoding::encode(emulator_id),
        current_os()
    );
    let mut request = ureq::get(&url);
    if !config.auth_token.is_empty() {
        request = request.header("Authorization", &format!("Bearer {}", config.auth_token));
    }
    match request.call() {
        Ok(response) => {
            let mut body = response.into_body();
            match body.read_to_vec() {
                Ok(bytes) => Ok(bytes),
                Err(error) => Err(BundleError::Other(error.into())),
            }
        }
        Err(ureq::Error::StatusCode(404)) => Err(BundleError::NotFound),
        Err(error) => Err(BundleError::Other(error.into())),
    }
}

/// Extract `bundle_bytes` (a zip archive whose entries are relative paths
/// inside the emulator's portable folder) into `install_dir`. When
/// `is_update` is true, files whose relative path matches any of the
/// emulator's `sync_exclude` glob patterns are skipped so the user's
/// per-device emulator config (controller bindings, GPU backend, RPCS3
/// `config.yml`, Cemu `settings.xml`, RetroArch `retroarch.cfg`, etc.) is
/// preserved across updates.
///
/// Hardened against zip-slip: every entry's resolved path must remain
/// inside `install_dir`.
pub fn extract_bundle_into(
    bundle_bytes: &[u8],
    install_dir: &Path,
    emulator: &Value,
    is_update: bool,
) -> AppResult<Vec<String>> {
    use std::io::Cursor;
    let exclude_patterns: Vec<glob::Pattern> = emulator["sync_exclude"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|raw| glob::Pattern::new(raw).ok())
        .collect();
    let mut archive = zip::ZipArchive::new(Cursor::new(bundle_bytes)).map_err(
        |error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("invalid emulator bundle: {error}").into()
        },
    )?;
    let install_canonical = install_dir
        .canonicalize()
        .unwrap_or_else(|_| install_dir.to_path_buf());
    let mut skipped: Vec<String> = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(
            |error| -> Box<dyn std::error::Error + Send + Sync> {
                format!("bundle entry {index}: {error}").into()
            },
        )?;
        // `enclosed_name` returns None for absolute or `..`-escaping paths.
        let enclosed = match entry.enclosed_name() {
            Some(name) => name,
            None => {
                return Err(format!("bundle contains unsafe path: {}", entry.name()).into());
            }
        };
        let relative_str = enclosed.to_string_lossy().replace('\\', "/");
        let target = install_dir.join(&enclosed);
        // Defence-in-depth zip-slip check.
        if let Some(parent) = target.parent()
            && let Ok(parent_canonical) = parent.canonicalize()
            && !parent_canonical.starts_with(&install_canonical)
        {
            return Err(format!("bundle entry would escape install dir: {relative_str}").into());
        }
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if is_update
            && exclude_patterns
                .iter()
                .any(|pattern| pattern.matches(&relative_str))
        {
            skipped.push(relative_str);
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut writer = fs::File::create(&target)?;
        secure_file(&target, &writer)?;
        std::io::copy(&mut entry, &mut writer)?;
    }
    Ok(skipped)
}

fn fetch_live_manifest(config: &DesktopConfig) -> AppResult<Value> {
    let server = validate_server_url(&config.server_url)?
        .trim_end_matches('/')
        .to_owned();
    let mut response = ureq::get(&format!("{server}/api/emulators"))
        .header("Authorization", &format!("Bearer {}", config.auth_token))
        .call()?
        .into_body();
    Ok(response.read_json()?)
}

/// Install (download) the Steam ROM Manager portable build into the SRM
/// directory. Resolution order:
///
///   1. Static `srm_download.{os}.url` from the manifest (lets an admin
///      pin a specific portable build with an SHA-256).
///   2. The `srm_download.release_source` feed (defaults to the
///      `SteamGridDB/steam-rom-manager` GitHub releases). This is what
///      keeps Windows + Linux clients on the latest published portable
///      build without anyone editing the manifest.
///
/// Returns the path on disk for the downloaded archive.
pub fn install_srm(config: &DesktopConfig) -> AppResult<PathBuf> {
    let manifest = manifest();
    let srm = manifest["srm_download"].as_object().ok_or(
        "manifest has no srm_download entry; configure shared/emulators.json with an srm_download URL",
    )?;
    let os = current_os();
    let static_entry = srm.get(os).cloned().unwrap_or(Value::Null);
    let static_url = static_entry["url"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let static_sha = static_entry["sha256"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let archive = static_entry["archive"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("zip")
        .to_owned();

    let (url, sha256) = if let Some(url) = static_url {
        (url, static_sha)
    } else {
        // Synthesize an emulator-shaped value so we can reuse the standard
        // release-source resolver (with per-OS overrides if any future
        // platform needs them).
        let mut shim = json!({});
        if let Some(rs) = srm.get("release_source") {
            shim["release_source"] = rs.clone();
        }
        if let Some(rso) = srm.get("release_source_overrides") {
            shim["release_source_overrides"] = rso.clone();
        }
        if effective_release_source(&shim, os).is_none() {
            return Err(format!("no SRM portable download URL for {os}").into());
        }
        let release = latest_release_for_os(&shim, os)?;
        let url = release.download_url.ok_or_else(|| {
            format!(
                "no SRM portable download URL for {os}; upstream release feed had no matching asset"
            )
        })?;
        (url, None)
    };

    let spec = DownloadSpec {
        url,
        sha256,
        archive,
        strip_components: 0,
    };
    let dir = if config.srm.steam_directory.trim().is_empty() {
        PathBuf::from(
            config
                .emulator_roots
                .first()
                .cloned()
                .ok_or("emulator_roots is empty; pick an install directory first")?,
        )
        .join("steam-rom-manager")
    } else {
        PathBuf::from(&config.srm.steam_directory).join("steam-rom-manager")
    };
    fs::create_dir_all(&dir)?;
    let filename = spec
        .url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("srm.bin");
    let destination = dir.join(filename);
    download_with_checksum(&spec, &destination)?;
    Ok(destination)
}

#[derive(Clone)]
struct JsonStore {
    path: PathBuf,
}

/// Wrap an `io::Result` so that the resulting error names the path and
/// operation that failed. Without this, errors bubbling up through
/// `AppResult` are rendered as bare strings like `Permission denied (os error
/// 13)` with no indication of which file or directory the process was trying
/// to touch — an especially common source of confusion when the Docker
/// container fails to start because the `/data` volume is owned by a
/// different UID than the runtime user (uid `10001`).
fn io_context<T>(op: &str, path: &Path, result: std::io::Result<T>) -> AppResult<T> {
    result.map_err(|err| -> Box<dyn std::error::Error + Send + Sync> {
        format!("failed to {op} {}: {err}", path.display()).into()
    })
}

impl JsonStore {
    fn new(path: PathBuf) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            io_context("create directory", parent, fs::create_dir_all(parent))?;
        }
        let store = Self { path };
        if !store.path.exists() {
            store.write(&json!({
                "setup_complete": false,
                "users": {},
                "invites": {},
                "sessions": {},
                "logs": [],
                "settings": {
                    "app_name": APP_NAME,
                    "smtp": {},
                    "branding": {}
                }
            }))?;
        }
        Ok(store)
    }

    fn read(&self) -> AppResult<Value> {
        let bytes = io_context("read", &self.path, fs::read(&self.path))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write(&self, data: &Value) -> AppResult<()> {
        if let Some(parent) = self.path.parent() {
            secure_create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut file = io_context("create", &tmp, fs::File::create(&tmp))?;
        secure_file(&tmp, &file)?;
        io_context(
            "write",
            &tmp,
            file.write_all(&serde_json::to_vec_pretty(data)?),
        )?;
        io_context("rename", &self.path, fs::rename(&tmp, &self.path))?;
        Ok(())
    }
}

fn secure_create_dir_all(path: &Path) -> AppResult<()> {
    io_context("create directory", path, fs::create_dir_all(path))?;
    secure_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_dir(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    io_context(
        "set permissions on",
        path,
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)),
    )
}

#[cfg(not(unix))]
fn secure_dir(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path, file: &fs::File) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    io_context(
        "set permissions on",
        path,
        file.set_permissions(fs::Permissions::from_mode(0o600)),
    )
}

#[cfg(not(unix))]
fn secure_file(_path: &Path, _file: &fs::File) -> AppResult<()> {
    Ok(())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    rand::random()
}

fn hash_password(password: &str, salt: Option<&str>) -> String {
    let salt_bytes = salt
        .and_then(|salt| general_purpose::STANDARD.decode(salt).ok())
        .unwrap_or_else(|| random_bytes::<16>().to_vec());
    let mut digest = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        &salt_bytes,
        PASSWORD_ITERATIONS,
        &mut digest,
    );
    format!(
        "pbkdf2_sha256${}${}${}",
        PASSWORD_ITERATIONS,
        general_purpose::STANDARD.encode(salt_bytes),
        general_purpose::STANDARD.encode(digest)
    )
}

fn verify_password(password: &str, encoded: &str) -> bool {
    let parts: Vec<_> = encoded.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let Ok(iterations) = parts[1].parse::<u32>() else {
        return false;
    };
    let Ok(salt) = general_purpose::STANDARD.decode(parts[2]) else {
        return false;
    };
    let Ok(expected) = general_purpose::STANDARD.decode(parts[3]) else {
        return false;
    };
    let mut digest = vec![0_u8; expected.len()];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut digest);
    digest == expected
}

fn new_totp_secret() -> String {
    BASE32_NOPAD.encode(&random_bytes::<20>())
}

fn totp(secret: &str, interval: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret.to_uppercase().as_bytes()).ok()?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&interval.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) % 1_000_000;
    Some(format!("{code:06}"))
}

fn verify_totp(secret: &str, code: &str, now: Option<u64>, window: i64) -> bool {
    if code.is_empty() || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let current = now.unwrap_or_else(unix_time) / 30;
    (-window..=window).any(|offset| {
        let interval = current as i64 + offset;
        interval >= 0 && totp(secret, interval as u64).as_deref() == Some(code)
    })
}

fn otpauth_uri(email: &str, secret: &str) -> String {
    let issuer = urlencoding::encode(APP_NAME);
    let label_text = format!("{APP_NAME}:{email}");
    let label = urlencoding::encode(&label_text);
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

/// Render the given `otpauth://` URI as a scannable QR code, encoded as a
/// `data:image/png;base64,...` URL. Returned alongside `otpauth_uri` from
/// the setup and invite-completion endpoints so the Web UI can show a QR code
/// the admin can scan with their authenticator app — previously only the raw
/// URI was returned and no QR code was rendered on the setup screen.
///
/// A raster PNG is used (rather than an SVG data URL) because PNGs render with
/// crisp integer-sized modules in every browser and screenshot-to-scan tool,
/// which makes the QR reliably scannable by mobile authenticator apps.
fn otpauth_qr_png(uri: &str) -> String {
    let code = match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => code,
        Err(_) => return String::new(),
    };
    let modules = code.width();
    let colors = code.to_colors();
    // Standard QR quiet zone is 4 modules on every side.
    const QUIET: usize = 4;
    // Pick the smallest integer scale that yields at least ~256px wide.
    let total_modules = modules + 2 * QUIET;
    let scale = ((256 + total_modules - 1) / total_modules).max(4);
    let side_px = total_modules * scale;
    let mut buf = vec![0xFFu8; side_px * side_px];
    for my in 0..modules {
        for mx in 0..modules {
            if colors[my * modules + mx] == qrcode::types::Color::Dark {
                let x0 = (QUIET + mx) * scale;
                let y0 = (QUIET + my) * scale;
                for dy in 0..scale {
                    let row = (y0 + dy) * side_px;
                    for dx in 0..scale {
                        buf[row + x0 + dx] = 0x00;
                    }
                }
            }
        }
    }
    let mut png_bytes: Vec<u8> = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, side_px as u32, side_px as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = match encoder.write_header() {
            Ok(w) => w,
            Err(_) => return String::new(),
        };
        if writer.write_image_data(&buf).is_err() {
            return String::new();
        }
    }
    format!(
        "data:image/png;base64,{}",
        general_purpose::STANDARD.encode(&png_bytes)
    )
}

fn new_token() -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// Hash a raw API token for storage. We never persist the raw token — only
/// this digest. Lookup is O(1) because `data["api_tokens"]` is keyed by the
/// digest. SHA-256 is sufficient here: the input is a 32-byte CSPRNG-derived
/// secret with ~256 bits of entropy, so brute force is infeasible regardless
/// of any per-token salt.
fn hash_api_token(raw: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Mint a fresh API token, persist its digest under `data["api_tokens"]`, and
/// return `(raw_token, token_id, public_metadata)`. The raw token is shown to
/// the caller exactly once; subsequent reads only return `public_metadata`.
fn mint_api_token(data: &mut Value, email: &str, label: &str) -> (String, String, Value) {
    let raw = new_token();
    let digest = hash_api_token(&raw);
    let id = general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<8>());
    let safe_label = label.trim();
    let safe_label = if safe_label.is_empty() {
        "Desktop client"
    } else {
        safe_label
    };
    let now = unix_time();
    if !data["api_tokens"].is_object() {
        data["api_tokens"] = json!({});
    }
    let entry = json!({
        "id": id,
        "email": email,
        "label": safe_label,
        "created_at": now,
        "last_used_at": 0
    });
    data["api_tokens"][&digest] = entry.clone();
    (raw, id, entry)
}

/// Resolve the email associated with a raw API token, if one exists. Updates
/// the token's `last_used_at` so the UI can show stale tokens.
fn api_token_owner(data: &mut Value, raw_token: &str) -> Option<String> {
    let digest = hash_api_token(raw_token);
    let entry = data["api_tokens"].get(&digest)?;
    let email = entry["email"].as_str()?.to_owned();
    let now = unix_time();
    data["api_tokens"][&digest]["last_used_at"] = json!(now);
    Some(email)
}

/// Snapshot the API tokens for a single user with the digest stripped out.
fn list_api_tokens_for(data: &Value, email: &str) -> Vec<Value> {
    let Some(map) = data["api_tokens"].as_object() else {
        return Vec::new();
    };
    let mut entries: Vec<Value> = map
        .values()
        .filter(|entry| entry["email"].as_str() == Some(email))
        .cloned()
        .collect();
    entries.sort_by_key(|entry| entry["created_at"].as_u64().unwrap_or(0));
    entries
}

/// Remove the API token whose `id` matches, scoped to `email`. Returns
/// `true` when a token was actually removed so callers can return 404 when
/// it wasn't.
fn revoke_api_token(data: &mut Value, email: &str, id: &str) -> bool {
    let Some(map) = data["api_tokens"].as_object_mut() else {
        return false;
    };
    let mut to_remove: Option<String> = None;
    for (digest, entry) in map.iter() {
        if entry["email"].as_str() == Some(email) && entry["id"].as_str() == Some(id) {
            to_remove = Some(digest.clone());
            break;
        }
    }
    match to_remove {
        Some(digest) => map.remove(&digest).is_some(),
        None => false,
    }
}

/// Drop every API token belonging to `email`. Used when an admin disables an
/// account so a leaked desktop token can't keep talking to the server.
fn revoke_all_api_tokens_for(data: &mut Value, email: &str) {
    let Some(map) = data["api_tokens"].as_object_mut() else {
        return;
    };
    let to_remove: Vec<String> = map
        .iter()
        .filter(|(_, entry)| entry["email"].as_str() == Some(email))
        .map(|(digest, _)| digest.clone())
        .collect();
    for digest in to_remove {
        map.remove(&digest);
    }
}

/// True when `actor` is the global admin.
fn is_global_admin(actor: &Value) -> bool {
    actor["is_admin"].as_bool().unwrap_or(false)
}

/// True when `actor` is listed as an admin of `group_id`.
fn is_group_admin(data: &Value, actor_email: &str, group_id: &str) -> bool {
    let Some(group) = data["groups"].get(group_id) else {
        return false;
    };
    group["admins"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|email| email.as_str() == Some(actor_email))
}

/// Group ids in which `actor_email` is listed as an admin.
fn admin_group_ids_for(data: &Value, actor_email: &str) -> Vec<String> {
    data["groups"]
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(id, group)| {
            let admins = group["admins"].as_array()?;
            if admins
                .iter()
                .any(|email| email.as_str() == Some(actor_email))
            {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Group ids `email` is a member of.
fn member_group_ids_for(data: &Value, email: &str) -> Vec<String> {
    data["groups"]
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(id, group)| {
            let members = group["members"].as_array()?;
            if members.iter().any(|m| m.as_str() == Some(email)) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Authorization helper: can `actor` administer `target_email`?
/// Global admins can administer everyone, group admins can administer any
/// member of any group they admin, and every user is allowed to administer
/// themselves (e.g. mint their own API tokens).
fn can_admin_user(data: &Value, actor: &Value, target_email: &str) -> bool {
    if is_global_admin(actor) {
        return true;
    }
    let actor_email = actor["email"].as_str().unwrap_or("");
    if actor_email == target_email {
        return true;
    }
    let actor_groups = admin_group_ids_for(data, actor_email);
    if actor_groups.is_empty() {
        return false;
    }
    let target_groups = member_group_ids_for(data, target_email);
    actor_groups.iter().any(|g| target_groups.contains(g))
}

/// Set of user emails `actor` is allowed to see, sorted ascending. Global
/// admins see everyone; group admins see themselves plus every member of any
/// group they admin; standard users see only themselves.
fn visible_user_emails(data: &Value, actor: &Value) -> Vec<String> {
    let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
    if is_global_admin(actor) {
        let mut all: Vec<String> = data["users"]
            .as_object()
            .into_iter()
            .flat_map(|map| map.keys().cloned())
            .collect();
        all.sort();
        return all;
    }
    let mut emails: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if !actor_email.is_empty() {
        emails.insert(actor_email.clone());
    }
    for group_id in admin_group_ids_for(data, &actor_email) {
        if let Some(members) = data["groups"][&group_id]["members"].as_array() {
            for member in members.iter().filter_map(Value::as_str) {
                emails.insert(member.to_owned());
            }
        }
    }
    emails.into_iter().collect()
}

/// Validate a group id supplied by the client. Group ids double as JSON
/// object keys and as URL path segments, so the alphabet is intentionally
/// narrow.
fn is_safe_group_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Path-segment whitelist used by the emulator-bundle endpoints. Only
/// lowercase ASCII alphanumerics, dashes, dots, and underscores are allowed
/// so a malicious admin upload cannot escape `data_dir/emulator-bundles/`.
fn is_safe_bundle_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn safe_relative_path(path: &str) -> AppResult<PathBuf> {
    let clean = PathBuf::from(path);
    if clean.is_absolute()
        || clean.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("unsafe path".into());
    }
    Ok(clean)
}

fn versions_to_keep() -> usize {
    manifest()["policy"]["file_versions_to_keep"]
        .as_u64()
        .unwrap_or(5) as usize
}

fn query_param<'a>(url: &'a str, name: &str) -> Option<&'a str> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(value);
        }
    }
    None
}

fn build_device_entry(email: &str, body: &Value) -> Value {
    let device_id = body["device_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(new_token);
    json!({
        "device_id": device_id,
        "email": email,
        "hostname": body["hostname"].as_str().unwrap_or(""),
        "os": body["os"].as_str().unwrap_or(""),
        "rom_roots": body.get("rom_roots").cloned().unwrap_or_else(|| json!([])),
        "emulator_roots": body.get("emulator_roots").cloned().unwrap_or_else(|| json!([])),
        "state": body["state"].as_str().unwrap_or("idle"),
        "last_seen": unix_time(),
        "last_sync": body.get("last_sync").cloned().unwrap_or(Value::Null),
        "last_error": body["last_error"].as_str().unwrap_or(""),
        "files_pushed": body["files_pushed"].as_u64().unwrap_or(0),
        "files_pulled": body["files_pulled"].as_u64().unwrap_or(0)
    })
}

fn list_synced_files(data_dir: &Path, user: &Value) -> AppResult<Value> {
    let is_admin = user["is_admin"].as_bool().unwrap_or(false);
    let user_email = user["email"].as_str().unwrap_or("").to_owned();
    let files_root = data_dir.join("files");
    let mut entries: Vec<Value> = Vec::new();
    if files_root.exists() {
        for owner_entry in fs::read_dir(&files_root)? {
            let owner_entry = owner_entry?;
            if !owner_entry.path().is_dir() {
                continue;
            }
            let owner = owner_entry.file_name().to_string_lossy().into_owned();
            if !is_admin && owner != user_email {
                continue;
            }
            collect_owner_files(
                &owner_entry.path(),
                &owner_entry.path(),
                data_dir,
                &owner,
                &mut entries,
            )?;
        }
    }
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(json!({"files": entries}))
}

fn collect_owner_files(
    base: &Path,
    path: &Path,
    data_dir: &Path,
    owner: &str,
    out: &mut Vec<Value>,
) -> AppResult<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_owner_files(base, &p, data_dir, owner, out)?;
        } else if p.is_file() {
            let relative = p.strip_prefix(base)?.to_string_lossy().replace('\\', "/");
            let metadata = fs::metadata(&p)?;
            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let version_dir = data_dir
                .join("versions")
                .join(owner)
                .join(
                    PathBuf::from(&relative)
                        .parent()
                        .unwrap_or_else(|| Path::new("")),
                )
                .join(PathBuf::from(&relative).file_name().unwrap_or_default());
            let versions_kept = if version_dir.exists() {
                fs::read_dir(&version_dir)?.count() + 1
            } else {
                1
            };
            out.push(json!({
                "path": relative,
                "owner": owner,
                "size": metadata.len(),
                "modified": modified,
                "versions": versions_kept
            }));
        }
    }
    Ok(())
}

fn list_file_versions(data_dir: &Path, owner: &str, rel_path: &str) -> AppResult<Value> {
    let relative = safe_relative_path(rel_path)?;
    let file_name = relative
        .file_name()
        .ok_or("file path must include a file name")?
        .to_owned();
    let version_dir = data_dir
        .join("versions")
        .join(owner)
        .join(relative.parent().unwrap_or_else(|| Path::new("")))
        .join(file_name);
    let mut versions: Vec<Value> = Vec::new();
    if version_dir.exists() {
        for entry in fs::read_dir(&version_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            versions.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "size": metadata.len()
            }));
        }
    }
    let current = data_dir.join("files").join(owner).join(&relative);
    let current_size = current.metadata().map(|m| m.len()).unwrap_or(0);
    versions.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!({
        "path": rel_path,
        "owner": owner,
        "current_size": current_size,
        "versions": versions
    }))
}

/// Restore a previously-stored version of a file as the current live file.
///
/// This intentionally does **not** delete any newer versions: the existing
/// `write_versioned_file` helper snapshots the current live file into the
/// version directory before overwriting it, so the state immediately prior to
/// the restore is preserved as a new version (and can itself be restored if
/// the revert needs to be undone). The chosen historical version's content is
/// then promoted to be the new live file.
fn restore_file_version(
    data_dir: &Path,
    owner: &str,
    rel_path: &str,
    version_name: &str,
) -> AppResult<Value> {
    let relative = safe_relative_path(rel_path)?;
    let file_name = relative
        .file_name()
        .ok_or("file path must include a file name")?
        .to_owned();
    if version_name.is_empty()
        || version_name.contains('/')
        || version_name.contains('\\')
        || version_name.contains("..")
    {
        return Err("invalid version name".into());
    }
    let version_dir = data_dir
        .join("versions")
        .join(owner)
        .join(relative.parent().unwrap_or_else(|| Path::new("")))
        .join(file_name);
    let version_path = version_dir.join(version_name);
    if !version_path.exists() {
        return Err("version not found".into());
    }
    let content = fs::read(&version_path)?;
    let mut result = write_versioned_file(data_dir, owner, rel_path, &content)?;
    if let Some(map) = result.as_object_mut() {
        map.insert("restored_from".to_owned(), json!(version_name));
    }
    Ok(result)
}

fn compute_stats(data_dir: &Path, data: &Value, user: &Value) -> AppResult<Value> {
    let is_admin = user["is_admin"].as_bool().unwrap_or(false);
    let user_email = user["email"].as_str().unwrap_or("").to_owned();
    let users = data["users"].as_object().map_or(0, |m| m.len());
    let invites = data["invites"].as_object().map_or(0, |m| m.len());
    let devices = data["devices"]
        .as_object()
        .map(|m| {
            m.values()
                .filter(|v| is_admin || v["email"].as_str() == Some(user_email.as_str()))
                .count()
        })
        .unwrap_or(0);
    let mut total_files: u64 = 0;
    let mut total_versions: u64 = 0;
    let mut storage_bytes: u64 = 0;
    let files_root = data_dir.join("files");
    if files_root.exists() {
        for owner_entry in fs::read_dir(&files_root)? {
            let owner_entry = owner_entry?;
            if !owner_entry.path().is_dir() {
                continue;
            }
            let owner = owner_entry.file_name().to_string_lossy().into_owned();
            if !is_admin && owner != user_email {
                continue;
            }
            walk_count(&owner_entry.path(), &mut total_files, &mut storage_bytes)?;
        }
    }
    let versions_root = data_dir.join("versions");
    if versions_root.exists() {
        for owner_entry in fs::read_dir(&versions_root)? {
            let owner_entry = owner_entry?;
            if !owner_entry.path().is_dir() {
                continue;
            }
            let owner = owner_entry.file_name().to_string_lossy().into_owned();
            if !is_admin && owner != user_email {
                continue;
            }
            let mut count: u64 = 0;
            walk_count(&owner_entry.path(), &mut count, &mut storage_bytes)?;
            total_versions += count;
        }
    }
    let logs = data["logs"].as_array().cloned().unwrap_or_default();
    let recent: Vec<_> = logs
        .iter()
        .rev()
        .filter(|entry| is_admin || entry["email"].as_str() == Some(user_email.as_str()))
        .take(10)
        .cloned()
        .collect();
    Ok(json!({
        "users": users,
        "devices": devices,
        "invites": invites,
        "files": total_files,
        "total_versions": total_versions,
        "storage_bytes": storage_bytes,
        "recent_logs": recent
    }))
}

fn walk_count(path: &Path, files: &mut u64, bytes: &mut u64) -> AppResult<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            walk_count(&p, files, bytes)?;
        } else if p.is_file() {
            *files += 1;
            *bytes += entry.metadata()?.len();
        }
    }
    Ok(())
}

fn write_versioned_file(
    root: &Path,
    owner: &str,
    rel_path: &str,
    content: &[u8],
) -> AppResult<Value> {
    let relative = safe_relative_path(rel_path)?;
    let base = root.join("files").join(owner).join(&relative);
    let file_name = relative
        .file_name()
        .ok_or("file path must include a file name")?
        .to_owned();
    let version_dir = root
        .join("versions")
        .join(owner)
        .join(relative.parent().unwrap_or_else(|| Path::new("")))
        .join(file_name);
    secure_create_dir_all(base.parent().ok_or("file path must include a parent")?)?;
    secure_create_dir_all(&version_dir)?;

    let changed = if base.exists() {
        fs::read(&base)? != content
    } else {
        true
    };
    if changed && base.exists() {
        let version_name = format!(
            "{}-{}",
            unix_millis(),
            general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<4>())
        );
        fs::copy(&base, version_dir.join(version_name))?;
        let mut existing: Vec<_> = fs::read_dir(&version_dir)?.filter_map(Result::ok).collect();
        existing.sort_by_key(|entry| entry.file_name());
        let max_old_versions = versions_to_keep().saturating_sub(1);
        let delete_count = existing.len().saturating_sub(max_old_versions);
        for old in existing.into_iter().take(delete_count) {
            fs::remove_file(old.path())?;
        }
    }
    if changed {
        let mut file = fs::File::create(&base)?;
        secure_file(&base, &file)?;
        file.write_all(content)?;
    }
    let versions_kept = fs::read_dir(&version_dir)?.count();
    Ok(
        json!({"path": relative.to_string_lossy(), "changed": changed, "versions_kept": versions_kept}),
    )
}

struct AppState {
    data_dir: PathBuf,
    store: Mutex<JsonStore>,
}

/// Resolve a user-supplied save path beneath `data_dir/files/{owner}` while
/// rejecting anything that would escape the owner's tree (path traversal,
/// absolute paths, drive prefixes). Returns the resolved absolute path.
/// Empty / "." / "/" all resolve to the owner root.
fn resolve_save_path(data_dir: &Path, owner: &str, raw: &str) -> AppResult<PathBuf> {
    let owner_root = data_dir.join("files").join(owner);
    let trimmed = raw.trim_matches('/').trim();
    if trimmed.is_empty() || trimmed == "." {
        return Ok(owner_root);
    }
    let relative = safe_relative_path(trimmed)?;
    Ok(owner_root.join(relative))
}

/// List the immediate children of a directory under a user's saves root,
/// returning entries grouped into directories and files with their size and
/// modification time.
fn list_save_directory(path: &Path) -> AppResult<Value> {
    if !path.exists() {
        return Ok(json!({"directories": [], "files": []}));
    }
    if !path.is_dir() {
        return Err("path is not a directory".into());
    }
    let mut directories: Vec<Value> = Vec::new();
    let mut files: Vec<Value> = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if entry_path.is_dir() {
            let mut file_count = 0_u64;
            let mut total_bytes = 0_u64;
            // Cheap recursive size for the leaf — bounded by the user's own
            // saves volume so it's safe to compute on demand.
            walk_count(&entry_path, &mut file_count, &mut total_bytes).ok();            directories.push(json!({
                "name": name,
                "modified": modified,
                "file_count": file_count,
                "size": total_bytes
            }));
        } else if entry_path.is_file() {
            files.push(json!({
                "name": name,
                "size": metadata.len(),
                "modified": modified
            }));
        }
    }
    directories.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!({"directories": directories, "files": files}))
}

/// Pack a directory subtree into an in-memory zip so the Game Saves UI can
/// offer a single-click "download whole folder" action. Caps the resulting
/// archive at `MAX_SAVES_ZIP_BYTES` so a malicious or accidentally giant
/// folder cannot exhaust the server's memory.
const MAX_SAVES_ZIP_BYTES: u64 = 256 * 1024 * 1024;

fn zip_directory(root: &Path) -> AppResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let mut total: u64 = 0;
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(current) = stack.pop() {
            for entry in fs::read_dir(&current)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| "path is not under root")?;
                let name = rel.to_string_lossy().replace('\\', "/");
                let bytes = fs::read(&path)?;
                total = total.saturating_add(bytes.len() as u64);
                if total > MAX_SAVES_ZIP_BYTES {
                    return Err(format!(
                        "folder is larger than the {} MiB download cap",
                        MAX_SAVES_ZIP_BYTES / 1024 / 1024
                    )
                    .into());
                }
                zip.start_file(name, opts)?;
                std::io::Write::write_all(&mut zip, &bytes)?;
            }
        }
        zip.finish()?;
    }
    Ok(buf)
}

fn bootstrap_store(data_dir: &Path) -> AppResult<JsonStore> {
    let store = JsonStore::new(data_dir.join("state.json"))?;
    let mut data = store.read()?;
    let changed = ensure_state_defaults(&mut data);
    if changed {
        store.write(&data)?;
    }
    Ok(store)
}

fn ensure_state_defaults(data: &mut Value) -> bool {
    let mut changed = false;
    for key in [
        "users",
        "invites",
        "sessions",
        "settings",
        "devices",
        "emulator_updates",
        "api_tokens",
        "groups",
    ] {
        if !data[key].is_object() {
            data[key] = json!({});
            changed = true;
        }
    }
    if !data["logs"].is_array() {
        data["logs"] = json!([]);
        changed = true;
    }
    if data["settings"]["app_name"].as_str() != Some(APP_NAME) {
        data["settings"]["app_name"] = json!(APP_NAME);
        changed = true;
    }
    if !data["settings"]["smtp"].is_object() {
        data["settings"]["smtp"] = json!({});
        changed = true;
    }
    if !data["settings"]["branding"].is_object() {
        data["settings"]["branding"] = json!({});
        changed = true;
    }
    if !data["setup_complete"].is_boolean() {
        let has_admin = data["users"].as_object().is_some_and(|users| {
            users
                .values()
                .any(|user| user["is_admin"].as_bool() == Some(true))
        });
        data["setup_complete"] = json!(has_admin);
        changed = true;
    }
    changed
}

fn setup_complete(data: &Value) -> bool {
    data["setup_complete"].as_bool().unwrap_or(false)
}

fn public_config(data: &Value) -> Value {
    json!({
        "app_name": APP_NAME,
        "setup_complete": setup_complete(data),
        "logo_data_url": data["settings"]["branding"]["logo_data_url"].as_str().unwrap_or("")
    })
}

fn require_setup_complete(data: &Value) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if setup_complete(data) {
        None
    } else {
        Some(json_response(428, json!({"error": "setup required"})))
    }
}

fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.contains("..")
        && email.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

fn sanitize_setup_value(body: &Value, key: &str) -> AppResult<String> {
    let value = body[key].as_str().unwrap_or("").trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(format!("{key} is required and must be a safe short value").into());
    }
    Ok(value.to_owned())
}

fn validate_logo_data_url(data_url: &str) -> AppResult<()> {
    let Some((mime, payload)) = data_url.split_once(',') else {
        return Err("logo must be a data URL".into());
    };
    if !matches!(
        mime,
        "data:image/png;base64" | "data:image/jpeg;base64" | "data:image/svg+xml;base64"
    ) {
        return Err("logo must be a PNG, JPEG, or SVG data URL".into());
    }
    if payload.len() > MAX_LOGO_BASE64_SIZE {
        return Err("logo must be smaller than 256 KiB".into());
    }
    let decoded = general_purpose::STANDARD.decode(payload)?;
    if decoded.len() > MAX_LOGO_BYTES {
        return Err("logo must be smaller than 256 KiB".into());
    }
    Ok(())
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_ui(data: &Value) -> String {
    let manifest = manifest();
    let count = manifest["emulators"].as_array().map_or(0, Vec::len);
    let versions = manifest["policy"]["file_versions_to_keep"]
        .as_u64()
        .unwrap_or(5);
    let logo = data["settings"]["branding"]["logo_data_url"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(|value| {
            format!(
                r#"<img class="mark logo-img" src="{}" alt="Crash Crafts Game Sync logo">"#,
                escape_html(value)
            )
        })
        .unwrap_or_else(|| r#"<span class="mark" id="brand-logo"></span>"#.to_owned());
    r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>@APP@</title>
  <link rel="stylesheet" href="/static/app.css">
</head>
<body>
<main class="shell">
  <nav>
    <div class="logo">@LOGO@<span>@APP@</span></div>
    <div class="nav-tabs">
      <a href="#" class="nav-link active" data-view="dashboard">Dashboard</a>
      <a href="#" class="nav-link" data-view="devices">Devices</a>
      <a href="#" class="nav-link" data-view="files">Files</a>
      <a href="#" class="nav-link admin-only" data-view="users">Users &amp; invites</a>
      <a href="#" class="nav-link admin-only" data-view="logs">Logs</a>
      <a href="#" class="nav-link admin-only" data-view="settings">Settings</a>
    </div>
    <div class="nav-actions">
      <span class="pill"><span id="me-email"></span> &middot; <span id="me-role"></span></span>
      <button id="logout-btn" class="secondary" type="button">Sign out</button>
    </div>
  </nav>

  <section id="setup-panel" class="card panel-grid hidden">
    <div>
      <p class="eyebrow">First-run setup</p>
      <h2>Configure the Docker after download</h2>
      <p>Create the initial admin and store Office365 OAuth SMTP metadata in the Docker data volume. No Docker environment variables are required.</p>
    </div>
    <form id="setup-form" class="form">
      <label>Admin email<input name="admin_email" type="email" autocomplete="username" required></label>
      <label>Admin password<input name="admin_password" type="password" autocomplete="new-password" minlength="12" required></label>
      <label>Office365 tenant ID<input name="smtp_tenant_id" autocomplete="off" required></label>
      <label>Office365 OAuth client ID<input name="smtp_client_id" autocomplete="off" required></label>
      <label>SMTP from email<input name="smtp_from_email" type="email" required></label>
      <button type="submit">Complete secure setup</button>
      <p id="setup-result" class="result"></p>
      <img id="setup-qr" alt="" class="hidden" width="240" height="240">
      <button type="button" id="setup-continue" class="hidden">Continue to sign in</button>
    </form>
  </section>

  <section id="login-panel" class="card panel-grid hidden">
    <div>
      <p class="eyebrow">Sign in</p>
      <h2>Crash Crafts Game Sync console</h2>
      <p>Sign in with your account email, password, and TOTP code from your authenticator app to access the management console.</p>
      <p class="muted">Server is configured. The Docker volume keeps state at <code>/data</code>.</p>
    </div>
    <form id="login-form" class="form">
      <label>Email<input name="email" type="email" autocomplete="username" required></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
      <label>2FA code<input name="totp_code" inputmode="numeric" autocomplete="one-time-code" required></label>
      <button type="submit">Sign in</button>
      <p id="login-result" class="result"></p>
    </form>
  </section>

  <section id="app-shell" class="hidden">
    <section class="view" data-view="dashboard">
      <h2>Dashboard</h2>
      <p class="muted">Live counters from the Docker volume, plus the latest client activity from connected desktop apps.</p>
      <div class="stats" id="dashboard-stats"></div>
      <div id="dashboard-recent"></div>
      <section class="features">
        <div class="feature"><h3>@COUNT@ emulators tracked</h3><p>DuckStation, PCSX2 nightly, RPCS3 nightly, Xenia Canary, xemu, Cemu, RetroArch, Eden nightly, and Dolphin dev builds.</p></div>
        <div class="feature"><h3>@VERSIONS@ copies retained</h3><p>Each changed save keeps the current copy plus older copies up to the configured retention.</p></div>
        <div class="feature"><h3>Device-local config</h3><p>Manifest exclusions keep gamepad bindings, ROM paths, and graphics settings local to each device.</p></div>
      </section>
    </section>

    <section class="view hidden" data-view="devices">
      <h2>Devices</h2>
      <p class="muted">Desktop companions report a heartbeat with hostname, OS, configured roots, and last sync result.</p>
      <div id="devices-table"></div>
    </section>

    <section class="view hidden" data-view="files">
      <h2>Files</h2>
      <p class="muted">Synced save files with version history per file.</p>
      <div id="files-table"></div>
    </section>

    <section class="view hidden admin-only" data-view="users">
      <h2>Users &amp; invites</h2>
      <form id="invite-form" class="form inline">
        <label>Invite email<input name="email" type="email" required></label>
        <button type="submit">Create invite</button>
        <p id="invite-result" class="result"></p>
      </form>
      <div id="users-table"></div>
      <div id="invites-list"></div>
    </section>

    <section class="view hidden admin-only" data-view="logs">
      <h2>Client logs</h2>
      <div id="logs-list"></div>
    </section>

    <section class="view hidden admin-only" data-view="settings">
      <h2>Settings</h2>
      <div id="settings-summary"></div>
      <form id="logo-form" class="form">
        <label>Upload logo (PNG, JPEG, or SVG, max 256 KiB)<input name="logo" type="file" accept="image/png,image/jpeg,image/svg+xml" required></label>
        <button type="submit">Save logo</button>
        <p id="logo-result" class="result"></p>
      </form>
    </section>
  </section>
</main>
<script src="/static/app.js"></script>
</body></html>"##
        .replace("@APP@", APP_NAME)
        .replace("@LOGO@", &logo)
        .replace("@COUNT@", &count.to_string())
        .replace("@VERSIONS@", &versions.to_string())
}

const STATIC_APP_CSS: &str = r#":root { color-scheme: dark; --bg: #070a12; --panel: rgba(17, 24, 39, .82); --panel-strong: rgba(12, 18, 31, .94); --text: #f8fafc; --muted: #aab7cf; --brand: #ff7a1a; --brand-2: #22d3ee; --good: #7ee787; --warn: #ffd166; --error: #ff6b6b; --border: rgba(255,255,255,.12); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
* { box-sizing: border-box; min-width: 0; }
body { margin: 0; min-height: 100vh; color: var(--text); background: radial-gradient(circle at 18% 12%, rgba(255,122,26,.23), transparent 32rem), radial-gradient(circle at 82% 4%, rgba(34,211,238,.20), transparent 30rem), linear-gradient(135deg, #070a12 0%, #101827 48%, #070a12 100%); overflow-wrap: anywhere; }
.shell { width: min(1280px, calc(100% - 32px)); margin: 0 auto; padding: 24px 0 56px; }
nav, .card, .stat, .feature, section.view { border: 1px solid var(--border); background: var(--panel); box-shadow: 0 24px 80px rgba(0,0,0,.35); backdrop-filter: blur(18px); border-radius: 24px; }
nav { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 18px; flex-wrap: wrap; }
.logo { display: flex; gap: 12px; align-items: center; font-weight: 800; letter-spacing: -.04em; font-size: clamp(1rem, 3vw, 1.25rem); }
.mark { flex: 0 0 auto; width: 38px; height: 38px; border-radius: 12px; background: linear-gradient(135deg, var(--brand), var(--brand-2)) center/cover no-repeat; box-shadow: 0 0 32px rgba(255,122,26,.45); }
.pill { color: var(--muted); border: 1px solid var(--border); border-radius: 999px; padding: 8px 12px; font-size: .85rem; }
.nav-tabs { display: flex; gap: 6px; flex-wrap: wrap; }
.nav-link { color: var(--muted); text-decoration: none; padding: 8px 12px; border-radius: 10px; font-weight: 600; }
.nav-link.active { color: var(--text); background: rgba(255,122,26,.18); }
.nav-actions { display: flex; align-items: center; gap: 10px; }
section.view, section#setup-panel, section#login-panel { padding: clamp(20px, 4vw, 40px); margin-top: 18px; }
h1, h2, h3 { letter-spacing: -.03em; margin: 0 0 12px; }
p { color: var(--muted); line-height: 1.6; }
p.muted, .muted { color: var(--muted); }
.actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 18px; }
button, a.button { text-decoration: none; color: #071019; background: linear-gradient(135deg, var(--brand), #ffd166); padding: 11px 16px; border-radius: 12px; font-weight: 800; border: 0; cursor: pointer; }
button.secondary, a.secondary { color: var(--text); background: rgba(255,255,255,.08); border: 1px solid var(--border); }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin: 14px 0; }
.stat { padding: 22px; }
.stat .value { display: block; font-size: clamp(1.55rem, 4vw, 2rem); font-weight: 900; color: var(--good); }
.stat .label { color: var(--muted); font-size: .95rem; }
.features { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 20px; }
.feature { padding: 22px; background: var(--panel-strong); }
.panel-grid { display: grid; grid-template-columns: minmax(0, .85fr) minmax(280px, 1fr); gap: 22px; align-items: start; }
.form { display: grid; gap: 12px; }
.form.inline { grid-template-columns: 1fr auto; align-items: end; gap: 10px; }
.form.inline p { grid-column: 1 / -1; margin: 0; }
label { color: var(--muted); display: grid; gap: 7px; font-size: .9rem; }
input, select { width: 100%; color: var(--text); background: rgba(255,255,255,.07); border: 1px solid var(--border); border-radius: 12px; padding: 11px 13px; font: inherit; }
.result { min-height: 1.2em; color: var(--good); }
.result[data-kind="error"] { color: var(--error); }
.result[data-kind="info"] { color: var(--muted); }
.eyebrow { margin: 0 0 8px; color: var(--brand-2); font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.hidden { display: none !important; }
table.data { width: 100%; border-collapse: collapse; margin-top: 12px; }
table.data th, table.data td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: .92rem; vertical-align: top; }
table.data th { color: var(--muted); font-weight: 700; }
.log-list { list-style: none; padding: 0; margin: 12px 0; display: grid; gap: 8px; }
.log-list li { padding: 10px 12px; background: var(--panel-strong); border-radius: 10px; }
.badge { padding: 2px 8px; border-radius: 999px; background: rgba(255,255,255,.08); font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; margin-right: 6px; }
.badge-error { background: rgba(255,107,107,.2); color: var(--error); }
.badge-warn { background: rgba(255,209,102,.2); color: var(--warn); }
.badge-info { background: rgba(34,211,238,.18); color: var(--brand-2); }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--muted); margin-right: 8px; vertical-align: middle; }
.dot-syncing { background: var(--brand-2); }
.dot-idle { background: var(--good); }
.dot-error { background: var(--error); }
code { background: rgba(255,255,255,.06); padding: 1px 6px; border-radius: 6px; font-size: .85em; }
body:not(.is-admin) .admin-only { display: none !important; }
.card-pair { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
.card-pair .card { padding: 18px; }
.toggle { display: flex; align-items: center; gap: 10px; }
.toggle input { width: auto; }
@media (max-width: 820px) { .panel-grid, .card-pair { grid-template-columns: 1fr; } .form.inline { grid-template-columns: 1fr; } }
"#;

fn json_response(status: u16, body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let payload = serde_json::to_vec_pretty(&body).unwrap_or_else(|_| b"{}".to_vec());
    response(status, payload, "application/json")
}

fn response(status: u16, body: Vec<u8>, content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_data(body).with_status_code(StatusCode(status));
    if let Ok(header) = Header::from_bytes("Content-Type", content_type) {
        response.add_header(header);
    }
    for (name, value) in [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        (
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ] {
        if let Ok(header) = Header::from_bytes(name, value) {
            response.add_header(header);
        }
    }
    response
}

fn read_body(request: &mut Request) -> AppResult<Value> {
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)?;
    if body.trim().is_empty() {
        Ok(json!({}))
    } else {
        Ok(serde_json::from_str(&body)?)
    }
}

fn bearer_email(state: &AppState, request: &Request) -> AppResult<Option<String>> {
    let token = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .and_then(|header| header.value.as_str().strip_prefix("Bearer "))
        .map(str::to_owned);
    let Some(token) = token else {
        return Ok(None);
    };
    let store = state.store.lock().unwrap();
    let mut data = store.read()?;
    // Web sessions take precedence: they are short-lived and tied to the
    // browser. If the bearer is not a known session, fall back to the
    // per-user persistent API token table used by the desktop client.
    if let Some(email) = data["sessions"][&token]["email"].as_str() {
        return Ok(Some(email.to_owned()));
    }
    if let Some(email) = api_token_owner(&mut data, &token) {
        // Persist the touched `last_used_at` so the UI can show stale
        // tokens. Best-effort: a write failure must not block authn.
        let _ = store.write(&data);
        return Ok(Some(email));
    }
    Ok(None)
}

fn require_user(state: &AppState, request: &Request) -> AppResult<Option<Value>> {
    let Some(email) = bearer_email(state, request)? else {
        return Ok(None);
    };
    let store = state.store.lock().unwrap();
    let data = store.read()?;
    Ok(data["users"].get(&email).cloned())
}

fn handle_request(mut request: Request, state: Arc<AppState>) {
    let method = request.method().clone();
    let raw_url = request.url().to_owned();
    let path = raw_url.split('?').next().unwrap_or(&raw_url).to_owned();
    let result: AppResult<Response<std::io::Cursor<Vec<u8>>>> = (|| match (method, path.as_str()) {
        (Method::Get, "/") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            Ok(response(
                200,
                render_ui(&data).into_bytes(),
                "text/html; charset=utf-8",
            ))
        }
        (Method::Get, "/api/health") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            Ok(json_response(
                200,
                json!({"ok": true, "setup_complete": setup_complete(&data)}),
            ))
        }
        (Method::Get, "/api/config") => {
            let store = state.store.lock().unwrap();
            Ok(json_response(200, public_config(&store.read()?)))
        }
        (Method::Get, "/api/emulators") => {
            let Some(_user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            Ok(json_response(200, live_manifest(&data)))
        }
        (Method::Post, "/api/admin/emulators") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let body = read_body(&mut request)?;
            let id = body["emulator_id"].as_str().unwrap_or("").to_lowercase();
            let os = body["os"].as_str().unwrap_or("").to_lowercase();
            if id.is_empty() || (os != "windows" && os != "linux") {
                return Ok(json_response(
                    400,
                    json!({"error": "emulator_id and os (windows|linux) are required"}),
                ));
            }
            if emulator_by_id(&id).is_none() {
                return Ok(json_response(404, json!({"error": "unknown emulator id"})));
            }
            let url = body["url"].as_str().unwrap_or("").to_owned();
            if !url.is_empty() && !url.starts_with("https://") {
                return Ok(json_response(
                    400,
                    json!({"error": "download URL must use HTTPS"}),
                ));
            }
            let entry = json!({
                "url": url,
                "sha256": body["sha256"].as_str().unwrap_or(""),
                "archive": body["archive"].as_str().unwrap_or("zip"),
                "version": body["version"].as_str().unwrap_or(""),
                "published_by": user["email"],
                "published_at": unix_time()
            });
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if !data["emulator_updates"].is_object() {
                data["emulator_updates"] = json!({});
            }
            if !data["emulator_updates"][&id].is_object() {
                data["emulator_updates"][&id] = json!({});
            }
            data["emulator_updates"][&id][&os] = entry;
            store.write(&data)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Get, "/api/admin/emulators") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            Ok(json_response(
                200,
                json!({"emulator_updates": data["emulator_updates"].clone()}),
            ))
        }
        // Admin uploads a tested portable emulator bundle (zip) for a given
        // OS. The next time any desktop client calls "Install / Update" for
        // that emulator, it downloads this bundle, extracts it on disk, and
        // — for everything after the first install — skips files that match
        // the emulator's `sync_exclude` patterns so per-device emulator
        // settings (controllers, GPU backend, RPCS3 `config.yml`, Cemu
        // `settings.xml`, etc.) survive updates.
        (Method::Put, path) if path.starts_with("/api/admin/emulator-bundle/") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let suffix = path.trim_start_matches("/api/admin/emulator-bundle/");
            let parts: Vec<&str> = suffix.split('/').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Ok(json_response(
                    400,
                    json!({"error": "expected /api/admin/emulator-bundle/{id}/{os}"}),
                ));
            }
            let emulator_id = urlencoding::decode(parts[0])?.into_owned();
            let os = urlencoding::decode(parts[1])?.into_owned();
            if !is_safe_bundle_segment(&emulator_id) || !is_safe_bundle_segment(&os) {
                return Ok(json_response(400, json!({"error": "invalid id or os"})));
            }
            let mut content = Vec::new();
            request.as_reader().read_to_end(&mut content)?;
            // Sanity-check the upload is actually a zip — fail fast so admins
            // don't silently publish broken bundles.
            if zip::ZipArchive::new(std::io::Cursor::new(&content)).is_err() {
                return Ok(json_response(
                    400,
                    json!({"error": "uploaded bundle is not a valid zip archive"}),
                ));
            }
            let dir = state.data_dir.join("emulator-bundles").join(&emulator_id);
            secure_create_dir_all(&dir)?;
            let target = dir.join(format!("{os}.zip"));
            fs::write(&target, &content)?;
            Ok(json_response(
                200,
                json!({"ok": true, "bytes": content.len(), "path": target.to_string_lossy()}),
            ))
        }
        // Authenticated download: every desktop client uses this to install
        // and to receive emulator updates from the server-curated bundle.
        (Method::Get, path) if path.starts_with("/api/emulator-bundle/") => {
            if require_user(&state, &request)?.is_none() {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            }
            let suffix = path.trim_start_matches("/api/emulator-bundle/");
            let parts: Vec<&str> = suffix.split('/').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Ok(json_response(
                    400,
                    json!({"error": "expected /api/emulator-bundle/{id}/{os}"}),
                ));
            }
            let emulator_id = urlencoding::decode(parts[0])?.into_owned();
            let os = urlencoding::decode(parts[1])?.into_owned();
            if !is_safe_bundle_segment(&emulator_id) || !is_safe_bundle_segment(&os) {
                return Ok(json_response(400, json!({"error": "invalid id or os"})));
            }
            let target = state
                .data_dir
                .join("emulator-bundles")
                .join(&emulator_id)
                .join(format!("{os}.zip"));
            if !target.exists() {
                return Ok(json_response(
                    404,
                    json!({"error": "no bundle published for this emulator/OS"}),
                ));
            }
            let bytes = fs::read(&target)?;
            Ok(response(200, bytes, "application/zip"))
        }
        // Single-click admin "Check for updates" — polls each emulator's
        // upstream release source and returns which ones have a version
        // newer than what the server has previously distributed. Backs the
        // "Update all emulators" Web UI button.
        (Method::Get, "/api/admin/check-emulator-updates") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let applied = {
                let store = state.store.lock().unwrap();
                let data = store.read()?;
                data["applied_emulator_versions"].clone()
            };
            let mut entries: Vec<Value> = Vec::new();
            for emulator in manifest()["emulators"].as_array().into_iter().flatten() {
                let id = emulator["id"].as_str().unwrap_or("").to_owned();
                let mut entry = json!({
                    "id": id,
                    "name": emulator["name"].as_str().unwrap_or(""),
                    "applied_version": applied[&id]["version"].as_str().unwrap_or(""),
                    "applied_at": applied[&id]["applied_at"].as_u64().unwrap_or(0),
                    "has_update": false,
                    "latest_version": "",
                    "latest_published_at": "",
                    "download_url": "",
                    "release_url": "",
                    "error": ""
                });
                match latest_release(emulator) {
                    Ok(release) => {
                        let applied_version = applied[&id]["version"].as_str().unwrap_or("");
                        entry["latest_version"] = json!(release.version);
                        entry["latest_published_at"] = json!(release.published_at);
                        entry["download_url"] =
                            json!(release.download_url.clone().unwrap_or_default());
                        entry["release_url"] = json!(release.source_url);
                        entry["has_update"] = json!(
                            !release.version.is_empty() && release.version != applied_version
                        );
                    }
                    Err(error) => {
                        entry["error"] = json!(error.to_string());
                    }
                }
                entries.push(entry);
            }
            Ok(json_response(200, json!({"emulators": entries})))
        }
        // Apply one selected update: server-side downloads the upstream
        // release for the given OS, validates it is a zip (the bundle
        // format every desktop client consumes), persists it under the
        // shared `emulator-bundles/` store, and records the applied
        // version. From this point on, every user's next "Install /
        // Update" pulls the new bundle — no per-user action required.
        (Method::Post, "/api/admin/apply-emulator-update") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let body = read_body(&mut request)?;
            let id = body["emulator_id"].as_str().unwrap_or("").to_owned();
            let target_os = body["os"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| "all".to_owned());
            let Some(emulator) = emulator_by_id(&id) else {
                return Ok(json_response(404, json!({"error": "unknown emulator id"})));
            };
            let release = match latest_release(&emulator) {
                Ok(release) => release,
                Err(error) => {
                    return Ok(json_response(
                        502,
                        json!({"error": format!("failed to query upstream: {error}")}),
                    ));
                }
            };
            // Decide which OS targets to publish for. "all" attempts both;
            // a specific value publishes only that bundle.
            let targets: Vec<&str> = match target_os.as_str() {
                "all" => vec!["windows", "linux"],
                "windows" => vec!["windows"],
                "linux" => vec!["linux"],
                _ => {
                    return Ok(json_response(
                        400,
                        json!({"error": "os must be 'windows', 'linux', or 'all'"}),
                    ));
                }
            };
            let mut published: Vec<Value> = Vec::new();
            let mut errors: Vec<Value> = Vec::new();
            for os in targets {
                let asset_url = if os == current_os() {
                    release.download_url.clone()
                } else {
                    // Re-poll the per-OS effective release source (Dolphin uses
                    // a dev-website source for Windows and the pkgforge
                    // AppImage feed for Linux, so each OS needs its own poll).
                    pick_asset(
                        &release_assets_for_os(&emulator, os).unwrap_or_default(),
                        os,
                    )
                };
                let Some(url) = asset_url else {
                    errors.push(json!({
                        "os": os,
                        "error": format!("no upstream asset matched for {os}")
                    }));
                    continue;
                };
                if !url.starts_with("https://") {
                    errors.push(json!({"os": os, "error": "asset URL must use HTTPS"}));
                    continue;
                }
                let bytes = match ureq::get(&url)
                    .header("User-Agent", "crash-crafts-game-sync")
                    .call()
                    .and_then(|r| r.into_body().read_to_vec())
                {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        errors.push(json!({
                            "os": os,
                            "error": format!("download failed: {error}")
                        }));
                        continue;
                    }
                };
                if zip::ZipArchive::new(std::io::Cursor::new(&bytes)).is_err() {
                    errors.push(json!({
                        "os": os,
                        "error": "upstream asset is not a zip; admin must repackage as a portable zip and upload via PUT /api/admin/emulator-bundle/{id}/{os}"
                    }));
                    continue;
                }
                let dir = state.data_dir.join("emulator-bundles").join(&id);
                secure_create_dir_all(&dir)?;
                let target_path = dir.join(format!("{os}.zip"));
                fs::write(&target_path, &bytes)?;
                published.push(json!({
                    "os": os,
                    "bytes": bytes.len(),
                    "path": target_path.to_string_lossy()
                }));
            }
            // Record the applied version so the next "Check for updates"
            // call can compare against it.
            if !published.is_empty() {
                let store = state.store.lock().unwrap();
                let mut data = store.read()?;
                if !data["applied_emulator_versions"].is_object() {
                    data["applied_emulator_versions"] = json!({});
                }
                data["applied_emulator_versions"][&id] = json!({
                    "version": release.version,
                    "published_at": release.published_at,
                    "applied_at": unix_time(),
                    "applied_by": user["email"].as_str().unwrap_or("")
                });
                store.write(&data)?;
            }
            Ok(json_response(
                200,
                json!({
                    "ok": !published.is_empty(),
                    "emulator_id": id,
                    "applied_version": release.version,
                    "published": published,
                    "errors": errors
                }),
            ))
        }
        (Method::Post, "/api/setup") => {
            let body = read_body(&mut request)?;
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if setup_complete(&data) {
                return Ok(json_response(
                    409,
                    json!({"error": "setup already complete"}),
                ));
            }
            let email = sanitize_setup_value(&body, "admin_email")?.to_lowercase();
            if !is_valid_email(&email) {
                return Ok(json_response(
                    400,
                    json!({"error": "valid admin_email required"}),
                ));
            }
            let password = body["admin_password"].as_str().unwrap_or_default();
            if password.len() < 12 {
                return Ok(json_response(
                    400,
                    json!({"error": "admin_password must be at least 12 characters"}),
                ));
            }
            let smtp_tenant_id = sanitize_setup_value(&body, "smtp_tenant_id")?;
            let smtp_client_id = sanitize_setup_value(&body, "smtp_client_id")?;
            let smtp_from_email = sanitize_setup_value(&body, "smtp_from_email")?.to_lowercase();
            if !is_valid_email(&smtp_from_email) {
                return Ok(json_response(
                    400,
                    json!({"error": "valid smtp_from_email required"}),
                ));
            }
            let secret = new_totp_secret();
            data["users"][&email] = json!({
                "email": email,
                "password_hash": hash_password(password, None),
                "totp_secret": secret,
                "is_admin": true,
                "registered": true
            });
            data["settings"]["smtp"] = json!({
                "provider": "office365",
                "auth": "oauth2",
                "tenant_id": smtp_tenant_id,
                "client_id": smtp_client_id,
                "from_email": smtp_from_email,
                "token_status": "authorization_pending"
            });
            data["setup_complete"] = json!(true);
            // Mint a starter desktop API token so the brand-new admin can
            // wire up the desktop client immediately. Without this, the
            // first-run admin had no way to obtain an `auth_token`.
            let (raw_token, token_id, _) = mint_api_token(&mut data, &email, "First-run admin token");
            let otpauth = otpauth_uri(&email, &secret);
            let otpauth_qr = otpauth_qr_png(&otpauth);
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({
                    "ok": true,
                    "email": email,
                    "otpauth_uri": otpauth,
                    "otpauth_qr_png": otpauth_qr,
                    "desktop_token": raw_token,
                    "desktop_token_id": token_id,
                    "desktop_token_label": "First-run admin token"
                }),
            ))
        }
        (Method::Get, "/api/users") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            // Global admins see every user; group admins see members of
            // any group they administer (plus themselves); standard users
            // see only their own row.
            let visible = visible_user_emails(&data, &user);
            let users = data["users"]
                .as_object()
                .into_iter()
                .flat_map(|users| users.iter())
                .filter(|(email, _)| visible.contains(email))
                .map(|(_, user)| {
                    let mut value = user.clone();
                    if let Some(object) = value.as_object_mut() {
                        object.remove("password_hash");
                        object.remove("totp_secret");
                    }
                    value
                })
                .collect::<Vec<_>>();
            Ok(json_response(200, json!({"users": users})))
        }
        (Method::Post, "/api/admin/logo") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let body = read_body(&mut request)?;
            let data_url = body["data_url"].as_str().unwrap_or("").trim();
            validate_logo_data_url(data_url)?;
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            data["settings"]["branding"]["logo_data_url"] = json!(data_url);
            store.write(&data)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Post, "/api/invites") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = read_body(&mut request)?;
            let group_id = body["group_id"]
                .as_str()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty());
            // Global admins can invite anyone. Group admins can invite
            // people but only into a group they administer, and the new
            // user is auto-added to that group on registration.
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let actor_email = user["email"].as_str().unwrap_or("").to_owned();
            if !is_global_admin(&user) {
                match &group_id {
                    None => {
                        return Ok(json_response(
                            403,
                            json!({"error": "group admins must specify group_id"}),
                        ));
                    }
                    Some(id) if !is_group_admin(&data, &actor_email, id) => {
                        return Ok(json_response(
                            403,
                            json!({"error": "you do not administer that group"}),
                        ));
                    }
                    _ => {}
                }
            }
            if let Some(id) = &group_id {
                if !is_safe_group_id(id) || data["groups"].get(id).is_none() {
                    return Ok(json_response(404, json!({"error": "group not found"})));
                }
            }
            let email = body["email"].as_str().unwrap_or("").trim().to_lowercase();
            if email.is_empty() {
                return Ok(json_response(400, json!({"error": "email required"})));
            }
            let token = general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<24>());
            let invite = match &group_id {
                Some(id) => json!({"email": email, "group_id": id}),
                None => json!({"email": email}),
            };
            data["invites"][&token] = invite;
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({
                    "email": email,
                    "invite_token": token,
                    "group_id": group_id,
                    "email_status": "Configure SMTP later; this invite token is returned for manual delivery."
                }),
            ))
        }
        (Method::Post, "/api/register") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let body = read_body(&mut request)?;
            let invite_token = body["invite_token"].as_str().unwrap_or("");
            let password = body["password"].as_str().unwrap_or_default();
            if password.len() < 12 {
                return Ok(json_response(
                    400,
                    json!({"error": "password must be at least 12 characters"}),
                ));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let invite = data["invites"][invite_token].clone();
            let Some(email) = invite["email"].as_str().map(str::to_owned) else {
                return Ok(json_response(400, json!({"error": "invalid invite"})));
            };
            let invite_group_id = invite["group_id"].as_str().map(str::to_owned);
            let secret = new_totp_secret();
            data["users"][&email] = json!({"email": email, "password_hash": hash_password(password, None), "totp_secret": secret, "is_admin": false, "registered": true});
            // Auto-add the new user to the inviting admin's group so the
            // group admin immediately has them in scope.
            if let Some(group_id) = invite_group_id.as_ref() {
                if data["groups"].get(group_id).is_some() {
                    let mut members: Vec<Value> = data["groups"][group_id]["members"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if !members.iter().any(|m| m.as_str() == Some(email.as_str())) {
                        members.push(json!(email));
                        data["groups"][group_id]["members"] = json!(members);
                    }
                }
            }
            if let Some(invites) = data["invites"].as_object_mut() {
                invites.remove(invite_token);
            }
            store.write(&data)?;
            let otpauth = otpauth_uri(&email, &secret);
            let otpauth_qr = otpauth_qr_png(&otpauth);
            Ok(json_response(
                201,
                json!({"email": email, "totp_secret": secret, "otpauth_uri": otpauth, "otpauth_qr_png": otpauth_qr, "group_id": invite_group_id}),
            ))
        }
        (Method::Post, "/api/login") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let body = read_body(&mut request)?;
            let email = body["email"].as_str().unwrap_or("").trim().to_lowercase();
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let user = data["users"].get(&email).cloned();
            let dummy = hash_password(&new_token(), None);
            let password_hash = user
                .as_ref()
                .and_then(|user| user["password_hash"].as_str())
                .unwrap_or(&dummy);
            let password_ok =
                verify_password(body["password"].as_str().unwrap_or_default(), password_hash);
            let totp_ok = user.as_ref().is_some_and(|user| {
                verify_totp(
                    user["totp_secret"].as_str().unwrap_or(""),
                    body["totp_code"].as_str().unwrap_or(""),
                    None,
                    1,
                )
            });
            let disabled = user
                .as_ref()
                .and_then(|user| user["disabled"].as_bool())
                .unwrap_or(false);
            if user.is_none() || !password_ok || !totp_ok || disabled {
                return Ok(json_response(
                    401,
                    json!({"error": "invalid credentials or 2fa code"}),
                ));
            }
            let token = new_token();
            data["sessions"][&token] = json!({"email": email});
            store.write(&data)?;
            Ok(json_response(
                200,
                json!({"token": token, "is_admin": user.unwrap()["is_admin"].as_bool().unwrap_or(false)}),
            ))
        }
        (Method::Post, "/api/logs") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = read_body(&mut request)?;
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if let Some(logs) = data["logs"].as_array_mut() {
                logs.push(json!({"email": user["email"], "level": body["level"].as_str().unwrap_or("info"), "message": body["message"].as_str().unwrap_or(""), "context": body.get("context").cloned().unwrap_or_else(|| json!({}))}));
                let drain = logs.len().saturating_sub(1000);
                logs.drain(0..drain);
            }
            store.write(&data)?;
            Ok(json_response(201, json!({"ok": true})))
        }
        (Method::Put, path) if path.starts_with("/api/files/") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let rel_path =
                urlencoding::decode(path.trim_start_matches("/api/files/"))?.into_owned();
            let mut content = Vec::new();
            request.as_reader().read_to_end(&mut content)?;
            Ok(json_response(
                200,
                write_versioned_file(
                    &state.data_dir,
                    user["email"].as_str().unwrap_or("unknown"),
                    &rel_path,
                    &content,
                )?,
            ))
        }
        (Method::Get, "/static/app.js") => Ok(response(
            200,
            STATIC_APP_JS.as_bytes().to_vec(),
            "application/javascript; charset=utf-8",
        )),
        (Method::Get, "/static/app.css") => Ok(response(
            200,
            STATIC_APP_CSS.as_bytes().to_vec(),
            "text/css; charset=utf-8",
        )),
        (Method::Get, "/api/me") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let email = user["email"].as_str().unwrap_or("").to_owned();
            let admin_groups = admin_group_ids_for(&data, &email);
            let member_groups = member_group_ids_for(&data, &email);
            Ok(json_response(
                200,
                json!({
                    "email": user["email"],
                    "is_admin": user["is_admin"].as_bool().unwrap_or(false),
                    "disabled": user["disabled"].as_bool().unwrap_or(false),
                    "registered": user["registered"].as_bool().unwrap_or(false),
                    "admin_group_ids": admin_groups,
                    "member_group_ids": member_groups,
                    "is_group_admin": !admin_group_ids_for(&data, &email).is_empty()
                }),
            ))
        }
        (Method::Get, "/api/stats") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            drop(store);
            Ok(json_response(
                200,
                compute_stats(&state.data_dir, &data, &user)?,
            ))
        }
        (Method::Get, "/api/devices") => {
            let Some(_user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let devices = data["devices"]
                .as_object()
                .into_iter()
                .flat_map(|map| map.values().cloned())
                .collect::<Vec<_>>();
            Ok(json_response(200, json!({"devices": devices})))
        }
        (Method::Post, "/api/devices/heartbeat") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = read_body(&mut request)?;
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let entry = build_device_entry(user["email"].as_str().unwrap_or(""), &body);
            let device_id = entry["device_id"].as_str().unwrap_or("").to_owned();
            if !data["devices"].is_object() {
                data["devices"] = json!({});
            }
            if let Some(map) = data["devices"].as_object_mut() {
                map.insert(device_id, entry);
                if map.len() > MAX_DEVICE_HEARTBEATS {
                    let mut entries: Vec<_> = map
                        .iter()
                        .map(|(k, v)| (k.clone(), v["last_seen"].as_u64().unwrap_or(0)))
                        .collect();
                    entries.sort_by_key(|(_, ts)| *ts);
                    let drop = entries.len().saturating_sub(MAX_DEVICE_HEARTBEATS);
                    for (key, _) in entries.into_iter().take(drop) {
                        map.remove(&key);
                    }
                }
            }
            store.write(&data)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Get, "/api/invites") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let invites = data["invites"]
                .as_object()
                .into_iter()
                .flat_map(|map| {
                    map.iter()
                        .map(|(token, value)| json!({"token": token, "email": value["email"]}))
                })
                .collect::<Vec<_>>();
            Ok(json_response(200, json!({"invites": invites})))
        }
        (Method::Post, path) if path.starts_with("/api/users/") && path.ends_with("/disable") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let target = urlencoding::decode(
                path.trim_start_matches("/api/users/")
                    .trim_end_matches("/disable"),
            )?
            .into_owned()
            .to_lowercase();
            if target.is_empty() {
                return Ok(json_response(400, json!({"error": "email required"})));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if data["users"].get(&target).is_none() {
                return Ok(json_response(404, json!({"error": "user not found"})));
            }
            data["users"][&target]["disabled"] = json!(true);
            if let Some(sessions) = data["sessions"].as_object_mut() {
                let drop_keys: Vec<_> = sessions
                    .iter()
                    .filter(|(_, v)| v["email"].as_str() == Some(target.as_str()))
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in drop_keys {
                    sessions.remove(&key);
                }
            }
            // Also revoke every desktop API token for the disabled user so
            // a leaked token cannot keep talking to the server after the
            // account has been turned off.
            revoke_all_api_tokens_for(&mut data, &target);
            store.write(&data)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Get, "/api/logs") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let limit = query_param(&raw_url, "limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(200)
                .min(MAX_LOG_ENTRIES);
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let logs = data["logs"].as_array().cloned().unwrap_or_default();
            let start = logs.len().saturating_sub(limit);
            let recent: Vec<_> = logs[start..].iter().rev().cloned().collect();
            Ok(json_response(200, json!({"logs": recent})))
        }
        (Method::Get, "/api/settings") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let smtp = data["settings"]["smtp"].clone();
            let logo_configured = data["settings"]["branding"]["logo_data_url"]
                .as_str()
                .map(|value| !value.is_empty())
                .unwrap_or(false);
            Ok(json_response(
                200,
                json!({
                    "app_name": APP_NAME,
                    "smtp": smtp,
                    "logo_configured": logo_configured,
                    "file_versions_to_keep": versions_to_keep()
                }),
            ))
        }
        (Method::Get, "/api/files") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            Ok(json_response(
                200,
                list_synced_files(&state.data_dir, &user)?,
            ))
        }
        (Method::Get, path) if path.starts_with("/api/files/") && path.ends_with("/versions") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let trimmed = path
                .trim_start_matches("/api/files/")
                .trim_end_matches("/versions");
            let rel_path = urlencoding::decode(trimmed)?.into_owned();
            let owner_param = query_param(&raw_url, "owner")
                .map(|s| s.to_lowercase())
                .filter(|email| {
                    user["is_admin"].as_bool().unwrap_or(false)
                        || email == user["email"].as_str().unwrap_or("")
                })
                .unwrap_or_else(|| user["email"].as_str().unwrap_or("").to_owned());
            Ok(json_response(
                200,
                list_file_versions(&state.data_dir, &owner_param, &rel_path)?,
            ))
        }
        (Method::Post, path)
            if path.starts_with("/api/files/")
                && path.contains("/versions/")
                && path.ends_with("/restore") =>
        {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            // Path layout: /api/files/{rel_path}/versions/{version_name}/restore
            // `rel_path` may contain slashes; `version_name` is generated by
            // write_versioned_file as `{millis}-{base64}` and never contains
            // slashes, so split on the *last* "/versions/" segment.
            let body = path.trim_end_matches("/restore");
            let Some((left, version_name_raw)) = body.rsplit_once("/versions/") else {
                return Ok(json_response(400, json!({"error": "invalid path"})));
            };
            let rel_path_encoded = left.trim_start_matches("/api/files/");
            let rel_path = urlencoding::decode(rel_path_encoded)?.into_owned();
            let version_name = urlencoding::decode(version_name_raw)?.into_owned();
            let owner_param = query_param(&raw_url, "owner")
                .map(|s| s.to_lowercase())
                .filter(|email| {
                    user["is_admin"].as_bool().unwrap_or(false)
                        || email == user["email"].as_str().unwrap_or("")
                })
                .unwrap_or_else(|| user["email"].as_str().unwrap_or("").to_owned());
            match restore_file_version(&state.data_dir, &owner_param, &rel_path, &version_name) {
                Ok(result) => Ok(json_response(200, result)),
                Err(err) => Ok(json_response(400, json!({"error": err.to_string()}))),
            }
        }
        (Method::Get, path) if path.starts_with("/api/files/") => {
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if let Some(response) = require_setup_complete(&data) {
                return Ok(response);
            }
            drop(store);
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let rel_path =
                urlencoding::decode(path.trim_start_matches("/api/files/"))?.into_owned();
            let relative = safe_relative_path(&rel_path)?;
            let owner = query_param(&raw_url, "owner")
                .map(|s| s.to_lowercase())
                .filter(|email| {
                    user["is_admin"].as_bool().unwrap_or(false)
                        || email == user["email"].as_str().unwrap_or("")
                })
                .unwrap_or_else(|| user["email"].as_str().unwrap_or("unknown").to_owned());
            let file_path = state.data_dir.join("files").join(&owner).join(relative);
            if !file_path.exists() {
                return Ok(json_response(404, json!({"error": "file not found"})));
            }
            Ok(response(
                200,
                fs::read(file_path)?,
                "application/octet-stream",
            ))
        }
        // ---------------------------------------------------------------
        // Persistent desktop API tokens. Web sessions remain the primary
        // bearer for the SPA, but the desktop client needs a long-lived
        // token it can paste into its config file. Every authenticated
        // user can manage their own tokens; admins can manage any user's.
        // ---------------------------------------------------------------
        (Method::Get, "/api/tokens") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let email = user["email"].as_str().unwrap_or("");
            Ok(json_response(
                200,
                json!({"tokens": list_api_tokens_for(&data, email)}),
            ))
        }
        (Method::Post, "/api/tokens") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = read_body(&mut request)?;
            let label = body["label"].as_str().unwrap_or("Desktop client");
            if label.len() > 64 {
                return Ok(json_response(
                    400,
                    json!({"error": "label must be 64 characters or fewer"}),
                ));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let email = user["email"].as_str().unwrap_or("").to_owned();
            let (raw, id, entry) = mint_api_token(&mut data, &email, label);
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({"token": raw, "id": id, "entry": entry}),
            ))
        }
        (Method::Delete, path) if path.starts_with("/api/tokens/") => {
            let Some(user) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let id = urlencoding::decode(path.trim_start_matches("/api/tokens/"))?.into_owned();
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let email = user["email"].as_str().unwrap_or("");
            let removed = revoke_api_token(&mut data, email, &id);
            if removed {
                store.write(&data)?;
                Ok(json_response(200, json!({"ok": true})))
            } else {
                Ok(json_response(404, json!({"error": "token not found"})))
            }
        }
        (Method::Get, path)
            if path.starts_with("/api/admin/users/") && path.ends_with("/tokens") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let target = urlencoding::decode(
                path.trim_start_matches("/api/admin/users/")
                    .trim_end_matches("/tokens"),
            )?
            .into_owned()
            .to_lowercase();
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if !can_admin_user(&data, &actor, &target) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            Ok(json_response(
                200,
                json!({"tokens": list_api_tokens_for(&data, &target)}),
            ))
        }
        (Method::Post, path)
            if path.starts_with("/api/admin/users/") && path.ends_with("/tokens") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let target = urlencoding::decode(
                path.trim_start_matches("/api/admin/users/")
                    .trim_end_matches("/tokens"),
            )?
            .into_owned()
            .to_lowercase();
            let body = read_body(&mut request)?;
            let label = body["label"].as_str().unwrap_or("Desktop client");
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if !can_admin_user(&data, &actor, &target) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            if data["users"].get(&target).is_none() {
                return Ok(json_response(404, json!({"error": "user not found"})));
            }
            let (raw, id, entry) = mint_api_token(&mut data, &target, label);
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({"token": raw, "id": id, "entry": entry}),
            ))
        }
        (Method::Delete, path)
            if path.starts_with("/api/admin/users/") && path.contains("/tokens/") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = path.trim_start_matches("/api/admin/users/");
            let Some((email_part, id_part)) = body.split_once("/tokens/") else {
                return Ok(json_response(400, json!({"error": "invalid path"})));
            };
            let target = urlencoding::decode(email_part)?.into_owned().to_lowercase();
            let id = urlencoding::decode(id_part)?.into_owned();
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if !can_admin_user(&data, &actor, &target) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            let removed = revoke_api_token(&mut data, &target, &id);
            if removed {
                store.write(&data)?;
                Ok(json_response(200, json!({"ok": true})))
            } else {
                Ok(json_response(404, json!({"error": "token not found"})))
            }
        }
        // ---------------------------------------------------------------
        // Group management. Groups exist so a non-global admin can
        // administer their own slice of users (a "family" or "friends"
        // group). Membership is many-to-many; each group can have
        // multiple admins; group admins can promote other members of the
        // same group to group admin.
        // ---------------------------------------------------------------
        (Method::Get, "/api/groups") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
            let visible: Vec<Value> = data["groups"]
                .as_object()
                .into_iter()
                .flat_map(|map| map.iter())
                .filter(|(id, _)| {
                    is_global_admin(&actor)
                        || is_group_admin(&data, &actor_email, id)
                        || data["groups"][*id]["members"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|m| m.as_str() == Some(actor_email.as_str()))
                })
                .map(|(_, group)| group.clone())
                .collect();
            Ok(json_response(200, json!({"groups": visible})))
        }
        (Method::Post, "/api/groups") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            // Only global admins can create new groups; group admins can
            // only manage groups they already admin.
            if !is_global_admin(&actor) {
                return Ok(json_response(
                    403,
                    json!({"error": "global admin required to create groups"}),
                ));
            }
            let body = read_body(&mut request)?;
            let id = body["id"].as_str().unwrap_or("").trim().to_lowercase();
            let name = body["name"].as_str().unwrap_or("").trim();
            if !is_safe_group_id(&id) {
                return Ok(json_response(
                    400,
                    json!({"error": "id must be 1-64 chars of [A-Za-z0-9_-]"}),
                ));
            }
            if name.is_empty() || name.len() > 128 {
                return Ok(json_response(
                    400,
                    json!({"error": "name is required (max 128 chars)"}),
                ));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if data["groups"].get(&id).is_some() {
                return Ok(json_response(409, json!({"error": "group already exists"})));
            }
            let initial_admins: Vec<Value> = body["admins"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| json!(s.to_lowercase())))
                .collect();
            let initial_members: Vec<Value> = body["members"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| json!(s.to_lowercase())))
                .collect();
            data["groups"][&id] = json!({
                "id": id,
                "name": name,
                "admins": initial_admins,
                "members": initial_members,
                "created_at": unix_time(),
                "created_by": actor["email"].as_str().unwrap_or("")
            });
            store.write(&data)?;
            Ok(json_response(201, data["groups"][&id].clone()))
        }
        (Method::Delete, path) if path.starts_with("/api/groups/") && !path.contains("/members") && !path.contains("/admins") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !is_global_admin(&actor) {
                return Ok(json_response(403, json!({"error": "global admin required"})));
            }
            let id = urlencoding::decode(path.trim_start_matches("/api/groups/"))?.into_owned();
            if !is_safe_group_id(&id) {
                return Ok(json_response(400, json!({"error": "invalid group id"})));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let removed = data["groups"]
                .as_object_mut()
                .map(|map| map.remove(&id).is_some())
                .unwrap_or(false);
            if removed {
                store.write(&data)?;
                Ok(json_response(200, json!({"ok": true})))
            } else {
                Ok(json_response(404, json!({"error": "group not found"})))
            }
        }
        (Method::Post, path)
            if path.starts_with("/api/groups/") && path.ends_with("/members") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let id = urlencoding::decode(
                path.trim_start_matches("/api/groups/")
                    .trim_end_matches("/members"),
            )?
            .into_owned();
            if !is_safe_group_id(&id) {
                return Ok(json_response(400, json!({"error": "invalid group id"})));
            }
            let body = read_body(&mut request)?;
            let target = body["email"]
                .as_str()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if target.is_empty() {
                return Ok(json_response(400, json!({"error": "email required"})));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
            if !is_global_admin(&actor) && !is_group_admin(&data, &actor_email, &id) {
                return Ok(json_response(
                    403,
                    json!({"error": "must be a global or group admin"}),
                ));
            }
            if data["groups"].get(&id).is_none() {
                return Ok(json_response(404, json!({"error": "group not found"})));
            }
            if data["users"].get(&target).is_none() {
                return Ok(json_response(404, json!({"error": "user not found"})));
            }
            let members = data["groups"][&id]["members"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if !members.iter().any(|m| m.as_str() == Some(target.as_str())) {
                let mut updated = members;
                updated.push(json!(target));
                data["groups"][&id]["members"] = json!(updated);
                store.write(&data)?;
            }
            Ok(json_response(200, data["groups"][&id].clone()))
        }
        (Method::Delete, path)
            if path.starts_with("/api/groups/") && path.contains("/members/") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = path.trim_start_matches("/api/groups/");
            let Some((id_part, email_part)) = body.split_once("/members/") else {
                return Ok(json_response(400, json!({"error": "invalid path"})));
            };
            let id = urlencoding::decode(id_part)?.into_owned();
            let target = urlencoding::decode(email_part)?.into_owned().to_lowercase();
            if !is_safe_group_id(&id) {
                return Ok(json_response(400, json!({"error": "invalid group id"})));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
            if !is_global_admin(&actor) && !is_group_admin(&data, &actor_email, &id) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            if data["groups"].get(&id).is_none() {
                return Ok(json_response(404, json!({"error": "group not found"})));
            }
            let mut members: Vec<Value> = data["groups"][&id]["members"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            members.retain(|m| m.as_str() != Some(target.as_str()));
            // Removing a member also strips them from the group's admins
            // list so we don't end up with an admin who isn't a member.
            let mut admins: Vec<Value> = data["groups"][&id]["admins"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            admins.retain(|m| m.as_str() != Some(target.as_str()));
            data["groups"][&id]["members"] = json!(members);
            data["groups"][&id]["admins"] = json!(admins);
            store.write(&data)?;
            Ok(json_response(200, data["groups"][&id].clone()))
        }
        (Method::Post, path)
            if path.starts_with("/api/groups/") && path.contains("/admins/") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = path.trim_start_matches("/api/groups/");
            let Some((id_part, email_part)) = body.split_once("/admins/") else {
                return Ok(json_response(400, json!({"error": "invalid path"})));
            };
            let id = urlencoding::decode(id_part)?.into_owned();
            let target = urlencoding::decode(email_part)?.into_owned().to_lowercase();
            if !is_safe_group_id(&id) {
                return Ok(json_response(400, json!({"error": "invalid group id"})));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
            if !is_global_admin(&actor) && !is_group_admin(&data, &actor_email, &id) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            if data["groups"].get(&id).is_none() {
                return Ok(json_response(404, json!({"error": "group not found"})));
            }
            // Promotion target must already be a member of the group.
            let is_member = data["groups"][&id]["members"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|m| m.as_str() == Some(target.as_str()));
            if !is_member {
                return Ok(json_response(
                    400,
                    json!({"error": "user must be a member of the group first"}),
                ));
            }
            let mut admins: Vec<Value> = data["groups"][&id]["admins"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if !admins.iter().any(|m| m.as_str() == Some(target.as_str())) {
                admins.push(json!(target));
                data["groups"][&id]["admins"] = json!(admins);
                store.write(&data)?;
            }
            Ok(json_response(200, data["groups"][&id].clone()))
        }
        (Method::Delete, path)
            if path.starts_with("/api/groups/") && path.contains("/admins/") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = path.trim_start_matches("/api/groups/");
            let Some((id_part, email_part)) = body.split_once("/admins/") else {
                return Ok(json_response(400, json!({"error": "invalid path"})));
            };
            let id = urlencoding::decode(id_part)?.into_owned();
            let target = urlencoding::decode(email_part)?.into_owned().to_lowercase();
            if !is_safe_group_id(&id) {
                return Ok(json_response(400, json!({"error": "invalid group id"})));
            }
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
            if !is_global_admin(&actor) && !is_group_admin(&data, &actor_email, &id) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            if data["groups"].get(&id).is_none() {
                return Ok(json_response(404, json!({"error": "group not found"})));
            }
            let mut admins: Vec<Value> = data["groups"][&id]["admins"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            admins.retain(|m| m.as_str() != Some(target.as_str()));
            data["groups"][&id]["admins"] = json!(admins);
            store.write(&data)?;
            Ok(json_response(200, data["groups"][&id].clone()))
        }
        // ---------------------------------------------------------------
        // Promote / demote a user as a global admin. Only the global
        // admin can change global-admin status. (Group admin promotion is
        // handled per-group above.)
        // ---------------------------------------------------------------
        (Method::Post, path)
            if path.starts_with("/api/admin/users/") && path.ends_with("/promote") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !is_global_admin(&actor) {
                return Ok(json_response(403, json!({"error": "global admin required"})));
            }
            let target = urlencoding::decode(
                path.trim_start_matches("/api/admin/users/")
                    .trim_end_matches("/promote"),
            )?
            .into_owned()
            .to_lowercase();
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if data["users"].get(&target).is_none() {
                return Ok(json_response(404, json!({"error": "user not found"})));
            }
            data["users"][&target]["is_admin"] = json!(true);
            store.write(&data)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Post, path)
            if path.starts_with("/api/admin/users/") && path.ends_with("/demote") =>
        {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            if !is_global_admin(&actor) {
                return Ok(json_response(403, json!({"error": "global admin required"})));
            }
            let target = urlencoding::decode(
                path.trim_start_matches("/api/admin/users/")
                    .trim_end_matches("/demote"),
            )?
            .into_owned()
            .to_lowercase();
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            if data["users"].get(&target).is_none() {
                return Ok(json_response(404, json!({"error": "user not found"})));
            }
            // Don't let the last global admin demote themselves into an
            // unmanageable system.
            let remaining_admins = data["users"]
                .as_object()
                .into_iter()
                .flat_map(|map| map.iter())
                .filter(|(email, user)| {
                    email.as_str() != target && user["is_admin"].as_bool().unwrap_or(false)
                })
                .count();
            if remaining_admins == 0 {
                return Ok(json_response(
                    400,
                    json!({"error": "cannot demote the last global admin"}),
                ));
            }
            data["users"][&target]["is_admin"] = json!(false);
            store.write(&data)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        // ---------------------------------------------------------------
        // Game Saves API. Backed by `data_dir/files/{owner}/...` (the same
        // tree the desktop client pushes to). The hierarchy is
        // owner → emulator → game → file. Drilldown is path-based:
        // every level is "list children" and every leaf is "download".
        // ---------------------------------------------------------------
        (Method::Get, "/api/saves/users") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let owners = visible_user_emails(&data, &actor);
            // Annotate each visible user with the count of emulator-level
            // subfolders so the UI can show empty rows distinctly.
            let entries: Vec<Value> = owners
                .into_iter()
                .map(|email| {
                    let dir = state.data_dir.join("files").join(&email);
                    let emulators = if dir.exists() {
                        fs::read_dir(&dir)
                            .ok()
                            .into_iter()
                            .flatten()
                            .filter_map(|e| e.ok())
                            .filter(|e| e.path().is_dir())
                            .count()
                    } else {
                        0
                    };
                    json!({"email": email, "emulator_count": emulators})
                })
                .collect();
            Ok(json_response(200, json!({"users": entries})))
        }
        (Method::Get, path) if path.starts_with("/api/saves/list/") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let owner = urlencoding::decode(path.trim_start_matches("/api/saves/list/"))?
                .into_owned()
                .to_lowercase();
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if !can_admin_user(&data, &actor, &owner) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            let sub = query_param(&raw_url, "path").unwrap_or("");
            let resolved = resolve_save_path(&state.data_dir, &owner, sub)?;
            Ok(json_response(200, list_save_directory(&resolved)?))
        }
        (Method::Get, path) if path.starts_with("/api/saves/file/") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let owner = urlencoding::decode(path.trim_start_matches("/api/saves/file/"))?
                .into_owned()
                .to_lowercase();
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if !can_admin_user(&data, &actor, &owner) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            let sub = query_param(&raw_url, "path").unwrap_or("");
            let decoded_sub = urlencoding::decode(sub)?.into_owned();
            let resolved = resolve_save_path(&state.data_dir, &owner, &decoded_sub)?;
            if !resolved.exists() || !resolved.is_file() {
                return Ok(json_response(404, json!({"error": "file not found"})));
            }
            Ok(response(
                200,
                fs::read(&resolved)?,
                "application/octet-stream",
            ))
        }
        (Method::Get, path) if path.starts_with("/api/saves/zip/") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let owner = urlencoding::decode(path.trim_start_matches("/api/saves/zip/"))?
                .into_owned()
                .to_lowercase();
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            if !can_admin_user(&data, &actor, &owner) {
                return Ok(json_response(403, json!({"error": "not allowed"})));
            }
            let sub = query_param(&raw_url, "path").unwrap_or("");
            let decoded_sub = urlencoding::decode(sub)?.into_owned();
            let resolved = resolve_save_path(&state.data_dir, &owner, &decoded_sub)?;
            if !resolved.exists() || !resolved.is_dir() {
                return Ok(json_response(404, json!({"error": "folder not found"})));
            }
            let bytes = zip_directory(&resolved)?;
            Ok(response(200, bytes, "application/zip"))
        }
        // ---------------------------------------------------------------
        // Scoped emulator-update fan-out. The bundle the server publishes
        // is shared (a single zip per emulator/os), so the underlying
        // mechanism is unchanged from `/api/admin/apply-emulator-update`,
        // but this endpoint records the targeted scope and enforces RBAC
        // so a non-global admin can only update users they administer.
        // Body: {"scope":"all|user|os|emulator","users":[...],"os":"all|windows|linux","emulator_ids":[...]}
        // ---------------------------------------------------------------
        (Method::Post, "/api/emulators/update") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let body = read_body(&mut request)?;
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            // Normalize the requested user list. Empty / "all" means "every
            // user the actor can administer".
            let actor_email = actor["email"].as_str().unwrap_or("").to_owned();
            let visible = visible_user_emails(&data, &actor);
            let requested_users: Vec<String> = body["users"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect();
            let target_users: Vec<String> = if requested_users.is_empty() {
                visible.clone()
            } else {
                requested_users
                    .into_iter()
                    .filter(|email| visible.contains(email))
                    .collect()
            };
            if target_users.is_empty() {
                return Ok(json_response(
                    403,
                    json!({"error": "no users in your administrable scope"}),
                ));
            }
            // Standard users without any group-admin powers can only
            // update their own emulators.
            if !is_global_admin(&actor)
                && admin_group_ids_for(&data, &actor_email).is_empty()
                && (target_users.len() != 1 || target_users[0] != actor_email)
            {
                return Ok(json_response(
                    403,
                    json!({"error": "standard users can only update their own emulators"}),
                ));
            }
            let target_os = body["os"].as_str().unwrap_or("all").to_owned();
            let os_targets: Vec<&str> = match target_os.as_str() {
                "all" => vec!["windows", "linux"],
                "windows" => vec!["windows"],
                "linux" => vec!["linux"],
                _ => {
                    return Ok(json_response(
                        400,
                        json!({"error": "os must be 'all', 'windows', or 'linux'"}),
                    ));
                }
            };
            let requested_emulators: Vec<String> = body["emulator_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            let target_emulators: Vec<String> = if requested_emulators.is_empty() {
                manifest()["emulators"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e["id"].as_str().map(str::to_owned))
                    .collect()
            } else {
                requested_emulators
            };
            drop(store);
            // Publish each (emulator, os) bundle once; the bundle is
            // shared across users but we record the targeted users for
            // audit purposes.
            let mut published: Vec<Value> = Vec::new();
            let mut errors: Vec<Value> = Vec::new();
            for id in &target_emulators {
                let Some(emulator) = emulator_by_id(id) else {
                    errors.push(
                        json!({"emulator_id": id, "error": "unknown emulator id"}),
                    );
                    continue;
                };
                let release = match latest_release(&emulator) {
                    Ok(r) => r,
                    Err(error) => {
                        errors.push(json!({
                            "emulator_id": id,
                            "error": format!("failed to query upstream: {error}")
                        }));
                        continue;
                    }
                };
                for os in &os_targets {
                    let asset_url = if *os == current_os() {
                        release.download_url.clone()
                    } else {
                        pick_asset(
                            &release_assets_for_os(&emulator, os).unwrap_or_default(),
                            os,
                        )
                    };
                    let Some(url) = asset_url else {
                        errors.push(json!({
                            "emulator_id": id,
                            "os": os,
                            "error": format!("no upstream asset matched for {os}")
                        }));
                        continue;
                    };
                    if !url.starts_with("https://") {
                        errors.push(json!({
                            "emulator_id": id,
                            "os": os,
                            "error": "asset URL must use HTTPS"
                        }));
                        continue;
                    }
                    let bytes = match ureq::get(&url)
                        .header("User-Agent", "crash-crafts-game-sync")
                        .call()
                        .and_then(|r| r.into_body().read_to_vec())
                    {
                        Ok(b) => b,
                        Err(error) => {
                            errors.push(json!({
                                "emulator_id": id,
                                "os": os,
                                "error": format!("download failed: {error}")
                            }));
                            continue;
                        }
                    };
                    if zip::ZipArchive::new(std::io::Cursor::new(&bytes)).is_err() {
                        errors.push(json!({
                            "emulator_id": id,
                            "os": os,
                            "error": "upstream asset is not a zip; admin must repackage"
                        }));
                        continue;
                    }
                    let dir = state.data_dir.join("emulator-bundles").join(id);
                    secure_create_dir_all(&dir)?;
                    let target_path = dir.join(format!("{os}.zip"));
                    fs::write(&target_path, &bytes)?;
                    published.push(json!({
                        "emulator_id": id,
                        "os": os,
                        "version": release.version,
                        "bytes": bytes.len(),
                        "users": target_users
                    }));
                    // Persist applied version + per-user audit trail.
                    let store = state.store.lock().unwrap();
                    let mut data = store.read()?;
                    if !data["applied_emulator_versions"].is_object() {
                        data["applied_emulator_versions"] = json!({});
                    }
                    data["applied_emulator_versions"][id] = json!({
                        "version": release.version,
                        "published_at": release.published_at,
                        "applied_at": unix_time(),
                        "applied_by": actor_email
                    });
                    if !data["user_emulator_targets"].is_object() {
                        data["user_emulator_targets"] = json!({});
                    }
                    for email in &target_users {
                        if !data["user_emulator_targets"][email].is_object() {
                            data["user_emulator_targets"][email] = json!({});
                        }
                        if !data["user_emulator_targets"][email][id].is_object() {
                            data["user_emulator_targets"][email][id] = json!({});
                        }
                        data["user_emulator_targets"][email][id][os] = json!({
                            "version": release.version,
                            "applied_at": unix_time(),
                            "applied_by": actor_email
                        });
                    }
                    store.write(&data)?;
                }
            }
            Ok(json_response(
                200,
                json!({
                    "ok": !published.is_empty(),
                    "users": target_users,
                    "os": target_os,
                    "emulators": target_emulators,
                    "published": published,
                    "errors": errors
                }),
            ))
        }
        // List the per-user / per-OS / per-emulator update state visible
        // to the actor. Drives the Emulators tab drilldown UI.
        (Method::Get, "/api/emulators/scoped") => {
            let Some(actor) = require_user(&state, &request)? else {
                return Ok(json_response(
                    401,
                    json!({"error": "missing or invalid bearer token"}),
                ));
            };
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let visible = visible_user_emails(&data, &actor);
            let manifest = manifest();
            let emulators: Vec<Value> = manifest["emulators"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|e| {
                    json!({
                        "id": e["id"],
                        "name": e["name"]
                    })
                })
                .collect();
            let users: Vec<Value> = visible
                .into_iter()
                .map(|email| {
                    let targets = data["user_emulator_targets"][&email].clone();
                    json!({"email": email, "targets": targets})
                })
                .collect();
            Ok(json_response(
                200,
                json!({
                    "users": users,
                    "emulators": emulators,
                    "applied": data["applied_emulator_versions"].clone()
                }),
            ))
        }
        _ => Ok(json_response(404, json!({"error": "not found"}))),
    })();
    let response =
        result.unwrap_or_else(|error| json_response(500, json!({"error": error.to_string()})));
    let _ = request.respond(response);
}

fn optional_arg_value(args: &[String], name: &str, fallback: &str) -> String {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
        .unwrap_or_else(|| fallback.to_owned())
}

fn run_server(args: &[String]) -> AppResult<()> {
    let data_dir = PathBuf::from(optional_arg_value(args, "--data-dir", "/data"));
    let host = optional_arg_value(args, "--host", "127.0.0.1");
    let port = optional_arg_value(args, "--port", "8080");
    // Step-by-step stderr logging so a crash-loop in Docker prints a
    // breadcrumb trail in `docker logs` instead of an empty buffer. stderr
    // is line-buffered, so each `eprintln!` is flushed before we move on.
    eprintln!(
        "{APP_NAME}: preparing data directory {} (host={host} port={port})",
        data_dir.display()
    );
    let store =
        bootstrap_store(&data_dir).map_err(|err| -> Box<dyn std::error::Error + Send + Sync> {
            format!(
                "failed to initialize data directory {}: {err} \
                 (the directory must be writable by the container's runtime user; \
                 if you reused an existing Docker volume from a previous build, \
                 either remove it with `docker volume rm <name>` or `chown` its \
                 contents to the container user)",
                data_dir.display(),
            )
            .into()
        })?;
    eprintln!("{APP_NAME}: binding TCP listener on {host}:{port}");
    let server = Server::http(format!("{host}:{port}")).map_err(
        |err| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to bind {host}:{port}: {err}").into()
        },
    )?;
    let state = Arc::new(AppState {
        data_dir: data_dir.clone(),
        store: Mutex::new(store),
    });
    eprintln!("{APP_NAME} server listening on http://{host}:{port}");
    for request in server.incoming_requests() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || handle_request(request, state));
    }
    Ok(())
}

pub fn validate_server_url(server: &str) -> AppResult<&str> {
    if server.starts_with("https://") {
        return Ok(server);
    }
    if let Some(host) = server.strip_prefix("http://") {
        if host.starts_with("[::1]") {
            return Ok(server);
        }
        let host = host.split(['/', ':']).next().unwrap_or("");
        if matches!(host, "localhost" | "127.0.0.1") {
            return Ok(server);
        }
    }
    Err("server URL must use HTTPS unless it targets localhost".into())
}

fn arg_value(args: &[String], name: &str) -> AppResult<String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
        .ok_or_else(|| format!("{name} is required").into())
}

fn cmd_upload_log(args: &[String]) -> AppResult<()> {
    let server = validate_server_url(&arg_value(args, "--server")?)?
        .trim_end_matches('/')
        .to_owned();
    let token = arg_value(args, "--token")?;
    let level = args
        .windows(2)
        .find(|window| window[0] == "--level")
        .map(|window| window[1].clone())
        .unwrap_or_else(|| "info".to_owned());
    let message = args.last().ok_or("message is required")?.clone();
    let mut response = ureq::post(&format!("{server}/api/logs"))
        .header("Authorization", &format!("Bearer {token}"))
        .send_json(
            json!({"level": level, "message": message, "context": {"client": "crash-crafts-game-sync-cli"}}),
        )?
        .into_body();
    let result: Value = response.read_json()?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn cmd_healthcheck(args: &[String]) -> AppResult<()> {
    let url = args
        .windows(2)
        .find(|window| window[0] == "--url")
        .map(|window| window[1].clone())
        .unwrap_or_else(|| "http://127.0.0.1:8080/api/health".to_owned());
    let mut response = ureq::get(validate_server_url(&url)?).call()?.into_body();
    let result: Value = response.read_json()?;
    if result["ok"].as_bool() == Some(true) {
        println!("OK");
        Ok(())
    } else {
        Err("healthcheck endpoint did not report ok".into())
    }
}

fn config_path_from_args(args: &[String]) -> AppResult<PathBuf> {
    let mut arg_pairs = args.windows(2);
    arg_pairs
        .find(|window| window[0] == "--config")
        .map(|window| PathBuf::from(&window[1]))
        .map(Ok)
        .unwrap_or_else(default_desktop_config_path)
}

fn all_arg_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|window| window[0] == name)
        .map(|window| window[1].clone())
        .collect()
}

fn cmd_desktop_config(args: &[String]) -> AppResult<()> {
    let path = config_path_from_args(args)?;
    let config = if path.exists() {
        read_desktop_config(&path)?
    } else {
        DesktopConfig::default()
    };
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

pub fn desktop_companion_status(path: &Path, config: &DesktopConfig) -> Value {
    let configured = !config.auth_token.trim().is_empty()
        && validate_server_url(&config.server_url).is_ok()
        && !config.sync_roots.is_empty();
    json!({
        "mode": "desktop_companion",
        "docker_server_url": config.server_url,
        "config_path": path,
        "configured": configured,
        "auth_token_configured": !config.auth_token.trim().is_empty(),
        "sync_roots": config.sync_roots,
        "next_steps": [
            "Run setup-desktop with the Docker server URL, user token, ROM roots, and emulator roots.",
            "Start daemon after setup to sync saves with the Docker server.",
            "Use the Docker Web UI for server administration, invites, branding, and account setup."
        ]
    })
}

fn cmd_companion(args: &[String]) -> AppResult<()> {
    let path = config_path_from_args(args)?;
    let config = if path.exists() {
        read_desktop_config(&path)?
    } else {
        DesktopConfig::default()
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&desktop_companion_status(&path, &config))?
    );
    Ok(())
}

fn cmd_setup_desktop(args: &[String]) -> AppResult<()> {
    let path = config_path_from_args(args)?;
    let mut config = if path.exists() {
        read_desktop_config(&path)?
    } else {
        DesktopConfig::default()
    };
    if let Ok(server) = arg_value(args, "--server") {
        config.server_url = validate_server_url(&server)?.to_owned();
    }
    if let Ok(token) = arg_value(args, "--token") {
        config.auth_token = token;
    }
    let rom_roots = all_arg_values(args, "--rom-root");
    if !rom_roots.is_empty() {
        config.rom_roots = rom_roots;
    }
    let emulator_roots = all_arg_values(args, "--emulator-root");
    if !emulator_roots.is_empty() {
        config.emulator_roots = emulator_roots.clone();
        config.sync_roots = emulator_roots
            .iter()
            .flat_map(|root| detect_emulators(Path::new(root)))
            .filter_map(|detected| {
                let emulator_id = detected["id"].as_str()?.to_owned();
                let path = detected["path"].as_str()?.to_owned();
                Some(SyncRoot {
                    remote_prefix: emulator_id.clone(),
                    emulator_id,
                    path,
                    emulator_executable: String::new(),
                    pull_paths: Vec::new(),
                })
            })
            .collect();
    }
    if let Ok(parsers_path) = arg_value(args, "--srm-parsers") {
        config.srm.parsers_path = parsers_path;
    }
    if let Some(first_rom_root) = config.rom_roots.first() {
        config.srm.roms_directory = first_rom_root.clone();
    }
    write_desktop_config(&path, &config)?;
    let srm_path = if config.srm.install {
        Some(write_srm_parsers(&config)?)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "config_path": path,
            "service": config.service,
            "sync_roots": config.sync_roots,
            "srm_parsers_path": srm_path
        }))?
    );
    Ok(())
}

fn cmd_daemon(args: &[String]) -> AppResult<()> {
    let path = config_path_from_args(args)?;
    let config = read_desktop_config(&path)?;
    let interval_arg = optional_arg_value(args, "--interval-seconds", "60");
    let interval_seconds = interval_arg
        .parse::<u64>()
        .map_err(|_| "--interval-seconds must be a positive integer")?
        .max(5);
    let skip_heartbeat = args.iter().any(|arg| arg == "--no-heartbeat");
    loop {
        let result = run_desktop_sync_once(&config)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        if !skip_heartbeat && let Err(error) = send_heartbeat(&config, &result) {
            eprintln!("heartbeat failed: {error}");
        }
        if args.iter().any(|arg| arg == "--once") {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(interval_seconds));
    }
}

fn cmd_generate_srm(args: &[String]) -> AppResult<()> {
    let path = config_path_from_args(args)?;
    let config = read_desktop_config(&path)?;
    let output = write_srm_parsers(&config)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"srm_parsers_path": output}))?
    );
    Ok(())
}

const STATIC_GUI_HTML: &str = include_str!("../shared/web/gui.html");
const STATIC_GUI_JS: &str = include_str!("../shared/web/gui.js");

/// Run the local desktop GUI: bind a tiny HTTP server on `127.0.0.1`, open the
/// system browser to it, and serve the desktop management SPA. The server
/// exposes `/api/local/*` endpoints that read and mutate the user's
/// `desktop-config.json` and trigger sync passes against the configured
/// Docker server.
pub fn run_desktop_gui(args: &[String]) -> AppResult<()> {
    let host = optional_arg_value(args, "--host", "127.0.0.1");
    let port_arg = optional_arg_value(args, "--port", "0");
    let no_browser = args.iter().any(|arg| arg == "--no-browser");
    let config_path = config_path_from_args(args)?;
    if let Some(parent) = config_path.parent()
        && !parent.exists()
    {
        secure_create_dir_all(parent)?;
    }
    if !config_path.exists() {
        let mut default = DesktopConfig::default();
        if default.device_id.is_empty() {
            default.device_id = new_token();
        }
        write_desktop_config(&config_path, &default)?;
    }
    let server = Server::http(format!("{host}:{port_arg}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or("failed to determine local server address")?;
    let url = format!("http://{}:{}/", addr.ip(), addr.port());
    eprintln!("Crash Crafts Game Sync desktop GUI listening on {url}");
    // Drop a port hint file so the Steam Deck Decky helper plugin (and any
    // future per-OS launcher) can discover the local GUI without scanning.
    let hint_dir = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".local").join("state"))
                .unwrap_or_else(std::env::temp_dir)
        })
        .join("crash-crafts-game-sync");
    let _ = fs::create_dir_all(&hint_dir);
    let _ = fs::write(hint_dir.join("gui-port"), addr.port().to_string());
    if !no_browser {
        let _ = open_in_browser(&url);
    }
    let state = Arc::new(LocalGuiState {
        config_path,
        recent: Mutex::new(Vec::new()),
        paused: Mutex::new(false),
        local_token: new_token(),
    });
    // Drop the local-only bearer token next to the port hint so trusted
    // helpers on the same machine (e.g. the Steam Deck Decky plugin) can
    // authenticate to the loopback GUI server. The hint directory is
    // already user-private; restrict the token file further on Unix.
    let token_path = hint_dir.join("gui-token");
    let _ = fs::write(&token_path, &state.local_token);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600));
    }
    for request in server.incoming_requests() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || handle_local_request(state, request));
    }
    Ok(())
}

struct LocalGuiState {
    config_path: PathBuf,
    recent: Mutex<Vec<Value>>,
    paused: Mutex<bool>,
    /// Random per-process bearer token. The HTML shell embeds this token in
    /// a `<meta>` tag so the loopback SPA can authenticate every fetch; any
    /// other process on the same machine that wants to talk to the GUI
    /// server must read the token from the `gui-token` hint file.
    local_token: String,
}

fn handle_local_request(state: Arc<LocalGuiState>, mut request: Request) {
    let raw_url = request.url().to_owned();
    let path = raw_url.split('?').next().unwrap_or("").to_owned();
    let method = request.method().clone();
    // Loopback bearer-token gate. The HTML shell, CSS, and JS bundle stay
    // unauthenticated so the browser can bootstrap and read the token from
    // the embedded <meta> tag; everything that reads or mutates desktop
    // state requires the per-process token.
    if path.starts_with("/api/local/") {
        let provided = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_owned())
            .unwrap_or_default();
        let expected = format!("Bearer {}", state.local_token);
        if provided != expected {
            let _ = request.respond(json_response(
                401,
                json!({"error": "missing or invalid local bearer token"}),
            ));
            return;
        }
    }
    let result: AppResult<Response<std::io::Cursor<Vec<u8>>>> = (|| match (&method, path.as_str()) {
        (Method::Get, "/") | (Method::Get, "/index.html") => {
            let html = STATIC_GUI_HTML.replace("@LOCAL_TOKEN@", &state.local_token);
            Ok(response(200, html.into_bytes(), "text/html; charset=utf-8"))
        }
        (Method::Get, "/static/app.css") => Ok(response(
            200,
            STATIC_APP_CSS.as_bytes().to_vec(),
            "text/css; charset=utf-8",
        )),
        (Method::Get, "/static/gui.js") => Ok(response(
            200,
            STATIC_GUI_JS.as_bytes().to_vec(),
            "application/javascript; charset=utf-8",
        )),
        (Method::Get, "/api/local/config") => {
            let config = read_desktop_config(&state.config_path)?;
            Ok(json_response(200, serde_json::to_value(config)?))
        }
        (Method::Post, "/api/local/config") => {
            let body = read_body(&mut request)?;
            let mut config = read_desktop_config(&state.config_path)?;
            if let Some(value) = body["server_url"].as_str() {
                config.server_url = value.to_owned();
            }
            if let Some(value) = body["auth_token"].as_str() {
                config.auth_token = value.to_owned();
            }
            if let Some(value) = body["device_name"].as_str() {
                config.device_name = value.to_owned();
            }
            if config.device_id.is_empty() {
                config.device_id = new_token();
            }
            if let Some(install) = body["install_service"].as_bool() {
                config.service.install_on_setup = install;
            }
            write_desktop_config(&state.config_path, &config)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Get, "/api/local/status") => {
            let config = read_desktop_config(&state.config_path)?;
            let recent = state.recent.lock().unwrap().clone();
            let last = recent.last().cloned();
            Ok(json_response(
                200,
                json!({
                    "configured": !config.server_url.is_empty() && !config.auth_token.is_empty(),
                    "server_url": config.server_url,
                    "sync_roots": config.sync_roots.len(),
                    "state": if *state.paused.lock().unwrap() { "paused" } else { "idle" },
                    "last_pushed": last.as_ref().and_then(|v| v["pushed"].as_u64()).unwrap_or(0),
                    "last_pulled": last.as_ref().and_then(|v| v["pulled"].as_u64()).unwrap_or(0),
                    "last_errors": last.as_ref().and_then(|v| v["errors"].as_u64()).unwrap_or(0),
                    "last_sync_at": last.as_ref().and_then(|v| v["timestamp"].as_u64()).unwrap_or(0),
                    "recent": recent.iter().rev().take(10).cloned().collect::<Vec<_>>()
                }),
            ))
        }
        (Method::Post, "/api/local/sync-now") => {
            if *state.paused.lock().unwrap() {
                return Ok(json_response(409, json!({"error": "sync is paused"})));
            }
            let config = read_desktop_config(&state.config_path)?;
            let result = run_desktop_sync_once(&config)?;
            let entry = json!({
                "timestamp": unix_time(),
                "pushed": result["pushed"].as_array().map_or(0, Vec::len),
                "pulled": result["pulled"].as_array().map_or(0, Vec::len),
                "errors": result["errors"].as_array().map_or(0, Vec::len),
                "first_error": result["errors"][0]["error"].as_str().unwrap_or("")
            });
            let mut recent = state.recent.lock().unwrap();
            recent.push(entry.clone());
            if recent.len() > 100 {
                let drop = recent.len() - 100;
                recent.drain(0..drop);
            }
            drop(recent);
            // Best-effort heartbeat.
            let _ = send_heartbeat(&config, &result);
            Ok(json_response(200, json!({"ok": true, "result": result})))
        }
        (Method::Post, "/api/local/pause") => {
            let mut paused = state.paused.lock().unwrap();
            *paused = !*paused;
            Ok(json_response(200, json!({"paused": *paused})))
        }
        (Method::Get, "/api/local/emulators") => {
            let config = read_desktop_config(&state.config_path)?;
            Ok(json_response(200, list_local_emulators(&config)))
        }
        (Method::Post, "/api/local/install-emulator") => {
            let body = read_body(&mut request)?;
            let id = body["emulator_id"].as_str().unwrap_or("").to_owned();
            let config = read_desktop_config(&state.config_path)?;
            match install_emulator(&config, &id) {
                Ok(path) => Ok(json_response(200, json!({"ok": true, "path": path}))),
                Err(error) => Ok(json_response(500, json!({"error": error.to_string()}))),
            }
        }
        (Method::Post, "/api/local/enable-portable") => {
            let body = read_body(&mut request)?;
            let id = body["emulator_id"].as_str().unwrap_or("").to_owned();
            let config = read_desktop_config(&state.config_path)?;
            let Some(emulator) = emulator_by_id(&id) else {
                return Ok(json_response(404, json!({"error": "unknown emulator id"})));
            };
            let mut detected_path: Option<PathBuf> = None;
            for root in &config.emulator_roots {
                let root_path = PathBuf::from(root);
                if !root_path.exists() {
                    continue;
                }
                for found in detect_emulators(&root_path) {
                    if found["id"].as_str() == Some(&id)
                        && let Some(path) = found["path"].as_str()
                    {
                        detected_path = Some(PathBuf::from(path));
                    }
                }
            }
            let Some(install_dir) = detected_path else {
                return Ok(json_response(
                    404,
                    json!({"error": "emulator is not installed in any configured emulator root"}),
                ));
            };
            match enable_portable_mode(&emulator, &install_dir) {
                Ok(Some(path)) => Ok(json_response(
                    200,
                    json!({"ok": true, "path": path.to_string_lossy()}),
                )),
                Ok(None) => Ok(json_response(
                    200,
                    json!({"ok": true, "path": install_dir.to_string_lossy()}),
                )),
                Err(error) => Ok(json_response(500, json!({"error": error.to_string()}))),
            }
        }
        (Method::Get, "/api/local/srm") => {
            let config = read_desktop_config(&state.config_path)?;
            Ok(json_response(200, srm_status(&config)))
        }
        (Method::Post, "/api/local/install-srm") => {
            let config = read_desktop_config(&state.config_path)?;
            match install_srm(&config) {
                Ok(path) => Ok(json_response(200, json!({"ok": true, "path": path}))),
                Err(error) => Ok(json_response(500, json!({"error": error.to_string()}))),
            }
        }
        (Method::Post, "/api/local/generate-srm") => {
            let config = read_desktop_config(&state.config_path)?;
            let path = write_srm_parsers(&config)?;
            Ok(json_response(200, json!({"ok": true, "path": path})))
        }
        (Method::Get, "/api/local/folders") => {
            let config = read_desktop_config(&state.config_path)?;
            Ok(json_response(
                200,
                json!({"emulator_roots": config.emulator_roots, "rom_roots": config.rom_roots}),
            ))
        }
        (Method::Post, "/api/local/folders") => {
            let body = read_body(&mut request)?;
            let mut config = read_desktop_config(&state.config_path)?;
            if let Some(add) = body.get("add") {
                let kind = add["type"].as_str().unwrap_or("");
                let path = add["path"].as_str().unwrap_or("").to_owned();
                if !path.is_empty() {
                    let target = if kind == "rom" {
                        &mut config.rom_roots
                    } else {
                        &mut config.emulator_roots
                    };
                    if !target.contains(&path) {
                        target.push(path);
                    }
                }
            }
            if let Some(remove) = body.get("remove") {
                let kind = remove["type"].as_str().unwrap_or("");
                let idx = remove["index"].as_u64().unwrap_or(0) as usize;
                let target = if kind == "rom" {
                    &mut config.rom_roots
                } else {
                    &mut config.emulator_roots
                };
                if idx < target.len() {
                    target.remove(idx);
                }
            }
            write_desktop_config(&state.config_path, &config)?;
            Ok(json_response(200, json!({"ok": true})))
        }
        (Method::Get, "/api/local/activity") => {
            let entries = state.recent.lock().unwrap().clone();
            Ok(json_response(
                200,
                json!({"entries": entries.iter().rev().cloned().collect::<Vec<_>>()}),
            ))
        }
        (Method::Post, "/api/local/open") => {
            let folder = query_param(&raw_url, "folder").unwrap_or("rom");
            let config = read_desktop_config(&state.config_path)?;
            let path = match folder {
                "emu" => config.emulator_roots.first().cloned(),
                "log" => Some(
                    state
                        .config_path
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                ),
                _ => config.rom_roots.first().cloned(),
            };
            if let Some(path) = path {
                let _ = open_in_browser(&path);
            }
            Ok(json_response(200, json!({"ok": true})))
        }
        _ => Ok(json_response(404, json!({"error": "not found"}))),
    })();
    let response =
        result.unwrap_or_else(|error| json_response(500, json!({"error": error.to_string()})));
    let _ = request.respond(response);
}

fn list_local_emulators(config: &DesktopConfig) -> Value {
    let manifest = manifest();
    let os = current_os();
    let mut detected: Vec<Value> = Vec::new();
    for root in &config.emulator_roots {
        let root_path = PathBuf::from(root);
        if root_path.exists() {
            for found in detect_emulators(&root_path) {
                detected.push(found);
            }
        }
    }
    let entries = manifest["emulators"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|emulator| {
            let id = emulator["id"].as_str().unwrap_or("").to_owned();
            let installed_match = detected.iter().find(|d| d["id"].as_str() == Some(&id));
            let installable = emulator_installable(&emulator, os);
            // Auto-detect available updates from the upstream release feed.
            // Network failures are tolerated so the GUI still loads when
            // offline; the front-end shows "unknown" in that case.
            let upstream = if emulator.get("release_source").is_some() {
                latest_release(&emulator).ok()
            } else {
                None
            };
            let save_paths = installed_match
                .and_then(|d| d["save_paths"].as_array().cloned())
                .unwrap_or_default();
            json!({
                "id": id,
                "name": emulator["name"].as_str().unwrap_or(""),
                "homepage": emulator["homepage"].as_str().unwrap_or(""),
                "channels": emulator["channels"].clone(),
                "installed": installed_match.is_some(),
                "portable": installed_match.and_then(|d| d["portable"].as_bool()).unwrap_or(false),
                "path": installed_match.and_then(|d| d["path"].as_str().map(str::to_owned)).unwrap_or_default(),
                "save_paths": save_paths,
                "installable": installable,
                "latest_version": upstream.as_ref().map(|r| r.version.clone()).unwrap_or_default(),
                "latest_published_at": upstream.as_ref().map(|r| r.published_at.clone()).unwrap_or_default(),
                "latest_download_url": upstream.as_ref().and_then(|r| r.download_url.clone()).unwrap_or_default(),
                "release_url": upstream.as_ref().map(|r| r.source_url.clone()).unwrap_or_default()
            })
        })
        .collect::<Vec<_>>();
    json!({"emulators": entries})
}

fn srm_status(config: &DesktopConfig) -> Value {
    let installed = !config.srm.steam_directory.trim().is_empty()
        && PathBuf::from(&config.srm.steam_directory).exists();
    let presets = srm_parser_presets(config)["parsers"].clone();
    json!({
        "installed": installed,
        "steam_directory": config.srm.steam_directory,
        "parsers_path": config.srm.parsers_path,
        "presets": presets
    })
}

fn open_in_browser(target: &str) -> AppResult<()> {
    #[cfg(target_os = "windows")]
    let cmd = ("cmd", vec!["/C", "start", "", target]);
    #[cfg(target_os = "macos")]
    let cmd: (&str, Vec<&str>) = ("open", vec![target]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd: (&str, Vec<&str>) = ("xdg-open", vec![target]);
    let _ = std::process::Command::new(cmd.0)
        .args(&cmd.1)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    Ok(())
}

fn print_usage() {
    eprintln!(
        "usage:
   crash-crafts-game-sync gui [--config <path>] [--host 127.0.0.1] [--port 0] [--no-browser]
   crash-crafts-game-sync companion [--config <path>]
   crash-crafts-game-sync server [--host 127.0.0.1] [--port 8080] [--data-dir /data]
   crash-crafts-game-sync manifest
   crash-crafts-game-sync scan --root <path>
   crash-crafts-game-sync status --root <path>
   crash-crafts-game-sync desktop-config [--config <path>]
   crash-crafts-game-sync setup-desktop [--config <path>] --server <url> --token <token> [--rom-root <path>] [--emulator-root <path>] [--srm-parsers <path>]
   crash-crafts-game-sync daemon [--config <path>] [--once] [--interval-seconds 60]
   crash-crafts-game-sync generate-srm [--config <path>]
   crash-crafts-game-sync upload-log --server <url> --token <token> [--level info] <message>
   crash-crafts-game-sync healthcheck [--url http://127.0.0.1:8080/api/health]"
    );
}

fn command_name(args: &[String]) -> &str {
    args.get(1)
        .filter(|arg| !arg.starts_with("--"))
        .map(String::as_str)
        .unwrap_or("companion")
}

pub fn run_cli() -> AppResult<()> {
    let args: Vec<String> = env::args().collect();
    match command_name(&args) {
        "companion" => cmd_companion(&args),
        "gui" => run_desktop_gui(&args),
        "server" => run_server(&args),
        "manifest" => {
            println!("{}", serde_json::to_string_pretty(&manifest())?);
            Ok(())
        }
        "scan" => {
            let root = PathBuf::from(arg_value(&args, "--root")?);
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"root": root, "emulators": detect_emulators(&root)})
                )?
            );
            Ok(())
        }
        "status" => {
            let root = PathBuf::from(arg_value(&args, "--root")?);
            let detected = detect_emulators(&root);
            let portable_missing: Vec<_> = detected
                .iter()
                .filter(|item| !item["portable"].as_bool().unwrap_or(false))
                .cloned()
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"detected": detected, "errors": [], "portable_mode_required": portable_missing})
                )?
            );
            if portable_missing.is_empty() {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        "upload-log" => cmd_upload_log(&args),
        "healthcheck" => cmd_healthcheck(&args),
        "desktop-config" => cmd_desktop_config(&args),
        "setup-desktop" => cmd_setup_desktop(&args),
        "daemon" => cmd_daemon(&args),
        "generate-srm" => cmd_generate_srm(&args),
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn manifest_contains_requested_emulators_and_dolphin_dev() {
        let manifest = manifest();
        let ids: Vec<_> = manifest["emulators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        for required in [
            "duckstation",
            "pcsx2-nightly",
            "rpcs3-nightly",
            "xenia-canary",
            "xemu",
            "cemu",
            "retroarch",
            "eden-nightly",
            "dolphin-dev",
        ] {
            assert!(ids.contains(&required));
        }
    }

    #[test]
    fn config_exclusion_prevents_device_local_config_sync() {
        let manifest = manifest();
        let dolphin = manifest["emulators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "dolphin-dev")
            .unwrap();
        assert!(should_sync("User/GC/MemoryCardA.USA.raw", dolphin));
        assert!(!should_sync("User/Config/Dolphin.ini", dolphin));
    }

    #[test]
    fn detect_emulator_and_portable_marker() {
        let temp = TempDir::new().unwrap();
        let duck = temp.path().join("DuckStation");
        fs::create_dir(&duck).unwrap();
        fs::write(duck.join("portable.txt"), "").unwrap();
        let found = detect_emulators(temp.path());
        assert_eq!(found[0]["id"], "duckstation");
        assert_eq!(found[0]["portable"], true);
    }

    #[test]
    fn detect_emulators_matches_versioned_install_dirs() {
        // Real-world install folders are versioned (PCSX2 nightlies),
        // case-mismatched (Xenia Canary), or use a brand-name binary that
        // the user dropped into a custom folder (Dolphin AppImage). The
        // detector must still recognize all of them.
        let temp = TempDir::new().unwrap();

        // PCSX2 nightly: pcsx2-v1.7.5945-windows-x64-Qt
        let pcsx2 = temp.path().join("pcsx2-v1.7.5945-windows-x64-Qt");
        fs::create_dir_all(&pcsx2).unwrap();
        fs::write(pcsx2.join("portable.ini"), "").unwrap();

        // Xenia Canary, lower-case underscore form (common on Linux).
        let xenia = temp.path().join("xenia_canary");
        fs::create_dir_all(&xenia).unwrap();
        fs::write(xenia.join("xenia_canary.exe"), "").unwrap();

        // Dolphin dev: a renamed sibling folder containing only the
        // AppImage binary — must be matched via detect_executables.
        let dolphin_parent = temp.path().join("emus-dolphin-test");
        fs::create_dir_all(&dolphin_parent).unwrap();
        fs::write(dolphin_parent.join("Dolphin-x86_64.AppImage"), "").unwrap();

        let found = detect_emulators(temp.path());
        let by_id = |id: &str| {
            found
                .iter()
                .find(|e| e["id"].as_str() == Some(id))
                .cloned()
                .unwrap_or_else(|| panic!("expected to detect {id}"))
        };

        let pcsx2_entry = by_id("pcsx2-nightly");
        assert!(
            pcsx2_entry["path"]
                .as_str()
                .unwrap()
                .ends_with("pcsx2-v1.7.5945-windows-x64-Qt"),
            "pcsx2 path was {}",
            pcsx2_entry["path"]
        );
        assert_eq!(pcsx2_entry["portable"], true);

        let xenia_entry = by_id("xenia-canary");
        assert!(
            xenia_entry["path"]
                .as_str()
                .unwrap()
                .ends_with("xenia_canary"),
            "xenia path was {}",
            xenia_entry["path"]
        );

        let dolphin_entry = by_id("dolphin-dev");
        assert!(
            dolphin_entry["path"]
                .as_str()
                .unwrap()
                .ends_with("emus-dolphin-test"),
            "dolphin path was {}",
            dolphin_entry["path"]
        );
    }

    #[test]
    fn detect_emulators_recognizes_root_when_user_points_at_install_dir() {
        // A user who points --emulator-root at the actual install folder
        // (not its parent) must still see the emulator detected.
        let temp = TempDir::new().unwrap();
        let install = temp.path().join("dolphin-master-5.0-21250-x64");
        fs::create_dir_all(&install).unwrap();
        fs::write(install.join("Dolphin.exe"), "").unwrap();
        let found = detect_emulators(&install);
        assert!(
            found.iter().any(|e| e["id"].as_str() == Some("dolphin-dev")),
            "expected dolphin-dev when root is the install dir, found={found:?}"
        );
    }

    #[test]
    fn restore_file_version_promotes_chosen_bytes_and_preserves_newer_versions() {
        let temp = TempDir::new().unwrap();
        let owner = "u@example.com";
        let rel = "saves/a.sav";

        // Three sequential writes -> live file is "v3" with two prior versions.
        write_versioned_file(temp.path(), owner, rel, b"v1").unwrap();
        write_versioned_file(temp.path(), owner, rel, b"v2").unwrap();
        write_versioned_file(temp.path(), owner, rel, b"v3").unwrap();

        let live = temp.path().join("files").join(owner).join(rel);
        assert_eq!(fs::read(&live).unwrap(), b"v3");

        let version_dir = temp.path().join("versions").join(owner).join(rel);
        let version_names: Vec<String> = fs::read_dir(&version_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            version_names.len(),
            2,
            "two prior versions should be stored"
        );
        // Sort order of versions written within the same millisecond is not
        // deterministic (tiebreaker is a random suffix), so locate the v1
        // snapshot by content rather than by index.
        let v1_name = version_names
            .iter()
            .find(|n| fs::read(version_dir.join(n)).unwrap() == b"v1")
            .expect("v1 snapshot must exist")
            .clone();

        // Restore the v1 snapshot. The current "v3" must be snapshotted as
        // a new version so the revert is non-destructive.
        let result = restore_file_version(temp.path(), owner, rel, &v1_name).unwrap();
        assert_eq!(result["restored_from"], json!(v1_name));

        // Live file is now v1.
        assert_eq!(fs::read(&live).unwrap(), b"v1");

        // Both originally-newer versions ("v1" and "v2" snapshots) must still
        // exist, and a new snapshot containing "v3" must have been added.
        let versions_after: Vec<Vec<u8>> = fs::read_dir(&version_dir)
            .unwrap()
            .map(|e| fs::read(e.unwrap().path()).unwrap())
            .collect();
        assert!(
            versions_after.iter().any(|b| b == b"v1"),
            "previously stored v1 version must remain"
        );
        assert!(
            versions_after.iter().any(|b| b == b"v2"),
            "previously stored v2 version must remain"
        );
        assert!(
            versions_after.iter().any(|b| b == b"v3"),
            "the live content prior to restore must be snapshotted, not destroyed"
        );
    }

    #[test]
    fn restore_file_version_rejects_traversal_and_missing_versions() {
        let temp = TempDir::new().unwrap();
        let owner = "u@example.com";
        let rel = "saves/a.sav";
        write_versioned_file(temp.path(), owner, rel, b"v1").unwrap();
        write_versioned_file(temp.path(), owner, rel, b"v2").unwrap();
        assert!(restore_file_version(temp.path(), owner, rel, "../etc/passwd").is_err());
        assert!(restore_file_version(temp.path(), owner, rel, "does-not-exist").is_err());
        assert!(restore_file_version(temp.path(), owner, rel, "").is_err());
    }

    #[test]
    fn versioned_storage_keeps_only_changed_versions() {
        let temp = TempDir::new().unwrap();
        assert_eq!(
            write_versioned_file(temp.path(), "u@example.com", "saves/a.sav", b"1").unwrap()["changed"],
            true
        );
        assert_eq!(
            write_versioned_file(temp.path(), "u@example.com", "saves/a.sav", b"1").unwrap()["changed"],
            false
        );
        for index in 2..9 {
            write_versioned_file(
                temp.path(),
                "u@example.com",
                "saves/a.sav",
                index.to_string().as_bytes(),
            )
            .unwrap();
        }
        let versions = fs::read_dir(temp.path().join("versions/u@example.com/saves/a.sav"))
            .unwrap()
            .count();
        assert_eq!(versions, 4);
    }

    #[test]
    fn client_requires_https_except_localhost() {
        assert_eq!(
            validate_server_url("https://sync.example.com").unwrap(),
            "https://sync.example.com"
        );
        assert_eq!(
            validate_server_url("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert!(validate_server_url("http://sync.example.com").is_err());
    }

    #[test]
    fn totp_verification() {
        let secret = new_totp_secret();
        let code = totp(&secret, 123456).unwrap();
        assert!(verify_totp(&secret, &code, Some(123456 * 30), 0));
    }

    #[test]
    fn new_store_starts_unconfigured_with_app_name() {
        let temp = TempDir::new().unwrap();
        let store = JsonStore::new(temp.path().join("state.json")).unwrap();
        let data = store.read().unwrap();
        assert_eq!(data["setup_complete"], false);
        assert_eq!(data["settings"]["app_name"], APP_NAME);
    }

    #[test]
    fn logo_upload_accepts_small_images_only() {
        let payload = general_purpose::STANDARD.encode([0_u8; 8]);
        assert!(validate_logo_data_url(&format!("data:image/png;base64,{payload}")).is_ok());
        assert!(validate_logo_data_url("data:text/html;base64,PGgxPm5vPC9oMT4=").is_err());
        let large = general_purpose::STANDARD.encode(vec![0_u8; 262_145]);
        assert!(validate_logo_data_url(&format!("data:image/png;base64,{large}")).is_err());
    }

    #[test]
    fn ui_uses_crash_crafts_branding_and_setup_panel() {
        let data = json!({
            "setup_complete": false,
            "settings": {"branding": {}, "smtp": {}, "app_name": APP_NAME}
        });
        let html = render_ui(&data);
        assert!(html.contains(APP_NAME));
        assert!(html.contains("First-run setup"));
        assert!(html.contains("Office365"));
    }

    #[test]
    fn desktop_config_round_trips_service_and_srm_settings() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("desktop-config.json");
        let config = DesktopConfig {
            server_url: "https://sync.example.com".to_owned(),
            rom_roots: vec!["/games/roms".to_owned()],
            sync_roots: vec![SyncRoot {
                emulator_id: "duckstation".to_owned(),
                path: "/games/emulators/DuckStation".to_owned(),
                emulator_executable: "/games/emulators/DuckStation/duckstation".to_owned(),
                remote_prefix: "duckstation".to_owned(),
                pull_paths: vec!["memcards/card.mcd".to_owned()],
            }],
            ..Default::default()
        };
        write_desktop_config(&path, &config).unwrap();
        let saved = read_desktop_config(&path).unwrap();
        assert_eq!(saved.service.windows_service_name, "CrashCraftsGameSync");
        assert_eq!(saved.sync_roots[0].remote_prefix, "duckstation");
    }

    #[test]
    fn companion_status_reports_docker_companion_setup_state() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("desktop-config.json");
        let empty = DesktopConfig::default();
        let empty_status = desktop_companion_status(&path, &empty);
        assert_eq!(empty_status["mode"], "desktop_companion");
        assert_eq!(empty_status["configured"], false);

        let configured = DesktopConfig {
            server_url: "https://sync.example.com".to_owned(),
            auth_token: "token".to_owned(),
            sync_roots: vec![SyncRoot {
                emulator_id: "duckstation".to_owned(),
                path: "/games/emulators/DuckStation".to_owned(),
                emulator_executable: String::new(),
                remote_prefix: "duckstation".to_owned(),
                pull_paths: Vec::new(),
            }],
            ..Default::default()
        };
        let configured_status = desktop_companion_status(&path, &configured);
        assert_eq!(configured_status["configured"], true);
        assert!(
            configured_status["next_steps"][0]
                .as_str()
                .unwrap()
                .contains("Docker server URL")
        );
    }

    #[test]
    fn no_command_or_config_only_defaults_to_companion() {
        assert_eq!(
            command_name(&["crash-crafts-game-sync".to_owned()]),
            "companion"
        );
        assert_eq!(
            command_name(&[
                "crash-crafts-game-sync".to_owned(),
                "--config".to_owned(),
                "desktop-config.json".to_owned()
            ]),
            "companion"
        );
        assert_eq!(
            command_name(&["crash-crafts-game-sync".to_owned(), "server".to_owned()]),
            "server"
        );
    }

    #[test]
    fn sync_collection_respects_manifest_include_and_exclude_rules() {
        let temp = TempDir::new().unwrap();
        let duck = temp.path().join("DuckStation");
        fs::create_dir_all(duck.join("memcards")).unwrap();
        fs::create_dir_all(duck.join("inputprofiles")).unwrap();
        fs::write(duck.join("memcards/card.mcd"), b"save").unwrap();
        fs::write(duck.join("settings.ini"), b"local").unwrap();
        fs::write(duck.join("inputprofiles/pad.ini"), b"local").unwrap();
        let emulator = emulator_by_id("duckstation").unwrap();
        let files = collect_sync_files(&duck, &emulator).unwrap();
        assert_eq!(files, vec![duck.join("memcards/card.mcd")]);
    }

    #[test]
    fn enable_portable_mode_creates_marker_file_idempotently() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("DuckStation");
        fs::create_dir_all(&install_dir).unwrap();
        let emulator = emulator_by_id("duckstation").unwrap();
        let path = enable_portable_mode(&emulator, &install_dir)
            .unwrap()
            .unwrap();
        assert!(path.ends_with("portable.txt"));
        assert!(path.exists());
        // Repeat invocation must not error and must not clobber any
        // existing content the user may have hand-edited.
        fs::write(&path, b"user-edited").unwrap();
        let path_again = enable_portable_mode(&emulator, &install_dir)
            .unwrap()
            .unwrap();
        assert_eq!(path, path_again);
        assert_eq!(fs::read(&path).unwrap(), b"user-edited");
    }

    #[test]
    fn extract_bundle_skips_device_local_config_files_on_update_for_rpcs3() {
        // Build a minimal in-memory zip that mimics a server-curated RPCS3
        // bundle: a fresh executable plus a default config.yml. On a first
        // install we want the config.yml to land so the emulator works out
        // of the box. On a subsequent install (update), the user's hand-
        // tuned config.yml MUST survive — the bundle's copy must be
        // skipped.
        use std::io::{Cursor, Write};
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("rpcs3.exe", opts).unwrap();
            zip.write_all(b"NEW-BINARY-v2").unwrap();
            zip.start_file("config.yml", opts).unwrap();
            zip.write_all(b"GPU: Default\n").unwrap();
            zip.start_file("GuiConfigs/CurrentSettings.ini", opts)
                .unwrap();
            zip.write_all(b"theme=light").unwrap();
            zip.finish().unwrap();
        }
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("RPCS3");
        let emulator = emulator_by_id("rpcs3-nightly").unwrap();
        // First install: no skips, every file should land.
        let skipped = extract_bundle_into(&buf, &install_dir, &emulator, false).unwrap();
        assert!(
            skipped.is_empty(),
            "first install must not skip anything, skipped={skipped:?}"
        );
        assert_eq!(
            fs::read(install_dir.join("config.yml")).unwrap(),
            b"GPU: Default\n"
        );
        // User now hand-edits config.yml with their device-specific GPU.
        fs::write(install_dir.join("config.yml"), b"GPU: Vulkan\n").unwrap();
        // Update: the bundle's config.yml MUST be skipped because RPCS3's
        // sync_exclude lists it.
        let skipped = extract_bundle_into(&buf, &install_dir, &emulator, true).unwrap();
        assert!(
            skipped.iter().any(|p| p == "config.yml"),
            "config.yml should have been skipped on update, skipped={skipped:?}"
        );
        // The user's hand-edited config.yml must be untouched.
        assert_eq!(
            fs::read(install_dir.join("config.yml")).unwrap(),
            b"GPU: Vulkan\n"
        );
        // The binary should have been refreshed.
        assert_eq!(
            fs::read(install_dir.join("rpcs3.exe")).unwrap(),
            b"NEW-BINARY-v2"
        );
    }

    #[test]
    fn extract_bundle_rejects_zip_slip_path() {
        use std::io::{Cursor, Write};
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("../escaped.txt", opts).unwrap();
            zip.write_all(b"escape").unwrap();
            zip.finish().unwrap();
        }
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("emu");
        fs::create_dir_all(&install_dir).unwrap();
        let emulator = emulator_by_id("duckstation").unwrap();
        let result = extract_bundle_into(&buf, &install_dir, &emulator, false);
        assert!(result.is_err(), "zip-slip entry must be rejected");
    }

    #[test]
    fn detect_emulators_reports_save_paths_for_each_emulator() {
        let temp = TempDir::new().unwrap();
        let cemu = temp.path().join("Cemu");
        fs::create_dir_all(cemu.join("mlc01/usr/save")).unwrap();
        fs::write(cemu.join("settings.xml"), b"").unwrap();
        let found = detect_emulators(temp.path());
        let cemu_entry = found.iter().find(|e| e["id"] == "cemu").unwrap();
        let save_paths: Vec<&str> = cemu_entry["save_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.as_str())
            .collect();
        assert!(save_paths.iter().any(|p| p.ends_with("mlc01/usr/save")));
    }

    #[test]
    fn manifest_has_release_source_and_save_paths_for_every_emulator() {
        let manifest = manifest();
        for emulator in manifest["emulators"].as_array().unwrap() {
            let id = emulator["id"].as_str().unwrap();
            assert!(
                emulator.get("release_source").is_some(),
                "{id} is missing release_source for upstream update detection"
            );
            assert!(
                emulator["save_paths"]
                    .as_array()
                    .map(|arr| !arr.is_empty())
                    .unwrap_or(false),
                "{id} is missing save_paths for save-location auto-detection"
            );
            assert!(
                emulator
                    .get("portable_marker_to_create")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false),
                "{id} is missing portable_marker_to_create for auto portable mode"
            );
        }
    }

    #[test]
    fn pick_asset_matches_per_os_naming_conventions() {
        let assets = json!([
            {"name": "duckstation-windows-x64.zip", "browser_download_url": "https://example/win.zip"},
            {"name": "duckstation-linux-x64.AppImage", "browser_download_url": "https://example/linux.AppImage"},
            {"name": "Source code (zip)", "browser_download_url": "https://example/source.zip"}
        ]);
        assert_eq!(
            pick_asset(&assets, "windows"),
            Some("https://example/win.zip".to_owned())
        );
        assert_eq!(
            pick_asset(&assets, "linux"),
            Some("https://example/linux.AppImage".to_owned())
        );
    }

    #[test]
    fn srm_presets_are_generated_from_sync_roots() {
        let config = DesktopConfig {
            srm: SrmConfig {
                roms_directory: "/games/roms".to_owned(),
                ..DesktopConfig::default().srm
            },
            sync_roots: vec![SyncRoot {
                emulator_id: "dolphin-dev".to_owned(),
                path: "/games/emulators/Dolphin".to_owned(),
                emulator_executable: "/games/emulators/Dolphin/dolphin-emu".to_owned(),
                remote_prefix: "dolphin-dev".to_owned(),
                pull_paths: Vec::new(),
            }],
            ..Default::default()
        };
        let presets = srm_parser_presets(&config);
        assert_eq!(presets["parsers"].as_array().unwrap().len(), 1);
        assert_eq!(presets["parsers"][0]["romDirectory"], "/games/roms");
        assert_eq!(
            presets["parsers"][0]["executable"],
            "/games/emulators/Dolphin/dolphin-emu"
        );
        assert!(
            presets["parsers"][0]["configTitle"]
                .as_str()
                .unwrap()
                .contains("Dolphin")
        );
    }

    #[test]
    fn query_param_parses_uri_query_string() {
        assert_eq!(
            query_param("/api/logs?limit=50&owner=a", "limit"),
            Some("50")
        );
        assert_eq!(
            query_param("/api/logs?limit=50&owner=a", "owner"),
            Some("a")
        );
        assert_eq!(query_param("/api/logs", "limit"), None);
    }

    #[test]
    fn heartbeat_payload_summarises_last_sync() {
        let config = DesktopConfig {
            server_url: "https://sync.example.com".to_owned(),
            auth_token: "t".to_owned(),
            device_id: "device-1".to_owned(),
            device_name: "couch-pc".to_owned(),
            rom_roots: vec!["/games/roms".to_owned()],
            emulator_roots: vec!["/games/emu".to_owned()],
            ..Default::default()
        };
        let last_sync = json!({
            "pushed": [{"local": "/x", "remote": "y"}, {"local": "/x2", "remote": "y2"}],
            "pulled": [],
            "errors": [{"local": "/z", "remote": "w", "error": "boom"}]
        });
        let payload = heartbeat_payload(&config, &last_sync);
        assert_eq!(payload["device_id"], "device-1");
        assert_eq!(payload["device_name"], "couch-pc");
        assert_eq!(payload["files_pushed"], 2);
        assert_eq!(payload["files_pulled"], 0);
        assert_eq!(payload["state"], "error");
        assert_eq!(payload["last_error"], "boom");
        assert_eq!(payload["rom_roots"], json!(["/games/roms"]));
        assert_eq!(payload["emulator_roots"], json!(["/games/emu"]));
        // OS must be reported separately for Linux vs Windows so the admin can
        // see which client built which.
        assert!(
            payload["os"].as_str().unwrap() == "linux"
                || payload["os"].as_str().unwrap() == "windows"
        );
    }

    #[test]
    fn live_manifest_overlays_admin_emulator_updates() {
        let state = json!({
            "emulator_updates": {
                "duckstation": {
                    "windows": {
                        "url": "https://example.invalid/duckstation-win.zip",
                        "sha256": "deadbeef",
                        "archive": "zip",
                        "version": "0.1.7080"
                    },
                    "linux": {
                        "url": "https://example.invalid/duckstation-linux.AppImage",
                        "sha256": "feedface",
                        "archive": "appimage",
                        "version": "0.1.7080"
                    }
                }
            }
        });
        let manifest = live_manifest(&state);
        let duck = manifest["emulators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "duckstation")
            .unwrap();
        assert_eq!(
            duck["downloads"]["windows"]["url"],
            "https://example.invalid/duckstation-win.zip"
        );
        assert_eq!(
            duck["downloads"]["linux"]["url"],
            "https://example.invalid/duckstation-linux.AppImage"
        );
        // Cemu wasn't overridden, so it must remain whatever the bundled
        // manifest carries (or absent).
        let cemu = manifest["emulators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "cemu")
            .unwrap();
        let cemu_url = cemu["downloads"]["windows"]["url"].as_str().unwrap_or("");
        assert!(cemu_url.is_empty() || cemu_url.starts_with("https://"));
    }

    #[test]
    fn emulator_download_spec_returns_none_when_no_url_for_os() {
        let mut emulator = json!({"downloads": {"linux": {"url": ""}}});
        assert!(emulator_download_spec(&emulator, "linux").is_none());
        emulator["downloads"]["linux"]["url"] = json!("https://example.invalid/x.AppImage");
        let spec = emulator_download_spec(&emulator, "linux").unwrap();
        assert_eq!(spec.url, "https://example.invalid/x.AppImage");
    }

    #[test]
    fn emulator_installable_uses_release_source_when_static_url_missing() {
        // Empty static download URLs but a release_source — still installable
        // because resolve_install_spec will fall back to the live feed.
        let emulator = json!({
            "downloads": {"windows": {"url": ""}, "linux": {"url": ""}},
            "release_source": {"type": "github_release", "repo": "x/y"}
        });
        assert!(emulator_installable(&emulator, "windows"));
        assert!(emulator_installable(&emulator, "linux"));
        // No static URL and no release_source — not installable.
        let bare = json!({"downloads": {"linux": {"url": ""}}});
        assert!(!emulator_installable(&bare, "linux"));
    }

    #[test]
    fn effective_release_source_prefers_per_os_override() {
        let emulator = json!({
            "release_source": {"type": "github_release", "repo": "default/repo"},
            "release_source_overrides": {
                "linux": {"type": "github_release", "repo": "linux/repo"}
            }
        });
        assert_eq!(
            effective_release_source(&emulator, "linux").unwrap()["repo"],
            "linux/repo"
        );
        assert_eq!(
            effective_release_source(&emulator, "windows").unwrap()["repo"],
            "default/repo"
        );
    }

    #[test]
    fn dolphin_manifest_targets_dev_channel_for_both_oses() {
        // The Dolphin entry must always pull the bleeding-edge dev channel:
        // dolphin-emu.org dev builds for Windows and the pkgforge AppImage
        // mirror for Linux.
        let dolphin = emulator_by_id("dolphin-dev").expect("dolphin-dev in manifest");
        let win_source = effective_release_source(&dolphin, "windows").unwrap();
        assert_eq!(win_source["type"], "dolphin_dev_website");
        let linux_source = effective_release_source(&dolphin, "linux").unwrap();
        assert_eq!(linux_source["type"], "github_release");
        assert_eq!(linux_source["repo"], "pkgforge-dev/Dolphin-emu-AppImage");
    }

    #[test]
    fn srm_manifest_has_release_source() {
        // The SRM portable install must have a release source so the desktop
        // GUI's "Install SRM portable" button works without anyone hand-pasting
        // a download URL into the manifest.
        let manifest = manifest();
        let srm = manifest["srm_download"]
            .as_object()
            .expect("srm_download present");
        assert!(
            srm.contains_key("release_source"),
            "srm_download must declare a release_source"
        );
        assert_eq!(srm["release_source"]["type"], "github_release");
        assert_eq!(
            srm["release_source"]["repo"], "SteamGridDB/steam-rom-manager",
            "SRM should track SteamGridDB/steam-rom-manager"
        );
    }

    #[test]
    fn pick_dolphin_dev_url_extracts_first_matching_artifact() {
        let html = r#"
            <table>
              <tr>
                <td>Dev 2603</td>
                <td><a href="https://dl.dolphin-emu.org/builds/aa/bb/dolphin-master-2603-x64.7z">Win x64</a></td>
                <td><a href="https://dl.dolphin-emu.org/builds/aa/bb/dolphin-master-2603-macos-arm64.dmg">Mac</a></td>
              </tr>
            </table>
        "#;
        assert_eq!(
            pick_dolphin_dev_url(html, "windows").as_deref(),
            Some("https://dl.dolphin-emu.org/builds/aa/bb/dolphin-master-2603-x64.7z")
        );
        assert_eq!(
            pick_dolphin_dev_url(html, "macos").as_deref(),
            Some("https://dl.dolphin-emu.org/builds/aa/bb/dolphin-master-2603-macos-arm64.dmg")
        );
        // Dolphin doesn't host Linux AppImages on dl.dolphin-emu.org — return
        // None so the manifest's Linux release_source_override (pkgforge) is
        // used instead.
        assert!(pick_dolphin_dev_url(html, "linux").is_none());
    }

    #[test]
    fn parse_dolphin_dev_version_pulls_master_build_number() {
        let html = r#"<a href=".../dolphin-master-2603-x64.7z">build</a>"#;
        assert_eq!(parse_dolphin_dev_version(html).as_deref(), Some("2603"));
        assert!(parse_dolphin_dev_version("nothing here").is_none());
    }

    #[test]
    fn release_cache_returns_cached_value_within_ttl() {
        // Seed the cache with a known release and confirm a follow-up lookup
        // for the same source is served from cache (no network). This is
        // what prevents 9 emulator listings from burning the unauthenticated
        // GitHub rate limit and silently returning "unknown" for everyone.
        let source = json!({
            "type": "github_release",
            "repo": "release-cache-test/repo",
            "prerelease": false,
            "_test_unique": unix_time().to_string()
        });
        let key = release_cache_key(&source, "linux");
        let seeded = LatestRelease {
            version: "v1.2.3".to_owned(),
            published_at: "2026-01-01T00:00:00Z".to_owned(),
            download_url: Some("https://example.invalid/x.AppImage".to_owned()),
            source_url: "https://example.invalid/release".to_owned(),
        };
        {
            let mut cache = release_cache().lock().unwrap();
            cache.insert(key.clone(), (unix_time(), seeded.clone()));
        }
        let got = latest_release_from_source(&source, "linux").unwrap();
        assert_eq!(got, seeded);

        // Stale entries must be discarded so the next call refetches; here we
        // just verify that an old timestamp would no longer satisfy the TTL.
        {
            let mut cache = release_cache().lock().unwrap();
            cache.insert(
                key.clone(),
                (
                    unix_time().saturating_sub(RELEASE_CACHE_TTL_SECS + 1),
                    seeded.clone(),
                ),
            );
            let entry = cache.get(&key).cloned().unwrap();
            assert!(unix_time().saturating_sub(entry.0) >= RELEASE_CACHE_TTL_SECS);
        }
    }

    #[test]
    fn list_synced_files_walks_owned_files_with_versions() {
        let temp = TempDir::new().unwrap();
        // Push the same file twice with different content so a version is
        // recorded.
        write_versioned_file(temp.path(), "user@example.com", "saves/a.sav", b"v1").unwrap();
        write_versioned_file(temp.path(), "user@example.com", "saves/a.sav", b"v2").unwrap();
        let user = json!({"email": "user@example.com", "is_admin": false});
        let listing = list_synced_files(temp.path(), &user).unwrap();
        let files = listing["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["path"], "saves/a.sav");
        assert!(files[0]["versions"].as_u64().unwrap() >= 2);
        // Other users must not see this owner's files.
        let other = json!({"email": "other@example.com", "is_admin": false});
        let listing = list_synced_files(temp.path(), &other).unwrap();
        assert!(listing["files"].as_array().unwrap().is_empty());
        // Admin sees everything.
        let admin = json!({"email": "admin@example.com", "is_admin": true});
        let listing = list_synced_files(temp.path(), &admin).unwrap();
        assert_eq!(listing["files"].as_array().unwrap().len(), 1);
    }

    /// End-to-end test: spin up the real Docker server in a temp dir, run
    /// first-run setup, mint an invite, register a desktop client, push a
    /// real save file via `run_desktop_sync_once`, then pull it back to a
    /// second device into a different filesystem layout (simulating
    /// Linux ↔ Windows save synchronization). Verifies that:
    ///
    /// * Saves matched by the manifest's `sync_include` ARE pushed.
    /// * Config files matched by `sync_exclude` are NOT pushed (controllers
    ///   and emulator settings stay device-local).
    /// * The pulled bytes on the second device are byte-identical to the
    ///   pushed bytes from the first device.
    #[test]
    fn push_pull_round_trip_syncs_only_manifest_approved_files_across_devices() {
        let server_dir = TempDir::new().unwrap();
        let port = pick_free_port();
        let bind = format!("127.0.0.1:{port}");
        let server_data = server_dir.path().to_path_buf();
        let listener = Server::http(&bind).unwrap();
        let state = Arc::new(AppState {
            store: Mutex::new(JsonStore::new(server_data.join("state.json")).unwrap()),
            data_dir: server_data.clone(),
        });
        let server_state = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            for request in listener.incoming_requests() {
                let s = Arc::clone(&server_state);
                std::thread::spawn(move || handle_request(request, s));
            }
        });

        let base = format!("http://{bind}");
        // 1. First-run setup creates the admin.
        let setup: Value = ureq::post(&format!("{base}/api/setup"))
            .send_json(json!({
                "admin_email": "admin@example.com",
                "admin_password": "supersecret-password-123",
                "smtp_tenant_id": "tenant",
                "smtp_client_id": "client",
                "smtp_from_email": "noreply@example.com"
            }))
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        assert!(
            setup["otpauth_uri"]
                .as_str()
                .unwrap()
                .contains("otpauth://")
        );
        // The setup response must also expose a scannable QR code so the
        // first-run admin can enrol their authenticator app from the Web UI
        // without copy/pasting the otpauth URI by hand.
        let qr = setup["otpauth_qr_png"].as_str().unwrap();
        assert!(qr.starts_with("data:image/png;base64,"));
        let qr_bytes = general_purpose::STANDARD
            .decode(qr.trim_start_matches("data:image/png;base64,"))
            .unwrap();
        assert!(qr_bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        // Mint an admin session by injecting one directly so the test does
        // not need a real TOTP roundtrip.
        let admin_token = {
            let store = state.store.lock().unwrap();
            let mut data = store.read().unwrap();
            let token = new_token();
            data["sessions"][&token] =
                json!({"email": "admin@example.com", "issued_at": unix_time()});
            store.write(&data).unwrap();
            token
        };

        // 2. Admin invites a device user.
        let invite: Value = ureq::post(&format!("{base}/api/invites"))
            .header("Authorization", &format!("Bearer {admin_token}"))
            .send_json(json!({"email": "device@example.com"}))
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let invite_token = invite["invite_token"].as_str().unwrap().to_owned();

        // 3. Promote the invite to a real user with a session token so the
        // desktop client can authenticate. We do this directly via the
        // store to keep the test focused on the push/pull mechanic.
        let device_token = {
            let store = state.store.lock().unwrap();
            let mut data = store.read().unwrap();
            data["users"]["device@example.com"] = json!({
                "email": "device@example.com",
                "is_admin": false,
                "registered": true,
                "disabled": false
            });
            data["invites"]
                .as_object_mut()
                .unwrap()
                .remove(&invite_token);
            let token = new_token();
            data["sessions"][&token] =
                json!({"email": "device@example.com", "issued_at": unix_time()});
            store.write(&data).unwrap();
            token
        };

        // 4. Set up a Linux-style emulator install on "device A" with a real
        // save and a real config file (which must NOT be synced).
        let device_a = TempDir::new().unwrap();
        let duck_a = device_a.path().join("DuckStation");
        fs::create_dir_all(duck_a.join("memcards")).unwrap();
        fs::create_dir_all(duck_a.join("inputprofiles")).unwrap();
        fs::write(duck_a.join("memcards/card1.mcd"), b"AAAAAA-this-is-a-save").unwrap();
        fs::write(duck_a.join("settings.ini"), b"DEVICE-A-LOCAL-SETTINGS").unwrap();
        fs::write(duck_a.join("inputprofiles/pad.ini"), b"DEVICE-A-CONTROLLER").unwrap();

        let config_a = DesktopConfig {
            server_url: base.clone(),
            auth_token: device_token.clone(),
            sync_roots: vec![SyncRoot {
                emulator_id: "duckstation".to_owned(),
                path: duck_a.to_string_lossy().into_owned(),
                emulator_executable: String::new(),
                remote_prefix: "duckstation".to_owned(),
                pull_paths: vec!["memcards/card1.mcd".to_owned()],
            }],
            ..Default::default()
        };

        let result = run_desktop_sync_once(&config_a).unwrap();
        let pushed = result["pushed"].as_array().unwrap();
        // Only the save was pushed; settings.ini and the controller profile
        // must remain device-local.
        assert_eq!(
            pushed.len(),
            1,
            "exactly one save should be pushed, got: {:#?}",
            pushed
        );
        let pushed_remote = pushed[0]["remote"].as_str().unwrap();
        assert_eq!(pushed_remote, "duckstation/memcards/card1.mcd");

        // 5. "Device B" is a different machine (Windows-style would behave
        // identically; the storage is path-based and OS-agnostic). Pull the
        // save into a fresh emulator directory.
        let device_b = TempDir::new().unwrap();
        let duck_b = device_b.path().join("DuckStation");
        fs::create_dir_all(&duck_b).unwrap();
        let config_b = DesktopConfig {
            server_url: base.clone(),
            auth_token: device_token.clone(),
            sync_roots: vec![SyncRoot {
                emulator_id: "duckstation".to_owned(),
                path: duck_b.to_string_lossy().into_owned(),
                emulator_executable: String::new(),
                remote_prefix: "duckstation".to_owned(),
                pull_paths: vec!["memcards/card1.mcd".to_owned()],
            }],
            ..Default::default()
        };
        let result_b = run_desktop_sync_once(&config_b).unwrap();
        assert!(
            result_b["errors"].as_array().unwrap().is_empty(),
            "pull should have no errors, got: {:#?}",
            result_b["errors"]
        );
        let pulled = result_b["pulled"].as_array().unwrap();
        assert_eq!(pulled.len(), 1);
        let pulled_bytes = fs::read(duck_b.join("memcards/card1.mcd")).unwrap();
        assert_eq!(pulled_bytes, b"AAAAAA-this-is-a-save");
        // The config file from device A must not have made it to the server,
        // so device B's directory must NOT contain it.
        assert!(!duck_b.join("settings.ini").exists());
        assert!(!duck_b.join("inputprofiles/pad.ini").exists());

        // 6. Heartbeat lands and is retrievable via /api/devices.
        send_heartbeat(&config_b, &result_b).unwrap();
        let devices: Value = ureq::get(&format!("{base}/api/devices"))
            .header("Authorization", &format!("Bearer {device_token}"))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        assert!(!devices["devices"].as_array().unwrap().is_empty());

        // 7. Admin publishes a per-OS emulator update; live manifest reflects
        // it and the desktop sees the new download URL.
        let _: Value = ureq::post(&format!("{base}/api/admin/emulators"))
            .header("Authorization", &format!("Bearer {admin_token}"))
            .send_json(json!({
                "emulator_id": "duckstation",
                "os": "linux",
                "url": "https://example.invalid/duckstation-linux.AppImage",
                "sha256": "feedface",
                "archive": "appimage",
                "version": "0.1.7100"
            }))
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let live: Value = ureq::get(&format!("{base}/api/emulators"))
            .header("Authorization", &format!("Bearer {device_token}"))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let duck = live["emulators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "duckstation")
            .unwrap();
        assert_eq!(
            duck["downloads"]["linux"]["url"],
            "https://example.invalid/duckstation-linux.AppImage"
        );

        // 8. Unauthenticated requests to non-public endpoints must be 401.
        for endpoint in [
            "/api/me",
            "/api/stats",
            "/api/devices",
            "/api/files",
            "/api/users",
            "/api/invites",
            "/api/logs",
            "/api/settings",
            "/api/emulators",
        ] {
            let status = ureq::get(&format!("{base}{endpoint}"))
                .call()
                .err()
                .and_then(|e| match e {
                    ureq::Error::StatusCode(code) => Some(code),
                    _ => None,
                })
                .expect("unauthenticated request must fail with a status error");
            assert_eq!(
                status, 401,
                "{endpoint} should require authentication, got {status}"
            );
        }

        drop(handle);
    }

    fn pick_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn api_token_mint_lookup_revoke_round_trip() {
        let mut data = json!({"api_tokens": {}});
        let (raw, id, entry) = mint_api_token(&mut data, "alice@example.com", "Desktop");
        assert_eq!(entry["email"], "alice@example.com");
        assert_eq!(entry["label"], "Desktop");

        // Lookup must locate the owner from the raw token (not from the
        // digest) and bump last_used_at.
        let owner = api_token_owner(&mut data, &raw);
        assert_eq!(owner.as_deref(), Some("alice@example.com"));
        let digest = hash_api_token(&raw);
        assert!(data["api_tokens"][&digest]["last_used_at"].as_u64().unwrap() > 0);

        // Listing should return the entry without exposing the digest as
        // a key inside the entry.
        let listed = list_api_tokens_for(&data, "alice@example.com");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["id"], id);

        // Revoke removes by id, scoped to the email.
        assert!(revoke_api_token(&mut data, "alice@example.com", &id));
        assert!(api_token_owner(&mut data, &raw).is_none());
        assert!(list_api_tokens_for(&data, "alice@example.com").is_empty());

        // Wrong-owner revoke must not delete somebody else's token.
        let (raw2, id2, _) = mint_api_token(&mut data, "alice@example.com", "Desktop");
        assert!(!revoke_api_token(&mut data, "bob@example.com", &id2));
        assert_eq!(
            api_token_owner(&mut data, &raw2).as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn group_admin_visibility_and_authorization() {
        let data = json!({
            "users": {
                "root@example.com": {"email": "root@example.com", "is_admin": true},
                "boss@example.com": {"email": "boss@example.com", "is_admin": false},
                "kid@example.com": {"email": "kid@example.com", "is_admin": false},
                "stranger@example.com": {"email": "stranger@example.com", "is_admin": false}
            },
            "groups": {
                "family": {
                    "id": "family",
                    "name": "Family",
                    "admins": ["boss@example.com"],
                    "members": ["boss@example.com", "kid@example.com"]
                }
            }
        });
        let root = data["users"]["root@example.com"].clone();
        let boss = data["users"]["boss@example.com"].clone();
        let kid = data["users"]["kid@example.com"].clone();
        let stranger = data["users"]["stranger@example.com"].clone();

        // Global admin sees every user.
        let visible_root = visible_user_emails(&data, &root);
        assert!(visible_root.contains(&"root@example.com".to_owned()));
        assert!(visible_root.contains(&"stranger@example.com".to_owned()));

        // Group admin sees only themselves + group members.
        let visible_boss = visible_user_emails(&data, &boss);
        assert!(visible_boss.contains(&"kid@example.com".to_owned()));
        assert!(!visible_boss.contains(&"stranger@example.com".to_owned()));

        // Standard user sees only themselves.
        let visible_kid = visible_user_emails(&data, &kid);
        assert_eq!(visible_kid, vec!["kid@example.com".to_owned()]);

        // can_admin_user enforces the same boundary.
        assert!(can_admin_user(&data, &boss, "kid@example.com"));
        assert!(!can_admin_user(&data, &boss, "stranger@example.com"));
        assert!(can_admin_user(&data, &kid, "kid@example.com"));
        assert!(!can_admin_user(&data, &kid, "boss@example.com"));
        assert!(!can_admin_user(&data, &stranger, "boss@example.com"));
        assert!(can_admin_user(&data, &root, "stranger@example.com"));
    }

    #[test]
    fn safe_group_id_rejects_traversal_and_special_chars() {
        assert!(is_safe_group_id("family"));
        assert!(is_safe_group_id("crew_42"));
        assert!(is_safe_group_id("a-b"));
        assert!(!is_safe_group_id(""));
        assert!(!is_safe_group_id("../etc"));
        assert!(!is_safe_group_id("with space"));
        assert!(!is_safe_group_id("a/b"));
        assert!(!is_safe_group_id(&"x".repeat(65)));
    }

    #[test]
    fn save_path_resolution_rejects_traversal() {
        let temp = TempDir::new().unwrap();
        let owner = "alice@example.com";
        let owner_root = temp.path().join("files").join(owner);
        fs::create_dir_all(&owner_root).unwrap();

        // Empty / "." resolve to the owner root.
        assert_eq!(
            resolve_save_path(temp.path(), owner, "").unwrap(),
            owner_root
        );
        assert_eq!(
            resolve_save_path(temp.path(), owner, ".").unwrap(),
            owner_root
        );

        // A normal sub path resolves under the owner root.
        let sub = resolve_save_path(temp.path(), owner, "duckstation/memcards").unwrap();
        assert!(sub.starts_with(&owner_root));

        // Traversal must be rejected.
        assert!(resolve_save_path(temp.path(), owner, "../bob").is_err());
        assert!(resolve_save_path(temp.path(), owner, "duckstation/../../etc/passwd").is_err());
    }

    #[test]
    fn list_save_directory_groups_into_dirs_and_files() {
        let temp = TempDir::new().unwrap();
        let owner_root = temp.path();
        fs::create_dir_all(owner_root.join("duckstation/memcards")).unwrap();
        fs::write(
            owner_root.join("duckstation/memcards/card.mcd"),
            b"savedata",
        )
        .unwrap();
        fs::write(owner_root.join("readme.txt"), b"hello").unwrap();

        let listing = list_save_directory(owner_root).unwrap();
        let dirs = listing["directories"].as_array().unwrap();
        let files = listing["files"].as_array().unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0]["name"], "duckstation");
        assert_eq!(dirs[0]["file_count"], 1);
        assert_eq!(dirs[0]["size"], 8);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["name"], "readme.txt");
        assert_eq!(files[0]["size"], 5);
    }

    #[test]
    fn zip_directory_preserves_subtree_relative_paths() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("dolphin");
        fs::create_dir_all(root.join("User/GC")).unwrap();
        fs::write(root.join("User/GC/MemoryCardA.USA.raw"), b"abc").unwrap();
        fs::write(root.join("User/GC/MemoryCardB.USA.raw"), b"def").unwrap();
        let zipped = zip_directory(&root).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zipped)).unwrap();
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "User/GC/MemoryCardA.USA.raw".to_owned(),
                "User/GC/MemoryCardB.USA.raw".to_owned()
            ]
        );
    }
}
