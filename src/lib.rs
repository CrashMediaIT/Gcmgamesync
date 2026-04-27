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
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
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
            emulator["detect_paths"]
                .as_array()?
                .iter()
                .find_map(|candidate| {
                    let candidate = candidate.as_str()?;
                    let path = root.join(candidate);
                    if !path.exists() {
                        return None;
                    }
                    let portable = emulator["portable_markers"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .any(|marker| path.join(marker).exists());
                    let update_policy = emulator["updates"]
                        .get(os)
                        .cloned()
                        .unwrap_or_else(|| json!({"source": "unsupported"}));
                    Some(json!({
                        "id": emulator["id"],
                        "name": emulator["name"],
                        "path": path.to_string_lossy(),
                        "portable": portable,
                        "update_policy": update_policy
                    }))
                })
        })
        .collect()
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
    if let Some(parent) = path.parent() {
        secure_create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    secure_file(&file)?;
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
    secure_file(&file)?;
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
    secure_file(&file)?;
    file.write_all(&serde_json::to_vec_pretty(&srm_parser_presets(config))?)?;
    Ok(path)
}

#[derive(Clone)]
struct JsonStore {
    path: PathBuf,
}

impl JsonStore {
    fn new(path: PathBuf) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
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
        Ok(serde_json::from_slice(&fs::read(&self.path)?)?)
    }

    fn write(&self, data: &Value) -> AppResult<()> {
        if let Some(parent) = self.path.parent() {
            secure_create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut file = fs::File::create(&tmp)?;
        secure_file(&file)?;
        file.write_all(&serde_json::to_vec_pretty(data)?)?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

fn secure_create_dir_all(path: &Path) -> AppResult<()> {
    fs::create_dir_all(path)?;
    secure_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_dir(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_dir(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(file: &fs::File) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_file(_file: &fs::File) -> AppResult<()> {
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

fn new_token() -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
            collect_owner_files(&owner_entry.path(), &owner_entry.path(), data_dir, &owner, &mut entries)?;
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
            let relative = p
                .strip_prefix(base)?
                .to_string_lossy()
                .replace('\\', "/");
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
                .join(
                    PathBuf::from(&relative)
                        .file_name()
                        .unwrap_or_default(),
                );
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
        secure_file(&file)?;
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
    for key in ["users", "invites", "sessions", "settings", "devices"] {
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
@media (max-width: 820px) { .panel-grid { grid-template-columns: 1fr; } .form.inline { grid-template-columns: 1fr; } }
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
    let data = store.read()?;
    Ok(data["sessions"][&token]["email"]
        .as_str()
        .map(str::to_owned))
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
        (Method::Get, "/api/emulators") => Ok(json_response(200, manifest())),
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
            let otpauth = otpauth_uri(&email, &secret);
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({"ok": true, "email": email, "otpauth_uri": otpauth}),
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
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let store = state.store.lock().unwrap();
            let data = store.read()?;
            let users = data["users"]
                .as_object()
                .into_iter()
                .flat_map(|users| users.values().cloned())
                .map(|mut user| {
                    if let Some(object) = user.as_object_mut() {
                        object.remove("password_hash");
                        object.remove("totp_secret");
                    }
                    user
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
            if !user["is_admin"].as_bool().unwrap_or(false) {
                return Ok(json_response(403, json!({"error": "admin required"})));
            }
            let body = read_body(&mut request)?;
            let email = body["email"].as_str().unwrap_or("").trim().to_lowercase();
            if email.is_empty() {
                return Ok(json_response(400, json!({"error": "email required"})));
            }
            let token = general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<24>());
            let store = state.store.lock().unwrap();
            let mut data = store.read()?;
            data["invites"][&token] = json!({"email": email});
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({"email": email, "invite_token": token, "email_status": "Configure SMTP later; this invite token is returned for manual delivery."}),
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
            let Some(email) = data["invites"][invite_token]["email"]
                .as_str()
                .map(str::to_owned)
            else {
                return Ok(json_response(400, json!({"error": "invalid invite"})));
            };
            let secret = new_totp_secret();
            data["users"][&email] = json!({"email": email, "password_hash": hash_password(password, None), "totp_secret": secret, "is_admin": false, "registered": true});
            if let Some(invites) = data["invites"].as_object_mut() {
                invites.remove(invite_token);
            }
            store.write(&data)?;
            Ok(json_response(
                201,
                json!({"email": email, "totp_secret": secret, "otpauth_uri": otpauth_uri(&email, &secret)}),
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
            Ok(json_response(
                200,
                json!({
                    "email": user["email"],
                    "is_admin": user["is_admin"].as_bool().unwrap_or(false),
                    "disabled": user["disabled"].as_bool().unwrap_or(false),
                    "registered": user["registered"].as_bool().unwrap_or(false)
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
            Ok(json_response(200, list_synced_files(&state.data_dir, &user)?))
        }
        (Method::Get, path)
            if path.starts_with("/api/files/") && path.ends_with("/versions") =>
        {
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
                .filter(|email| user["is_admin"].as_bool().unwrap_or(false) || email == user["email"].as_str().unwrap_or(""))
                .unwrap_or_else(|| user["email"].as_str().unwrap_or("").to_owned());
            Ok(json_response(
                200,
                list_file_versions(&state.data_dir, &owner_param, &rel_path)?,
            ))
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
    let server = Server::http(format!("{host}:{port}"))?;
    let state = Arc::new(AppState {
        data_dir: data_dir.clone(),
        store: Mutex::new(bootstrap_store(&data_dir)?),
    });
    println!("{APP_NAME} server listening on http://{host}:{port}");
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
    loop {
        let result = run_desktop_sync_once(&config)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
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

fn print_usage() {
    eprintln!(
        "usage:
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
}
