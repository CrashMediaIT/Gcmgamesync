use base64::{Engine, engine::general_purpose};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
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

const MANIFEST_JSON: &str = include_str!("../shared/emulators.json");
const APP_NAME: &str = "Crash Crafts Game Sync";
const PASSWORD_ITERATIONS: u32 = 240_000;

type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn manifest() -> Value {
    serde_json::from_str(MANIFEST_JSON).expect("embedded manifest is valid JSON")
}

fn current_os() -> &'static str {
    match env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    }
}

fn detect_emulators(root: &Path) -> Vec<Value> {
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

#[cfg(test)]
fn should_sync(relative_path: &str, emulator: &Value) -> bool {
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
    for key in ["users", "invites", "sessions", "settings"] {
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
    if payload.len() > 349_528 {
        return Err("logo must be smaller than 256 KiB".into());
    }
    let decoded = general_purpose::STANDARD.decode(payload)?;
    if decoded.len() > 262_144 {
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
                r#"<img class="mark logo-img" src="{}" alt="">"#,
                escape_html(value)
            )
        })
        .unwrap_or_else(|| r#"<span class="mark"></span>"#.to_owned());
    let configured = setup_complete(data);
    let setup_panel = if configured {
        r#"<section class="card panel-grid" id="admin">
  <div>
    <p class="eyebrow">Admin</p>
    <h2>Manage the Docker setup from the Web UI</h2>
    <p>Log in with the setup admin account to create invites, update branding, and keep configuration inside the mounted Docker data volume instead of environment variables.</p>
  </div>
  <form id="login-form" class="form">
    <label>Email<input name="email" type="email" autocomplete="username" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <label>2FA code<input name="totp_code" inputmode="numeric" required></label>
    <button type="submit">Unlock admin panel</button>
  </form>
  <form id="logo-form" class="form hidden">
    <label>Upload logo for web and OS app metadata<input name="logo" type="file" accept="image/png,image/jpeg,image/svg+xml" required></label>
    <button type="submit">Save logo</button>
  </form>
  <p id="admin-result" class="result"></p>
</section>"#
            .to_owned()
    } else {
        r#"<section class="card panel-grid" id="setup">
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
  </form>
  <p id="setup-result" class="result"></p>
</section>"#
            .to_owned()
    };
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>@APP@</title>
  <style>
    :root { color-scheme: dark; --bg: #070a12; --panel: rgba(17, 24, 39, .82); --panel-strong: rgba(12, 18, 31, .94); --text: #f8fafc; --muted: #aab7cf; --brand: #ff7a1a; --brand-2: #22d3ee; --good: #7ee787; --border: rgba(255,255,255,.12); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; min-width: 0; } body { margin: 0; min-height: 100vh; color: var(--text); background: radial-gradient(circle at 18% 12%, rgba(255,122,26,.23), transparent 32rem), radial-gradient(circle at 82% 4%, rgba(34,211,238,.20), transparent 30rem), linear-gradient(135deg, #070a12 0%, #101827 48%, #070a12 100%); overflow-wrap: anywhere; }
    .shell { width: min(1160px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 56px; } nav, .card, .stat, .feature { border: 1px solid var(--border); background: var(--panel); box-shadow: 0 24px 80px rgba(0,0,0,.35); backdrop-filter: blur(18px); border-radius: 24px; }
    nav { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 18px; flex-wrap: wrap; } .logo { display: flex; gap: 12px; align-items: center; font-weight: 800; letter-spacing: -.04em; font-size: clamp(1rem, 3vw, 1.25rem); } .mark { flex: 0 0 auto; width: 38px; height: 38px; border-radius: 12px; background: linear-gradient(135deg, var(--brand), var(--brand-2)); box-shadow: 0 0 32px rgba(255,122,26,.45); object-fit: cover; } .pill { color: var(--muted); border: 1px solid var(--border); border-radius: 999px; padding: 8px 12px; font-size: .85rem; }
    .hero { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(260px, .8fr); gap: 24px; margin-top: 28px; } .card { padding: clamp(24px, 5vw, 52px); } h1 { font-size: clamp(2.2rem, 8vw, 5.2rem); line-height: 1; margin: 0 0 20px; letter-spacing: -.07em; max-width: 10ch; } h2 { margin: 0 0 12px; font-size: clamp(1.2rem, 3vw, 1.6rem); } p { color: var(--muted); line-height: 1.7; max-width: 68ch; } .accent { background: linear-gradient(90deg, var(--brand), var(--brand-2)); -webkit-background-clip: text; color: transparent; } .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px; } a.button, button { text-decoration: none; color: #071019; background: linear-gradient(135deg, var(--brand), #ffd166); padding: 13px 18px; border-radius: 14px; font-weight: 800; border: 0; cursor: pointer; } a.secondary { color: var(--text); background: rgba(255,255,255,.08); border: 1px solid var(--border); }
    .stats { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; height: 100%; } .stat { padding: 22px; } .value { display: block; font-size: clamp(1.55rem, 4vw, 2rem); font-weight: 900; color: var(--good); } .label { color: var(--muted); font-size: .95rem; } .features { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; margin-top: 20px; } .feature { padding: 22px; background: var(--panel-strong); } .panel-grid { display: grid; grid-template-columns: minmax(0, .85fr) minmax(280px, 1fr); gap: 22px; margin-top: 20px; align-items: start; } .form { display: grid; gap: 12px; } label { color: var(--muted); display: grid; gap: 7px; font-size: .9rem; } input { width: 100%; color: var(--text); background: rgba(255,255,255,.07); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; } .result { color: var(--good); } .eyebrow { margin: 0 0 8px; color: var(--brand-2); font-weight: 800; text-transform: uppercase; letter-spacing: .08em; } .hidden { display: none; } @media (max-width: 820px) { .hero, .features, .panel-grid { grid-template-columns: 1fr; } .stats { grid-template-columns: 1fr 1fr; } h1 { max-width: none; } } @media (max-width: 520px) { .stats { grid-template-columns: 1fr; } }
  </style>
</head>
<body><main class="shell"><nav><div class="logo">@LOGO@<span>@APP@</span></div><span class="pill">Docker Web UI setup</span></nav><section class="hero"><div class="card"><h1>Save sync for <span class="accent">every emulator rig.</span></h1><p>Docker-hosted backup with Web UI setup, five-copy version retention, TOTP-protected accounts, Office365 OAuth SMTP metadata, and device-local emulator configuration protection.</p><div class="actions"><a class="button" href="/api/emulators">View emulator manifest</a><a class="button secondary" href="/api/health">Check server health</a></div></div><div class="stats"><div class="stat"><span class="value">@COUNT@</span><span class="label">emulator profiles reviewed for Docker setup</span></div><div class="stat"><span class="value">@VERSIONS@</span><span class="label">total copies retained per changed file</span></div><div class="stat"><span class="value">2FA</span><span class="label">required admin login model</span></div><div class="stat"><span class="value">OAuth</span><span class="label">Office365 SMTP setup fields</span></div></div></section>@SETUP@<section class="features"><div class="feature"><h2>No Docker env required</h2><p>Initial admin, SMTP, and branding settings are configured after startup through the Web UI and persisted under /data.</p></div><div class="feature"><h2>Config-safe</h2><p>Manifest exclusions keep controllers, paths, graphics, and other user configuration local to each device.</p></div><div class="feature"><h2>Security-aware</h2><p>Use HTTPS at the reverse proxy for transit security; stored app state is written with restrictive file permissions where supported.</p></div></section></main><script>
const result = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
const token = () => localStorage.getItem('ccgs_token') || '';
document.getElementById('setup-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const response = await fetch('/api/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  const body = await response.json();
  result('setup-result', response.ok ? `Setup complete. Add this TOTP URI to your authenticator: ${body.otpauth_uri}` : body.error);
});
document.getElementById('login-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const response = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  const body = await response.json();
  if (response.ok && body.is_admin) { localStorage.setItem('ccgs_token', body.token); document.getElementById('logo-form')?.classList.remove('hidden'); result('admin-result', 'Admin unlocked.'); } else { result('admin-result', body.error || 'Admin login required.'); }
});
document.getElementById('logo-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = event.target.logo.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async () => {
    const response = await fetch('/api/admin/logo', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token()}` }, body: JSON.stringify({ data_url: reader.result }) });
    const body = await response.json();
    result('admin-result', response.ok ? 'Logo saved. Refresh to preview it.' : body.error);
  };
  reader.readAsDataURL(file);
});
</script></body></html>"#
        .replace("@APP@", APP_NAME)
        .replace("@LOGO@", &logo)
        .replace("@COUNT@", &count.to_string())
        .replace("@VERSIONS@", &versions.to_string())
        .replace("@SETUP@", &setup_panel)
}

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
            "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
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
            if user.is_none() || !password_ok || !totp_ok {
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

fn validate_server_url(server: &str) -> AppResult<&str> {
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

fn print_usage() {
    eprintln!(
        "usage:
   crash-crafts-game-sync server [--host 127.0.0.1] [--port 8080] [--data-dir /data]
   crash-crafts-game-sync manifest
   crash-crafts-game-sync scan --root <path>
   crash-crafts-game-sync status --root <path>
   crash-crafts-game-sync upload-log --server <url> --token <token> [--level info] <message>"
    );
}

fn main() -> AppResult<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("server") {
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
}
