// Crash Crafts Game Sync — Web UI single-page app.
// Vanilla JS. No build step. Loaded as an external file so Content-Security-Policy
// can drop 'unsafe-inline' for scripts.
(function () {
  "use strict";

  const TOKEN_KEY = "ccgs_token";
  const ADMIN_KEY = "ccgs_is_admin";
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const state = {
    token: localStorage.getItem(TOKEN_KEY) || "",
    isAdmin: localStorage.getItem(ADMIN_KEY) === "1",
    me: null,
    setupComplete: true,
    view: "dashboard",
  };

  function authHeaders(extra) {
    const headers = Object.assign({}, extra || {});
    if (state.token) headers["Authorization"] = "Bearer " + state.token;
    return headers;
  }

  async function api(path, options) {
    const opts = Object.assign({}, options || {});
    opts.headers = authHeaders(opts.headers);
    if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== "string") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const response = await fetch(path, opts);
    let body = null;
    const text = await response.text();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch (_) {
        body = { raw: text };
      }
    }
    return { ok: response.ok, status: response.status, body: body || {} };
  }

  function setMessage(id, text, kind) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text || "";
    el.dataset.kind = kind || "info";
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function bytes(n) {
    if (n == null || isNaN(n)) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let value = Number(n);
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return value.toFixed(value < 10 && unit > 0 ? 1 : 0) + " " + units[unit];
  }

  function timeAgo(unix) {
    if (!unix) return "never";
    const seconds = Math.max(0, Math.floor(Date.now() / 1000) - Number(unix));
    if (seconds < 60) return seconds + "s ago";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
    return Math.floor(seconds / 86400) + "d ago";
  }

  function setView(name) {
    state.view = name;
    $$(".view").forEach((view) => {
      view.classList.toggle("hidden", view.dataset.view !== name);
    });
    $$(".nav-link").forEach((link) => {
      link.classList.toggle("active", link.dataset.view === name);
    });
    if (state.token) {
      loadView(name);
    }
  }

  async function loadView(name) {
    switch (name) {
      case "dashboard":
        return loadDashboard();
      case "devices":
        return loadDevices();
      case "files":
        return loadFiles();
      case "users":
        return loadUsers();
      case "logs":
        return loadLogs();
      case "settings":
        return loadSettings();
    }
  }

  async function loadDashboard() {
    const stats = await api("/api/stats");
    const el = $("#dashboard-stats");
    if (!stats.ok) {
      el.innerHTML = "<p class=\"muted\">" + escapeHtml(stats.body.error || "Failed to load stats.") + "</p>";
      return;
    }
    const tiles = [
      { label: "Users", value: stats.body.users },
      { label: "Devices", value: stats.body.devices },
      { label: "Synced files", value: stats.body.files },
      { label: "Storage used", value: bytes(stats.body.storage_bytes) },
      { label: "Versions kept", value: stats.body.total_versions },
      { label: "Outstanding invites", value: stats.body.invites },
    ];
    el.innerHTML = tiles
      .map(
        (tile) =>
          '<div class="stat"><span class="value">' +
          escapeHtml(tile.value) +
          '</span><span class="label">' +
          escapeHtml(tile.label) +
          "</span></div>"
      )
      .join("");
    const recent = $("#dashboard-recent");
    if (Array.isArray(stats.body.recent_logs) && stats.body.recent_logs.length) {
      recent.innerHTML =
        "<h3>Recent activity</h3><ul class=\"log-list\">" +
        stats.body.recent_logs
          .map(
            (entry) =>
              "<li><span class=\"badge badge-" +
              escapeHtml(entry.level || "info") +
              "\">" +
              escapeHtml(entry.level || "info") +
              "</span> <strong>" +
              escapeHtml(entry.email || "") +
              "</strong> " +
              escapeHtml(entry.message || "") +
              "</li>"
          )
          .join("") +
        "</ul>";
    } else {
      recent.innerHTML = "<p class=\"muted\">No client activity yet.</p>";
    }
  }

  async function loadDevices() {
    const devices = await api("/api/devices");
    const el = $("#devices-table");
    if (!devices.ok) {
      el.innerHTML = "<p class=\"muted\">" + escapeHtml(devices.body.error || "Failed to load devices.") + "</p>";
      return;
    }
    const list = devices.body.devices || [];
    if (!list.length) {
      el.innerHTML = "<p class=\"muted\">No desktop companions have checked in yet. Install the desktop app and complete first-run setup.</p>";
      return;
    }
    el.innerHTML =
      "<table class=\"data\"><thead><tr><th>Hostname</th><th>OS</th><th>Owner</th><th>Last sync</th><th>State</th><th>ROM roots</th><th>Emulator roots</th><th>Last error</th></tr></thead><tbody>" +
      list
        .map(
          (device) =>
            "<tr><td>" +
            escapeHtml(device.hostname || "(unknown)") +
            "</td><td>" +
            escapeHtml(device.os || "") +
            "</td><td>" +
            escapeHtml(device.email || "") +
            "</td><td>" +
            escapeHtml(timeAgo(device.last_seen)) +
            "</td><td><span class=\"dot dot-" +
            escapeHtml(device.state || "idle") +
            "\"></span>" +
            escapeHtml(device.state || "idle") +
            "</td><td>" +
            escapeHtml((device.rom_roots || []).join(", ")) +
            "</td><td>" +
            escapeHtml((device.emulator_roots || []).join(", ")) +
            "</td><td>" +
            escapeHtml(device.last_error || "") +
            "</td></tr>"
        )
        .join("") +
      "</tbody></table>";
  }

  async function loadFiles() {
    const files = await api("/api/files");
    const el = $("#files-table");
    if (!files.ok) {
      el.innerHTML = "<p class=\"muted\">" + escapeHtml(files.body.error || "Failed to load files.") + "</p>";
      return;
    }
    const list = files.body.files || [];
    if (!list.length) {
      el.innerHTML = "<p class=\"muted\">No files have been synced yet.</p>";
      return;
    }
    el.innerHTML =
      "<table class=\"data\"><thead><tr><th>Path</th><th>Owner</th><th>Size</th><th>Versions</th><th>Modified</th><th>Actions</th></tr></thead><tbody>" +
      list
        .map((file) => {
          const enc = encodeURIComponent(file.path);
          return (
            "<tr><td><code>" +
            escapeHtml(file.path) +
            "</code></td><td>" +
            escapeHtml(file.owner) +
            "</td><td>" +
            escapeHtml(bytes(file.size)) +
            "</td><td>" +
            escapeHtml(file.versions) +
            "</td><td>" +
            escapeHtml(timeAgo(file.modified)) +
            "</td><td><a href=\"#\" data-versions=\"" +
            escapeHtml(enc) +
            "\" data-owner=\"" +
            escapeHtml(file.owner) +
            "\">Versions</a></td></tr>"
          );
        })
        .join("") +
      "</tbody></table><div id=\"file-versions\"></div>";

    $$('#files-table a[data-versions]').forEach((link) => {
      link.addEventListener("click", async (event) => {
        event.preventDefault();
        const path = link.getAttribute("data-versions");
        const owner = link.getAttribute("data-owner");
        await renderVersions(path, owner);
      });
    });
  }

  async function renderVersions(path, owner) {
    const result = await api("/api/files/" + path + "/versions?owner=" + encodeURIComponent(owner));
    const target = $("#file-versions");
    if (!target) return;
    if (!result.ok) {
      target.innerHTML = "<p class=\"muted\">" + escapeHtml(result.body.error || "Failed.") + "</p>";
      return;
    }
    const versions = (result.body.versions || []).slice().reverse();
    target.innerHTML =
      "<h3>Versions for " +
      escapeHtml(decodeURIComponent(path)) +
      "</h3>" +
      "<p class=\"muted\">Restoring an older version snapshots the current file as a new version first, so newer versions are preserved and the revert can itself be undone.</p>" +
      "<div id=\"file-versions-msg\" class=\"muted\"></div>" +
      "<ul class=\"log-list\">" +
      versions
        .map(
          (v) =>
            "<li>" +
            escapeHtml(v.name) +
            " — " +
            escapeHtml(bytes(v.size)) +
            " <button type=\"button\" class=\"btn-secondary\" data-restore=\"" +
            escapeHtml(encodeURIComponent(v.name)) +
            "\">Restore</button>" +
            "</li>"
        )
        .join("") +
      "</ul>";
    $$('#file-versions button[data-restore]').forEach((btn) => {
      btn.addEventListener("click", async () => {
        const versionName = decodeURIComponent(btn.getAttribute("data-restore"));
        if (!confirm("Restore version " + versionName + "? The current file will be saved as a new version first.")) {
          return;
        }
        btn.disabled = true;
        const restore = await api(
          "/api/files/" + path + "/versions/" + encodeURIComponent(versionName) + "/restore?owner=" + encodeURIComponent(owner),
          { method: "POST" }
        );
        const msg = $("#file-versions-msg");
        if (!restore.ok) {
          if (msg) msg.textContent = "Restore failed: " + (restore.body.error || "unknown error");
          btn.disabled = false;
          return;
        }
        if (msg) msg.textContent = "Restored. Devices will receive the reverted file on their next sync.";
        await renderVersions(path, owner);
      });
    });
  }

  async function loadUsers() {
    const users = await api("/api/users");
    const invites = await api("/api/invites");
    const el = $("#users-table");
    if (!users.ok) {
      el.innerHTML = "<p class=\"muted\">" + escapeHtml(users.body.error || "Admin required.") + "</p>";
      return;
    }
    const userList = users.body.users || [];
    el.innerHTML =
      "<table class=\"data\"><thead><tr><th>Email</th><th>Admin</th><th>Disabled</th><th>Action</th></tr></thead><tbody>" +
      userList
        .map(
          (u) =>
            "<tr><td>" +
            escapeHtml(u.email) +
            "</td><td>" +
            (u.is_admin ? "yes" : "no") +
            "</td><td>" +
            (u.disabled ? "yes" : "no") +
            "</td><td>" +
            (u.disabled
              ? ""
              : '<button class="secondary" data-disable="' + escapeHtml(u.email) + '">Disable</button>') +
            "</td></tr>"
        )
        .join("") +
      "</tbody></table>";
    $$("button[data-disable]").forEach((btn) =>
      btn.addEventListener("click", async () => {
        const email = btn.getAttribute("data-disable");
        if (!confirm("Disable " + email + "?")) return;
        const result = await api("/api/users/" + encodeURIComponent(email) + "/disable", { method: "POST" });
        if (result.ok) loadUsers();
        else alert(result.body.error || "Failed");
      })
    );
    if (invites.ok) {
      const invitesEl = $("#invites-list");
      const list = invites.body.invites || [];
      invitesEl.innerHTML = list.length
        ? "<h3>Outstanding invites</h3><ul class=\"log-list\">" +
          list
            .map(
              (i) =>
                "<li><strong>" +
                escapeHtml(i.email) +
                "</strong> — token <code>" +
                escapeHtml(i.token) +
                "</code></li>"
            )
            .join("") +
          "</ul>"
        : "<p class=\"muted\">No outstanding invites.</p>";
    }
  }

  async function loadLogs() {
    const logs = await api("/api/logs?limit=200");
    const el = $("#logs-list");
    if (!logs.ok) {
      el.innerHTML = "<p class=\"muted\">" + escapeHtml(logs.body.error || "Admin required.") + "</p>";
      return;
    }
    const list = logs.body.logs || [];
    el.innerHTML = list.length
      ? "<ul class=\"log-list\">" +
        list
          .map(
            (entry) =>
              "<li><span class=\"badge badge-" +
              escapeHtml(entry.level || "info") +
              "\">" +
              escapeHtml(entry.level || "info") +
              "</span> <strong>" +
              escapeHtml(entry.email || "") +
              "</strong> " +
              escapeHtml(entry.message || "") +
              "</li>"
          )
          .join("") +
        "</ul>"
      : "<p class=\"muted\">No client logs yet.</p>";
  }

  async function loadSettings() {
    const settings = await api("/api/settings");
    if (!settings.ok) {
      $("#settings-summary").innerHTML =
        "<p class=\"muted\">" + escapeHtml(settings.body.error || "Admin required.") + "</p>";
      return;
    }
    const data = settings.body;
    $("#settings-summary").innerHTML =
      "<p class=\"muted\">SMTP: " +
      escapeHtml(data.smtp && data.smtp.from_email ? data.smtp.from_email : "not configured") +
      " — Retention: " +
      escapeHtml(data.file_versions_to_keep) +
      " copies — Logo: " +
      (data.logo_configured ? "configured" : "default") +
      "</p>" +
      '<div class="card"><h3>Emulator updates</h3>' +
      '<p class="muted">Push a single new version to every desktop user. The server downloads the upstream release, validates it, and stores it as the shared bundle that every desktop client pulls on its next install/update.</p>' +
      '<button id="check-emulator-updates">Check for updates</button>' +
      '<div id="emulator-updates-result" class="mt"></div></div>';
    const button = $("#check-emulator-updates");
    if (button) {
      button.addEventListener("click", async () => {
        button.disabled = true;
        button.textContent = "Checking...";
        const r = await api("/api/admin/check-emulator-updates");
        button.disabled = false;
        button.textContent = "Check for updates";
        renderEmulatorUpdates(r.ok ? r.body.emulators || [] : [], r.ok ? "" : (r.body.error || "Failed"));
      });
    }
  }

  function renderEmulatorUpdates(list, error) {
    const container = $("#emulator-updates-result");
    if (!container) return;
    if (error) {
      container.innerHTML = '<p class="error">' + escapeHtml(error) + "</p>";
      return;
    }
    const updatable = list.filter((e) => e.has_update);
    if (updatable.length === 0) {
      container.innerHTML = '<p class="muted">All published bundles are up to date.</p>';
      return;
    }
    container.innerHTML =
      '<p class="muted">' +
      updatable.length +
      " update(s) available. Select which to apply for all users:</p>" +
      '<table class="data"><thead><tr><th>Apply</th><th>Emulator</th><th>Currently published</th><th>Latest upstream</th><th>Released</th></tr></thead><tbody>' +
      updatable
        .map(
          (e) =>
            '<tr><td><input type="checkbox" data-update="' +
            escapeHtml(e.id) +
            '" checked></td><td>' +
            escapeHtml(e.name) +
            '</td><td>' +
            escapeHtml(e.applied_version || "—") +
            '</td><td><a href="' +
            escapeHtml(e.release_url) +
            '" target="_blank" rel="noopener">' +
            escapeHtml(e.latest_version) +
            "</a></td><td>" +
            escapeHtml(e.latest_published_at) +
            "</td></tr>"
        )
        .join("") +
      "</tbody></table>" +
      '<button id="apply-selected-updates" class="mt">Apply selected updates for all users</button>' +
      '<div id="apply-result" class="mt"></div>';
    $("#apply-selected-updates").addEventListener("click", async () => {
      const ids = $$("#emulator-updates-result input[data-update]:checked").map((i) =>
        i.getAttribute("data-update")
      );
      const button = $("#apply-selected-updates");
      const result = $("#apply-result");
      button.disabled = true;
      button.textContent = "Applying...";
      result.innerHTML = "";
      const responses = [];
      for (const id of ids) {
        const r = await api("/api/admin/apply-emulator-update", {
          method: "POST",
          body: { emulator_id: id, os: "all" },
        });
        responses.push({ id, response: r });
      }
      button.disabled = false;
      button.textContent = "Apply selected updates for all users";
      result.innerHTML = responses
        .map(({ id, response }) => {
          if (!response.ok) {
            return '<p class="error">' + escapeHtml(id) + ": " + escapeHtml(response.body.error || "failed") + "</p>";
          }
          const body = response.body;
          const errs = (body.errors || []).map((e) => e.os + ": " + e.error).join("; ");
          return (
            '<p>' +
            escapeHtml(id) +
            " → applied " +
            escapeHtml(body.applied_version || "") +
            " (" +
            (body.published || []).length +
            " bundle(s) published" +
            (errs ? "; errors: " + escapeHtml(errs) : "") +
            ")</p>"
          );
        })
        .join("");
    });
  }

  async function refreshConfig() {
    const config = await api("/api/config");
    if (config.ok) {
      state.setupComplete = !!config.body.setup_complete;
      const logoEl = $("#brand-logo");
      if (logoEl && config.body.logo_data_url) {
        logoEl.style.backgroundImage = "url(" + config.body.logo_data_url + ")";
      }
    }
  }

  async function refreshMe() {
    if (!state.token) return false;
    const me = await api("/api/me");
    if (!me.ok) {
      logout();
      return false;
    }
    state.me = me.body;
    state.isAdmin = !!me.body.is_admin;
    localStorage.setItem(ADMIN_KEY, state.isAdmin ? "1" : "0");
    $("#me-email").textContent = me.body.email || "";
    $("#me-role").textContent = state.isAdmin ? "admin" : "user";
    document.body.classList.toggle("is-admin", state.isAdmin);
    return true;
  }

  function logout() {
    state.token = "";
    state.isAdmin = false;
    state.me = null;
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ADMIN_KEY);
    showAuth();
  }

  function showAuth() {
    document.body.classList.remove("authed");
    if (!state.setupComplete) {
      $("#setup-panel").classList.remove("hidden");
      $("#login-panel").classList.add("hidden");
    } else {
      $("#setup-panel").classList.add("hidden");
      $("#login-panel").classList.remove("hidden");
    }
    $("#app-shell").classList.add("hidden");
  }

  function showApp() {
    document.body.classList.add("authed");
    $("#setup-panel").classList.add("hidden");
    $("#login-panel").classList.add("hidden");
    $("#app-shell").classList.remove("hidden");
    setView(state.view || "dashboard");
  }

  async function init() {
    await refreshConfig();
    if (state.token) {
      const ok = await refreshMe();
      if (ok) {
        showApp();
        return;
      }
    }
    showAuth();
  }

  document.addEventListener("DOMContentLoaded", () => {
    $$(".nav-link").forEach((link) =>
      link.addEventListener("click", (event) => {
        event.preventDefault();
        setView(link.dataset.view);
      })
    );

    const setupForm = $("#setup-form");
    if (setupForm) {
      setupForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const data = Object.fromEntries(new FormData(setupForm));
        const result = await api("/api/setup", { method: "POST", body: data });
        if (result.ok) {
          setMessage(
            "setup-result",
            "Setup complete. Scan the QR code below with your authenticator app, or save this TOTP URI: " + result.body.otpauth_uri,
            "good"
          );
          const qr = document.getElementById("setup-qr");
          if (qr && result.body.otpauth_qr_png) {
            qr.src = result.body.otpauth_qr_png;
            qr.alt = "TOTP QR code for " + result.body.email;
            qr.classList.remove("hidden");
          }
          const cont = document.getElementById("setup-continue");
          if (cont) {
            cont.classList.remove("hidden");
          }
          state.setupComplete = true;
          // Do not auto-redirect: the admin needs time to scan the QR code
          // with their authenticator app before the setup view is replaced
          // by the login form.
        } else {
          setMessage("setup-result", result.body.error || "Setup failed.", "error");
        }
      });
    }

    const setupContinue = document.getElementById("setup-continue");
    if (setupContinue) {
      setupContinue.addEventListener("click", () => {
        showAuth();
      });
    }

    const loginForm = $("#login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const data = Object.fromEntries(new FormData(loginForm));
        const result = await api("/api/login", { method: "POST", body: data });
        if (result.ok) {
          state.token = result.body.token;
          state.isAdmin = !!result.body.is_admin;
          localStorage.setItem(TOKEN_KEY, state.token);
          localStorage.setItem(ADMIN_KEY, state.isAdmin ? "1" : "0");
          await refreshMe();
          showApp();
        } else {
          setMessage("login-result", result.body.error || "Login failed.", "error");
        }
      });
    }

    const logoForm = $("#logo-form");
    if (logoForm) {
      logoForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const file = logoForm.logo.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async () => {
          const result = await api("/api/admin/logo", {
            method: "POST",
            body: { data_url: reader.result },
          });
          setMessage("logo-result", result.ok ? "Logo saved." : result.body.error || "Failed", result.ok ? "good" : "error");
          if (result.ok) refreshConfig();
        };
        reader.readAsDataURL(file);
      });
    }

    const inviteForm = $("#invite-form");
    if (inviteForm) {
      inviteForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const data = Object.fromEntries(new FormData(inviteForm));
        const result = await api("/api/invites", { method: "POST", body: data });
        if (result.ok) {
          setMessage("invite-result", "Invite token: " + result.body.invite_token, "good");
          loadUsers();
        } else {
          setMessage("invite-result", result.body.error || "Failed", "error");
        }
      });
    }

    const logoutBtn = $("#logout-btn");
    if (logoutBtn) logoutBtn.addEventListener("click", logout);

    init();
  });
})();
