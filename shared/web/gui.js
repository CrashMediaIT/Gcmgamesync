// Crash Crafts Game Sync — Desktop GUI front-end.
// Loaded by the local-only HTTP server started by `crash-crafts-game-sync gui`.
// Communicates with the same process over /api/local/* endpoints.
(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

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

  async function api(path, options) {
    const opts = Object.assign({}, options || {});
    if (opts.body && typeof opts.body !== "string") {
      opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
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

  function setView(name) {
    $$(".view").forEach((view) => {
      view.classList.toggle("hidden", view.dataset.view !== name);
    });
    $$(".nav-link").forEach((link) => {
      link.classList.toggle("active", link.dataset.view === name);
    });
    loadView(name);
  }

  async function loadView(name) {
    switch (name) {
      case "status":
        return loadStatus();
      case "emulators":
        return loadEmulators();
      case "srm":
        return loadSrm();
      case "folders":
        return loadFolders();
      case "activity":
        return loadActivity();
      case "settings":
        return loadSettings();
    }
  }

  async function loadStatus() {
    const status = await api("/api/local/status");
    if (!status.ok) {
      $("#status-tiles").innerHTML =
        "<p class=\"muted\">" + escapeHtml(status.body.error || "Failed.") + "</p>";
      return;
    }
    const data = status.body;
    setConnection(data);
    $("#status-tiles").innerHTML = [
      { label: "State", value: data.state || "idle" },
      { label: "Sync roots", value: data.sync_roots || 0 },
      { label: "Files pushed (last)", value: data.last_pushed || 0 },
      { label: "Files pulled (last)", value: data.last_pulled || 0 },
      { label: "Last sync", value: timeAgo(data.last_sync_at) },
      { label: "Errors (last)", value: data.last_errors || 0 },
    ]
      .map(
        (tile) =>
          '<div class="stat"><span class="value">' +
          escapeHtml(tile.value) +
          '</span><span class="label">' +
          escapeHtml(tile.label) +
          "</span></div>"
      )
      .join("");
    const recent = data.recent || [];
    $("#status-recent").innerHTML = recent.length
      ? "<ul class=\"log-list\">" +
        recent
          .map(
            (entry) =>
              "<li>" +
              escapeHtml(timeAgo(entry.timestamp)) +
              " — pushed " +
              escapeHtml(entry.pushed) +
              ", pulled " +
              escapeHtml(entry.pulled) +
              ", errors " +
              escapeHtml(entry.errors) +
              "</li>"
          )
          .join("") +
        "</ul>"
      : "<p class=\"muted\">No sync passes yet. Click <strong>Sync now</strong>.</p>";
  }

  function setConnection(data) {
    const dot = $("#conn-dot");
    const label = $("#conn-label");
    if (!dot || !label) return;
    if (data.configured && data.last_errors === 0) {
      dot.className = "dot dot-idle";
      label.textContent = "connected to " + (data.server_url || "server");
    } else if (data.configured) {
      dot.className = "dot dot-error";
      label.textContent = "errors during last sync";
    } else {
      dot.className = "dot dot-error";
      label.textContent = "not configured";
    }
  }

  async function loadEmulators() {
    const result = await api("/api/local/emulators");
    if (!result.ok) {
      $("#emulators-table").innerHTML =
        "<p class=\"muted\">" + escapeHtml(result.body.error || "Failed.") + "</p>";
      return;
    }
    const list = result.body.emulators || [];
    $("#emulators-table").innerHTML =
      "<table class=\"data\"><thead><tr><th>Emulator</th><th>Installed</th><th>Portable</th><th>Save folders</th><th>Latest upstream</th><th>Action</th></tr></thead><tbody>" +
      list
        .map(
          (em) =>
            "<tr><td><strong>" +
            escapeHtml(em.name) +
            "</strong><br><span class=\"muted\">" +
            escapeHtml(em.id) +
            "</span></td><td>" +
            (em.installed ? "yes" : "no") +
            "</td><td>" +
            (em.portable
              ? "yes"
              : em.installed
              ? '<button class="secondary" data-portable="' + escapeHtml(em.id) + '">Set portable</button>'
              : "—") +
            "</td><td>" +
            ((em.save_paths || []).length
              ? '<ul class="log-list">' +
                em.save_paths.map((p) => "<li><code>" + escapeHtml(p) + "</code></li>").join("") +
                "</ul>"
              : '<span class="muted">—</span>') +
            "</td><td>" +
            (em.latest_version
              ? '<a href="' +
                escapeHtml(em.release_url) +
                '" target="_blank" rel="noopener">' +
                escapeHtml(em.latest_version) +
                "</a>" +
                (em.latest_published_at ? '<br><span class="muted">' + escapeHtml(em.latest_published_at) + "</span>" : "")
              : '<span class="muted">unknown</span>') +
            "</td><td>" +
            (em.installable
              ? '<button data-install="' + escapeHtml(em.id) + '">' + (em.installed ? "Update" : "Install portable") + "</button> "
              : '<a class="secondary" href="' + escapeHtml(em.homepage) + '" target="_blank" rel="noopener">Open homepage</a>') +
            "</td></tr>"
        )
        .join("") +
      "</tbody></table>";
    $$("button[data-install]").forEach((btn) =>
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-install");
        btn.disabled = true;
        const original = btn.textContent;
        btn.textContent = "Installing...";
        const r = await api("/api/local/install-emulator", { method: "POST", body: { emulator_id: id } });
        btn.disabled = false;
        btn.textContent = original;
        alert(r.ok ? "Installed: " + r.body.path : (r.body.error || "Failed"));
        loadEmulators();
      })
    );
    $$("button[data-portable]").forEach((btn) =>
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-portable");
        btn.disabled = true;
        btn.textContent = "Enabling...";
        const r = await api("/api/local/enable-portable", { method: "POST", body: { emulator_id: id } });
        alert(r.ok ? "Portable mode enabled at " + r.body.path : (r.body.error || "Failed"));
        loadEmulators();
      })
    );
  }

  async function loadSrm() {
    const status = await api("/api/local/srm");
    if (!status.ok) {
      $("#srm-status").innerHTML = "<p class=\"muted\">" + escapeHtml(status.body.error || "Failed.") + "</p>";
      return;
    }
    const data = status.body;
    $("#srm-status").innerHTML =
      "<p>SRM installed: <strong>" +
      (data.installed ? "yes" : "no") +
      "</strong></p><p>Steam directory: <code>" +
      escapeHtml(data.steam_directory || "(not set)") +
      "</code></p><p>Parsers file: <code>" +
      escapeHtml(data.parsers_path || "(not set)") +
      "</code></p>";
    const presets = data.presets || [];
    $("#srm-presets").innerHTML = presets.length
      ? "<h3>Generated parsers</h3><ul class=\"log-list\">" +
        presets
          .map(
            (p) =>
              "<li><strong>" +
              escapeHtml(p.configTitle) +
              "</strong> — ROM dir <code>" +
              escapeHtml(p.romDirectory) +
              "</code></li>"
          )
          .join("") +
        "</ul>"
      : "<p class=\"muted\">No parsers generated yet.</p>";
  }

  $("#install-srm-btn")?.addEventListener("click", async () => {
    setMessage("srm-result", "Downloading SRM...", "info");
    const r = await api("/api/local/install-srm", { method: "POST" });
    setMessage("srm-result", r.ok ? "Installed: " + r.body.path : (r.body.error || "Failed"), r.ok ? "good" : "error");
    loadSrm();
  });
  $("#generate-srm-btn")?.addEventListener("click", async () => {
    const r = await api("/api/local/generate-srm", { method: "POST" });
    setMessage("srm-result", r.ok ? "Parsers written to " + r.body.path : (r.body.error || "Failed"), r.ok ? "good" : "error");
    loadSrm();
  });

  function renderRoots(listId, items, type) {
    const el = $(listId);
    el.innerHTML = items.length
      ? items
          .map(
            (path, idx) =>
              "<li><code>" +
              escapeHtml(path) +
              '</code> <button class="secondary" data-remove-' +
              type +
              '="' +
              idx +
              '">Remove</button></li>'
          )
          .join("")
      : '<li class="muted">No paths configured yet.</li>';
    $$('[data-remove-' + type + ']').forEach((btn) =>
      btn.addEventListener("click", async () => {
        const idx = parseInt(btn.getAttribute("data-remove-" + type), 10);
        await api("/api/local/folders", { method: "POST", body: { remove: { type: type, index: idx } } });
        loadFolders();
      })
    );
  }

  async function loadFolders() {
    const r = await api("/api/local/folders");
    if (!r.ok) return;
    renderRoots("#emu-roots-list", r.body.emulator_roots || [], "emu");
    renderRoots("#rom-roots-list", r.body.rom_roots || [], "rom");
  }

  $("#add-emu-root")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    await api("/api/local/folders", { method: "POST", body: { add: { type: "emu", path: data.path } } });
    event.target.reset();
    loadFolders();
  });
  $("#add-rom-root")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    await api("/api/local/folders", { method: "POST", body: { add: { type: "rom", path: data.path } } });
    event.target.reset();
    loadFolders();
  });

  async function loadActivity() {
    const r = await api("/api/local/activity");
    if (!r.ok) return;
    const list = r.body.entries || [];
    $("#activity-list").innerHTML = list.length
      ? "<ul class=\"log-list\">" +
        list
          .map(
            (e) =>
              "<li><span class=\"badge badge-" +
              escapeHtml(e.errors > 0 ? "error" : "info") +
              "\">" +
              escapeHtml(timeAgo(e.timestamp)) +
              "</span> pushed " +
              escapeHtml(e.pushed) +
              ", pulled " +
              escapeHtml(e.pulled) +
              ", errors " +
              escapeHtml(e.errors) +
              (e.first_error ? " — " + escapeHtml(e.first_error) : "") +
              "</li>"
          )
          .join("") +
        "</ul>"
      : "<p class=\"muted\">No activity yet.</p>";
  }

  async function loadSettings() {
    const r = await api("/api/local/config");
    if (!r.ok) return;
    const form = $("#settings-form");
    form.server_url.value = r.body.server_url || "";
    form.auth_token.value = r.body.auth_token || "";
    form.interval_seconds.value = r.body.interval_seconds || 60;
    form.device_name.value = r.body.device_name || "";
    $("#install-service-toggle").checked = !!(r.body.service && r.body.service.install_on_setup);
  }

  $("#settings-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    data.install_service = $("#install-service-toggle").checked;
    const r = await api("/api/local/config", { method: "POST", body: data });
    setMessage("settings-result", r.ok ? "Saved." : (r.body.error || "Failed"), r.ok ? "good" : "error");
  });

  $("#sync-now-btn")?.addEventListener("click", async () => {
    const btn = $("#sync-now-btn");
    btn.disabled = true;
    btn.textContent = "Syncing...";
    await api("/api/local/sync-now", { method: "POST" });
    btn.disabled = false;
    btn.textContent = "Sync now";
    loadStatus();
  });
  $("#pause-btn")?.addEventListener("click", async () => {
    await api("/api/local/pause", { method: "POST" });
    loadStatus();
  });
  $("#open-rom-btn")?.addEventListener("click", () => api("/api/local/open?folder=rom", { method: "POST" }));
  $("#open-emu-btn")?.addEventListener("click", () => api("/api/local/open?folder=emu", { method: "POST" }));
  $("#open-log-btn")?.addEventListener("click", () => api("/api/local/open?folder=log", { method: "POST" }));

  document.addEventListener("DOMContentLoaded", () => {
    $$(".nav-link").forEach((link) =>
      link.addEventListener("click", (event) => {
        event.preventDefault();
        setView(link.dataset.view);
      })
    );
    setView("status");
    setInterval(() => {
      const active = document.querySelector(".nav-link.active");
      if (active) loadView(active.dataset.view);
    }, 5000);
  });
})();
