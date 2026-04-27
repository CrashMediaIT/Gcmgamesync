// Crash Crafts Game Sync — Decky Loader Game-Mode helper.
//
// Read-only mini-UI for Steam Deck Game Mode. Mirrors the desktop GUI's
// Status panel: shows current sync state, configured roots, last error, and
// exposes a "Sync now" button that pokes the local
// crash-crafts-game-sync-gui server via the Python backend. Designed to work
// on every Linux install type the daemon supports (SteamOS, Arch, Debian,
// RPM, AppImage, Flatpak) — discovery is done by the backend.

(function () {
  "use strict";

  const SDK = window.SP_REACT && window.DeckyPluginLoader ? window : null;

  function call(method) {
    if (!SDK || !SDK.DeckyPluginLoader) {
      return Promise.resolve({ ok: false, error: "Decky SDK unavailable" });
    }
    return SDK.DeckyPluginLoader.callServerMethod("crash-crafts-game-sync", method, {});
  }

  function format(state) {
    if (!state) return "unknown";
    if (state.last_errors && state.last_errors > 0) return "error";
    if (!state.configured) return "not configured";
    if (state.state === "paused") return "paused";
    return state.state || "idle";
  }

  function render(container, status) {
    container.innerHTML = "";
    const heading = document.createElement("h3");
    heading.textContent = "Crash Crafts Game Sync";
    container.appendChild(heading);

    const stateLine = document.createElement("p");
    stateLine.textContent = "State: " + format(status);
    container.appendChild(stateLine);

    if (status && status.last_sync_at) {
      const lastLine = document.createElement("p");
      const seconds = Math.max(0, Math.floor(Date.now() / 1000) - status.last_sync_at);
      lastLine.textContent =
        "Last sync: " +
        (status.last_pushed || 0) +
        " pushed, " +
        (status.last_pulled || 0) +
        " pulled, " +
        (status.last_errors || 0) +
        " errors (" +
        seconds +
        "s ago)";
      container.appendChild(lastLine);
    }

    const button = document.createElement("button");
    button.textContent = "Sync now";
    button.disabled = !status || !status.configured;
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Syncing...";
      await call("sync_now");
      const refreshed = await call("status");
      render(container, refreshed);
    });
    container.appendChild(button);

    if (status && status.error) {
      const err = document.createElement("p");
      err.style.color = "var(--decky-error, #ff6b6b)";
      err.textContent = status.error;
      container.appendChild(err);
    }
  }

  window.CrashCraftsGameSyncDecky = {
    async render(container) {
      const status = await call("status");
      render(container, status);
    },
  };
})();
