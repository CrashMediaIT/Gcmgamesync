#!/bin/sh
# Self-heal /data ownership on every container start.
#
# Why this script exists:
#   A named Docker volume (or a host bind mount, e.g. a TrueNAS Scale
#   ix-applications dataset) keeps whatever ownership it was created with;
#   Docker only copies image content/ownership into a *named* volume on its
#   FIRST attach, and a host bind mount is never touched. So if the mount
#   point on the host is owned by uid X but the binary runs as uid Y, the
#   server crashes on startup with `Permission denied` and an empty log
#   buffer — and no amount of image rebuilding fixes it.
#
# What this script does:
#   1. Resolve the target UID/GID from the PUID/PGID environment variables
#      (defaulting to 10001:10001, the user baked into the image). Set
#      these on TrueNAS Scale / Unraid / Synology / any other host where
#      the volume is owned by a different non-root user — the entrypoint
#      will adopt that identity instead.
#   2. If we are running as root, fix /data ownership to PUID:PGID (only if
#      it isn't already correct, to avoid spurious writes) and then drop
#      privileges to that uid/gid via `setpriv` before exec'ing the real
#      command.
#   3. If we are already non-root (e.g. a developer running the image with
#      `--user …` directly), just exec — no privileges to drop and no way
#      to chown anyway.
#
# `setpriv` ships with util-linux, which is part of the debian:bookworm-slim
# base image, so no extra package install is required.

set -eu

# `PUID`/`PGID` follow the de-facto convention popularised by linuxserver.io
# images and supported by TrueNAS Scale's app UI. Fall back to the uid/gid
# baked into the image when they are not provided, so the defaults still
# work for plain `docker run` / `docker compose up`.
TARGET_UID="${PUID:-10001}"
TARGET_GID="${PGID:-10001}"
DATA_DIR="${CCGS_DATA_DIR:-/data}"

# Defensive validation: PUID/PGID must be non-negative integers, otherwise
# `chown` and `setpriv` would either fail with confusing errors or silently
# end up running as the wrong identity.
case "$TARGET_UID" in
    ''|*[!0-9]*)
        printf 'entrypoint: PUID=%s is not a non-negative integer\n' "$TARGET_UID" >&2
        exit 1
        ;;
esac
case "$TARGET_GID" in
    ''|*[!0-9]*)
        printf 'entrypoint: PGID=%s is not a non-negative integer\n' "$TARGET_GID" >&2
        exit 1
        ;;
esac

log() {
    # Write to stderr so messages appear immediately in `docker logs`
    # (stdout is block-buffered and would hide entrypoint output if the
    # process crashes before the buffer is flushed).
    printf 'entrypoint: %s\n' "$*" >&2
}

if [ "$(id -u)" = "0" ]; then
    if [ -d "$DATA_DIR" ]; then
        current_uid="$(stat -c '%u' "$DATA_DIR" 2>/dev/null || echo unknown)"
        current_gid="$(stat -c '%g' "$DATA_DIR" 2>/dev/null || echo unknown)"
        if [ "$current_uid" != "$TARGET_UID" ] || [ "$current_gid" != "$TARGET_GID" ]; then
            log "$DATA_DIR is owned by ${current_uid}:${current_gid}; chowning to ${TARGET_UID}:${TARGET_GID}"
            # If chown fails (e.g. CAP_CHOWN was dropped) we still try to
            # exec — the binary will surface a clear "failed to write" error
            # with the offending path, which is more useful than aborting
            # silently here.
            chown -R "$TARGET_UID:$TARGET_GID" "$DATA_DIR" \
                || log "warning: chown failed; the binary will report the underlying error"
        fi
    else
        log "$DATA_DIR does not exist; the binary will create it"
    fi
    log "dropping privileges to uid ${TARGET_UID} and exec'ing: $*"
    exec setpriv \
        --reuid="$TARGET_UID" \
        --regid="$TARGET_GID" \
        --clear-groups \
        -- "$@"
fi

log "running as uid $(id -u); exec'ing: $*"
exec "$@"
