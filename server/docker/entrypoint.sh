#!/bin/sh
# Run MedVault as PUID:PGID (default 10001). On a NAS set these to the owner of
# the data folder (Synology: `id <user>` over SSH, usually 1026:100).
set -e
PUID="${PUID:-10001}"
PGID="${PGID:-10001}"
DATA="${MEDVAULT_DATA:-${SCANVAULT_DATA:-/data}}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA"
  if [ "$(stat -c %u:%g "$DATA")" != "$PUID:$PGID" ]; then
    echo "medvault: setting owner of $DATA to $PUID:$PGID"
    chown -R "$PUID:$PGID" "$DATA"
  fi
  chmod 700 "$DATA"
  umask 077
  exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups --inh-caps=-all -- "$@"
fi
umask 077
exec "$@"
