#!/bin/sh
set -e
# This image's documented startup brings up its intended vulnerable services.
/bin/services.sh || true
# Ensure the fixed G01 Samba service is running even if another legacy service fails.
/usr/sbin/smbd -D || true
/usr/sbin/nmbd -D || true

echo "[entrypoint] target ready"
exec sleep infinity
