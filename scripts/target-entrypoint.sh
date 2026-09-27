#!/bin/sh
set -e
mkdir -p /var/log/samba /var/run/samba /var/lib/samba/private
/usr/sbin/smbd -D || true
/usr/sbin/nmbd -D || true

if ! command -v Xvfb >/dev/null 2>&1; then
    echo "[entrypoint] installing Xvfb + x11vnc (one-time, ~30s)..."
    apt-get update -qq 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xvfb x11vnc xterm 2>/dev/null || true
fi

if command -v Xvfb >/dev/null 2>&1; then
    Xvfb :1 -screen 0 800x600x24 >/tmp/xvfb.log 2>&1 &
    sleep 2
    x11vnc -display :1 -forever -nopw -listen 127.0.0.1 -rfbport 5900 -bg -o /tmp/x11vnc.log 2>/dev/null &
    echo "[entrypoint] Xvfb + x11vnc up on 127.0.0.1:5900"
fi

echo "[entrypoint] target ready"
exec sleep infinity
