#!/bin/sh
set -eu
: "${WHAXON_MSF_PASS:?CI-only MSF RPC password required}"
ruby /usr/src/metasploit-framework/msfrpcd -U "$WHAXON_MSF_USER" -P "$WHAXON_MSF_PASS" -a 127.0.0.1 -p 55553 -S -f -n >/tmp/g01-msfrpcd.log 2>&1 &
rpc_pid=$!
trap 'kill "$rpc_pid" 2>/dev/null || true' EXIT INT TERM
for attempt in $(seq 1 60); do
  kill -0 "$rpc_pid" 2>/dev/null || { cat /tmp/g01-msfrpcd.log; exit 1; }
  if curl --silent --max-time 1 http://127.0.0.1:55553/ >/dev/null; then
    break
  fi
  sleep 1
done
if ! /opt/whaxon-venv/bin/python -c 'from whaxon.core.msf import MSFClient; MSFClient().connect()'; then
  cat /tmp/g01-msfrpcd.log
  exit 1
fi
touch /tmp/g01-msfrpc-ready
wait "$rpc_pid"
