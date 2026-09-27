# Deploying WHAXON

WHAXON web interface can run headless and be accessed from any browser.

## Foreground

    whaxon web

Dev mode: reload on change, verbose logs.

## Daemon

    whaxon serve --daemon --log data/whaxon.log

Double-forks, writes data/whaxon.pid, redirects stdout/stderr. Rejects startup if a live pid already occupies data/whaxon.pid.

Stop:

    kill $(cat data/whaxon.pid)
    rm -f data/whaxon.pid

## Environment

- WHAXON_HOST       default 127.0.0.1   bind address
- WHAXON_PORT       default 5001        port
- WHAXON_DATA       default data        data directory
- WHAXON_AUTH_USER  default whaxon      basic auth user
- WHAXON_AUTH_PASS  default whaxon      basic auth password

Change the auth credentials before binding to a non-loopback address.

## systemd

whaxon.service is included in the repo root. Install:

    sudo cp whaxon.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now whaxon

Adjust User, WorkingDirectory, and paths to your layout.

## Docker

Hardened container:

    docker build -t whaxon:secure .
    docker run --rm -d --name whaxon --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop=ALL --security-opt=no-new-privileges:true -p 127.0.0.1:5001:5001 -v data:/data -e HOME=/tmp -e WHAXON_AUTH_USER=whaxon -e WHAXON_AUTH_PASS=change-me -e WHAXON_DATA=/data whaxon:secure

Notes:

- --read-only filesystem; /tmp is a tmpfs.
- -v data:/data is the persistent volume.
- WHAXON_DATA points at the mounted volume.
- Tools installed inside the container are not persisted. Bake them into the image.

## HTTPS

Recommended: reverse-proxy. Terminate TLS at nginx/caddy/traefik in front of 127.0.0.1:5001. Keep the WHAXON bind on loopback and let the proxy handle certificates, HSTS, and rate limiting.

nginx example:

    server {
      listen 443 ssl http2;
      server_name whaxon.example.com;
      ssl_certificate     /etc/letsencrypt/live/whaxon.example.com/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/whaxon.example.com/privkey.pem;
      location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
      }
    }