# Deploying WHAXON

WHAXON's web interface can run on a headless server and be accessed from any browser.

## Security checklist (do this first)

- [ ] Change the default credentials (`whaxon`/`whaxon`)
- [ ] Put WHAXON behind HTTPS (reverse proxy or SSH tunnel)
- [ ] Do NOT expose the raw HTTP port to the internet
- [ ] Bind to `127.0.0.1` and proxy from a TLS terminator

Without HTTPS, credentials are sent in plaintext over the wire.

## Option 1 — Docker Compose (recommended)

```bash
export WHAXON_AUTH_USER=yourname
export WHAXON_AUTH_PASS='a-strong-password'
docker compose up -d
