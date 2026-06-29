# Selfhosted Vault

A low-resource, Docker Compose password manager inspired by Vaultwarden/Bitwarden. It is a standalone application, not a Bitwarden protocol-compatible server.

## Features

- Browser-side encrypted vault items and folder names.
- User accounts with Argon2-hashed client auth proofs.
- TOTP two-factor authentication.
- Password generator using `crypto.getRandomValues`.
- Personal folders and shared team vaults.
- RSA-OAEP wrapped shared vault keys for existing users.
- SQLite storage with online backup, verification, and restore scripts.
- Admin panel for users, registration, audit log, and verified backups.
- HTTPS-ready Caddy reverse proxy example.
- Hardened Docker defaults: non-root user, dropped capabilities, read-only root filesystem, tmpfs `/tmp`.

## Quick Start

```sh
cd /Users/DTU/Documents/selfhosted-vault
cp .env.example .env
```

Edit `.env` and replace both secrets:

```sh
openssl rand -base64 48
openssl rand -base64 48
```

For direct local HTTP testing, set:

```env
ENVIRONMENT=development
SECURE_COOKIES=false
TRUSTED_HOSTS=localhost,127.0.0.1
```

Start the app:

```sh
docker compose up -d --build
```

Open `http://127.0.0.1:8080`. The first account becomes the administrator.

## Project Layout

- `app/main.py` creates the FastAPI app, installs middleware, registers routers, and serves the static frontend.
- `app/api/` contains feature routers for auth, profile/TOTP, folders, items, collections, user lookup, admin, and config endpoints.
- `app/repositories/` contains reusable SQLite queries and updates.
- `app/schemas.py`, `app/deps.py`, `app/serializers.py`, `app/validation.py`, and `app/permissions.py` hold shared request models, dependencies, API serialization, payload validation, and access checks.
- `app/db.py` owns SQLite connection/session handling and schema initialization.
- `app/security.py` owns password verifier hashing, session tokens, server-secret encryption, and rate limiting.
- `app/maintenance.py` powers backup, verify, and restore commands.
- `static/` contains the browser app, including client-side encryption and rendering.

## Development Checks

Install development dependencies into a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

Run the backend checks:

```sh
.venv/bin/python -m compileall app
.venv/bin/pytest -q
```

The app requires distinct, non-placeholder `APP_SECRET_KEY` and `JWT_SECRET` values in production. Use `ENVIRONMENT=development` for local import checks that do not use `.env`.

## Production Readiness

This project can be hardened for a small self-hosted deployment, but do not treat it as an enterprise password-manager release until the checklist below is complete. Password managers have a higher bar than normal CRUD apps because XSS, weak operational controls, or a compromised update path can expose decrypted secrets during future browser sessions.

### Minimum Production Preflight

Before exposing the app to real users:

- Run `.venv/bin/python -m compileall app` and `.venv/bin/pytest -q`.
- Build and inspect the Compose configuration with `docker compose config`.
- Set `ENVIRONMENT=production`.
- Generate unique values for `APP_SECRET_KEY` and `JWT_SECRET` with `openssl rand -base64 48`; never reuse placeholders or the same value for both.
- Keep `SECURE_COOKIES=true` and serve the browser only over HTTPS.
- Set `TRUSTED_HOSTS` to the exact public hostname plus any local reverse-proxy or health-check hostnames that are required.
- Keep the default `127.0.0.1:8080` bind unless a private network boundary protects the app.
- Create the first admin account, enable TOTP for every admin, then disable open registration in the admin panel.
- Run `scripts/backup.sh`, `scripts/verify-backup.sh`, and at least one restore drill before storing real vault data.

### Deployment Controls

Use one of the access patterns in [docs/reverse-proxy.md](docs/reverse-proxy.md): public HTTPS through Caddy, VPN-only HTTPS, or an SSH tunnel for maintenance. Block direct access to port `8080` from untrusted networks, patch the host OS and Docker engine, restrict Docker socket access to administrators, and protect `.env` separately from database backups.

The default container is intentionally constrained: non-root user, dropped capabilities, `no-new-privileges`, read-only root filesystem, and writable storage limited to `/data`, `/backups`, and tmpfs `/tmp`. Review [docs/hardening.md](docs/hardening.md) before changing those defaults.

### Release Gates

For a serious production process, require every release to pass:

- automated tests in CI;
- dependency vulnerability scanning for Python packages and the base image;
- Docker image rebuilds from a clean source checkout;
- backup and restore verification against the release candidate;
- manual review of auth, permissions, encryption, and migration changes;
- rollback notes for database and configuration changes.

The included GitHub Actions workflow runs compile and test checks. Add dependency scanning, image scanning, and deployment-specific smoke tests before relying on unattended updates.

### Operations

Operate the app as if the database, backups, logs, and `.env` are all sensitive:

- Monitor failed logins, admin actions, backup job status, disk space, and container health.
- Export backups off-host and test restore regularly.
- Keep a documented incident process for leaked `.env`, exposed backups, disabled admins, lost TOTP devices, and compromised hosts.
- Rotate `JWT_SECRET` to invalidate sessions after suspected session exposure.
- Rotate `APP_SECRET_KEY` only with a planned maintenance window; existing server-encrypted TOTP secrets may need to be reset.

### Enterprise Release Bar

Before an enterprise-level release, obtain an independent security audit covering the browser crypto, XSS surface, session handling, access control, backup/restore flow, and deployment model. Also add threat modeling, SAST/DAST, SBOM generation, signed images or provenance attestations, centralized monitoring, documented RTO/RPO, and a tested incident-response runbook.

## HTTPS With Caddy

```sh
cp Caddyfile.example Caddyfile
```

Edit `Caddyfile` and `.env`:

```env
ENVIRONMENT=production
SECURE_COOKIES=true
TRUSTED_HOSTS=vault.example.com,127.0.0.1,localhost
```

Then run:

```sh
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

See [docs/reverse-proxy.md](docs/reverse-proxy.md).

## Backup And Restore

Create and verify a backup:

```sh
scripts/backup.sh
```

Verify the latest backup:

```sh
scripts/verify-backup.sh
```

Restore a backup:

```sh
scripts/restore.sh backups/vault-YYYYMMDDTHHMMSSZ.tar.gz
```

Run a restore drill before trusting any backup plan. Full details are in [docs/backup-restore.md](docs/backup-restore.md).

## Updates

For this local-build deployment:

```sh
scripts/update.sh
```

For registry-based deployments, `docker-compose.watchtower.yml` provides a Watchtower service:

```sh
docker compose -f docker-compose.yml -f docker-compose.watchtower.yml up -d
```

Watchtower updates pulled images; it does not rebuild local source code changes.

## Security Notes

The server stores encrypted vault blobs. The master password is used in the browser to derive:

- an AES-GCM vault encryption key, kept in browser memory;
- an auth proof, sent to the server and hashed again with Argon2.

Shared vaults use a random AES-GCM collection key. That key is wrapped to each member using the member's RSA-OAEP public key.

This project is a secure-by-design scaffold, not an independently audited password manager. Review [SECURITY.md](SECURITY.md) before exposing it to real users.
