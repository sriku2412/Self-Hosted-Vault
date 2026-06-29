# Security Model

## What The Server Sees

The backend stores encrypted vault payloads, encrypted folder names, encrypted shared vault names, public keys, encrypted private keys, account metadata, and TOTP secrets encrypted with the server secret.

The browser never sends the master password to the server. During registration and login it derives an auth proof from the master password. The server hashes that proof with Argon2 before storage.

## Vault Encryption

Personal items and folders are encrypted in the browser with AES-GCM.

Shared vaults use a random AES-GCM key per collection. Each member receives the collection key encrypted with their RSA-OAEP public key. A member's private key is encrypted by their own master-derived AES key.

## Important Limits

- This is not Bitwarden-compatible.
- This code has not had a professional security audit.
- A malicious or compromised server can serve hostile JavaScript to future browser sessions.
- XSS would be critical because the encryption key lives in browser memory after unlock.
- Lost master passwords cannot be recovered.
- TOTP protects login, not an already-unlocked browser session.

## Recommended Deployment Controls

- Serve only over HTTPS, or over a private VPN with HTTPS at the edge.
- Keep `SECURE_COOKIES=true` in production.
- Set `TRUSTED_HOSTS` to exact hostnames.
- Keep the default `127.0.0.1:8080` bind when using a reverse proxy.
- Block direct access to port `8080` from untrusted networks.
- Disable registration after creating initial users.
- Enforce strong master passwords operationally.
- Run `scripts/backup.sh` on a schedule and test `scripts/restore.sh`.
- Patch the host OS and Docker engine regularly.
- Protect `.env`; it contains server-side encryption and session secrets.

## Incident Response

If `.env` is exposed, rotate `APP_SECRET_KEY` and `JWT_SECRET`. Existing TOTP secrets are encrypted with `APP_SECRET_KEY`; users may need to re-enable TOTP after rotation.

If the database is exposed without `.env`, vault item contents remain encrypted, but attackers can attempt offline guessing against account auth verifiers. Raise `KDF_ITERATIONS`, require stronger master passwords, and rotate sensitive entries.

