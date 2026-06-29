# Hardening Checklist

## Application

- Create the first admin account.
- Disable registration in the admin panel.
- Enable TOTP for every admin.
- Use unique, high-entropy master passwords.
- Confirm backups decrypt after restore.

## Docker

The default service:

- runs as UID `10001`;
- drops all Linux capabilities;
- uses `no-new-privileges`;
- uses a read-only root filesystem;
- writes only to `/data`, `/backups`, and tmpfs `/tmp`.

## Host

- Patch the OS and Docker engine.
- Restrict SSH to keys only.
- Keep Docker socket access limited to administrators.
- Use a firewall default deny policy.
- Back up `.env` separately in a secure password manager or offline secret store.

## Monitoring

- Review the admin audit panel for repeated failed logins.
- Monitor backup job exit status.
- Monitor disk space for the Docker volume and `backups/`.
- Export backups off-host.

