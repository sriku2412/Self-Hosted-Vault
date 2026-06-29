# Reverse Proxy And Access

The default Compose file binds the app to localhost only:

```yaml
ports:
  - "127.0.0.1:8080:8080"
```

This is deliberate. Use one of these access patterns:

- Caddy on the same Docker network for public HTTPS.
- A private VPN such as WireGuard or Tailscale, with HTTPS at the reverse proxy.
- SSH tunnel for single-admin maintenance.

## Caddy

```sh
cp Caddyfile.example Caddyfile
```

Edit the hostname in `Caddyfile`, then set:

```env
ENVIRONMENT=production
SECURE_COOKIES=true
TRUSTED_HOSTS=vault.example.com,127.0.0.1,localhost
```

Start:

```sh
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Caddy will request and renew certificates automatically when DNS points to the host and ports `80` and `443` are reachable.

## Existing Reverse Proxy

Proxy to:

```text
http://127.0.0.1:8080
```

Forward these headers:

```text
Host
X-Forwarded-Proto
X-Forwarded-Host
```

Keep `SECURE_COOKIES=true` when the browser reaches the app over HTTPS.

## Firewall Examples

With Caddy public HTTPS:

```sh
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 8080/tcp
```

With VPN-only access, allow `443` only on the VPN interface or keep the Caddy listener bound to a VPN address.
