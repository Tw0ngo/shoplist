# Shoplist

Shared shopping lists and pantry lists for you and your groups – a small web app you can install on your phone's home screen.

- Groups with invite links, any number of admins, private lists
- Pantry lists: mark what runs low, move it onto the shopping list with one tap
- Works offline; changes are sent once the connection is back
- German and English
- No email, no tracking, no external requests: accounts are just a username and a password (stored as a scrypt hash)

## Run it

You need Docker with Compose and a reverse proxy that serves HTTPS (needed for sign-in cookies and the home screen app).

```sh
mkdir -p secrets
openssl rand -hex 32 > secrets/dbkey      # key for the encrypted database – keep a copy somewhere safe
docker compose up -d --build
```

The app runs as user `1000` in the container; if it can't read the key file, run `sudo chown 1000 secrets/dbkey`.

The app listens on `127.0.0.1:8080`. Point your proxy at it, for example with Caddy:

```
shoplist.example.org {
	reverse_proxy 127.0.0.1:8080
}
```

The first account can always be created; it gets its own group and can invite others from the group menu.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `REGISTRATION` | `open` | `open`: anyone can sign up. `invite`: only with an invite link (the first account always works). |
| `DB_KEY_FILE` | – | File with 64 hex characters; the database is encrypted with it (AES-256-GCM). Without it, the database is a plain JSON file. |
| `COOKIE_SECURE` | `1` | `0` only for testing over plain http. |
| `TRUST_PROXY` | `private` | Whose `X-Real-IP` / `X-Forwarded-For` is believed for the rate limits: `private` = proxies in private networks (Docker), anything else = only `127.0.0.1`. |
| `PORT` | `8080` | Port inside the container. |

Optional branding: mount a folder at `/branding`. Files there replace the built-in ones with the same name; a `hero.png` appears in the header (the built-in icons are `favicon-32.png`, `icon-180.png`, `icon-192.png`, `icon-512.png`).

## Forgotten passwords

There are no emails, so an admin sets a new one. Stop the app first (otherwise the running app would overwrite the change):

```sh
docker compose stop shoplist
docker compose run --rm shoplist node server.js reset-password <username>
docker compose start shoplist
```

It prints a new password and signs that account out on all devices; the user can change it under Settings.

## Data and backups

Everything is in one file, `db.json`, in the `shoplist-data` volume. Back up that file **and** `secrets/dbkey` – without the key the backup can't be read.

```sh
docker compose cp shoplist:/data/db.json ./db.json.bak
```

## Licenses

The fonts DotGothic16 and Shippori Mincho B1 are licensed under the SIL Open Font License 1.1 (`public/fonts/OFL-*.txt`).
