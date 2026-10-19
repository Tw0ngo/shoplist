# Shoplist

Shared shopping lists and pantry lists for you and your groups – a small web app you can install on your phone's home screen.

- Groups with invite links, any number of admins, private lists
- Pantry lists: mark what runs low, move it onto the shopping list with one tap
- Works offline; changes are sent once the connection is back
- German and English
- No email, no tracking, no external requests: accounts are just a username and a password

## Run it

You need [Docker](https://docs.docker.com/get-docker/). Then, in this folder:

```sh
docker compose up -d
```

Open **http://localhost:8080** on the same computer, or **http://&lt;the computer's IP&gt;:8080** on phones in the same Wi-Fi (for example `http://192.168.1.20:8080`). The first person to sign up gets their own group and can invite everyone else from the group menu.

To update later: `git pull && docker compose up -d --build`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `REGISTRATION` | `open` | `open`: anyone can sign up. `invite`: only with an invite link (the first account always works). |
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

## Home screen app and offline mode

Phones only offer "Add to Home Screen" as a real app, and only keep working offline, when the site is opened over **https**. Over plain `http://…:8080` everything else works normally. If you want the app version, put a reverse proxy with HTTPS in front, for example [Caddy](https://caddyserver.com/) with `reverse_proxy 127.0.0.1:8080`.

## Data and backups

Everything is in one file, `db.json`, in the `shoplist-data` volume. To back it up:

```sh
docker compose cp shoplist:/data/db.json ./db.json.bak
```

## Licenses

The fonts DotGothic16 and Shippori Mincho B1 are licensed under the SIL Open Font License 1.1 (`public/fonts/OFL-*.txt`).
