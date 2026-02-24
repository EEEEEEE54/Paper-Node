# Ghost

> [!WARNING] 
> This repository is no longer maintained!

A very cool games website :D

Join Our Discord server https://discord.gg/dbyDXfs5dN

<img src="/readme/ss.png">

# Features

A proxy
Lots of games
Cloaking
Theming
And More!

# Deploying

```
git clone https://github.com/The-Ghost-Network/Ghost-Node.git
cd Ghost-Node
npm i
npm start
```

# Credits

Credit to [Titanium Network](https://github.com/titaniumnetwork-dev) for Ultraviolet

Credit to [3kho](https://github.com/3kh0) for the games


## Authentication

This project now requires login before any app page or API is accessible.
The site opens a login popup page first, then returns users to their original URL after successful login.
Set credentials using environment variables before running:

```bash
export GHOST_ADMIN_USERNAME=your-username
export GHOST_ADMIN_PASSWORD=your-strong-password
npm start
```

If those variables are not set, the fallback is:
- username: `admin`
- password: `change-me-now`

You should always override the fallback values in production.


### Multi-account management

- Accounts are stored in `server_data/accounts.json` and support roles (`admin` / `user`), disable/enable, and expiration times.
- Visit `/admin` while logged in as an admin to manage accounts with the control panel UI.
- You can force-logout users, expire users immediately, or remove accounts entirely from the panel.
- Bare proxy, pages, and APIs are all server-side protected to prevent login bypass.


### Netlify deployment notes

If deploying to Netlify, this repo now includes `netlify.toml` and a function router at `netlify/functions/app.mjs` so `/login`, `/api/login`, and protected routes do not 404.

Set these Netlify environment variables:

- `GHOST_SESSION_SECRET` (a long random secret)
- `GHOST_ADMIN_USERNAME`
- `GHOST_ADMIN_PASSWORD`

Optional multi-account JSON (for Netlify function mode):

- `GHOST_ACCOUNTS_JSON`

Netlify function account changes made in `/admin` are runtime-only (memory for that function instance). For permanent account data, keep `GHOST_ACCOUNTS_JSON` updated in Netlify environment settings.

Example:

```json
{"admin":{"password":"StrongPass123!","role":"admin"},"user1":{"password":"UserPass123!","role":"user","expiresAt":null}}
```


### Local run / ngrok

Default local port is `3000` (or set `PORT` to override). For ngrok, forward to the same port your server is listening on.

```bash
PORT=3000 npm start
# then in another terminal
ngrok http 3000
```
