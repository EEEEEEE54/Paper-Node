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
