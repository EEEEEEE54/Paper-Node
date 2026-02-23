import { createBareServer } from "@tomphttp/bare-server-node";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import express from "express";
import g from "./server_lib/games.mjs";
import a from "./server_lib/apps.mjs";
import deg from "./server_lib/deg.mjs";
import fetch from "node-fetch";

const bare = createBareServer("/bare/");
const server = http.createServer();
const PORT = 8080;
const app = express();
const __dirname = process.cwd();

const SESSION_COOKIE = "ghost_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const sessions = new Map();

const ACCOUNT_FILE = path.join(__dirname, "server_data", "accounts.json");
const accounts = new Map();

const ADMIN_USERNAME = process.env.GHOST_ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.GHOST_ADMIN_PASSWORD || "change-me-now";

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

function parseCookies(cookieHeader = "") {
  return cookieHeader
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, entry) => {
      const separatorIndex = entry.indexOf("=");
      if (separatorIndex < 0) {
        return cookies;
      }

      const key = entry.slice(0, separatorIndex);
      const value = decodeURIComponent(entry.slice(separatorIndex + 1));
      cookies[key] = value;
      return cookies;
    }, {});
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const derivedKey = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash: derivedKey };
}

function verifyPassword(password, salt, expectedHash) {
  const calculatedHash = crypto.scryptSync(password, salt, 64).toString("hex");
  const left = Buffer.from(calculatedHash, "hex");
  const right = Buffer.from(expectedHash, "hex");

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,32}$/.test(username);
}

function sanitizeAccount(account) {
  return {
    username: account.username,
    role: account.role,
    disabled: account.disabled,
    expiresAt: account.expiresAt,
    createdAt: account.createdAt,
  };
}

function isAccountExpired(account) {
  return Number.isFinite(account.expiresAt) && account.expiresAt <= Date.now();
}

function isAccountActive(account) {
  return Boolean(account) && !account.disabled && !isAccountExpired(account);
}

async function saveAccounts() {
  const folder = path.dirname(ACCOUNT_FILE);
  await fs.mkdir(folder, { recursive: true });
  const payload = JSON.stringify(Array.from(accounts.values()), null, 2);
  await fs.writeFile(ACCOUNT_FILE, payload, "utf8");
}

async function loadAccounts() {
  try {
    const content = await fs.readFile(ACCOUNT_FILE, "utf8");
    const parsed = JSON.parse(content);
    for (const account of parsed) {
      if (account?.username) {
        accounts.set(account.username, account);
      }
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  const existingAdmin = accounts.get(ADMIN_USERNAME);
  if (!existingAdmin) {
    const { salt, hash } = hashPassword(ADMIN_PASSWORD);
    accounts.set(ADMIN_USERNAME, {
      username: ADMIN_USERNAME,
      salt,
      passwordHash: hash,
      role: "admin",
      disabled: false,
      expiresAt: null,
      createdAt: Date.now(),
    });
    await saveAccounts();
  }
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
  );
}

function clearSessionsForUser(username) {
  for (const [token, session] of sessions.entries()) {
    if (session.username === username) {
      sessions.delete(token);
    }
  }
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[SESSION_COOKIE];
  if (!token) {
    return null;
  }

  const session = sessions.get(token);
  if (!session) {
    return null;
  }

  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  const account = accounts.get(session.username);
  if (!isAccountActive(account)) {
    sessions.delete(token);
    return null;
  }

  return { token, ...session, account };
}

function isAuthenticatedRequest(req) {
  return Boolean(getSessionFromRequest(req));
}

function ensureAuthenticated(req, res, next) {
  const session = getSessionFromRequest(req);
  if (!session) {
    const isApiRoute = req.path.startsWith("/api/");
    if (isApiRoute) {
      return res.status(401).json({ error: "Authentication required" });
    }

    return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl || "/")}`);
  }

  sessions.set(session.token, {
    username: session.username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  setSessionCookie(res, session.token);
  req.user = {
    username: session.username,
    role: session.account.role,
  };
  return next();
}

function ensureAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  return next();
}

app.use((req, res, next) => {
  const publicPaths = new Set([
    "/login",
    "/api/login",
    "/api/logout",
    "/api/session",
    "/404.html",
    "/blocked.html",
    "/favicon.ico",
  ]);

  if (
    publicPaths.has(req.path) ||
    req.path.startsWith("/assets/") ||
    bare.shouldRoute(req)
  ) {
    return next();
  }

  return ensureAuthenticated(req, res, next);
});

server.on("request", (req, res) => {
  if (bare.shouldRoute(req)) {
    if (!isAuthenticatedRequest(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Authentication required" }));
      return;
    }

    bare.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

server.on("upgrade", (req, socket, head) => {
  if (bare.shouldRoute(req)) {
    if (!isAuthenticatedRequest(req)) {
      socket.end();
      return;
    }

    bare.routeUpgrade(req, socket, head);
  } else {
    socket.end();
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/login", (req, res) => {
  const session = getSessionFromRequest(req);
  const returnTo = typeof req.query.returnTo === "string" ? req.query.returnTo : "/";

  if (session) {
    return res.redirect(returnTo.startsWith("/") ? returnTo : "/");
  }

  return res.sendFile("/public/login.html", { root: __dirname });
});

app.get("/admin", (req, res) => {
  if (req.user?.role !== "admin") {
    return res.status(403).send("Admin access required");
  }

  return res.sendFile("/public/admin.html", { root: __dirname });
});

app.get("/api/session", (req, res) => {
  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(200).json({ authenticated: false });
  }

  return res.status(200).json({
    authenticated: true,
    user: {
      username: session.username,
      role: session.account.role,
    },
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid payload" });
  }

  const account = accounts.get(username);
  if (!isAccountActive(account)) {
    clearSessionCookie(res);
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const passwordMatches = verifyPassword(password, account.salt, account.passwordHash);
  if (!passwordMatches) {
    clearSessionCookie(res);
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = crypto.randomBytes(48).toString("hex");
  sessions.set(token, {
    username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  setSessionCookie(res, token);
  return res.status(200).json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const session = getSessionFromRequest(req);
  if (session) {
    sessions.delete(session.token);
  }

  clearSessionCookie(res);
  return res.status(200).json({ ok: true });
});

app.get("/api/admin/accounts", ensureAdmin, (req, res) => {
  const list = Array.from(accounts.values()).map(sanitizeAccount);
  res.status(200).json(list);
});

app.post("/api/admin/accounts", ensureAdmin, async (req, res) => {
  const { username, password, role, expiresAt } = req.body || {};

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: "Username must be 3-32 chars using letters, numbers, _, -, ." });
  }

  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  if (accounts.has(username)) {
    return res.status(409).json({ error: "Account already exists" });
  }

  const normalizedRole = role === "admin" ? "admin" : "user";
  const parsedExpiresAt = expiresAt ? Number(expiresAt) : null;
  if (parsedExpiresAt !== null && !Number.isFinite(parsedExpiresAt)) {
    return res.status(400).json({ error: "expiresAt must be a timestamp or empty" });
  }

  const { salt, hash } = hashPassword(password);
  accounts.set(username, {
    username,
    salt,
    passwordHash: hash,
    role: normalizedRole,
    disabled: false,
    expiresAt: parsedExpiresAt,
    createdAt: Date.now(),
  });

  await saveAccounts();
  return res.status(201).json({ ok: true });
});

app.patch("/api/admin/accounts/:username", ensureAdmin, async (req, res) => {
  const username = req.params.username;
  const account = accounts.get(username);
  if (!account) {
    return res.status(404).json({ error: "Account not found" });
  }

  if (req.body.password !== undefined) {
    if (typeof req.body.password !== "string" || req.body.password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const { salt, hash } = hashPassword(req.body.password);
    account.salt = salt;
    account.passwordHash = hash;
    clearSessionsForUser(username);
  }

  if (req.body.disabled !== undefined) {
    account.disabled = Boolean(req.body.disabled);
    if (account.disabled) {
      clearSessionsForUser(username);
    }
  }

  if (req.body.expiresAt !== undefined) {
    if (req.body.expiresAt === null || req.body.expiresAt === "") {
      account.expiresAt = null;
    } else {
      const parsedExpiresAt = Number(req.body.expiresAt);
      if (!Number.isFinite(parsedExpiresAt)) {
        return res.status(400).json({ error: "expiresAt must be a timestamp" });
      }
      account.expiresAt = parsedExpiresAt;
      if (isAccountExpired(account)) {
        clearSessionsForUser(username);
      }
    }
  }

  if (req.body.role !== undefined) {
    if (req.body.role !== "admin" && req.body.role !== "user") {
      return res.status(400).json({ error: "Invalid role" });
    }
    account.role = req.body.role;
  }

  accounts.set(username, account);
  await saveAccounts();
  return res.status(200).json({ ok: true });
});

app.delete("/api/admin/accounts/:username", ensureAdmin, async (req, res) => {
  const username = req.params.username;
  if (!accounts.has(username)) {
    return res.status(404).json({ error: "Account not found" });
  }

  accounts.delete(username);
  clearSessionsForUser(username);
  await saveAccounts();
  return res.status(200).json({ ok: true });
});

app.post("/api/admin/accounts/:username/logout", ensureAdmin, (req, res) => {
  const username = req.params.username;
  clearSessionsForUser(username);
  return res.status(200).json({ ok: true });
});

app.get("/", (req, res) => {
  res.sendFile("/public/index.html", { root: __dirname });
});

app.get("/tools/", (req, res) => {
  res.sendFile("/public/tools.html", { root: __dirname });
});

app.get("/dl/", (req, res) => {
  res.sendFile("/public/dl.html", { root: __dirname });
});

app.get("/check/", (req, res) => {
  res.sendFile("/public/check.html", { root: __dirname });
});

app.get("/s/", (req, res) => {
  res.sendFile("/public/settings.html", { root: __dirname });
});

app.get("/w/", (req, res) => {
  res.sendFile("/public/browser.html", { root: __dirname });
});

app.get("/b/", (req, res) => {
  res.sendFile("/public/browser.html", { root: __dirname });
});

app.get("/c/", (req, res) => {
  res.sendFile("/public/ag.html", { root: __dirname });
});

app.get("/a/", (req, res) => {
  res.sendFile("/public/algebra.html", { root: __dirname });
});

app.get("/q/", (req, res) => {
  res.sendFile("/public/g.html", { root: __dirname });
});

//forward the api req to lightspeed
//if your in here then you are either a skid or just wondering how this works
//either way get out :3
app.get("/api/fl/lightspeed/v1/", (req, res) => {
  const url = req.query.url;
  fetch(
    "https://production-archive-proxy-api.lightspeedsystems.com/archiveproxy",
    {
      method: "POST",
      body: JSON.stringify({
        query:
          "query getDeviceCategorization($itemA: CustomHostLookupInput!, $itemB: CustomHostLookupInput!){ a: custom_HostLookup(item: $itemA) {cat}  b: custom_HostLookup(item: $itemB) {cat}}",
        variables: {
          itemA: { hostname: url },
          itemB: { hostname: url },
        },
      }),
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "onEkoztnFpTi3VG7XQEq6skQWN3aFm3h",
      },
    },
  )
    .then((response) => {
      if (!response.ok) {
        return res.json(["Error"]);
      }
      return response.json();
    })
    .then((data) => {
      res.json(data);
    })
    .catch((error) => {
      res.json(["Error", error]);
    });
});

//fortigaurd
app.get("/api/fl/fortigaurd/v1/", async (req, res) => {
  const url = req.query.url;
  const r = await fetch("https://www.fortiguard.com/learnmore/dns", {
    method: "POST",
    body: JSON.stringify({
      value: url,
      version: 9,
    }),
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
    },
  });
  const data = await r.json();
  res.json(data);
});

//blocksi
app.get("/api/fl/blocksi/v1/", async (req, res) => {
  const url = req.query.url;
  const r = await fetch(`https://service1.blocksi.net/getRating.json?url=${url}`);
  const d = await r.json();
  res.json(d);
});

//palo alto
app.get("/api/fl/paloalto/v1/", async (req, res) => {
  const url = req.query.url;
  const r = await fetch(`https://urlfiltering.paloaltonetworks.com/single_cr/?url=${url}`);
  const data = await r.text();
  //janky weird way of parsing it
  const cutstr = data
    .substring(
      data.indexOf('<label class="control-label col-sm-2 col-lg-2 " for="id_new_category">Current Risk Level</label>') + 1,
      data.lastIndexOf("<!-- New Dropdown -->"),
    )
    .replace(
      'label class="control-label col-sm-2 col-lg-2 " for="id_new_category">Current Risk Level</label>\n                        <div class=" col-sm-10 col-lg-10 form-text">\n                            \n    ',
      "",
    );
  const thestr = cutstr.replace(
    '\n                            \n                        </div>\n                    </div>\n                \n                <div class="form-group">\n                    <label class="control-label col-sm-2 col-lg-2 " for="id_new_category">Current Category</label>\n                    <div class=" col-sm-10 col-lg-10 form-text">\n                        \n                             \n       ',
    "|",
  );
  const str = thestr.replace(
    "\n                            \n                        \n                        \n                    </div>\n                </div>",
    "|",
  );
  const resp = str.replace(/\s/g, "");
  res.json(`{"risk": "${resp.split("|")[0]}", "e": {"categoryname": "${resp.split("|")[1]}"}}`);
});

const sg = [];
const sa = [];
function getrand() {
  sg.splice(0, sg.length);
  for (let i = 0; i < 8; i++) {
    const rg = g.length;
    const random = Math.floor(Math.random() * rg);
    if (!sg.includes(g[random])) {
      sg.push(g[random]);
    } else {
      i--;
    }
  }
}

function getrandapps() {
  sa.splice(0, sa.length);
  for (let i = 0; i < 8; i++) {
    const ra = a.length;
    const random = Math.floor(Math.random() * ra);
    if (!sa.includes(a[random])) {
      sa.push(a[random]);
    } else {
      i--;
    }
  }
}

setInterval(getrand, 500000);
setInterval(getrandapps, 500000);
getrand();
getrandapps();

app.get("/api/g/v1/", (req, res) => {
  res.json(g);
});

app.get("/api/deg/v1/", (req, res) => {
  res.json(deg);
});

app.get("/api/rg/v1/", (req, res) => {
  res.json(sg);
});

app.get("/api/a/v1/", (req, res) => {
  res.json(a);
});

app.get("/api/ra/v1/", (req, res) => {
  res.json(sa);
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(token);
    }
  }

  for (const [username, account] of accounts.entries()) {
    if (isAccountExpired(account)) {
      clearSessionsForUser(username);
    }
  }
}, 60_000);

await loadAccounts();

server.listen(PORT);

server.on("listening", () => {
  console.log("Ghost Is On http://localhost:" + PORT + ":3");
});
