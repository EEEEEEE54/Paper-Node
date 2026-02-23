import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const rootDir = process.cwd();
const publicDir = path.join(rootDir, "public");
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const SECRET = process.env.GHOST_SESSION_SECRET || "change-this-netlify-secret";

const accountStore = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, passwordHash };
}

function verifyPassword(password, salt, expectedHash) {
  const calculated = crypto.scryptSync(password, salt, 64).toString("hex");
  const left = Buffer.from(calculated, "hex");
  const right = Buffer.from(expectedHash, "hex");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,32}$/.test(username);
}

function now() {
  return Date.now();
}

function isExpired(account) {
  return Number.isFinite(account.expiresAt) && account.expiresAt <= now();
}

function isActive(account) {
  return Boolean(account) && !account.disabled && !isExpired(account);
}

function parseConfiguredAccounts() {
  const fallbackUsername = process.env.GHOST_ADMIN_USERNAME || "admin";
  const fallbackPassword = process.env.GHOST_ADMIN_PASSWORD || "change-me-now";

  let input = {
    [fallbackUsername]: {
      password: fallbackPassword,
      role: "admin",
      disabled: false,
      expiresAt: null,
    },
  };

  if (process.env.GHOST_ACCOUNTS_JSON) {
    try {
      const parsed = JSON.parse(process.env.GHOST_ACCOUNTS_JSON);
      if (parsed && typeof parsed === "object") {
        input = parsed;
      }
    } catch {
      // keep fallback
    }
  }

  for (const [username, cfg] of Object.entries(input)) {
    if (!isValidUsername(username)) continue;
    const role = cfg?.role === "admin" ? "admin" : "user";
    const disabled = Boolean(cfg?.disabled);
    const expiresAt = Number.isFinite(cfg?.expiresAt) ? Number(cfg.expiresAt) : null;

    if (typeof cfg?.passwordHash === "string" && typeof cfg?.salt === "string") {
      accountStore.set(username, {
        username,
        role,
        disabled,
        expiresAt,
        salt: cfg.salt,
        passwordHash: cfg.passwordHash,
        tokenVersion: Number.isFinite(cfg?.tokenVersion) ? Number(cfg.tokenVersion) : 1,
        createdAt: Number.isFinite(cfg?.createdAt) ? Number(cfg.createdAt) : now(),
      });
      continue;
    }

    const password = typeof cfg?.password === "string" ? cfg.password : null;
    if (!password) continue;
    const { salt, passwordHash } = hashPassword(password);
    accountStore.set(username, {
      username,
      role,
      disabled,
      expiresAt,
      salt,
      passwordHash,
      tokenVersion: 1,
      createdAt: now(),
    });
  }

  if (accountStore.size === 0) {
    const { salt, passwordHash } = hashPassword(fallbackPassword);
    accountStore.set(fallbackUsername, {
      username: fallbackUsername,
      role: "admin",
      disabled: false,
      expiresAt: null,
      salt,
      passwordHash,
      tokenVersion: 1,
      createdAt: now(),
    });
  }
}

parseConfiguredAccounts();

function parseCookies(cookieHeader = "") {
  return cookieHeader
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce((acc, pair) => {
      const idx = pair.indexOf("=");
      if (idx < 0) return acc;
      acc[pair.slice(0, idx)] = decodeURIComponent(pair.slice(idx + 1));
      return acc;
    }, {});
}

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function sign(value) {
  return b64url(crypto.createHmac("sha256", SECRET).update(value).digest());
}

function createToken(account) {
  const payload = {
    username: account.username,
    role: account.role,
    tv: account.tokenVersion,
    exp: now() + SESSION_TTL_MS,
  };
  const data = b64url(JSON.stringify(payload));
  return `${data}.${sign(data)}`;
}

function verifyToken(token) {
  if (!token || !token.includes(".")) return null;
  const [data, sig] = token.split(".");
  if (sign(data) !== sig) return null;

  try {
    const payload = JSON.parse(Buffer.from(data.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    if (!payload?.username || payload.exp <= now()) return null;

    const account = accountStore.get(payload.username);
    if (!isActive(account)) return null;
    if (payload.tv !== account.tokenVersion) return null;

    return { username: account.username, role: account.role };
  } catch {
    return null;
  }
}

function response(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      "Cache-Control": "no-store",
      ...headers,
    },
    body,
  };
}

function json(statusCode, value, headers = {}) {
  return response(statusCode, JSON.stringify(value), {
    "Content-Type": "application/json",
    ...headers,
  });
}

function redirect(location, headers = {}) {
  return response(302, "", { Location: location, ...headers });
}

function clearCookieHeader() {
  return "ghost_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
}

function sessionCookieHeader(token) {
  return `ghost_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

async function serveFile(relativePath) {
  const filePath = path.join(publicDir, relativePath);
  const content = await fs.readFile(filePath);
  const ext = path.extname(filePath).toLowerCase();
  const contentType =
    ext === ".html"
      ? "text/html; charset=utf-8"
      : ext === ".css"
        ? "text/css; charset=utf-8"
        : ext === ".js"
          ? "application/javascript; charset=utf-8"
          : ext === ".json"
            ? "application/json; charset=utf-8"
            : "application/octet-stream";

  return {
    statusCode: 200,
    isBase64Encoded: true,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "public, max-age=0",
    },
    body: content.toString("base64"),
  };
}

function normalizePath(rawPath = "/") {
  return rawPath.replace(/^\/.netlify\/functions\/app/, "") || "/";
}

function routeToPublicFile(pathname) {
  const aliases = {
    "/": "index.html",
    "/login": "login.html",
    "/admin": "admin.html",
    "/tools": "tools.html",
    "/tools/": "tools.html",
    "/dl": "dl.html",
    "/dl/": "dl.html",
    "/check": "check.html",
    "/check/": "check.html",
    "/s": "settings.html",
    "/s/": "settings.html",
    "/w": "browser.html",
    "/w/": "browser.html",
    "/b": "browser.html",
    "/b/": "browser.html",
    "/c": "ag.html",
    "/c/": "ag.html",
    "/a": "algebra.html",
    "/a/": "algebra.html",
    "/q": "g.html",
    "/q/": "g.html",
  };

  if (aliases[pathname]) return aliases[pathname];
  if (pathname.startsWith("/assets/")) return pathname.slice(1);
  if (pathname.startsWith("/u/")) return pathname.slice(1);
  if (pathname.endsWith(".html")) return pathname.slice(1);
  return null;
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

function parseBody(event) {
  if (!event.body) return {};
  try {
    return JSON.parse(event.body);
  } catch {
    return {};
  }
}

function requireAuth(currentUser) {
  if (!currentUser) {
    return json(401, { error: "Authentication required" });
  }
  return null;
}

function requireAdmin(currentUser) {
  if (!currentUser || currentUser.role !== "admin") {
    return json(403, { error: "Admin access required" });
  }
  return null;
}

export async function handler(event) {
  const pathname = normalizePath(event.path || "/");
  const method = event.httpMethod || "GET";
  const cookies = parseCookies(event.headers?.cookie || event.headers?.Cookie || "");
  const currentUser = verifyToken(cookies.ghost_session);

  if (pathname === "/api/login" && method === "POST") {
    const payload = parseBody(event);
    const username = typeof payload.username === "string" ? payload.username : "";
    const password = typeof payload.password === "string" ? payload.password : "";
    const account = accountStore.get(username);

    if (!isActive(account) || !verifyPassword(password, account.salt, account.passwordHash)) {
      return json(401, { error: "Invalid username or password" }, { "Set-Cookie": clearCookieHeader() });
    }

    const token = createToken(account);
    return json(200, { ok: true }, { "Set-Cookie": sessionCookieHeader(token) });
  }

  if (pathname === "/api/logout" && method === "POST") {
    return json(200, { ok: true }, { "Set-Cookie": clearCookieHeader() });
  }

  if (pathname === "/api/session" && method === "GET") {
    if (!currentUser) return json(200, { authenticated: false });
    return json(200, { authenticated: true, user: currentUser });
  }

  if (pathname === "/api/admin/accounts" && method === "GET") {
    const authError = requireAdmin(currentUser);
    if (authError) return authError;
    const list = Array.from(accountStore.values()).map(sanitizeAccount);
    return json(200, list);
  }

  if (pathname === "/api/admin/accounts" && method === "POST") {
    const authError = requireAdmin(currentUser);
    if (authError) return authError;

    const payload = parseBody(event);
    const username = payload.username;
    const password = payload.password;
    const role = payload.role === "admin" ? "admin" : "user";
    const expiresAt = payload.expiresAt === null || payload.expiresAt === "" || payload.expiresAt === undefined
      ? null
      : Number(payload.expiresAt);

    if (!isValidUsername(username)) {
      return json(400, { error: "Username must be 3-32 chars using letters, numbers, _, -, ." });
    }
    if (typeof password !== "string" || password.length < 8) {
      return json(400, { error: "Password must be at least 8 characters" });
    }
    if (expiresAt !== null && !Number.isFinite(expiresAt)) {
      return json(400, { error: "expiresAt must be a timestamp or empty" });
    }
    if (accountStore.has(username)) {
      return json(409, { error: "Account already exists" });
    }

    const { salt, passwordHash } = hashPassword(password);
    accountStore.set(username, {
      username,
      role,
      disabled: false,
      expiresAt,
      salt,
      passwordHash,
      tokenVersion: 1,
      createdAt: now(),
    });

    return json(201, { ok: true });
  }

  const adminAccountMatch = pathname.match(/^\/api\/admin\/accounts\/([^/]+)$/);
  if (adminAccountMatch && method === "PATCH") {
    const authError = requireAdmin(currentUser);
    if (authError) return authError;

    const username = decodeURIComponent(adminAccountMatch[1]);
    const account = accountStore.get(username);
    if (!account) {
      return json(404, { error: "Account not found" });
    }

    const payload = parseBody(event);
    if (payload.password !== undefined) {
      if (typeof payload.password !== "string" || payload.password.length < 8) {
        return json(400, { error: "Password must be at least 8 characters" });
      }
      const { salt, passwordHash } = hashPassword(payload.password);
      account.salt = salt;
      account.passwordHash = passwordHash;
      account.tokenVersion += 1;
    }

    if (payload.disabled !== undefined) {
      account.disabled = Boolean(payload.disabled);
      if (account.disabled) {
        account.tokenVersion += 1;
      }
    }

    if (payload.expiresAt !== undefined) {
      if (payload.expiresAt === null || payload.expiresAt === "") {
        account.expiresAt = null;
      } else {
        const ts = Number(payload.expiresAt);
        if (!Number.isFinite(ts)) {
          return json(400, { error: "expiresAt must be a timestamp" });
        }
        account.expiresAt = ts;
        if (isExpired(account)) {
          account.tokenVersion += 1;
        }
      }
    }

    if (payload.role !== undefined) {
      if (payload.role !== "admin" && payload.role !== "user") {
        return json(400, { error: "Invalid role" });
      }
      account.role = payload.role;
      account.tokenVersion += 1;
    }

    accountStore.set(username, account);
    return json(200, { ok: true });
  }

  if (adminAccountMatch && method === "DELETE") {
    const authError = requireAdmin(currentUser);
    if (authError) return authError;

    const username = decodeURIComponent(adminAccountMatch[1]);
    if (!accountStore.has(username)) {
      return json(404, { error: "Account not found" });
    }
    accountStore.delete(username);
    return json(200, { ok: true });
  }

  const adminLogoutMatch = pathname.match(/^\/api\/admin\/accounts\/([^/]+)\/logout$/);
  if (adminLogoutMatch && method === "POST") {
    const authError = requireAdmin(currentUser);
    if (authError) return authError;

    const username = decodeURIComponent(adminLogoutMatch[1]);
    const account = accountStore.get(username);
    if (!account) {
      return json(404, { error: "Account not found" });
    }
    account.tokenVersion += 1;
    accountStore.set(username, account);
    return json(200, { ok: true });
  }

  if (pathname.startsWith("/api/")) {
    const authError = requireAuth(currentUser);
    if (authError) return authError;
    return json(501, { error: "This API route is not available in Netlify function mode." });
  }

  if (pathname === "/admin" && (!currentUser || currentUser.role !== "admin")) {
    if (!currentUser) {
      return redirect(`/login?returnTo=${encodeURIComponent("/admin")}`);
    }
    return response(403, "Admin access required", { "Content-Type": "text/plain; charset=utf-8" });
  }

  const publicNoAuth = new Set(["/login", "/login.html", "/404.html", "/blocked.html"]);
  if (!publicNoAuth.has(pathname) && !pathname.startsWith("/assets/") && !pathname.startsWith("/u/")) {
    if (!currentUser) {
      return redirect(`/login?returnTo=${encodeURIComponent(pathname || "/")}`);
    }
  }

  const file = routeToPublicFile(pathname);
  if (!file) {
    return response(404, "Not Found", { "Content-Type": "text/plain; charset=utf-8" });
  }

  try {
    return await serveFile(file);
  } catch {
    return response(404, "Not Found", { "Content-Type": "text/plain; charset=utf-8" });
  }
}
