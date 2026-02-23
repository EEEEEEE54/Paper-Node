import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const rootDir = process.cwd();
const publicDir = path.join(rootDir, "public");
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const SECRET = process.env.GHOST_SESSION_SECRET || "change-this-netlify-secret";

const defaultAccounts = {
  [process.env.GHOST_ADMIN_USERNAME || "admin"]: {
    password: process.env.GHOST_ADMIN_PASSWORD || "change-me-now",
    role: "admin",
    disabled: false,
    expiresAt: null,
  },
};

const configuredAccounts = (() => {
  try {
    return process.env.GHOST_ACCOUNTS_JSON
      ? JSON.parse(process.env.GHOST_ACCOUNTS_JSON)
      : defaultAccounts;
  } catch {
    return defaultAccounts;
  }
})();

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

function createToken(username, role) {
  const payload = {
    username,
    role,
    exp: Date.now() + SESSION_TTL_MS,
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
    if (!payload?.username || payload.exp <= Date.now()) return null;

    const account = configuredAccounts[payload.username];
    if (!account || account.disabled) return null;
    if (Number.isFinite(account.expiresAt) && account.expiresAt <= Date.now()) return null;

    return { username: payload.username, role: payload.role || account.role || "user" };
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
  const withoutFunctionPrefix = rawPath.replace(/^\/.netlify\/functions\/app/, "") || "/";
  return withoutFunctionPrefix;
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

export async function handler(event) {
  const pathname = normalizePath(event.path || "/");
  const method = event.httpMethod || "GET";
  const cookies = parseCookies(event.headers?.cookie || event.headers?.Cookie || "");
  const currentUser = verifyToken(cookies.ghost_session);

  if (pathname === "/api/login" && method === "POST") {
    const payload = event.body ? JSON.parse(event.body) : {};
    const username = typeof payload.username === "string" ? payload.username : "";
    const password = typeof payload.password === "string" ? payload.password : "";
    const account = configuredAccounts[username];

    if (!account || account.password !== password || account.disabled) {
      return json(401, { error: "Invalid username or password" }, {
        "Set-Cookie": "ghost_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
      });
    }

    if (Number.isFinite(account.expiresAt) && account.expiresAt <= Date.now()) {
      return json(401, { error: "Account expired" });
    }

    const token = createToken(username, account.role || "user");
    return json(200, { ok: true }, {
      "Set-Cookie": `ghost_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    });
  }

  if (pathname === "/api/logout" && method === "POST") {
    return json(200, { ok: true }, {
      "Set-Cookie": "ghost_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
    });
  }

  if (pathname === "/api/session" && method === "GET") {
    if (!currentUser) return json(200, { authenticated: false });
    return json(200, { authenticated: true, user: currentUser });
  }

  if (pathname.startsWith("/api/")) {
    if (!currentUser) return json(401, { error: "Authentication required" });
    return json(501, { error: "This API route is not available in Netlify function mode." });
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
