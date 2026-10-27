import http from "node:http";
import { randomUUID, randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import WebSocket, { WebSocketServer } from "ws";
import * as oidc from "openid-client";
import { createStorage } from "./storage.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_FRAME = 1024 * 1024;
const MAX_HTTP_BODY = 16 * 1024;
const AUTH_TIMEOUT = 5000;
const TICKET_TTL = 60_000;
const SESSION_ID = /^[0-9a-f]{128}$/;
const CODE_BLOCK_COMPONENT_URL = "https://sodium.static.apphor.de/code-block.html";
const HIGHLIGHTJS_SCRIPT_URL = "https://unpkg.com/@highlightjs/cdn-assets@11.11.1/es/highlight.min.js";
const HIGHLIGHTJS_THEME_URL = "https://unpkg.com/@highlightjs/cdn-assets@11.11.1/styles/atom-one-dark.min.css";

function bearerMatches(header, secret) {
  if (!secret || typeof header !== "string") {
    return false;
  }
  const match = /^Bearer ([^\s]+)$/.exec(header);
  if (!match) {
    return false;
  }
  const supplied = Buffer.from(match[1]);
  const expected = Buffer.from(secret);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function createRelay({
  env = process.env,
  ticketTtlMs = TICKET_TTL,
  db: injectedDb,
  authUserInfo,
  oidcClient = oidc,
} = {}) {
  const relays = new Map();
  const tickets = new Map();
  const bridges = new Map();
  const registering = new Set();
  const controllers = new Map();
  const webSessions = new Map();
  const transactions = new Map();
  let keyOperations = Promise.resolve();
  let oidcConfig;
  let storage;
  let initialized = false;
  const loadMachines = async () => {
    storage = await createStorage({ env, db: injectedDb });
    initialized = true;
  };
  const oidcReady = async () => {
    if (oidcConfig) {
      return oidcConfig;
    }
    if (!env.OIDC_CLIENT_ID || !env.OIDC_CLIENT_SECRET || !env.OIDC_ISSUER || !env.APP_URL) {
      throw new Error("OIDC is not configured");
    }
    const appUrl = new URL(env.APP_URL);
    const localHost = (host) => ["localhost", "127.0.0.1", "[::1]"].includes(host);
    if (
      (appUrl.protocol !== "https:" && !(appUrl.protocol === "http:" && localHost(appUrl.hostname))) ||
      appUrl.username ||
      appUrl.password ||
      appUrl.pathname !== "/" ||
      appUrl.search ||
      appUrl.hash
    ) {
      throw new Error("APP_URL must be an HTTPS origin");
    }
    const issuer = new URL(env.OIDC_ISSUER);
    if (
      (issuer.protocol !== "https:" && !(issuer.protocol === "http:" && localHost(issuer.hostname))) ||
      issuer.username ||
      issuer.password ||
      issuer.search ||
      issuer.hash
    ) {
      throw new Error("OIDC_ISSUER must be an HTTPS URL without credentials or query parameters");
    }
    const localIssuer = issuer.protocol === "http:" && localHost(issuer.hostname);
    oidcConfig = await oidcClient.discovery(
      issuer,
      env.OIDC_CLIENT_ID,
      env.OIDC_CLIENT_SECRET,
      undefined,
      localIssuer ? { execute: [oidcClient.allowInsecureRequests] } : undefined,
    );
    return oidcConfig;
  };
  const userInfo = async (token) => {
    if (!token || token.length > 8192) {
      return null;
    }
    try {
      const info = authUserInfo
        ? await authUserInfo(token)
        : await oidcClient.fetchUserInfo(await oidcReady(), token, oidcClient.skipSubjectCheck);
      return typeof info?.sub === "string" && info.sub.trim() ? info : null;
    } catch {
      return null;
    }
  };
  const cookie = (req, name) =>
    (req.headers.cookie || "")
      .split(";")
      .map((v) => v.trim())
      .find((v) => v.startsWith(`${name}=`))
      ?.slice(name.length + 1);
  const setCookie = (res, value, maxAge) =>
    res.setHeader(
      "set-cookie",
      `relay_session=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${env.APP_URL && new URL(env.APP_URL).protocol === "https:" ? "; Secure" : ""}`,
    );
  const browserSession = (req) => {
    const key = cookie(req, "relay_session");
    const s = key && webSessions.get(key);
    if (!s || s.expiresAt < Date.now()) {
      if (key) {
        webSessions.delete(key);
      }
      return null;
    }
    return s;
  };
  const withKeyOperation = async (operation) => {
    const previous = keyOperations;
    let release;
    keyOperations = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  };

  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch(() => {
      if (res.headersSent) {
        res.destroy();
      } else {
        res.writeHead(503).end();
      }
    });
  });
  async function handleRequest(req, res) {
    const pathname = new URL(req.url || "/", "http://localhost").pathname;
    const isSnippetFrame = pathname === "/snippet-frame.html";
    const connectOrigins = [env.OIDC_ISSUER, env.AUTH_API_URL].filter(Boolean).flatMap((value) => {
      try {
        return [new URL(value).origin];
      } catch {
        return [];
      }
    });
    const connectSources = [...new Set(connectOrigins)].join(" ");
    const cspNonce = randomBytes(16).toString("base64");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", isSnippetFrame ? "SAMEORIGIN" : "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "serial=()");
    // Keep the upstream component's runtime and CDN permissions inside its sandboxed frame only.
    res.setHeader(
      "Content-Security-Policy",
      isSnippetFrame
        ? `default-src 'none'; script-src 'self' 'unsafe-eval' 'nonce-${cspNonce}' ${HIGHLIGHTJS_SCRIPT_URL} blob:; style-src 'self' ${HIGHLIGHTJS_THEME_URL}; style-src-attr 'unsafe-inline'; connect-src ${CODE_BLOCK_COMPONENT_URL}; frame-src 'none'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'; form-action 'none'`
        : `default-src 'self'; script-src 'self' 'nonce-${cspNonce}'; style-src 'self'; connect-src 'self' ${connectSources}; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'`,
    );

    if (env.APP_URL?.startsWith("https://")) {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }

    const json = (status, data) =>
      res
        .writeHead(status, { "content-type": "application/json", "cache-control": "no-store" })
        .end(JSON.stringify(data));
    if (pathname === "/api/v1/health" && req.method === "GET") {
      let ready =
        initialized &&
        Boolean(
          env.DATABASE_URL &&
            env.OIDC_CLIENT_ID &&
            env.OIDC_CLIENT_SECRET &&
            env.OIDC_ISSUER &&
            env.AUTH_API_URL &&
            env.APP_URL &&
            env.AUTH_TOKEN_AUDIENCE,
        );
      if (ready) {
        try {
          await storage.ping();
        } catch {
          ready = false;
        }
      }
      res.setHeader("cache-control", "no-store");
      return json(ready ? 200 : 503, { ready });
    }
    if (pathname === "/") {
      try {
        const html = (await readFile(new URL("./public/index.html", import.meta.url), "utf8")).replaceAll(
          "__CSP_NONCE__",
          cspNonce,
        );
        res.setHeader("cache-control", "no-store");
        return res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(html);
      } catch {
        return res.writeHead(500).end();
      }
    }
    if (isSnippetFrame && req.method === "GET") {
      try {
        const html = (await readFile(new URL("./public/snippet-frame.html", import.meta.url), "utf8")).replaceAll(
          "__CSP_NONCE__",
          cspNonce,
        );
        res.setHeader("cache-control", "no-store");
        return res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(html);
      } catch {
        return res.writeHead(500).end();
      }
    }
    if (
      pathname === "/app.js" ||
      pathname === "/snippet-frame.js" ||
      pathname === "/style.css" ||
      pathname === "/vendor/li3-web.js"
    ) {
      try {
        const isStyle = pathname === "/style.css";
        const ext = isStyle ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8";
        const assetPath =
          pathname === "/vendor/li3-web.js" ? "./node_modules/@li3/web/index.js" : `./public${pathname}`;
        const asset = await readFile(new URL(assetPath, import.meta.url));
        if (
          req.headers.origin === "null" &&
          ["/snippet-frame.js", "/style.css", "/vendor/li3-web.js"].includes(pathname)
        ) {
          res.setHeader("Access-Control-Allow-Origin", "null");
          res.setHeader("Vary", "Origin");
        }
        return res.writeHead(200, { "content-type": ext, "cache-control": "no-cache" }).end(asset);
      } catch {
        return res.writeHead(404).end();
      }
    }
    if (pathname === "/api/v1/auth/login" && req.method === "GET") {
      try {
        const config = await oidcReady();
        const verifier = oidcClient.randomPKCECodeVerifier();
        const state = oidcClient.randomState();
        const nonce = oidcClient.randomNonce();
        const binding = randomBytes(32).toString("base64url");
        const now = Date.now();
        for (const [key, value] of transactions) {
          if (value.expiresAt <= now) {
            transactions.delete(key);
          }
        }
        if (transactions.size >= 2048) {
          return res.writeHead(503).end("Authentication temporarily unavailable");
        }
        const url = oidcClient.buildAuthorizationUrl(config, {
          redirect_uri: new URL("/auth/callback", env.APP_URL).href,
          scope: "openid profile offline_access",
          code_challenge: await oidcClient.calculatePKCECodeChallenge(verifier),
          code_challenge_method: "S256",
          state,
          nonce,
        });
        transactions.set(binding, {
          verifier,
          state,
          nonce,
          expiresAt: Date.now() + 5 * 60_000,
        });
        res.setHeader(
          "set-cookie",
          `relay_tx=${binding}; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age=300${new URL(env.APP_URL).protocol === "https:" ? "; Secure" : ""}`,
        );
        return res.writeHead(302, { location: url.href }).end();
      } catch {
        return res.writeHead(503).end("Authentication unavailable");
      }
    }
    if (pathname === "/auth/callback" && req.method === "GET") {
      try {
        const binding = cookie(req, "relay_tx");
        const tx = binding && transactions.get(binding);
        if (binding) {
          transactions.delete(binding);
        }
        if (!tx || tx.expiresAt < Date.now()) {
          throw new Error("transaction expired");
        }
        const config = await oidcReady();
        const currentUrl = new URL(req.url, env.APP_URL);
        const tokens = await oidcClient.authorizationCodeGrant(config, currentUrl, {
          pkceCodeVerifier: tx.verifier,
          expectedState: tx.state,
          expectedNonce: tx.nonce,
        });
        const idTokenSubject = tokens.claims()?.sub;
        if (typeof idTokenSubject !== "string" || !tokens.access_token) {
          throw new Error("missing identity token subject");
        }
        const info = await oidcClient.fetchUserInfo(config, tokens.access_token, idTokenSubject);
        if (typeof info.sub !== "string" || info.sub !== idTokenSubject) {
          throw new Error("missing identity");
        }
        const key = randomBytes(32).toString("base64url");
        webSessions.set(key, {
          sub: info.sub,
          expiresAt: Date.now() + 8 * 60 * 60_000,
        });
        setCookie(res, key, 8 * 60 * 60);
        res.setHeader(
          "set-cookie",
          [res.getHeader("set-cookie"), "relay_tx=; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age=0"].flat(),
        );
        return res.writeHead(302, { location: "/" }).end();
      } catch {
        return res.writeHead(400).end("Authentication failed");
      }
    }
    if (pathname === "/api/v1/auth/logout" && req.method === "POST") {
      if (env.APP_URL && req.headers.origin !== new URL(env.APP_URL).origin) {
        return res.writeHead(403).end();
      }
      const session = browserSession(req);
      const key = cookie(req, "relay_session");
      if (session) {
        webSessions.delete(key);
      }
      setCookie(res, "", 0);
      return res.writeHead(303, { location: "/" }).end();
    }
    if (pathname === "/api/v1/auth/status" && req.method === "GET") {
      const s = browserSession(req);
      if (!s) {
        return res.writeHead(401).end();
      }
      res.setHeader("cache-control", "no-store");
      return json(200, { authenticated: true });
    }
    if (pathname === "/api/v1/auth/config" && req.method === "GET") {
      if (!browserSession(req)) {
        return res.writeHead(401).end();
      }
      if (!env.AUTH_TOKEN_AUDIENCE) {
        return res.writeHead(503).end();
      }
      const authApiUrl = env.AUTH_API_URL;
      try {
        const parsedAuthApi = new URL(authApiUrl);
        const localAuth =
          parsedAuthApi.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsedAuthApi.hostname);
        if (
          (parsedAuthApi.protocol !== "https:" && !localAuth) ||
          parsedAuthApi.username ||
          parsedAuthApi.password ||
          parsedAuthApi.pathname !== "/" ||
          parsedAuthApi.search ||
          parsedAuthApi.hash
        ) {
          return res.writeHead(503).end();
        }
      } catch {
        return res.writeHead(503).end();
      }
      return json(200, {
        authApiUrl,
        audience: env.AUTH_TOKEN_AUDIENCE,
      });
    }
    if (pathname === "/api" && req.method === "GET") {
      try {
        const host = req.headers.host;
        if (typeof host !== "string" || !/^[a-z0-9.-]+(?::\d{1,5})?$/i.test(host)) {
          return res.writeHead(400).end();
        }
        const forwardedProto = env.TRUST_PROXY === "true" ? req.headers["x-forwarded-proto"] : undefined;
        const configuredProtocol = env.APP_URL ? new URL(env.APP_URL).protocol : "http:";
        const protocol =
          forwardedProto === "https" ||
          (forwardedProto !== "http" && (req.socket.encrypted || configuredProtocol === "https:"))
            ? "https:"
            : "http:";
        const origin = new URL(`${protocol}//${host}`).origin;
        const spec = await readFile(new URL("./openapi.json", import.meta.url), "utf8");
        res.setHeader("cache-control", "no-store");
        return res
          .writeHead(200, { "content-type": "application/vnd.oai.openapi+json;version=3.1" })
          .end(spec.replaceAll("__HOSTNAME__", origin));
      } catch {
        return res.writeHead(500).end();
      }
    }
    if (pathname.startsWith("/api/v1/") && !pathname.startsWith("/api/v1/admin/")) {
      if (env.APP_URL && req.headers.origin && req.headers.origin !== new URL(env.APP_URL).origin) {
        return res.writeHead(403).end();
      }
      const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization || "");
      const info = match && (await userInfo(match[1]));
      if (!info) {
        return res.writeHead(401).end();
      }
      if (pathname === "/api/v1/sessions" && req.method === "GET") {
        const sessions = await storage.listSessions(info.sub);
        return json(
          200,
          await Promise.all(
            sessions.map(async (s) => ({
              id: s.id,
              isPublic: s.isPublic,
              createdAt: s.createdAt,
              connectedClients: relays.get(s.id)?.clients.size || 0,
              keys: s.isPublic ? [] : await storage.listKeys(s.id),
            })),
          ),
        );
      }
      if (pathname === "/api/v1/sessions" && req.method === "POST") {
        let body;
        try {
          body = await readJsonBody(req);
        } catch {
          return res.writeHead(400).end();
        }
        if (!body || !SESSION_ID.test(body.id || "") || typeof body.isPublic !== "boolean") {
          return res.writeHead(400).end();
        }
        const existing = await storage.getSession(body.id);
        if (existing) {
          return existing.ownerSub === info.sub && existing.isPublic === body.isPublic
            ? json(200, { id: existing.id })
            : res.writeHead(409).end();
        }
        if (await storage.getMachine(body.id)) {
          return res.writeHead(409).end();
        }
        const record = {
          id: body.id,
          ownerSub: info.sub,
          isPublic: body.isPublic,
          createdAt: new Date().toISOString(),
        };
        try {
          await storage.createSession(record);
        } catch {
          const raced = await storage.getSession(body.id);
          if (raced && raced.ownerSub === info.sub && raced.isPublic === body.isPublic) {
            return json(200, { id: raced.id });
          }
          return res.writeHead(409).end();
        }
        return json(201, { id: body.id });
      }
      const del = /^\/api\/v1\/sessions\/([0-9a-f]{128})$/.exec(pathname);
      const keysPath = /^\/api\/v1\/sessions\/([0-9a-f]{128})\/keys(?:\/([a-f0-9-]+))?$/.exec(pathname);
      if (keysPath) {
        const session = await storage.getSession(keysPath[1]);
        if (!session || session.ownerSub !== info.sub) {
          return res.writeHead(404).end();
        }
        if (req.method === "GET" && !keysPath[2]) {
          return json(200, await storage.listKeys(session.id));
        }
        if (req.method === "POST" && !keysPath[2]) {
          let body;
          try {
            body = await readJsonBody(req);
          } catch {
            return res.writeHead(400).end();
          }
          if (session.isPublic) {
            return res.writeHead(409).end();
          }
          const secret = randomBytes(32).toString("base64url");
          const id = randomUUID();
          await storage.createKey({
            id,
            sessionId: session.id,
            label: String(body.label || "Key").slice(0, 100),
            keyHash: createHash("sha256").update(secret).digest("hex"),
            createdAt: new Date().toISOString(),
          });
          return json(201, { id, secret });
        }
        if (req.method === "DELETE" && keysPath[2]) {
          await withKeyOperation(async () => {
            await storage.deleteKey(keysPath[2], session.id);
            relays.get(session.id)?.clients.forEach((client) => {
              if (client.keyId === keysPath[2]) {
                client.close(1008, "session key revoked");
              }
            });
          });
          return res.writeHead(204).end();
        }
      }
      if (del && req.method === "DELETE") {
        const record = await storage.getSession(del[1]);
        if (!record || record.ownerSub !== info.sub) {
          return res.writeHead(404).end();
        }
        await storage.deleteSession(del[1], info.sub);
        relays.get(del[1])?.clients.forEach((client) => client.close(1001, "session deleted"));
        relays.get(del[1])?.close();
        relays.delete(del[1]);
        return res.writeHead(204).end();
      }
      return res.writeHead(404).end();
    }
    if (pathname.startsWith("/api/v1/admin/")) {
      if (!bearerMatches(req.headers.authorization, env.RELAY_API_TOKEN)) {
        return res.writeHead(401).end();
      }
      if (!env.RELAY_API_TOKEN) {
        return res.writeHead(503).end();
      }
      if (req.method === "GET" && pathname === "/api/v1/admin/machines") {
        const storedMachines = await storage.listMachines();
        return json(
          200,
          storedMachines.map((m) => ({
            machineId: m.machineId,
            sessionId: m.machineId,
            claimedBy: m.claimedBy,
            online: bridges.get(m.machineId)?.readyState === WebSocket.OPEN,
            registeredAt: m.registeredAt,
            claimedAt: m.claimedAt,
          })),
        );
      }
      const match = /^\/api\/v1\/admin\/machines\/([^/]+)\/(claim|ticket)$/.exec(pathname);
      if (!match || !UUID.test(match[1]) || req.method !== "POST") {
        return res.writeHead(404).end();
      }
      let body;
      try {
        body = await readJsonBody(req);
      } catch {
        return res.writeHead(400).end();
      }
      if (typeof body.ownerSub !== "string" || !body.ownerSub.trim() || body.ownerSub.length > 512) {
        return res.writeHead(400).end();
      }
      if (match[2] === "claim") {
        let machine;
        try {
          machine = await storage.claimMachine(match[1], body.ownerSub);
        } catch {
          return res.writeHead(500).end();
        }
        if (!machine) {
          return res.writeHead(404).end();
        }
        if (machine.claimedBy !== body.ownerSub) {
          return res.writeHead(409).end();
        }
        return json(200, {
          machineId: machine.machineId,
          claimedBy: machine.claimedBy,
          claimedAt: machine.claimedAt,
        });
      }
      const machine = await storage.getMachine(match[1]);
      if (!machine) {
        return res.writeHead(404).end();
      }
      if (machine.claimedBy !== body.ownerSub) {
        return res.writeHead(403).end();
      }
      for (const [key, value] of tickets) {
        if (value.expiresAt <= Date.now()) {
          tickets.delete(key);
        }
      }
      if (tickets.size >= 10000) {
        return res.writeHead(503).end();
      }
      const ticket = randomBytes(32).toString("base64url");
      tickets.set(ticket, {
        machineId: machine.machineId,
        ownerSub: body.ownerSub,
        expiresAt: Date.now() + Math.min(ticketTtlMs, TICKET_TTL),
      });
      return json(200, {
        ticket,
        expiresIn: Math.ceil(Math.min(ticketTtlMs, TICKET_TTL) / 1000),
      });
    }
    return res.writeHead(404).end();
  }

  const bridgeWss = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_FRAME,
    perMessageDeflate: false,
  });
  const machineWss = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_FRAME,
    perMessageDeflate: false,
  });
  server.on("upgrade", async (req, socket, head) => {
    try {
      const url = new URL(req.url || "/", "http://localhost");
      if (url.pathname === "/api/v1/bridge/register") {
        if (
          !env.BRIDGE_REGISTRATION_TOKEN ||
          !bearerMatches(req.headers.authorization, env.BRIDGE_REGISTRATION_TOKEN)
        ) {
          return socket.destroy();
        }
        bridgeWss.handleUpgrade(req, socket, head, (ws) => {
          let registeringMachineId;
          const timer = setTimeout(() => ws.close(1008, "registration timeout"), AUTH_TIMEOUT);
          ws.once("message", async (data, binary) => {
            if (binary || data.length > MAX_HTTP_BODY) {
              return ws.close(1008, "invalid registration");
            }
            let message;
            try {
              message = JSON.parse(data.toString());
            } catch {
              return ws.close(1008, "invalid registration");
            }
            if (
              message.type !== "register" ||
              typeof message.machineId !== "string" ||
              !UUID.test(message.machineId) ||
              !env.BRIDGE_REGISTRATION_TOKEN
            ) {
              return ws.close(1008, "invalid registration");
            }
            if (registering.has(message.machineId) || bridges.get(message.machineId)?.readyState === WebSocket.OPEN) {
              return ws.close(1008, "bridge already connected");
            }
            registeringMachineId = message.machineId;
            registering.add(message.machineId);
            clearTimeout(timer);
            let machine;
            try {
              machine = await storage.getMachine(message.machineId);
              if (!machine) {
                if (await storage.getSession(message.machineId)) {
                  return ws.close(1008, "machine ID collision");
                }
                try {
                  machine = await storage.registerMachine(message.machineId);
                } catch {
                  machine = await storage.getMachine(message.machineId);
                  if (!machine) {
                    return ws.close(1008, "machine ID collision");
                  }
                }
              }
            } catch {
              registering.delete(message.machineId);
              return ws.close(1011, "registry unavailable");
            }
            if (ws.readyState !== WebSocket.OPEN) {
              registering.delete(message.machineId);
              return;
            }
            const legacyRoom = relays.get(message.machineId);
            if (legacyRoom) {
              for (const client of legacyRoom.clients) {
                client.close(1008, "machine session reserved");
              }
              legacyRoom.close();
              relays.delete(message.machineId);
            }
            bridges.set(message.machineId, ws);
            registering.delete(message.machineId);
            ws.machineId = message.machineId;
            ws.send(
              JSON.stringify({
                type: "registered",
                machineId: message.machineId,
                sessionId: message.machineId,
                claimedBy: machine.claimedBy,
                online: true,
              }),
            );
            ws.on("message", (frame, isBinary) => forward(controllers.get(message.machineId), frame, isBinary));
            ws.once("close", () => {
              if (bridges.get(message.machineId) === ws) {
                bridges.delete(message.machineId);
              }
              const ui = controllers.get(message.machineId);
              if (ui) {
                ui.close(1001, "bridge disconnected");
              }
            });
          });
          ws.once("close", () => clearTimeout(timer));
          ws.on("close", () => {
            if (registeringMachineId) {
              registering.delete(registeringMachineId);
            }
          });
        });
        return;
      }
      const connectionMatch = /^\/api\/v1\/sessions\/([^/]+)\/connect$/.exec(url.pathname);
      const sessionId = connectionMatch?.[1];
      if (!sessionId) {
        return socket.destroy();
      }
      const machine = await storage.getMachine(sessionId);
      if (machine) {
        machineWss.handleUpgrade(req, socket, head, (ws) => {
          const timer = setTimeout(() => ws.close(1008, "authorization timeout"), AUTH_TIMEOUT);
          ws.once("message", (data, binary) => {
            if (binary || data.length > MAX_HTTP_BODY) {
              return ws.close(1008, "authorization required");
            }
            let auth;
            try {
              auth = JSON.parse(data.toString());
            } catch {
              return ws.close(1008, "authorization required");
            }
            const ticket = typeof auth.ticket === "string" ? tickets.get(auth.ticket) : null;
            if (
              auth.type !== "authorize" ||
              !ticket ||
              ticket.machineId !== sessionId ||
              ticket.expiresAt < Date.now() ||
              ticket.ownerSub !== machine.claimedBy
            ) {
              if (typeof auth.ticket === "string") {
                tickets.delete(auth.ticket);
              }
              return ws.close(1008, "unauthorized");
            }
            tickets.delete(auth.ticket);
            clearTimeout(timer);
            if (controllers.get(sessionId)?.readyState === WebSocket.OPEN) {
              return ws.close(1008, "controller already connected");
            }
            if (bridges.get(sessionId)?.readyState !== WebSocket.OPEN) {
              return ws.close(1013, "bridge offline");
            }
            controllers.set(sessionId, ws);
            ws.send(JSON.stringify({ type: "authorized", machineId: sessionId }));
            ws.on("message", (frame, isBinary) => forward(bridges.get(sessionId), frame, isBinary));
            ws.once("close", () => {
              if (controllers.get(sessionId) === ws) {
                controllers.delete(sessionId);
              }
            });
          });
          ws.once("close", () => clearTimeout(timer));
        });
        return;
      }
      if (!SESSION_ID.test(sessionId)) {
        return socket.destroy();
      }
      const record = await storage.getSession(sessionId);
      if (!record) {
        return socket.destroy();
      }
      const origin = req.headers.origin;
      if (origin && env.APP_URL && origin !== new URL(env.APP_URL).origin) {
        return socket.destroy();
      }
      {
        let relay = relays.get(sessionId);
        if (!relay) {
          relay = new WebSocketServer({
            noServer: true,
            maxPayload: MAX_FRAME,
            perMessageDeflate: false,
          });
          relay.sessionId = sessionId;
          relays.set(sessionId, relay);
        }
        relay.handleUpgrade(req, socket, head, (ws) => {
          ws.uid = randomUUID();
          ws.textOnly = url.searchParams.has("text");
          const relayMessage = (message, isBinary) => broadcast(sessionId, ws.uid, message, isBinary);
          if (record.isPublic) {
            ws.on("message", relayMessage);
          } else {
            const timer = setTimeout(() => ws.close(1008, "authorization timeout"), AUTH_TIMEOUT);
            ws.once("message", async (frame, binary) => {
              let auth;
              try {
                auth = !binary && JSON.parse(frame.toString());
              } catch {
                auth = null;
              }
              const secret = typeof auth?.key === "string" ? auth.key : "";
              try {
                const authorizedKey = await withKeyOperation(async () => {
                  const key = secret ? await storage.getKey(createHash("sha256").update(secret).digest("hex")) : null;
                  if (
                    auth?.type !== "authorize" ||
                    !key ||
                    key.session_id !== sessionId ||
                    ws.readyState !== WebSocket.OPEN
                  ) {
                    return false;
                  }
                  ws.keyId = key.id;
                  ws.send(JSON.stringify({ type: "authorized" }));
                  ws.on("message", relayMessage);
                  return true;
                });
                if (!authorizedKey) {
                  return ws.close(1008, "unauthorized");
                }
                clearTimeout(timer);
              } catch {
                return ws.close(1011, "authorization unavailable");
              }
            });
            ws.once("close", () => clearTimeout(timer));
          }
          ws.once("close", () => {
            if (relay.clients.size === 0 && relays.get(sessionId) === relay) {
              relay.close();
              relays.delete(sessionId);
            }
          });
        });
      }
      return;
    } catch {
      socket.destroy();
    }
  });

  function forward(target, data, isBinary) {
    if (!target || target.readyState !== WebSocket.OPEN) {
      return;
    }
    if (target.bufferedAmount > MAX_FRAME * 4) {
      target.close(1013, "backpressure");
      return;
    }
    target.send(data, { binary: isBinary });
  }
  function broadcast(to, from, message, isBinary) {
    const relay = relays.get(to);
    if (!relay) {
      return;
    }
    for (const client of relay.clients) {
      if (client.uid === from || client.readyState !== WebSocket.OPEN) {
        continue;
      }
      if (client.bufferedAmount > MAX_FRAME * 4) {
        client.close(1013, "backpressure");
        continue;
      }
      client.send(client.textOnly && isBinary ? Buffer.from(message).toString("hex") : message, {
        binary: client.textOnly ? false : isBinary,
      });
    }
  }
  const close = async () => {
    for (const relay of relays.values()) {
      for (const client of relay.clients) {
        client.terminate();
      }
      relay.close();
    }
    for (const ws of [...bridges.values(), ...controllers.values()]) {
      ws.terminate();
    }
    await new Promise((resolve) => server.close(resolve));
  };
  return {
    server,
    loadMachines,
    close,
  };
}

async function readJsonBody(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_HTTP_BODY) {
      throw new Error("body too large");
    }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const relay = createRelay();
  await relay.loadMachines();
  const port = Number(process.env.PORT || 3000);
  relay.server.listen(port);
  console.log(`[${new Date().toISOString()}] relay running at ${port}`);
}
