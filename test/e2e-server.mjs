import { DatabaseSync } from "node:sqlite";
import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInMemorySqliteAdapter } from "../storage.mjs";
import { createRelay } from "../index.js";

const database = new DatabaseSync(":memory:");
const port = 4174;
const authPort = 4175;
const dataPath = await mkdtemp(join(tmpdir(), "relay-e2e-"));
const env = {
  APP_URL: `http://127.0.0.1:${port}`,
  AUTH_TOKEN_AUDIENCE: "relay-ui-test",
  AUTH_API_URL: `http://127.0.0.1:${authPort}`,
  DATA_PATH: dataPath,
  DATABASE_URL: "https://db.apphor.de/db~test/index.mjs",
  DB_AUTH_TOKEN: "test-db-token",
  OIDC_CLIENT_ID: "relay-test-client",
  OIDC_CLIENT_SECRET: "test-oidc-secret",
  OIDC_ISSUER: `http://127.0.0.1:${authPort}`,
  PORT: String(port),
};
const oidcClient = {
  skipSubjectCheck: Symbol("skip-subject-check"),
  async discovery() {
    return { issuer: env.OIDC_ISSUER };
  },
  randomPKCECodeVerifier: () => "e2e-verifier",
  randomState: () => "e2e-state",
  randomNonce: () => "e2e-nonce",
  async calculatePKCECodeChallenge() {
    return "e2e-challenge";
  },
  buildAuthorizationUrl(_configuration, parameters) {
    const authorizationUrl = new URL(`${env.OIDC_ISSUER}/authorize`);
    for (const [key, value] of Object.entries(parameters)) {
      authorizationUrl.searchParams.set(key, value);
    }
    return authorizationUrl;
  },
  async authorizationCodeGrant(_configuration, callbackUrl, checks) {
    if (
      callbackUrl.searchParams.get("code") !== "e2e-code" ||
      callbackUrl.searchParams.get("state") !== checks.expectedState ||
      checks.expectedState !== "e2e-state" ||
      checks.expectedNonce !== "e2e-nonce" ||
      checks.pkceCodeVerifier !== "e2e-verifier"
    ) {
      throw new Error("Invalid mock OIDC transaction");
    }
    return {
      access_token: "e2e-oidc-access-token",
      expires_in: 300,
      claims: () => ({ sub: "e2e-user" }),
    };
  },
  async fetchUserInfo(_configuration, accessToken) {
    if (accessToken === "e2e-oidc-access-token") {
      return { sub: "e2e-user" };
    }
    return {};
  },
};
const authServer = http.createServer((request, response) => {
  const url = new URL(request.url || "/", env.OIDC_ISSUER);
  const corsHeaders = {
    "Access-Control-Allow-Origin": env.APP_URL,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
  };
  if (request.method === "GET" && url.pathname === "/authorize") {
    const callback = new URL(url.searchParams.get("redirect_uri"));
    callback.searchParams.set("code", "e2e-code");
    callback.searchParams.set("state", url.searchParams.get("state"));
    response.writeHead(302, { location: callback.href }).end();
    return;
  }
  if (url.pathname === "/api/v1/session/token" && request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders).end();
    return;
  }
  if (url.pathname === "/api/v1/session/token" && request.method === "POST") {
    response
      .writeHead(200, { ...corsHeaders, "content-type": "application/json" })
      .end(JSON.stringify({ access_token: "e2e-api-access-token", token_type: "Bearer", expires_in: 600 }));
    return;
  }
  response.writeHead(404).end();
});
const relay = createRelay({
  env,
  db: createInMemorySqliteAdapter(database),
  authUserInfo: async (accessToken) => (accessToken === "e2e-api-access-token" ? { sub: "e2e-user" } : null),
  oidcClient,
});

await relay.loadMachines();
await new Promise((resolve) => authServer.listen(authPort, "127.0.0.1", resolve));
relay.server.listen(port, "127.0.0.1");
const shutdown = () => {
  authServer.close(() => {
    relay.server.close(() => {
      database.close();
      rm(dataPath, { recursive: true, force: true }).finally(() => process.exit(0));
    });
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
