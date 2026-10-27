import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import WebSocket from "ws";
import { createRelay } from "../index.js";
import { createInMemorySqliteAdapter, createStorage } from "../storage.mjs";

const token = "test-registration-secret";
const admin = "test-admin-secret";
const machineId = "f1a3ed01-7bc9-4e34-9a2b-144587e3fe12";
const sessionId = "a".repeat(128);
const authTokens = new Map([
  ["auth-user-a", { sub: "subject-a" }],
  ["auth-user-b", { sub: "subject-b" }],
]);
const fixtures = [];

function memoryDb(database) {
  return createInMemorySqliteAdapter(database);
}

async function setup(ticketTtlMs, { oidcClient } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "relay-test-"));
  const database = new DatabaseSync(":memory:");
  const db = memoryDb(database);
  const env = {
    DATA_PATH: dir,
    BRIDGE_REGISTRATION_TOKEN: token,
    RELAY_API_TOKEN: admin,
    OIDC_ISSUER: "https://issuer.test",
    AUTH_API_URL: "https://auth.test",
    ...(oidcClient
      ? { OIDC_CLIENT_ID: "test-client", OIDC_CLIENT_SECRET: "test-secret", AUTH_TOKEN_AUDIENCE: "test-audience" }
      : {}),
  };
  const relay = createRelay({
    env,
    ticketTtlMs,
    db,
    authUserInfo: async (accessToken) => authTokens.get(accessToken) || null,
    oidcClient,
  });
  await relay.loadMachines();
  await new Promise((resolve) => relay.server.listen(0, "127.0.0.1", resolve));
  const address = relay.server.address();
  const base = `http://127.0.0.1:${address.port}`;
  env.APP_URL = base;
  fixtures.push(async () => {
    await relay.close();
    database.close();
    await rm(dir, { recursive: true, force: true });
  });
  return { base, ws: base.replace("http", "ws"), relay, dir, db, database };
}
after(async () => {
  for (const cleanup of fixtures) {
    await cleanup();
  }
});

function connect(url, headers) {
  return new WebSocket(url, { headers });
}
const socketPath = (id) => `/api/v1/sessions/${id}/connect`;
function nextMessage(ws) {
  return new Promise((resolve, reject) => {
    ws.once("message", (data, binary) => resolve([data, binary]));
    ws.once("error", reject);
  });
}
function opened(ws) {
  return new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
}
function closed(ws) {
  return new Promise((resolve) => {
    ws.once("close", (...args) => resolve(args[0]));
    ws.once("error", () => resolve(1006));
  });
}
async function post(base, path, body, auth = admin) {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${auth}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

test("user session routes require Auth bearer and never enumerate rooms", async () => {
  const { base, ws } = await setup();
  assert.equal((await fetch(`${base}/api/v1/sessions`)).status, 401);
  assert.equal(
    (
      await fetch(`${base}/api/v1/sessions`, {
        headers: { authorization: "Bearer invalid" },
      })
    ).status,
    401,
  );
  assert.equal((await fetch(`${base}/new`)).status, 404);
  const apiDoc = await fetch(`${base}/api`);
  assert.equal(apiDoc.status, 200);
  const spec = await apiDoc.json();
  assert.equal(spec.servers[0].url, base);
  assert.ok(spec.paths["/api/v1/sessions"]);
  assert.equal((await fetch(`${base}/status`)).status, 404);
  assert.equal((await post(base, "/publish", { sessionId: "anything", data: "x" })).status, 404);
  const generic = connect(`${ws}${socketPath("a".repeat(128))}`);
  assert.equal(await closed(generic), 1006);
  const malformed = connect(`${ws}${socketPath("ordinary")}`);
  assert.equal(await closed(malformed), 1006);
});

test("OIDC sign-in binds state to a browser cookie and exposes only a short-lived Auth token", async () => {
  const fakeOidc = {
    skipSubjectCheck: Symbol("skip-subject-check"),
    allowInsecureRequests() {},
    async discovery() {
      return { marker: true };
    },
    randomPKCECodeVerifier: () => "test-verifier",
    randomState: () => "test-state",
    randomNonce: () => "test-nonce",
    async calculatePKCECodeChallenge(verifier) {
      assert.equal(verifier, "test-verifier");
      return "test-challenge";
    },
    buildAuthorizationUrl(_config, params) {
      const url = new URL("https://auth.test/authorize");
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
      return url;
    },
    async authorizationCodeGrant(_config, callback, checks) {
      assert.equal(callback.searchParams.get("code"), "test-code");
      assert.equal(callback.searchParams.get("state"), checks.expectedState);
      assert.equal(checks.expectedState, "test-state");
      assert.equal(checks.expectedNonce, "test-nonce");
      assert.equal(checks.pkceCodeVerifier, "test-verifier");
      return {
        access_token: "auth-user-a",
        refresh_token: "refresh-a",
        expires_in: 300,
        claims: () => ({ sub: "subject-a" }),
      };
    },
    async fetchUserInfo(_config, accessToken) {
      return accessToken === "auth-user-a" ? { sub: "subject-a" } : {};
    },
  };
  const { base } = await setup(undefined, { oidcClient: fakeOidc });
  const login = await fetch(`${base}/api/v1/auth/login`, { redirect: "manual" });
  assert.equal(login.status, 302);
  assert.equal(new URL(login.headers.get("location")).searchParams.get("state"), "test-state");
  const cookieHeader = login.headers.get("set-cookie");
  const transactionCookie = cookieHeader.split(";")[0];

  const crossBrowserCallback = await fetch(`${base}/auth/callback?code=test-code&state=test-state`, {
    redirect: "manual",
  });
  assert.equal(crossBrowserCallback.status, 400);

  const callback = await fetch(`${base}/auth/callback?code=test-code&state=test-state`, {
    headers: { cookie: transactionCookie },
    redirect: "manual",
  });
  assert.equal(callback.status, 302);
  const sessionCookie = callback.headers
    .getSetCookie()
    .find((value) => value.startsWith("relay_session="))
    .split(";")[0];
  const browserStatus = await fetch(`${base}/api/v1/auth/status`, { headers: { cookie: sessionCookie } });
  assert.equal(browserStatus.status, 200);
  assert.equal(browserStatus.headers.get("cache-control"), "no-store");
  assert.deepEqual(await browserStatus.json(), { authenticated: true });
  const authConfig = await fetch(`${base}/api/v1/auth/config`, { headers: { cookie: sessionCookie } });
  assert.deepEqual(await authConfig.json(), { authApiUrl: "https://auth.test", audience: "test-audience" });

  const sessions = await fetch(`${base}/api/v1/sessions`, { headers: { authorization: "Bearer auth-user-a" } });
  assert.equal(sessions.status, 200);
  assert.deepEqual(await sessions.json(), []);
  assert.equal(
    (
      await fetch(`${base}/api/v1/auth/logout`, {
        method: "POST",
        headers: { cookie: sessionCookie },
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await fetch(`${base}/api/v1/auth/logout`, {
        method: "POST",
        headers: { cookie: sessionCookie, origin: base },
        redirect: "manual",
      })
    ).status,
    303,
  );
  assert.equal((await fetch(`${base}/api/v1/auth/status`, { headers: { cookie: sessionCookie } })).status, 401);
});

test("private sessions require independent hashed keys; public sessions allow bidirectional traffic", async () => {
  const { base, ws, database } = await setup();
  const auth = (value) => ({ authorization: `Bearer ${value}` });
  const create = (id, isPublic, tokenValue = "auth-user-a") =>
    fetch(`${base}/api/v1/sessions`, {
      method: "POST",
      headers: { ...auth(tokenValue), "content-type": "application/json" },
      body: JSON.stringify({ id, isPublic }),
    });

  assert.equal((await create("short", false)).status, 400);
  assert.equal((await create(sessionId, false)).status, 201);
  assert.equal((await create(sessionId, false)).status, 200);
  assert.equal((await create(sessionId, true)).status, 409);
  assert.equal((await create(sessionId, false, "auth-user-b")).status, 409);

  const ownerList = await (await fetch(`${base}/api/v1/sessions`, { headers: auth("auth-user-a") })).json();
  const otherList = await (await fetch(`${base}/api/v1/sessions`, { headers: auth("auth-user-b") })).json();
  assert.equal(ownerList.length, 1);
  assert.equal(ownerList[0].id, sessionId);
  assert.deepEqual(otherList, []);

  const createdKeyResponse = await post(
    base,
    `/api/v1/sessions/${sessionId}/keys`,
    { label: "integration" },
    "auth-user-a",
  );
  assert.equal(createdKeyResponse.status, 201);
  const { id: keyId, secret } = await createdKeyResponse.json();
  assert.equal(
    database.prepare("SELECT key_hash FROM session_keys WHERE id=?").get(keyId).key_hash,
    createHash("sha256").update(secret).digest("hex"),
  );
  const keys = await (await fetch(`${base}/api/v1/sessions`, { headers: auth("auth-user-a") })).json();
  assert.equal(keys[0].keys.length, 1);
  assert.equal(keys[0].keys[0].id, keyId);
  assert.equal("secret" in keys[0].keys[0], false);
  const secondKeyResponse = await post(
    base,
    `/api/v1/sessions/${sessionId}/keys`,
    { label: "rotation" },
    "auth-user-a",
  );
  assert.equal(secondKeyResponse.status, 201);
  const { id: secondKeyId, secret: secondSecret } = await secondKeyResponse.json();

  const unauthorized = connect(`${ws}${socketPath(sessionId)}`);
  await opened(unauthorized);
  const unauthorizedClosed = closed(unauthorized);
  unauthorized.send(JSON.stringify({ type: "authorize", key: "wrong-key" }));
  assert.equal(await unauthorizedClosed, 1008);

  const owner = connect(`${ws}${socketPath(sessionId)}`);
  await opened(owner);
  const authorized = nextMessage(owner);
  owner.send(JSON.stringify({ type: "authorize", key: secret }));
  assert.deepEqual(JSON.parse((await authorized)[0]), { type: "authorized" });
  assert.equal(owner.readyState, WebSocket.OPEN);
  const stats = await (await fetch(`${base}/api/v1/sessions`, { headers: auth("auth-user-a") })).json();
  assert.equal(stats[0].connectedClients, 1);
  const activeOwnerClosed = closed(owner);
  const revoked = await fetch(`${base}/api/v1/sessions/${sessionId}/keys/${keyId}`, {
    method: "DELETE",
    headers: auth("auth-user-a"),
  });
  assert.equal(revoked.status, 204);
  assert.equal(await activeOwnerClosed, 1008);
  const replacement = connect(`${ws}${socketPath(sessionId)}`);
  await opened(replacement);
  const replacementAuthorized = nextMessage(replacement);
  replacement.send(JSON.stringify({ type: "authorize", key: secondSecret }));
  assert.deepEqual(JSON.parse((await replacementAuthorized)[0]), { type: "authorized" });
  const revokeReplacement = await fetch(`${base}/api/v1/sessions/${sessionId}/keys/${secondKeyId}`, {
    method: "DELETE",
    headers: auth("auth-user-a"),
  });
  assert.equal(revokeReplacement.status, 204);
  assert.equal(await closed(replacement), 1008);
  const revokedSocket = connect(`${ws}${socketPath(sessionId)}`);
  await opened(revokedSocket);
  const revokedClosed = closed(revokedSocket);
  revokedSocket.send(JSON.stringify({ type: "authorize", key: secret }));
  assert.equal(await revokedClosed, 1008);

  const publicId = "b".repeat(128);
  assert.equal((await create(publicId, true)).status, 201);
  const listener = connect(`${ws}${socketPath(publicId)}`);
  await opened(listener);

  const otherListener = connect(`${ws}${socketPath(publicId)}`);
  await opened(otherListener);
  const publisher = connect(`${ws}${socketPath(publicId)}`);
  await opened(publisher);
  const received = nextMessage(otherListener);
  publisher.send("owner-publish");
  assert.equal((await received)[0].toString(), "owner-publish");
  publisher.close();
  otherListener.close();

  const remove = await fetch(`${base}/api/v1/sessions/${publicId}`, {
    method: "DELETE",
    headers: auth("auth-user-b"),
  });
  assert.equal(remove.status, 404);
  assert.equal(database.prepare("SELECT COUNT(*) AS n FROM user_sessions").get().n, 2);
});

test("registration requires bearer and UUID, machine claims are immutable and idempotent", async () => {
  const { base, ws, dir, database } = await setup();
  const unauth = connect(`${ws}/api/v1/bridge/register`);
  assert.equal(await closed(unauth), 1006);
  const bridge = connect(`${ws}/api/v1/bridge/register`, {
    authorization: `Bearer ${token}`,
  });
  await opened(bridge);
  const invalidClosed = closed(bridge);
  bridge.send(JSON.stringify({ type: "register", machineId: "not-uuid" }));
  assert.ok(await invalidClosed);

  const valid = connect(`${ws}/api/v1/bridge/register`, {
    authorization: `Bearer ${token}`,
  });
  await opened(valid);
  const reg = nextMessage(valid);
  valid.send(JSON.stringify({ type: "register", machineId }));
  assert.deepEqual(JSON.parse((await reg)[0]), {
    type: "registered",
    machineId,
    sessionId: machineId,
    claimedBy: null,
    online: true,
  });
  assert.equal(
    (
      await post(base, `/api/v1/admin/machines/${machineId}/claim`, {
        ownerSub: "subject-a",
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await post(base, `/api/v1/admin/machines/${machineId}/claim`, {
        ownerSub: "subject-a",
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await post(base, `/api/v1/admin/machines/${machineId}/claim`, {
        ownerSub: "subject-b",
      })
    ).status,
    409,
  );
  assert.equal(
    (
      await (
        await fetch(`${base}/api/v1/admin/machines`, {
          headers: { authorization: `Bearer ${admin}` },
        })
      ).json()
    )[0].online,
    true,
  );
  const restarted = createRelay({
    env: {
      DATA_PATH: dir,
      BRIDGE_REGISTRATION_TOKEN: token,
      RELAY_API_TOKEN: admin,
    },
    db: memoryDb(database),
    authUserInfo: async (accessToken) => authTokens.get(accessToken) || null,
  });
  await restarted.loadMachines();
  await new Promise((resolve) => restarted.server.listen(0, "127.0.0.1", resolve));
  const restartedBase = `http://127.0.0.1:${restarted.server.address().port}`;
  const persisted = await fetch(`${restartedBase}/api/v1/admin/machines`, {
    headers: { authorization: `Bearer ${admin}` },
  });
  assert.equal((await persisted.json())[0].claimedBy, "subject-a");
  await new Promise((resolve) => restarted.server.close(resolve));
  valid.close();
});

test("fails closed on a malformed persisted ownership registry", async () => {
  const dir = await mkdtemp(join(tmpdir(), "relay-corrupt-test-"));
  const database = new DatabaseSync(":memory:");
  try {
    await writeFile(join(dir, "machines.json"), "{broken", { mode: 0o600 });
    const relay = createRelay({
      env: {
        DATA_PATH: dir,
        BRIDGE_REGISTRATION_TOKEN: token,
        RELAY_API_TOKEN: admin,
      },
      db: memoryDb(database),
    });
    await assert.rejects(relay.loadMachines());
  } finally {
    database.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("imports existing machine/session JSON once and never resurrects deleted records", async () => {
  const dir = await mkdtemp(join(tmpdir(), "relay-import-test-"));
  const database = new DatabaseSync(":memory:");
  const storageOptions = {
    env: { DATA_PATH: dir },
    db: memoryDb(database),
  };
  try {
    await writeFile(
      join(dir, "machines.json"),
      JSON.stringify([
        {
          machineId,
          claimedBy: "subject-a",
          registeredAt: "2026-01-01T00:00:00.000Z",
          claimedAt: "2026-01-02T00:00:00.000Z",
        },
      ]),
    );
    await writeFile(
      join(dir, "sessions.json"),
      JSON.stringify([{ id: sessionId, ownerSub: "subject-a", isPublic: true, createdAt: "2026-01-03T00:00:00.000Z" }]),
    );
    const storage = await createStorage(storageOptions);
    assert.equal((await storage.getMachine(machineId)).claimedBy, "subject-a");
    assert.equal((await storage.getSession(sessionId)).ownerSub, "subject-a");
    await storage.deleteSession(sessionId, "subject-a");

    const restartedStorage = await createStorage(storageOptions);
    assert.equal(await restartedStorage.getSession(sessionId), null);
    assert.equal((await restartedStorage.getMachine(machineId)).claimedBy, "subject-a");
  } finally {
    database.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("machine socket does not forward before authorization; tickets one-use and frame routing reconnects", async () => {
  const { base, ws } = await setup();
  const bridge = connect(`${ws}/api/v1/bridge/register`, {
    authorization: `Bearer ${token}`,
  });
  await opened(bridge);
  const registered = nextMessage(bridge);
  bridge.send(JSON.stringify({ type: "register", machineId }));
  await registered;
  await post(base, `/api/v1/admin/machines/${machineId}/claim`, {
    ownerSub: "subject-a",
  });
  const ticketResponse = await post(base, `/api/v1/admin/machines/${machineId}/ticket`, { ownerSub: "subject-a" });
  const { ticket } = await ticketResponse.json();
  const ui = connect(`${ws}${socketPath(machineId)}`);
  await opened(ui);
  const leaked = new Promise((resolve) => {
    ui.once("message", (data) => resolve(data.toString()));
    setTimeout(() => resolve(null), 80);
  });
  bridge.send("before-auth");
  assert.equal(await leaked, null);
  const authAck = nextMessage(ui);
  ui.send(JSON.stringify({ type: "authorize", ticket }));
  assert.equal(JSON.parse((await authAck)[0]).type, "authorized");
  const toBridge = nextMessage(bridge);
  ui.send(Buffer.from([2, 3]));
  const [uplink, binary] = await toBridge;
  assert.equal(binary, true);
  assert.deepEqual([...uplink], [2, 3]);
  const toUi = nextMessage(ui);
  bridge.send(Buffer.from([4, 5]));
  const [downlink, downBinary] = await toUi;
  assert.equal(downBinary, true);
  assert.deepEqual([...downlink], [4, 5]);
  const replay = connect(`${ws}${socketPath(machineId)}`);
  await opened(replay);
  const replayClose = closed(replay);
  replay.send(JSON.stringify({ type: "authorize", ticket }));
  assert.equal(await replayClose, 1008);
  ui.close();
  bridge.close();

  const replacement = connect(`${ws}/api/v1/bridge/register`, {
    authorization: `Bearer ${token}`,
  });
  await opened(replacement);
  const reconnectMsg = nextMessage(replacement);
  replacement.send(JSON.stringify({ type: "register", machineId }));
  assert.equal(JSON.parse((await reconnectMsg)[0]).claimedBy, "subject-a");
  replacement.close();
});

test("machine authorization times out without ticket", async () => {
  const { ws } = await setup();
  const bridge = connect(`${ws}/api/v1/bridge/register`, {
    authorization: `Bearer ${token}`,
  });
  await opened(bridge);
  const msg = nextMessage(bridge);
  bridge.send(JSON.stringify({ type: "register", machineId }));
  await msg;
  const ui = connect(`${ws}${socketPath(machineId)}`);
  await opened(ui);
  const close = closed(ui);
  // The machine is intentionally unclaimed and therefore cannot receive a ticket.
  assert.equal(await close, 1008);
  bridge.close();
});

test("expired machine ticket is rejected", async () => {
  const { base, ws } = await setup(1);
  const bridge = connect(`${ws}/api/v1/bridge/register`, {
    authorization: `Bearer ${token}`,
  });
  await opened(bridge);
  const registration = nextMessage(bridge);
  bridge.send(JSON.stringify({ type: "register", machineId }));
  await registration;
  await post(base, `/api/v1/admin/machines/${machineId}/claim`, {
    ownerSub: "subject-a",
  });
  const { ticket } = await (
    await post(base, `/api/v1/admin/machines/${machineId}/ticket`, {
      ownerSub: "subject-a",
    })
  ).json();
  await new Promise((resolve) => setTimeout(resolve, 10));
  const ui = connect(`${ws}${socketPath(machineId)}`);
  await opened(ui);
  const close = closed(ui);
  ui.send(JSON.stringify({ type: "authorize", ticket }));
  assert.equal(await close, 1008);
  bridge.close();
});
