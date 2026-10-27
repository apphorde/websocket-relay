# WebSocket relay

A WebSocket relay for persistent user sessions and registered machine bridges.

The UI uses Li3 reactive state primitives from [`@li3/web`](https://li3.dev), served locally from the pinned package dependency.

## Configuration

Set `DATABASE_URL` to the configured provider's HTTPS consumer module URL. `DB_AUTH_TOKEN` is optional and is used only when the provider requires bearer authentication. `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `AUTH_API_URL`, `AUTH_TOKEN_AUDIENCE`, and `APP_URL` configure browser sign-in and API tokens. Register `${APP_URL}/auth/callback` as the OIDC redirect URI. This callback is an OIDC protocol endpoint; application APIs use `/api/v1/*`. For TLS-terminating reverse proxies, set `TRUST_PROXY=true` so `/api` uses the forwarded HTTPS scheme. No provider URLs are built into the application.

Persistent machine claims, sessions, and hashes of session keys are stored in the database. Existing `DATA_PATH/machines.json` and `sessions.json` are imported once; originals remain untouched.

## Session API

The versioned API uses `/api/v1/*`. `GET /api` returns the OpenAPI JSON document; its server URL is populated from the request host and scheme. Session CRUD and key management require an Auth access token in `Authorization: Bearer <token>`:

- `GET` and `POST /api/v1/sessions`
- `DELETE /api/v1/sessions/{sessionId}`
- `GET` and `POST /api/v1/sessions/{sessionId}/keys`
- `DELETE /api/v1/sessions/{sessionId}/keys/{keyId}`

Session IDs identify rooms; they are not credentials. Private sessions accept multiple independently generated long-lived keys. The plaintext key is returned only once at creation; the database stores its SHA-256 hash. Keep a key safe, and revoke it to disable it. To rotate a key, generate a replacement and revoke the old key. Public sessions require no key and allow anyone to read and write. Private connections authorize with their first WebSocket frame:

```js
const socket = new WebSocket("wss://<relay-host>/api/v1/sessions/<session-id>/connect");
socket.addEventListener(
  "open",
  () => {
    socket.send(JSON.stringify({ type: "authorize", key: "<session-key>" }));
  },
  { once: true },
);
```

Use the session-specific address and key shown in the dashboard. The dashboard uses the current hostname in its snippet. Do not put long-lived keys in URLs or logs.

## Machine bridges

Set `BRIDGE_REGISTRATION_TOKEN` and `RELAY_API_TOKEN`. A bridge connects to `wss://<relay-host>/api/v1/bridge/register` using the bridge registration bearer token, then sends `{"type":"register","machineId":"<UUID>"}` as its first frame.

Machine administration requires `Authorization: Bearer <RELAY_API_TOKEN>`:

- `GET /api/v1/admin/machines`
- `POST /api/v1/admin/machines/{uuid}/claim` with `{"ownerSub":"OIDC subject"}`
- `POST /api/v1/admin/machines/{uuid}/ticket` with the same owner to issue a one-use ticket (up to 60 seconds)

A machine controller connects at `/api/v1/sessions/{uuid}/connect` and sends `{"type":"authorize","ticket":"..."}` first. Tickets are single-use; do not log or persist them.

The readiness endpoint is `GET /api/v1/health`.
