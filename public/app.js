import { effect, ref } from "@li3/web";

const controlButtonClasses =
  "inline-flex min-h-8 cursor-pointer items-center justify-center rounded-md border border-[#e4e4df] bg-white px-2.5 py-1.5 text-xs font-semibold text-[#555852] transition hover:border-[#c7c9bf] hover:bg-canvas focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:cursor-not-allowed disabled:opacity-50";
const dangerButtonClasses =
  "inline-flex min-h-8 cursor-pointer items-center justify-center rounded-md border border-[#e4e4df] bg-white px-2.5 py-1.5 text-xs font-semibold text-muted transition hover:border-danger-border hover:text-danger focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:cursor-not-allowed disabled:opacity-50";

const $ = (selector) => document.querySelector(selector);
const signedOut = $("#signed-out");
const sessionsView = $("#sessions-view");
const list = $("#session-list");
const message = $("#message");
const messageState = ref("");
const sessionsState = ref([]);
const publicState = ref(false);
let renderedSessionSnapshot;

effect(
  () => messageState.value,
  (text) => {
    message.textContent = text;
  },
);
effect(
  () => sessionsState.value,
  (sessions) => {
    const snapshot = JSON.stringify(sessions);
    if (snapshot === renderedSessionSnapshot) {
      return;
    }
    renderedSessionSnapshot = snapshot;
    list.replaceChildren(...sessions.map(addSession));
    if (sessions.length === 0) {
      const empty = document.createElement("li");
      empty.className = "py-2 text-sm text-muted";
      empty.textContent = "No sessions yet.";
      list.append(empty);
    }
  },
);
effect(
  () => publicState.value,
  (isPublic) => {
    $("#visibility-copy").textContent = isPublic
      ? "Anyone can connect to this session."
      : "Only connections with a session key can connect.";
  },
);

let authApiUrl;
let audience;
let accessToken;
let tokenExpiresAt = 0;
const sessionSecrets = new Map();

function showMessage(text, success = false) {
  messageState.value = text;
  message.classList.toggle("text-sage", success);
  message.classList.toggle("text-danger", !success);
}

async function getAuthToken() {
  if (accessToken && tokenExpiresAt > Date.now() + 30_000) {
    return accessToken;
  }

  const response = await fetch(`${authApiUrl}/api/v1/session/token`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ audience }),
  });
  if (!response.ok) {
    accessToken = undefined;
    throw new Error("Could not get an Auth API token. Check Auth sign-in and allowed-origin settings.");
  }
  const token = await response.json();
  accessToken = token.access_token;
  tokenExpiresAt = Date.now() + token.expires_in * 1000;
  return accessToken;
}

async function api(path, options = {}) {
  const token = await getAuthToken();
  return fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
}

function addSession(session) {
  const item = document.createElement("li");
  item.className = "flex min-w-0 items-start justify-between gap-4 border-b border-divider py-3.5 last:border-b-0";
  const details = document.createElement("div");
  details.className = "min-w-0 flex-1";
  const idRow = document.createElement("div");
  idRow.className = "flex min-w-0 items-center gap-2";
  const id = document.createElement("input");
  id.className =
    "w-full min-w-0 max-w-[190px] truncate rounded border border-border bg-canvas px-2 py-[7px] font-mono text-[11px] text-ink focus-visible:outline-3 focus-visible:outline-focus";
  id.value = session.id;
  id.readOnly = true;
  id.setAttribute("aria-label", "Session ID");
  const copyId = document.createElement("button");
  copyId.className = controlButtonClasses;
  copyId.type = "button";
  copyId.textContent = "Copy ID";
  copyId.addEventListener("click", async () => {
    await navigator.clipboard.writeText(session.id);
    showMessage("Session ID copied.", true);
  });
  idRow.append(id, copyId);
  const meta = document.createElement("p");
  meta.className = "mt-1 text-xs text-muted";
  meta.textContent = `${session.isPublic ? "Public · open read/write" : "Private"} · ${session.connectedClients} connected`;
  details.append(idRow, meta);
  const source = session.isPublic
    ? `const socket = new WebSocket("wss://${location.host}/api/v1/sessions/${session.id}/connect");`
    : `const socket = new WebSocket("wss://${location.host}/api/v1/sessions/${session.id}/connect");\nsocket.addEventListener("open", () => socket.send(JSON.stringify({ type: "authorize", key: "<session-key>" })), { once: true });`;
  const snippet = document.createElement("iframe");
  const channel = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  snippet.title = "WebSocket snippet";
  snippet.className = `mt-3 block w-full min-w-0 rounded-lg border-0 bg-ink ${session.isPublic ? "h-[56px]" : "h-[76px]"}`;
  snippet.setAttribute("sandbox", "allow-scripts");
  snippet.referrerPolicy = "no-referrer";
  snippet.src = `/snippet-frame.html?channel=${channel}`;
  snippet.addEventListener("load", () => {
    snippet.contentWindow?.postMessage({ type: "websocket-snippet", channel, source }, "*");
  });
  const snippetHint = document.createElement("p");
  snippetHint.className = "mt-1 text-xs text-muted";
  snippetHint.textContent = "Scroll horizontally to view the full snippet.";
  details.append(snippet, snippetHint);

  const keyArea = document.createElement("div");
  keyArea.className = "mt-3 grid max-w-full gap-2 text-[13px]";
  const keysTitle = document.createElement("strong");
  keysTitle.textContent = session.isPublic ? "Public session" : "Session keys";
  keyArea.append(keysTitle);
  if (!session.isPublic) {
    const keys = document.createElement("ul");
    keys.className = "grid list-none gap-1.5 p-0";
    (session.keys || []).forEach((key) => {
      const row = document.createElement("li");
      row.className = "flex min-w-0 flex-wrap items-center gap-2";
      const label = document.createElement("span");
      label.textContent = key.label;
      if (sessionSecrets.has(key.id)) {
        const secret = document.createElement("input");
        secret.className =
          "w-full min-w-0 max-w-[240px] rounded-md border border-border bg-canvas px-2 py-1.5 font-mono text-xs text-ink focus-visible:outline-3 focus-visible:outline-focus";
        secret.value = sessionSecrets.get(key.id);
        secret.readOnly = true;
        secret.setAttribute("aria-label", "New session key; copy and store safely");
        const copy = document.createElement("button");
        copy.className = controlButtonClasses;
        copy.type = "button";
        copy.textContent = "Copy key";
        copy.addEventListener("click", async () => {
          await navigator.clipboard.writeText(sessionSecrets.get(key.id));
          showMessage("Key copied. Store it safely; it will not be shown again.", true);
        });
        row.append(secret, copy);
      }
      const revoke = document.createElement("button");
      revoke.className = dangerButtonClasses;
      revoke.type = "button";
      revoke.textContent = "Revoke";
      revoke.addEventListener("click", async () => {
        const response = await api(`/api/v1/sessions/${session.id}/keys/${key.id}`, { method: "DELETE" });
        if (!response.ok) {
          return showMessage("Could not revoke key.");
        }
        sessionSecrets.delete(key.id);
        await refreshSessions();
      });
      row.append(label, revoke);
      keys.append(row);
    });
    keyArea.append(keys);
    const createKey = document.createElement("button");
    createKey.className = controlButtonClasses;
    createKey.type = "button";
    createKey.textContent = "Generate key";
    createKey.addEventListener("click", async () => {
      const response = await api(`/api/v1/sessions/${session.id}/keys`, {
        method: "POST",
        body: JSON.stringify({ label: "Session key" }),
      });
      if (!response.ok) {
        return showMessage("Could not generate session key.");
      }
      const created = await response.json();
      sessionSecrets.set(created.id, created.secret);
      await refreshSessions();
      showMessage("Copy this key now. It will not be shown again.", true);
    });
    keyArea.append(createKey);
  }
  details.append(keyArea);

  const remove = document.createElement("button");
  remove.className = `${dangerButtonClasses} shrink-0`;
  remove.type = "button";
  remove.textContent = "Delete";
  remove.setAttribute("aria-label", `Delete session ${session.id}`);
  remove.addEventListener("click", async () => {
    remove.disabled = true;
    try {
      const response = await api(`/api/v1/sessions/${session.id}`, { method: "DELETE" });
      if (!response.ok) {
        throw new Error("Could not delete this session.");
      }
      showMessage("Session deleted.", true);
      await refreshSessions();
    } catch (error) {
      showMessage(error.message);
      remove.disabled = false;
    }
  });
  item.append(details, remove);
  return item;
}

async function refreshSessions() {
  const response = await api("/api/v1/sessions");
  if (!response.ok) {
    throw new Error(response.status === 401 ? "Your Auth token expired. Sign in again." : "Could not load sessions.");
  }
  const sessions = await response.json();
  sessionsState.value = sessions;
}

async function createSession() {
  const button = $("#create-session");
  button.disabled = true;
  showMessage("");
  try {
    const random = crypto.getRandomValues(new Uint8Array(64));
    const digest = await crypto.subtle.digest("SHA-512", random);
    const id = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const isPublic = publicState.value;
    const response = await api("/api/v1/sessions", {
      method: "POST",
      body: JSON.stringify({ id, isPublic }),
    });
    if (!response.ok) {
      throw new Error(
        response.status === 401 ? "Your Auth token expired. Sign in again." : "Could not create session.",
      );
    }
    if (!isPublic) {
      const keyResponse = await api(`/api/v1/sessions/${id}/keys`, {
        method: "POST",
        body: JSON.stringify({ label: "Default key" }),
      });
      if (!keyResponse.ok) {
        throw new Error("Session created, but its key could not be generated.");
      }
      const createdKey = await keyResponse.json();
      sessionSecrets.set(createdKey.id, createdKey.secret);
    }
    showMessage("Session created.", true);
    await refreshSessions();
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
  }
}

async function signOut() {
  await fetch("/api/v1/auth/logout", { method: "POST" });
  accessToken = undefined;
  location.reload();
}

async function start() {
  const status = await fetch("/api/v1/auth/status", { cache: "no-store" });
  if (!status.ok) {
    signedOut.classList.remove("hidden");
    return;
  }

  const configResponse = await fetch("/api/v1/auth/config", { cache: "no-store" });
  if (!configResponse.ok) {
    signedOut.classList.remove("hidden");
    showMessage("Relay authentication is not configured.");
    return;
  }
  ({ authApiUrl, audience } = await configResponse.json());
  signedOut.classList.add("hidden");
  sessionsView.classList.remove("hidden");
  $("#sign-out").classList.remove("hidden");
  $("#sign-out").addEventListener("click", signOut);
  $("#create-session").addEventListener("click", createSession);
  $("#public-session").addEventListener("change", (event) => {
    publicState.value = event.target.checked;
  });

  try {
    await refreshSessions();
  } catch (error) {
    showMessage(error.message);
  }
  window.setInterval(async () => {
    try {
      await refreshSessions();
    } catch (error) {
      showMessage(error.message);
    }
  }, 5000);
}

start().catch(() => {
  signedOut.classList.remove("hidden");
  showMessage("Unable to initialize relay sessions.");
});
