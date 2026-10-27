const $ = (selector) => document.querySelector(selector);
const signedOut = $("#signed-out");
const sessionsView = $("#sessions-view");
const list = $("#session-list");
const message = $("#message");

let authApiUrl;
let audience;
let accessToken;
let tokenExpiresAt = 0;

function showMessage(text, success = false) {
  message.textContent = text;
  message.classList.toggle("success", success);
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
  item.className = "session-row";
  const details = document.createElement("div");
  details.className = "session-details";
  const id = document.createElement("code");
  id.className = "session-id";
  id.textContent = session.id;
  const meta = document.createElement("p");
  meta.className = "session-meta";
  meta.textContent = `${session.isPublic ? "Public · listen-only" : "Private"} · ${session.connectedClients} connected`;
  details.append(id, meta);

  const remove = document.createElement("button");
  remove.className = "delete-session";
  remove.type = "button";
  remove.textContent = "Delete";
  remove.setAttribute("aria-label", `Delete session ${session.id}`);
  remove.addEventListener("click", async () => {
    remove.disabled = true;
    try {
      const response = await api(`/api/sessions/${session.id}`, { method: "DELETE" });
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
  const response = await api("/api/sessions");
  if (!response.ok) {
    throw new Error(response.status === 401 ? "Your Auth token expired. Sign in again." : "Could not load sessions.");
  }
  const sessions = await response.json();
  list.replaceChildren(...sessions.map(addSession));
  if (!sessions.length) {
    const empty = document.createElement("li");
    empty.className = "session-meta";
    empty.textContent = "No sessions yet.";
    list.append(empty);
  }
}

async function createSession() {
  const button = $("#create-session");
  button.disabled = true;
  showMessage("");
  try {
    const random = crypto.getRandomValues(new Uint8Array(64));
    const digest = await crypto.subtle.digest("SHA-512", random);
    const id = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const response = await api("/api/sessions", {
      method: "POST",
      body: JSON.stringify({ id, isPublic: $("#public-session").checked }),
    });
    if (!response.ok) {
      throw new Error(
        response.status === 401 ? "Your Auth token expired. Sign in again." : "Could not create session.",
      );
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
  await fetch("/auth/logout", { method: "POST" });
  accessToken = undefined;
  location.reload();
}

async function start() {
  const status = await fetch("/auth/status", { cache: "no-store" });
  if (!status.ok) {
    signedOut.classList.remove("hidden");
    return;
  }

  const configResponse = await fetch("/auth/config", { cache: "no-store" });
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
