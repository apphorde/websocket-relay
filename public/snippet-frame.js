import "@li3/web";

const channel = new URLSearchParams(location.search).get("channel");
const snippet = document.querySelector("#snippet");
let source = "";

function wrapCode() {
  const code = snippet.shadowRoot?.querySelector("code");
  if (code) {
    code.style.whiteSpace = "pre-wrap";
    code.style.overflowWrap = "anywhere";
  }
}

function postHeight() {
  const height = Math.ceil(snippet.getBoundingClientRect().height);
  parent.postMessage({ type: "snippet-height", channel, height }, "*");
}

if (!/^[a-f0-9]{32}$/.test(channel || "")) {
  throw new Error("Invalid snippet channel");
}

window.addEventListener("message", (event) => {
  const message = event.data;
  if (
    event.source !== parent ||
    message?.type !== "websocket-snippet" ||
    message.channel !== channel ||
    typeof message.source !== "string" ||
    message.source.length > 4096
  ) {
    return;
  }

  source = message.source;
  snippet.source = source;
  requestAnimationFrame(wrapCode);
});

customElements.whenDefined("code-block").then(() => {
  wrapCode();
  if (source) {
    snippet.source = source;
    requestAnimationFrame(wrapCode);
  }
  const resizeObserver = new ResizeObserver(postHeight);
  resizeObserver.observe(snippet);
  requestAnimationFrame(postHeight);
});
