import "@li3/web";

const channel = new URLSearchParams(location.search).get("channel");
const snippet = document.querySelector("#snippet");
let source = "";

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
});

customElements.whenDefined("code-block").then(() => {
  if (source) {
    snippet.source = source;
  }
});
