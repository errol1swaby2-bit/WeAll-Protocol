import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import { TxQueueProvider } from "./components/TxQueueProvider";
import { AccountProvider } from "./context/AccountContext";

import { config } from "./lib/config";
import { connectPublicTestnetBrowser } from "./lib/connectPublicTestnetBrowser";

import "./styles.css";

function installGlobalGuards() {
  window.addEventListener("unhandledrejection", (ev) => {
    console.error("Unhandled promise rejection:", ev.reason);
  });
  window.addEventListener("error", (ev) => {
    console.error("Global error:", ev.error || ev.message);
  });
}

installGlobalGuards();

const root = ReactDOM.createRoot(document.getElementById("root")!);
const app = (
  <React.StrictMode>
    <ErrorBoundary>
      <AccountProvider>
        <TxQueueProvider>
          <App />
        </TxQueueProvider>
      </AccountProvider>
    </ErrorBoundary>
  </React.StrictMode>
);

// Hosted public testnet users discover a compatible node before the first API
// request. Local/dev builds keep their existing immediate boot behavior.
if (config.publicTestnet) {
  root.render(
    <main role="status" aria-live="polite" style={{ padding: "2rem" }}>
      Finding an available WeAll testnet node…
    </main>,
  );

  void connectPublicTestnetBrowser()
    .catch((error: unknown) => {
      console.warn("Testnet node discovery unavailable; manual selection remains possible.", error);
    })
    .finally(() => {
      root.render(app);
    });
} else {
  root.render(app);
}
