import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import { TxQueueProvider } from "./components/TxQueueProvider";
import { AccountProvider } from "./context/AccountContext";

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

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <AccountProvider>
        <TxQueueProvider>
          <App />
        </TxQueueProvider>
      </AccountProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
