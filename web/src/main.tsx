// src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";

function installGlobalGuards() {
  // These help catch async crashes not caught by React boundaries.
  window.addEventListener("unhandledrejection", (ev) => {
    // eslint-disable-next-line no-console
    console.error("Unhandled promise rejection:", ev.reason);
  });
  window.addEventListener("error", (ev) => {
    // eslint-disable-next-line no-console
    console.error("Global error:", ev.error || ev.message);
  });
}

installGlobalGuards();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
