import React from "react";
import ConnectionPill from "./ConnectionPill";
import SessionPill from "./SessionPill";

type Props = {
  children: React.ReactNode;
};

export default function AppShell({ children }: Props) {
  return (
    <div
      style={{
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
        background: "#fafafa",
        minHeight: "100vh",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          padding: 12,
          borderBottom: "1px solid #ddd",
          background: "#fff",
          position: "sticky",
          top: 0,
          zIndex: 10,
        }}
      >
        <ConnectionPill />
        <SessionPill />
      </div>

      <div style={{ padding: 16 }}>{children}</div>
    </div>
  );
}
