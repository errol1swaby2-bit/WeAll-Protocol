import React from "react";
import Target from "./Settings";

/**
 * Canonical route-entry wrapper for the connection and environment surface.
 * Keep this wrapper as the stable page-layer entrypoint so App.tsx
 * depends on route-entry modules rather than underlying implementation filenames.
 */
export default function SettingsPage(): JSX.Element {
  return <Target />;
}
