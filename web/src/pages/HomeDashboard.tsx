import React from "react";
import Target from "./Home";

/**
 * Canonical route-entry wrapper for the Home mission-control surface.
 * Keep this wrapper as the stable page-layer entrypoint so App.tsx
 * depends on route-entry modules rather than underlying implementation filenames.
 */
export default function HomeDashboard(): JSX.Element {
  return <Target />;
}
