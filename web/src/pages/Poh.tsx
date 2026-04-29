import React from "react";
import Target from "./PohPage";

/**
 * Canonical route-entry wrapper for the Proof-of-Humanity lifecycle surface.
 * Keep this wrapper as the stable page-layer entrypoint so App.tsx
 * depends on route-entry modules rather than underlying implementation filenames.
 */
export default function Poh(): JSX.Element {
  return <Target />;
}
