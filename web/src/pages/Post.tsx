import React from "react";
import Target from "./CreatePostPage";

/**
 * Canonical route-entry wrapper for the create-post transaction surface.
 * Keep this wrapper as the stable page-layer entrypoint so App.tsx
 * depends on route-entry modules rather than underlying implementation filenames.
 */
export default function Post(): JSX.Element {
  return <Target />;
}
