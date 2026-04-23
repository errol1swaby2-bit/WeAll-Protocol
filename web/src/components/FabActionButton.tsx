import React from "react";

import { nav } from "../lib/router";
import { prefetchRouteChunk } from "../lib/routePrefetch";

export default function FabActionButton({ href, label }: { href: string; label: string }): JSX.Element {
  const warmRoute = () => prefetchRouteChunk(href);

  return (
    <button
      type="button"
      className="fabActionButton"
      onClick={() => nav(href)}
      onMouseEnter={warmRoute}
      onFocus={warmRoute}
      onTouchStart={warmRoute}
      aria-label={label}
      data-testid="fab-action-button"
    >
      <span className="fabActionButtonIcon" aria-hidden="true">
        +
      </span>
      <span className="fabActionButtonLabel">{label}</span>
    </button>
  );
}
