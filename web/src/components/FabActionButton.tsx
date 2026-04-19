import React from "react";

import { nav } from "../lib/router";

export default function FabActionButton({ href, label }: { href: string; label: string }): JSX.Element {
  return (
    <button
      type="button"
      className="fabActionButton"
      onClick={() => nav(href)}
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
