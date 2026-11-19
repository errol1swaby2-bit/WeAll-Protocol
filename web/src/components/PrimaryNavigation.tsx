import React from "react";
import { isActiveNavPath, nav } from "../lib/router";

type Item = { label: string; href: string; sessionOnly: boolean; glyph: string };

const ITEMS: readonly Item[] = [
  { label: "Home", href: "/home", sessionOnly: true, glyph: "⌂" },
  { label: "Feed", href: "/feed", sessionOnly: true, glyph: "≋" },
  { label: "Groups", href: "/groups", sessionOnly: false, glyph: "◌" },
  { label: "Decisions", href: "/decisions", sessionOnly: false, glyph: "▣" },
  { label: "Account", href: "/profile", sessionOnly: true, glyph: "☺" },
];

/**
 * Five stable destinations for every role. Authorization is still checked
 * by route/backend; a disabled control is only a local navigation affordance.
 */
export default function PrimaryNavigation({ currentPath, ready }: { currentPath: string; ready: boolean }): JSX.Element {
  return (
    <nav className="primaryNavigation" aria-label="Main navigation">
      {ITEMS.map((item) => {
        const active = isActiveNavPath(currentPath, item.href);
        const unavailable = item.sessionOnly && !ready;
        return (
          <button
            key={item.href}
            className={`primaryNavigationItem ${active ? "isActive" : ""}`}
            type="button"
            aria-current={active ? "page" : undefined}
            title={unavailable ? `${item.label}: sign in to access` : item.label}
            disabled={unavailable}
            onClick={() => nav(item.href)}
          >
            <span className="primaryNavigationGlyph" aria-hidden="true">{item.glyph}</span>
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}
