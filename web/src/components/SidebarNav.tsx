import React, { useEffect, useMemo, useState } from "react";

import { getKeypair, getSession } from "../auth/session";
import { useAccount } from "../context/AccountContext";
import { nav } from "../lib/router";

type NavItem = {
  href: string;
  label: string;
  icon: string;
  requiresReady?: boolean;
};

const LOGGED_OUT_ITEMS: NavItem[] = [
  { href: "/login", label: "Login", icon: "◉" },
  { href: "/feed", label: "Feed", icon: "≋" },
];

const READY_ITEMS: NavItem[] = [
  { href: "/home", label: "Home", icon: "⌂" },
  { href: "/feed", label: "Feed", icon: "≋" },
  { href: "/post", label: "Create", icon: "+" },
  { href: "/poh", label: "PoH", icon: "◉" },
  { href: "/juror", label: "Juror", icon: "⚖", requiresReady: true },
  { href: "/groups", label: "Groups", icon: "◌" },
  { href: "/proposals", label: "Governance", icon: "▣" },
  { href: "/settings", label: "Settings", icon: "⚙" },
];

function currentHashPath(): string {
  if (typeof window === "undefined") return "/login";
  const hash = window.location.hash || "#/login";
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  return raw || "/login";
}

function isActive(currentPath: string, href: string): boolean {
  if (href === "/home") {
    return currentPath === "/" || currentPath === "/home";
  }
  return currentPath === href || currentPath.startsWith(`${href}/`);
}

export default function SidebarNav(): JSX.Element {
  const [currentPath, setCurrentPath] = useState<string>(currentHashPath());
  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const { state: accountState } = useAccount();
  const ready = !!session?.account && !!keypair?.secretKeyB64;
  const tier = Number(accountState?.poh_tier ?? 0);
  const items = ready ? READY_ITEMS : LOGGED_OUT_ITEMS;

  useEffect(() => {
    function onHashChange() {
      setCurrentPath(currentHashPath());
    }
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <nav className="sidebarNav" aria-label="Primary">
      {items
        .filter((item) => {
          if (item.href === "/juror") return ready && tier >= 3;
          return !item.requiresReady || ready;
        })
        .map((item) => {
          const active = isActive(currentPath, item.href);
          return (
            <button
              key={item.href}
              className={`sidebarNavItem ${active ? "active" : ""}`}
              onClick={() => nav(item.href)}
            >
              <span className="sidebarNavIcon" aria-hidden="true">
                {item.icon}
              </span>
              <span className="sidebarNavLabel">{item.label}</span>
            </button>
          );
        })}
    </nav>
  );
}
