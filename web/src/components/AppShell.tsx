import React, { useEffect, useMemo, useRef, useState } from "react";

import ConnectionPill from "./ConnectionPill";
import SessionPill from "./SessionPill";
import SidebarNav from "./SidebarNav";
import AppRightRail from "./AppRightRail";
import FabActionButton from "./FabActionButton";
import type { SessionHealth } from "../auth/session";
import { getKeypair, getSession } from "../auth/session";
import { getFabHref, nav, type RouteMatch, type RouteMeta } from "../lib/router";

type AppShellProps = {
  children: React.ReactNode;
  route: RouteMatch;
  meta: RouteMeta;
  sessionHealth?: SessionHealth;
  showAdvancedMode?: boolean;
};

function modeLabel(meta: RouteMeta): string {
  switch (meta.mode) {
    case "hub":
      return "Hub page";
    case "detail":
      return "Detail page";
    case "action":
      return "Action page";
    case "utility":
      return "Utility page";
    case "advanced":
      return "Advanced page";
    default:
      return meta.mode;
  }
}

function modeContract(meta: RouteMeta): string {
  switch (meta.mode) {
    case "hub":
      return "Browse and route only. Creation and one-shot decisions stay off the hub.";
    case "detail":
      return "Inspect one object and expose one clear next step.";
    case "action":
      return "Complete one focused action with clear saving, done, and failed states.";
    case "utility":
      return "Manage account, settings, or safety state without crowding core social flows.";
    default:
      return meta.dataContract.primaryObject;
  }
}

function fabLabel(meta: RouteMeta): string {
  switch (meta.fab) {
    case "post":
      return "Create post";
    case "group":
      return "Create group";
    case "decision":
      return "Create decision";
    default:
      return "Create";
  }
}

function formatRouteValue(value: string): string {
  const raw = decodeURIComponent(String(value || "").trim());
  if (!raw) return "";
  if (raw.startsWith("@")) return raw;
  if (/^[a-z0-9._-]+$/i.test(raw)) return raw;
  return raw;
}

function titleForRoute(route: RouteMatch, meta: RouteMeta): string {
  if ("id" in route && route.id) {
    if (meta.mode === "detail") return `${meta.title} · ${formatRouteValue(route.id)}`;
    if (meta.mode === "action") return `${meta.title} · ${formatRouteValue(route.id)}`;
  }
  if ("account" in route && route.account) {
    return `${meta.title} · ${formatRouteValue(route.account)}`;
  }
  return meta.title;
}

function deriveBreadcrumbs(route: RouteMatch, meta: RouteMeta): Array<{ label: string; href: string }> {
  const crumbs = [...(meta.breadcrumbs || [])];
  if (route.path === "/reviews/:id" && "id" in route && route.id) {
    return crumbs.map((crumb) =>
      crumb.href === "/reports/:id" ? { ...crumb, href: `/reports/${encodeURIComponent(route.id)}` } : crumb,
    );
  }
  return crumbs;
}


function handleBrandActivate(ready: boolean): void {
  nav(ready ? "/home" : "/login");
}

export default function AppShell({ children, route, meta, sessionHealth, showAdvancedMode = false }: AppShellProps): JSX.Element {
  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const ready = !!account && !!keypair?.secretKeyB64;
  const writesLocked = !!meta.authRequired && !!sessionHealth && !["active", "expiring_soon"].includes(sessionHealth.state);
  const fabHref = ready && !writesLocked && meta.mode === "hub" ? getFabHref(route) : null;
  const showFab = !!fabHref && meta.fab !== "none";
  const breadcrumbs = deriveBreadcrumbs(route, meta);
  const headerTitle = titleForRoute(route, meta);
  const routeKey = JSON.stringify(route);

  const [menuOpen, setMenuOpen] = useState(false);
  const [infoOpen, setInfoOpen] = useState(false);
  const menuAnchorRef = useRef<HTMLDivElement>(null);
  const menuToggleRef = useRef<HTMLButtonElement>(null);
  const infoDrawerRef = useRef<HTMLElement>(null);
  const infoCloseRef = useRef<HTMLButtonElement>(null);

  // Navigation should close temporary surfaces, leaving the next task in focus.
  useEffect(() => {
    setMenuOpen(false);
    setInfoOpen(false);
  }, [routeKey]);

  useEffect(() => {
    if (!menuOpen) return;

    const onPointerDown = (event: PointerEvent) => {
      if (menuAnchorRef.current && !menuAnchorRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    };
    const onEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      setMenuOpen(false);
      menuToggleRef.current?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onEscape);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onEscape);
    };
  }, [menuOpen]);

  useEffect(() => {
    const drawer = infoDrawerRef.current;
    if (!drawer) return;
    if (!infoOpen) {
      drawer.setAttribute("inert", "");
      return;
    }

    drawer.removeAttribute("inert");
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    infoCloseRef.current?.focus();

    const onDrawerKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setInfoOpen(false);
        return;
      }
      if (event.key !== "Tab") return;

      const focusable = Array.from(
        drawer.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'),
      ).filter((element) => element.getClientRects().length > 0);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (event.shiftKey && (document.activeElement === first || !drawer.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !drawer.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onDrawerKeyDown);
    return () => {
      document.removeEventListener("keydown", onDrawerKeyDown);
      document.body.style.overflow = previousOverflow;
      if (previousFocus && document.contains(previousFocus)) previousFocus.focus();
    };
  }, [infoOpen]);

  return (
    <div className={`appShell appShell--focus appShell--${meta.mode} ${writesLocked ? "writesLocked" : ""}`.trim()}>
      <a className="appShellSkipLink" href="#app-shell-content">
        Skip to content
      </a>

      <div className="appShellMain">
        <header className="appShellHeader">
          <div className="appShellHeaderBar">
            <div className="appShellMenuAnchor" ref={menuAnchorRef}>
              <button
                type="button"
                ref={menuToggleRef}
                className="appShellMenuToggle"
                aria-controls="app-shell-primary-menu"
                aria-haspopup="true"
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen((current) => !current)}
              >
                <span aria-hidden="true">☰</span>
                <span>Menu</span>
                <span aria-hidden="true">▾</span>
              </button>

              {menuOpen ? (
                <div id="app-shell-primary-menu" className="appShellMenuPopover">
                  <SidebarNav showAdvancedMode={showAdvancedMode} onNavigate={() => setMenuOpen(false)} />
                  <div className="appShellMenuFooter">
                    <ConnectionPill />
                    <SessionPill />
                    <div className="appShellMenuQuickLinks">
                      <button type="button" onClick={() => { setMenuOpen(false); nav(ready ? "/profile" : "/login"); }}>
                        {ready ? "Profile" : "Sign in"}
                      </button>
                      <button type="button" onClick={() => { setMenuOpen(false); nav("/settings"); }}>Settings</button>
                    </div>
                  </div>
                </div>
              ) : null}
            </div>

            <button className="appShellBrandCompact" type="button" onClick={() => handleBrandActivate(ready)}>
              <span className="appShellBrandMark" aria-hidden="true">W</span>
              <span>WeAll</span>
            </button>

            <button
              className="appShellInfoToggle"
              type="button"
              onClick={() => { setMenuOpen(false); setInfoOpen(true); }}
              aria-haspopup="dialog"
              aria-controls="app-shell-context-drawer"
              aria-expanded={infoOpen}
            >
              <span aria-hidden="true">☷</span> Context &amp; status
            </button>
          </div>

          <div className="appShellHeaderText">
            <div className="appShellEyebrow">{meta.section}</div>
            <h1 className="appShellTitle">{headerTitle}</h1>
            <p className="appShellSubtitle">{meta.description}</p>
            {breadcrumbs.length ? (
              <div className="appShellBreadcrumbs" aria-label="Breadcrumbs">
                {breadcrumbs.map((crumb) => (
                  <button key={`${meta.title}:${crumb.href}`} className="appShellBreadcrumb" onClick={() => nav(crumb.href)}>
                    {crumb.label}
                  </button>
                ))}
                <span className="appShellBreadcrumb appShellBreadcrumb-current">{headerTitle}</span>
              </div>
            ) : null}
          </div>

          <div className="appShellHeaderMeta">
            <div className="appShellModePill">{modeLabel(meta)}</div>
            <div className="appShellContractNote">{modeContract(meta)}</div>
            {writesLocked ? <div className="appShellLockPill">writes locked</div> : null}
          </div>
        </header>

        <section className="appShellRouteStrip" aria-label="Helpful page summary">
          <div className="appShellRouteStripSummary">
            <span className="appShellRouteStripPill">{modeLabel(meta)}</span>
            <span className="appShellRouteStripText">{meta.dataContract.contextPanelData}</span>
            {showFab && fabHref ? <span className="appShellRouteStripPill appShellRouteStripPill-accent">{fabLabel(meta)}</span> : null}
          </div>
          <div className="appShellRouteStripActions">
            <button
              className="appShellRouteStripAction appShellRouteStripAction-secondary"
              onClick={() => setInfoOpen(true)}
              type="button"
            >
              Open context panel
            </button>
            {writesLocked ? (
              <button className="appShellRouteStripAction" onClick={() => nav("/session")}>
                Recover session
              </button>
            ) : null}
          </div>
        </section>

        <div className="appShellBody">
          <main key={routeKey} id="app-shell-content" className="appShellContent" tabIndex={-1}>
            {children}
          </main>
        </div>
      </div>

      <div className={`appShellDrawerLayer ${infoOpen ? "isOpen" : ""}`} aria-hidden={!infoOpen}>
        <div className="appShellDrawerBackdrop" onClick={() => setInfoOpen(false)} aria-hidden="true" />
        <section
          id="app-shell-context-drawer"
          className="appShellContextDrawer"
          ref={infoDrawerRef}
          role="dialog"
          aria-modal={infoOpen}
          aria-label="Context and status"
        >
          <div className="appShellDrawerHeader">
            <div>
              <strong>Context &amp; status</strong>
              <p>Helpful information, pending work, and network posture.</p>
            </div>
            <button type="button" className="appShellDrawerClose" ref={infoCloseRef} onClick={() => setInfoOpen(false)} aria-label="Close context and status panel">
              ✕
            </button>
          </div>
          <div className="appShellDrawerContents">
            <AppRightRail route={route} meta={meta} sessionHealth={sessionHealth} showAdvancedMode={showAdvancedMode} />
          </div>
        </section>
      </div>

      {showFab && fabHref ? <FabActionButton href={fabHref} label={fabLabel(meta)} /> : null}
    </div>
  );
}
