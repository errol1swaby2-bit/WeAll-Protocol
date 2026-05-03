import React, { useMemo } from "react";

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

  return (
    <div className={`appShell ${writesLocked ? "writesLocked" : ""}`.trim()}>
      <a className="appShellSkipLink" href="#app-shell-content">
        Skip to content
      </a>
      <aside className="appShellSidebar">
        <div className="appShellSidebarBody">
          <div
            className="appShellBrand"
            onClick={() => handleBrandActivate(ready)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                handleBrandActivate(ready);
              }
            }}
            role="button"
            tabIndex={0}
            aria-label={ready ? "Open home" : "Open login"}
          >
            <div className="appShellBrandMark">W</div>
            <div className="appShellBrandText">
              <strong>WeAll</strong>
              <small>{ready ? "Social trust network" : "Sign in to continue"}</small>
            </div>
          </div>

          <SidebarNav showAdvancedMode={showAdvancedMode} />
        </div>

        <div className="appShellSidebarFooter">
          <ConnectionPill />
          <SessionPill />
          <div className="buttonRow buttonRowWide">
            {ready ? (
              <>
                <button className="appShellAccountBtn" onClick={() => nav("/profile")}>
                  Profile
                </button>
                <button className="appShellAccountBtn" onClick={() => nav("/session")}>
                  Session
                </button>
              </>
            ) : (
              <button className="appShellAccountBtn" onClick={() => nav("/login")}>
                Open login
              </button>
            )}
            <button className="appShellAccountBtn" onClick={() => nav("/settings")}>
              Settings
            </button>
          </div>
        </div>
      </aside>

      <div className="appShellMain">
        <header className="appShellHeader">
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
              onClick={() => document.getElementById("protocol-awareness-rail")?.scrollIntoView({ behavior: "smooth", block: "start" })}
              type="button"
            >
              Jump to helpful panel
            </button>
            {writesLocked ? (
              <button className="appShellRouteStripAction" onClick={() => nav('/session')}>
                Recover session
              </button>
            ) : null}
          </div>
        </section>

        <div className="appShellBody">
          <main id="app-shell-content" className="appShellContent">{children}</main>
          <AppRightRail route={route} meta={meta} sessionHealth={sessionHealth} showAdvancedMode={showAdvancedMode} />
        </div>
      </div>

      {showFab && fabHref ? <FabActionButton href={fabHref} label={fabLabel(meta)} /> : null}
    </div>
  );
}
