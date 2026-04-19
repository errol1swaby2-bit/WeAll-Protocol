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
};

function fabLabel(meta: RouteMeta): string {
  switch (meta.fab) {
    case "post":
      return "Create post";
    case "group":
      return "Create group";
    case "proposal":
      return "Create proposal";
    default:
      return "Create";
  }
}

export default function AppShell({ children, route, meta, sessionHealth }: AppShellProps): JSX.Element {
  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const ready = !!account && !!keypair?.secretKeyB64;
  const writesLocked = !!meta.authRequired && !!sessionHealth && !["active", "expiring_soon"].includes(sessionHealth.state);
  const fabHref = ready && !writesLocked && meta.mode === "hub" ? getFabHref(route) : null;
  const showFab = !!fabHref && meta.fab !== "none";

  return (
    <div className={`appShell ${writesLocked ? "writesLocked" : ""}`.trim()}>
      <aside className="appShellSidebar">
        <div className="appShellSidebarBody">
          <div className="appShellBrand" onClick={() => nav(ready ? "/home" : "/login")} role="button" tabIndex={0}>
            <div className="appShellBrandMark">W</div>
            <div className="appShellBrandText">
              <strong>WeAll</strong>
              <small>{ready ? "Protocol client" : "Sign in to continue"}</small>
            </div>
          </div>

          <SidebarNav />
        </div>

        <div className="appShellSidebarFooter">
          <ConnectionPill />
          <SessionPill />
          {ready ? (
            <button className="appShellAccountBtn" onClick={() => nav(`/account/${encodeURIComponent(account)}`)}>
              My account
            </button>
          ) : (
            <button className="appShellAccountBtn" onClick={() => nav("/login")}>
              Open login
            </button>
          )}
        </div>
      </aside>

      <div className="appShellMain">
        <header className="appShellHeader">
          <div className="appShellHeaderText">
            <div className="appShellEyebrow">{meta.section}</div>
            <h1 className="appShellTitle">{meta.title}</h1>
            <p className="appShellSubtitle">{meta.description}</p>
            {meta.breadcrumbs?.length ? (
              <div className="appShellBreadcrumbs" aria-label="Breadcrumbs">
                {meta.breadcrumbs.map((crumb) => (
                  <button key={`${meta.title}:${crumb.href}`} className="appShellBreadcrumb" onClick={() => nav(crumb.href)}>
                    {crumb.label}
                  </button>
                ))}
                <span className="appShellBreadcrumb appShellBreadcrumb-current">{meta.title}</span>
              </div>
            ) : null}
          </div>

          <div className="appShellHeaderMeta">
            <div className="appShellModePill">{meta.mode}</div>
            <div className="appShellContractNote">{meta.dataContract.primaryObject}</div>
            {writesLocked ? <div className="appShellLockPill">writes locked</div> : null}
          </div>
        </header>

        <div className="appShellBody">
          <main className="appShellContent">{children}</main>
          <AppRightRail route={route} meta={meta} />
        </div>
      </div>

      {showFab && fabHref ? <FabActionButton href={fabHref} label={fabLabel(meta)} /> : null}
    </div>
  );
}
