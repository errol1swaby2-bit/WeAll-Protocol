import React, { useMemo } from "react";

import ConnectionPill from "./ConnectionPill";
import SessionPill from "./SessionPill";
import SidebarNav from "./SidebarNav";
import { getKeypair, getSession } from "../auth/session";
import { nav } from "../lib/router";

export default function AppShell({
  children,
  title,
  subtitle,
  actions,
}: {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
}): JSX.Element {
  const session = getSession();
  const acct = session?.account || "";
  const kp = useMemo(() => (acct ? getKeypair(acct) : null), [acct]);
  const ready = !!acct && !!kp?.secretKeyB64;

  return (
    <div className="appShell">
      <aside className="appShellSidebar">
        <div className="appShellBrand" onClick={() => nav(ready ? "/home" : "/login")} role="button" tabIndex={0}>
          <div className="appShellBrandMark">W</div>
          <div className="appShellBrandText">
            <strong>WeAll</strong>
            <small>{ready ? "Genesis client" : "Login required"}</small>
          </div>
        </div>

        <SidebarNav />

        <div className="appShellSidebarFooter">
          <ConnectionPill />
          <SessionPill />
          {ready ? (
            <button
              className="appShellAccountBtn"
              onClick={() => nav(`/account/${encodeURIComponent(acct)}`)}
            >
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
        {(title || subtitle || actions) && (
          <header className="appShellHeader">
            <div className="appShellHeaderText">
              {title ? <h1 className="appShellTitle">{title}</h1> : null}
              {subtitle ? <p className="appShellSubtitle">{subtitle}</p> : null}
            </div>
            {actions ? <div className="appShellHeaderActions">{actions}</div> : null}
          </header>
        )}

        <main className="appShellContent">{children}</main>
      </div>
    </div>
  );
}
