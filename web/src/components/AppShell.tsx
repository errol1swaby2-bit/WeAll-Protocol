import React, { useMemo } from "react";

import ConnectionPill from "./ConnectionPill";
import SessionPill from "./SessionPill";
import SidebarNav from "./SidebarNav";
import ProtocolStatusSummary from "./ProtocolStatusSummary";
import { getKeypair, getSession } from "../auth/session";
import { nav } from "../lib/router";

type AppShellProps = {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  section?: string;
  label?: string;
  description?: string;
};

export default function AppShell({
  children,
  title,
  subtitle,
  actions,
  section,
  label,
  description,
}: AppShellProps): JSX.Element {
  const session = getSession();
  const acct = session?.account || "";
  const kp = useMemo(() => (acct ? getKeypair(acct) : null), [acct]);
  const ready = !!acct && !!kp?.secretKeyB64;

  const resolvedTitle = title ?? label;
  const resolvedSubtitle = subtitle ?? description;
  const resolvedSection = section;

  return (
    <div className="appShell">
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
            <button className="appShellAccountBtn" onClick={() => nav(`/account/${encodeURIComponent(acct)}`)}>
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
        {(resolvedSection || resolvedTitle || resolvedSubtitle || actions) && (
          <header className="appShellHeader">
            <div className="appShellHeaderText">
              {resolvedSection ? <div className="appShellEyebrow">{resolvedSection}</div> : null}
              {resolvedTitle ? <h1 className="appShellTitle">{resolvedTitle}</h1> : null}
              {resolvedSubtitle ? <p className="appShellSubtitle">{resolvedSubtitle}</p> : null}
            </div>
            {actions ? <div className="appShellHeaderActions">{actions}</div> : null}
          </header>
        )}

        <ProtocolStatusSummary />

        <main className="appShellContent">{children}</main>
      </div>
    </div>
  );
}
