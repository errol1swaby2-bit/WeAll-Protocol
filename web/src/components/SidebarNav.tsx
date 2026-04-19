import React, { useEffect, useMemo, useState } from "react";

import { getKeypair, getSession } from "../auth/session";
import { useAccount } from "../context/AccountContext";
import { currentHashPath, getNavSections, isActiveNavPath, nav } from "../lib/router";
import { loadSettings } from "../lib/settings";

export default function SidebarNav(): JSX.Element {
  const [currentPath, setCurrentPath] = useState<string>(currentHashPath());
  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const { state: accountState } = useAccount();
  const ready = !!session?.account && !!keypair?.secretKeyB64;
  const tier = Number(accountState?.poh_tier ?? 0);
  const settings = loadSettings();
  const sections = getNavSections({ ready, tier, showAdvanced: settings.showAdvancedMode });

  useEffect(() => {
    function onHashChange() {
      setCurrentPath(currentHashPath());
    }
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <div className="sidebarNavFrame">
      <div className="sidebarAccountChip" aria-label="Current account summary">
        <div className="sidebarAccountChipLabel">Current account</div>
        <strong>{account || "No account selected"}</strong>
        <div className="sidebarAccountChipMeta">{ready ? `PoH tier ${tier || 0}` : "Sign in to unlock gated flows"}</div>
      </div>

      <nav className="sidebarNav" aria-label="Primary">
        {sections.map((section) => (
          <section key={section.key} className="sidebarNavSection" aria-label={section.label}>
            <div className="sidebarNavSectionHead">
              <div className="sidebarNavSectionLabel">{section.label}</div>
            </div>

            <div className="sidebarNavItems">
              {section.items.map((item) => {
                const active = isActiveNavPath(currentPath, item.href);
                return (
                  <button
                    key={`${section.key}:${item.href}`}
                    className={`sidebarNavItem ${active ? "active" : ""}`}
                    onClick={() => nav(item.href)}
                    aria-current={active ? "page" : undefined}
                    title={item.description}
                  >
                    <span className="sidebarNavLead">
                      <span className="sidebarNavIcon" aria-hidden="true">
                        {item.icon}
                      </span>
                      <span className="sidebarNavText">
                        <span className="sidebarNavLabel">{item.label}</span>
                        <span className="sidebarNavHint">{item.description}</span>
                      </span>
                    </span>
                    <span className="sidebarNavArrow" aria-hidden="true">
                      ›
                    </span>
                  </button>
                );
              })}
            </div>
          </section>
        ))}
      </nav>
    </div>
  );
}
