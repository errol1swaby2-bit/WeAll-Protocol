import React, { useEffect, useMemo, useState } from "react";

import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { getApiBaseUrl, weall } from "../api/weall";
import { resolveOnboardingSnapshot } from "../lib/onboarding";
import { nav } from "../lib/router";

export default function SessionPill(): JSX.Element {
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : "";
  const kp = useMemo(() => (acct ? getKeypair(acct) : null), [acct]);

  const [acctView, setAcctView] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      if (!acct) {
        setAcctView(null);
        setRegistration(null);
        return;
      }

      try {
        const [accountView, registrationView] = await Promise.all([
          weall.account(acct, getApiBaseUrl()),
          weall.accountRegistered(acct, getApiBaseUrl()),
        ]);
        if (cancelled) return;
        setAcctView(accountView);
        setRegistration(registrationView);
      } catch {
        if (cancelled) return;
        setAcctView(null);
        setRegistration(null);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [acct]);

  if (!acct) {
    return (
      <button className="statusPill" onClick={() => nav("/login")}>
        <span>No session</span>
      </button>
    );
  }

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: acctView,
    registrationView: registration,
  });

  return (
    <button
      className={`statusPill ${snapshot.hasLocalSigner ? "ok" : ""}`}
      onClick={() => nav(snapshot.next.route)}
    >
      <span className="mono">{acct}</span>
      <span>{snapshot.hasLocalSigner ? "signing ready" : "no key"}</span>
      <span>{`tier ${snapshot.tier}`}</span>
      <span>{snapshot.registered ? "registered" : "register"}</span>
      {snapshot.locked ? <span>locked</span> : null}
      {snapshot.banned ? <span>banned</span> : null}
    </button>
  );
}
