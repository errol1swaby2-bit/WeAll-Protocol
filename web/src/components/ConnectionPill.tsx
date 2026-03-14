import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { resolveOnboardingSnapshot } from "../lib/onboarding";
import { nav } from "../lib/router";

function statusClass(kind: "ok" | "warn" | "bad"): string {
  if (kind === "ok") return "ok";
  if (kind === "bad") return "danger";
  return "";
}

export default function ConnectionPill(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : "";
  const kp = useMemo(() => (acct ? getKeypair(acct) : null), [acct]);

  const [label, setLabel] = useState<string>("Checking");
  const [kind, setKind] = useState<"ok" | "warn" | "bad">("warn");
  const [meta, setMeta] = useState<string>("");
  const [acctView, setAcctView] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      try {
        const r: any = await weall.status(base);
        if (cancelled) return;

        const height = Number(r?.height ?? 0);
        const chainId = String(r?.chain_id || "unknown");
        const mode = String(r?.mode || "unknown");

        setKind(r?.ok ? "ok" : "warn");
        setLabel(r?.ok ? "Connected" : "Degraded");
        setMeta(`${chainId} · h${height} · ${mode}`);
      } catch {
        if (cancelled) return;
        setKind("bad");
        setLabel("Offline");
        setMeta(base);
      }
    }

    void run();
    const t = window.setInterval(run, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(t);
    };
  }, [base]);

  useEffect(() => {
    let cancelled = false;

    async function loadAccount() {
      if (!acct) {
        setAcctView(null);
        setRegistration(null);
        return;
      }

      try {
        const [accountView, registrationView] = await Promise.all([
          weall.account(acct, base),
          weall.accountRegistered(acct, base).catch(() => ({ registered: false })),
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

    void loadAccount();
    return () => {
      cancelled = true;
    };
  }, [acct, base]);

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: acctView,
    registrationView: registration,
  });

  const title = acct
    ? `${base} • ${acct} • tier ${snapshot.tier} • ${snapshot.registered ? "registered" : "registration needed"}`
    : base;

  return (
    <button
      className={`statusPill ${statusClass(kind)}`}
      title={title}
      onClick={() => nav(acct ? snapshot.next.route : "/login")}
    >
      <span>{label}</span>
      <span className="mono connectionMeta">{meta}</span>
      {acct ? <span className="mono">{acct}</span> : null}
      {acct ? <span>{`tier ${snapshot.tier}`}</span> : null}
      {acct ? (
        <span className={snapshot.hasLocalSigner ? "" : "danger"}>
          {snapshot.hasLocalSigner ? "signing ready" : "no signer"}
        </span>
      ) : null}
    </button>
  );
}
