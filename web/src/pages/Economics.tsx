import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { WEALL_API_BASE_CHANGED_EVENT } from "../lib/nodeConnectionManager";
import { nav } from "../lib/router";

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function asBool(value: unknown): boolean {
  return value === true;
}

function valueText(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

export default function Economics(): JSX.Element {
  const [apiBase, setApiBaseState] = useState(() => getApiBaseUrl());
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [activation, setActivation] = useState<Record<string, any> | null>(null);
  const [treasuryStatus, setTreasuryStatus] = useState<Record<string, any> | null>(null);
  const [toAccount, setToAccount] = useState("");
  const [transferAmount, setTransferAmount] = useState("0");
  const [transferPreview, setTransferPreview] = useState<Record<string, any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>("");

  async function load(): Promise<void> {
    setBusy(true);
    setErr("");
    try {
      const [res, activationRes, treasuryRes]: any[] = await Promise.all([
        weall.economicsStatus(account ? { account } : undefined, apiBase),
        weall.economicsActivationReadiness(apiBase),
        weall.treasuryStatus(apiBase),
      ]);
      setStatus(asRecord(res));
      setActivation(asRecord(activationRes));
      setTreasuryStatus(asRecord(treasuryRes));
    } catch (e: any) {
      setErr(e?.message || "Economics status failed to load.");
      setStatus(null);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const onBaseChanged = () => setApiBaseState(getApiBaseUrl());
    window.addEventListener(WEALL_API_BASE_CHANGED_EVENT, onBaseChanged as EventListener);
    window.addEventListener("storage", onBaseChanged);
    return () => {
      window.removeEventListener(WEALL_API_BASE_CHANGED_EVENT, onBaseChanged as EventListener);
      window.removeEventListener("storage", onBaseChanged);
    };
  }, []);

  useEffect(() => {
    void load();
  }, [apiBase, account]);

  async function previewTransfer(): Promise<void> {
    setErr("");
    try {
      const res: any = await weall.economicsTransferPreview({
        from_account: account,
        to_account: toAccount.trim(),
        amount: Number(transferAmount || 0),
      }, apiBase);
      setTransferPreview(asRecord(res));
    } catch (e: any) {
      setErr(e?.message || "Transfer preview failed.");
      setTransferPreview(null);
    }
  }

  const capabilities = asRecord(status?.capabilities);
  const acct = asRecord(status?.account);
  const treasury = asRecord(status?.treasury);
  const activationRequirements = Array.isArray(activation?.requirements) ? activation?.requirements as Record<string, any>[] : [];
  const treasuryRead = asRecord(treasuryStatus);
  const requirements = Array.isArray(status?.activation_requirements) ? status?.activation_requirements as string[] : [];
  const feeViolations = Array.isArray(status?.civic_fee_violations) ? status?.civic_fee_violations as string[] : [];

  const stageLabel = useMemo(() => {
    if (!status) return "Loading";
    return asBool(status.enabled) ? "Economics activated" : "Genesis economics locked";
  }, [status]);

  return (
    <div className="pageStack economicsPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Economics & Treasury</div>
              <h1 className="heroTitle heroTitleSm">{stageLabel}</h1>
              <p className="heroText">
                WeCoin, fees, rewards, and treasury spending are shown here as a protocol status surface. This page never unlocks economics by itself.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current posture</div>
              <div className="heroInfoList">
                <span className={`statusPill ${status && !status.enabled ? "warn" : "ok"}`}>{status?.truth_label || "Loading economics status"}</span>
                <span className="statusPill">Transfers {capabilities.balance_transfer_enabled ? "enabled" : "locked"}</span>
                <span className="statusPill">Treasury {capabilities.treasury_spend_enabled ? "enabled" : "locked"}</span>
              </div>
            </div>
          </div>
          <div className="heroActions">
            <button className="btn btnPrimary" onClick={() => void load()} disabled={busy}>{busy ? "Refreshing…" : "Refresh economics"}</button>
            <button className="btn" onClick={() => nav("/advanced")}>View advanced status</button>
          </div>
        </div>
      </section>

      {err ? <ErrorBanner message={err} details={null} /> : null}

      <section className="grid2 economicsGrid">
        <div className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Wallet</div>
                <h2 className="cardTitle">Your WeCoin status</h2>
                <div className="cardDesc">Balances are visible for rehearsal, but transfers remain locked unless economics activation succeeds.</div>
              </div>
            </div>
            <div className="detailList">
              <div><strong>Account</strong><span>{acct.account_id || account || "No active session"}</span></div>
              <div><strong>Balance known</strong><span>{valueText(acct.balance_known)}</span></div>
              <div><strong>Balance</strong><span>{valueText(acct.balance)}</span></div>
              <div><strong>Transfer status</strong><span>{capabilities.balance_transfer_enabled ? "enabled" : acct.transfer_disabled_reason || "locked"}</span></div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Activation</div>
                <h2 className="cardTitle">Locked model requirements</h2>
                <div className="cardDesc">Economics must remain subordinate to civic rights and governance activation.</div>
              </div>
            </div>
            <div className="requirementList">
              {requirements.map((item) => <div className="requirementItem" key={item}>{item}</div>)}
              {activationRequirements.map((item) => <div className="requirementItem" key={String(item.key || item.label)}>{item.ok ? "✓" : "•"} {String(item.label || item.key || "requirement")}</div>)}
            </div>
            <div className="calloutInfo">Activation readiness: {activation?.ready_for_activation_tx ? "ready for governance/system activation tx" : "not ready or still locked"}</div>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Protocol safeguards</div>
              <h2 className="cardTitle">Fee-free civic/social/governance protection</h2>
              <div className="cardDesc">Posting, comments, likes, PoH, reviews, proposals, and votes should not become pay-to-participate actions.</div>
            </div>
            <span className={`statusPill ${feeViolations.length ? "bad" : "ok"}`}>{feeViolations.length ? "fee violation" : "fee-free protected"}</span>
          </div>
          {feeViolations.length ? <pre className="codePanel mono">{JSON.stringify(feeViolations, null, 2)}</pre> : <div className="calloutInfo">No positive civic/social/governance fee fields are visible in the current fee policy.</div>}
          <div className="grid3 economicsMetricGrid">
            <div className="miniMetric"><strong>Stage</strong><span>{valueText(status?.stage)}</span></div>
            <div className="miniMetric"><strong>Unlocked</strong><span>{valueText(status?.unlocked)}</span></div>
            <div className="miniMetric"><strong>Enabled</strong><span>{valueText(status?.enabled)}</span></div>
            <div className="miniMetric"><strong>Treasury wallets</strong><span>{valueText(treasury.wallet_count)}</span></div>
            <div className="miniMetric"><strong>Treasury spends</strong><span>{valueText(treasury.spend_count)}</span></div>
            <div className="miniMetric"><strong>Treasury read lock</strong><span>{valueText(treasuryRead.locked)}</span></div>
            <div className="miniMetric"><strong>Rewards</strong><span>{capabilities.rewards_enabled ? "enabled" : "locked"}</span></div>
          </div>
        </div>
      </section>
    </div>
  );
}
