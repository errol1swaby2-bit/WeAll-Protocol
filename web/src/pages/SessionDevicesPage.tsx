import React, { useCallback, useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import SessionRecoveryBanner from "../components/SessionRecoveryBanner";
import { clearSession, endSession, getKeypair, getSession, getSessionHealth, loginOnThisDevice, revokeSessionKeyOnChain } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { consumeReturnTo, nav, peekReturnTo } from "../lib/router";
import { maybeRepairDevBootstrapSession } from "../lib/devBootstrap";
import { useAppConfig } from "../lib/config";
import { summarizeAccountStanding, summarizeSessionState } from "../lib/status";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSessionHealth } from "../hooks/useSessionHealth";
import { useAccount } from "../context/AccountContext";
import { refreshMutationSlices } from "../lib/revalidation";

type DeviceRecord = {
  deviceId: string;
  device_type?: string;
  kind?: string;
  type?: string;
  label?: string | null;
  pubkey?: string | null;
  revoked?: boolean;
  [key: string]: any;
};

function asRecord(value: any): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function fmtTs(value: any): string {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try {
    return new Date(n).toLocaleString();
  } catch {
    return String(value);
  }
}

function describeDevice(rec: DeviceRecord): string {
  return String(rec.label || rec.device_type || rec.kind || rec.type || "device");
}

export default function SessionDevicesPage(): JSX.Element {
  const config = useAppConfig();
  const base = useMemo(() => getApiBaseUrl(), []);
  const tx = useTxQueue();
  const session = getSession();
  const account = session?.account ? normalizeAccount(session.account) : "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const sessionHealth = useSessionHealth();
  const { refresh: refreshAccountContext } = useAccount();

  const [accountView, setAccountView] = useState<any>(null);
  const [registrationView, setRegistrationView] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{ msg: string; details: any } | null>(null);
  const [actionError, setActionError] = useState<string>("");
  const [renewing, setRenewing] = useState(false);
  const [validating, setValidating] = useState(false);

  const load = useCallback(async () => {
    if (!account) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [acct, registered] = await Promise.all([
        weall.account(account, base),
        weall.accountRegistered(account, base).catch(() => null),
      ]);
      setAccountView(acct ?? null);
      setRegistrationView(registered ?? null);
    } catch (e: any) {
      setError({ msg: e?.message || "Failed to load session/device state.", details: e });
    } finally {
      setLoading(false);
    }
  }, [account, base]);

  async function refreshSessionSurface(): Promise<void> {
    await refreshMutationSlices(load, refreshAccountContext);
  }

  useEffect(() => {
    void load();
  }, [load]);

  const standing = summarizeAccountStanding({ accountView, registrationView });
  const sessionSummary = summarizeSessionState({ accountView, registrationView });
  const pendingReturnTo = peekReturnTo();

  const devicesById = useMemo(() => asRecord(asRecord(accountView?.state?.devices).by_id), [accountView]);
  const activeDevices = useMemo<DeviceRecord[]>(() => {
    return Object.entries(devicesById)
      .map(([deviceId, rec]): DeviceRecord => ({
        deviceId,
        ...(rec as Record<string, any>),
      }))
      .filter((rec: DeviceRecord) => !rec.revoked);
  }, [devicesById]);

  const matchingDevice = useMemo(() => {
    const localPubkey = String(keypair?.pubkeyB64 || "").trim();
    if (!localPubkey) return null;
    return activeDevices.find((rec) => String(rec.pubkey || "").trim() === localPubkey) || null;
  }, [activeDevices, keypair?.pubkeyB64]);

  const sessionKeyEntries = useMemo(() => {
    const byId = asRecord(asRecord(accountView?.state?.session_keys).by_id);
    return Object.entries(byId).map(([key, rec]) => ({
      sessionKey: key,
      ...(rec as Record<string, any>),
    }));
  }, [accountView]);

  async function handleRenewSession(): Promise<void> {
    if (!account) return;
    setRenewing(true);
    setActionError("");
    try {
      await loginOnThisDevice({ account, base });
      await load();
      const target = consumeReturnTo("");
      if (target) {
        nav(target);
        return;
      }
    } catch (e: any) {
      const msg = String(e?.message || "").trim();
      if (msg === "pubkey is not an active key on this account" || msg === "pubkey_not_authorized" || msg === "session_invalid") {
        const repaired = await maybeRepairDevBootstrapSession(config).catch(() => false);
        if (repaired) {
          await load();
          setActionError("This device was holding an old local signer. Dev bootstrap credentials were re-applied. Try the action again.");
        } else {
          setActionError("This browser’s local signer no longer matches the current on-chain account keys. Restore the correct keypair for this account, then renew the browser session again.");
        }
      } else {
        setActionError(e?.message || "Failed to renew browser session.");
      }
    } finally {
      setRenewing(false);
    }
  }

  async function handleRevokeCurrentSession(): Promise<void> {
    if (!account || !session?.sessionKey) return;
    setActionError("");
    try {
      await tx.runTx({
        title: "Revoke session key",
        pendingMessage: "Submitting session-key revoke transaction…",
        successMessage: "Revocation submitted. Backend confirmation may still be pending.",
        task: async () => revokeSessionKeyOnChain({ account, sessionKey: session.sessionKey!, base }),
        getTxId: (result: any) => result?.tx_id || result?.result?.tx_id,
      });
      clearSession();
      setActionError("The current local session was cleared after submitting the revoke. Re-open session recovery if you need to renew from this device.");
    } catch (e: any) {
      setActionError(e?.message || "Failed to revoke session key.");
    }
  }

  async function handleValidateCurrentPosture(): Promise<void> {
    setValidating(true);
    setActionError("");
    try {
      const next = getSessionHealth();
      if (next.state === "active" || next.state === "expiring_soon") {
        setActionError("Local session posture looks valid on this device. Refresh the route data if you were waiting for the account view to catch up.");
      } else if (next.recoverableAccount) {
        setActionError(next.message);
      } else {
        setActionError("No recoverable local session is currently stored. Open login to start a fresh browser session.");
      }
      await load();
    } finally {
      setValidating(false);
    }
  }

  function handleClearLocalSession(): void {
    endSession();
    nav("/login");
  }

  return (
    <div className="stack pageStack utilityPage sessionDevicesPage">
      <SessionRecoveryBanner health={sessionHealth} />

      <section className="surfaceSummary surfaceSummarySpacious">
        <div className="surfaceSummaryHeader">
          <div>
            <div className="eyebrow">Identity & Access</div>
            <h1 className="surfaceTitle">Session and device posture</h1>
            <p className="surfaceSummaryHint">
              This surface separates local signer state, local browser session state, and authoritative on-chain device records so the frontend does not imply they are the same thing.
            </p>
          </div>
          <div className="statusRowWrap">
            <span className={`statusPill ${sessionSummary.account ? "ok" : ""}`}>{sessionSummary.account ? "Session loaded" : "No session"}</span>
            <span className={`statusPill ${sessionSummary.hasLocalSigner ? "ok" : ""}`}>{sessionSummary.hasLocalSigner ? "Signer ready" : "Signer missing"}</span>
            <span className={`statusPill ${sessionSummary.hasBrowserSession ? "ok" : ""}`}>{sessionSummary.hasBrowserSession ? "Browser session key" : "No browser session key"}</span>
          </div>
        </div>

        <div className="summaryCardGrid summaryCardGridThree">
          <article className="summaryCard">
            <span className="summaryCardLabel">Current account</span>
            <div className="summaryCardValue mono">{account || "—"}</div>
            <div className="summaryCardHint">The active browser session determines who this device acts as.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">On-chain standing</span>
            <div className="summaryCardValue">{standing.registered ? `Tier ${standing.tier}` : "Unregistered"}</div>
            <div className="summaryCardHint">{standing.detail}</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Matching device record</span>
            <div className="summaryCardValue">{matchingDevice ? "Present" : "Missing"}</div>
            <div className="summaryCardHint">
              {matchingDevice
                ? `The local signer matches on-chain device ${matchingDevice.deviceId}.`
                : "The current local signer is not yet matched to an active on-chain device record."}
            </div>
          </article>
        </div>
      </section>

      <section className="detailFocusStrip utilityFocusStrip">
        <article className="detailFocusCard utilityFocusCard">
          <div className="detailFocusLabel">Utility contract</div>
          <div className="detailFocusValue">Repair local access posture</div>
          <div className="detailFocusText">This page exists to reconcile three separate layers: browser session, local signer storage, and authoritative on-chain device records.</div>
        </article>
        <article className="detailFocusCard utilityFocusCard">
          <div className="detailFocusLabel">Safe recovery</div>
          <div className="detailFocusValue">Validate before you mutate</div>
          <div className="detailFocusText">Renew, revoke, and clear actions live here so recovery stays deliberate instead of being scattered across unrelated product pages.</div>
        </article>
        <article className="detailFocusCard utilityFocusCard">
          <div className="detailFocusLabel">Return path</div>
          <div className="detailFocusValue">{pendingReturnTo ? pendingReturnTo : "Stay in utility mode"}</div>
          <div className="detailFocusText">Recovery should preserve context. If a route sent you here, use the return action after signer posture is valid again.</div>
        </article>
      </section>

      {error ? <ErrorBanner message={error.msg} details={error.details} onRetry={() => void refreshSessionSurface()} onDismiss={() => setError(null)} /> : null}
      {actionError ? <div className="inlineError">{actionError}</div> : null}

      {pendingReturnTo ? (
        <div className="calloutInfo">
          After recovering the signer or renewing the browser session, this page can return you to <strong>{pendingReturnTo}</strong> instead of dropping you back at Home.
        </div>
      ) : null}

      <section className="infoGrid twoCol">
        <article className="card">
          <div className="cardHeaderRow">
            <div>
              <div className="eyebrow">Local device state</div>
              <h2 className="cardTitle">What this browser currently has</h2>
            </div>
            <div className="row gap8">
              <button className="btn" onClick={() => void refreshSessionSurface()} disabled={loading}>Refresh</button>
              <button className="btn" onClick={() => void handleValidateCurrentPosture()} disabled={validating}>Validate posture</button>
              <button className="btn" onClick={() => void handleRenewSession()} disabled={renewing || !account || !keypair}>Renew browser session</button>
              {pendingReturnTo ? <button className="btn" onClick={() => nav(consumeReturnTo("/home"))}>Return to previous route</button> : null}
              <button className="btn ghost" onClick={handleClearLocalSession}>Clear local session</button>
            </div>
          </div>
          <div className="stack gap12">
            <div className="kvList">
              <div className="kvRow"><span>Local account</span><strong className="mono">{account || "—"}</strong></div>
              <div className="kvRow"><span>Local signer pubkey</span><strong className="mono wrapAnywhere">{keypair?.pubkeyB64 || "Not present on this device"}</strong></div>
              <div className="kvRow"><span>Browser session key</span><strong className="mono wrapAnywhere">{session?.sessionKey || "Not present"}</strong></div>
              <div className="kvRow"><span>Session expiry</span><strong>{fmtTs(session?.expiresAtMs)}</strong></div>
              <div className="kvRow"><span>Session health</span><strong>{sessionHealth.state.replace(/_/g, " ")}</strong></div>
            </div>
            <p className="cardDesc">
              The local signer and browser session key are device-local facts. They can exist even when the network has not yet confirmed or matched an on-chain device record.
            </p>
          </div>
        </article>

        <article className="card">
          <div className="cardHeaderRow">
            <div>
              <div className="eyebrow">Current session key</div>
              <h2 className="cardTitle">Authoritative session-key posture</h2>
            </div>
            <button className="btn danger" disabled={!session?.sessionKey} onClick={() => void handleRevokeCurrentSession()}>
              Revoke current session key
            </button>
          </div>
          <p className="cardDesc">
            Revoking the current session key submits an on-chain transaction. Clearing the local session only removes this browser’s local state.
          </p>
          <div className="summaryCallout">
            <strong>Important:</strong> “Clear local session” and “revoke on-chain session key” are intentionally separate because the frontend must not imply that local logout changes authoritative chain state.
          </div>
          <div className="kvList">
            <div className="kvRow"><span>Tracked session-key records</span><strong>{sessionKeyEntries.length}</strong></div>
            <div className="kvRow"><span>Current local key present</span><strong>{session?.sessionKey ? "Yes" : "No"}</strong></div>
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardHeaderRow">
          <div>
            <div className="eyebrow">On-chain devices</div>
            <h2 className="cardTitle">Known device records for this account</h2>
          </div>
          <div className="miniTag">{activeDevices.length} active</div>
        </div>
        <p className="cardDesc">
          Device records are part of the authoritative account state. They matter for operator preparation and higher-trust local-to-network alignment.
        </p>
        {loading ? (
          <div className="emptyState">Loading device state…</div>
        ) : activeDevices.length ? (
          <div className="deviceRecordList">
            {activeDevices.map((rec) => {
              const matches = String(rec.pubkey || "").trim() && String(rec.pubkey || "").trim() === String(keypair?.pubkeyB64 || "").trim();
              return (
                <article key={rec.deviceId} className={`deviceRecordCard ${matches ? "matching" : ""}`}>
                  <div className="deviceRecordHeader">
                    <div>
                      <div className="deviceRecordId mono">{rec.deviceId}</div>
                      <div className="deviceRecordMeta">{describeDevice(rec)}</div>
                    </div>
                    <span className={`statusPill ${matches ? "ok" : ""}`}>{matches ? "Matches local signer" : "Different device"}</span>
                  </div>
                  <div className="deviceRecordBody">
                    <div><span className="mutedLabel">Pubkey</span><div className="mono wrapAnywhere">{String(rec.pubkey || "—")}</div></div>
                    <div><span className="mutedLabel">Raw label/type</span><div>{describeDevice(rec)}</div></div>
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          <div className="emptyState">No active device records are currently visible for this account.</div>
        )}
      </section>
    </div>
  );
}
