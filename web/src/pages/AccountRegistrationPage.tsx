import { useCallback, useEffect, useMemo, useState } from "react";

import { getApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import {
  readAccountRegistrationStatus,
  readRegistrationFinality,
  submitBasicAccountRegistration,
  type RegistrationStatus,
} from "../lib/accountSetupRegistration";
import { nav } from "../lib/router";

function pendingRegistrationKey(account: string): string {
  return "weall.account_registration_pending::" + account;
}

function readPendingTransaction(account: string): string {
  try {
    return String(localStorage.getItem(pendingRegistrationKey(account)) || "").trim();
  } catch {
    return "";
  }
}

function rememberPendingTransaction(account: string, txId: string): void {
  if (!account) return;
  try {
    if (txId) localStorage.setItem(pendingRegistrationKey(account), txId);
    else localStorage.removeItem(pendingRegistrationKey(account));
  } catch {
    // The current screen still holds the transaction ID when storage is blocked.
  }
}

export default function AccountRegistrationPage(): JSX.Element {
  const session = getSession();
  const account = session?.account || "";
  const signer = account ? getKeypair(account) : null;
  const base = useMemo(() => getApiBaseUrl(), []);

  const [registration, setRegistration] = useState<RegistrationStatus>("unavailable");
  const [transactionId, setTransactionId] = useState(() => readPendingTransaction(account));
  const [synced, setSynced] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    if (!account || !signer?.secretKeyB64) return;
    setChecking(true);
    try {
      const next = await readAccountRegistrationStatus(account, base);
      setRegistration(next);
      if (transactionId === "submission_unknown") {
        if (next === "registered") {
          setSynced(true);
          setRejected(false);
          setError("");
          setMessage("Your account is registered on this node. The original submission receipt was not preserved.");
          rememberPendingTransaction(account, "");
        } else {
          setSynced(false);
          setMessage("The previous registration attempt has an unknown outcome. Do not submit again until the network confirms its status.");
        }
      } else if (transactionId) {
        const finality = await readRegistrationFinality(transactionId, base);
        if (finality === "rejected") {
          setRejected(true);
          setError("The registration transaction was rejected. Review the transaction before trying again.");
          setSynced(false);
        } else if (finality === "confirmed" && next === "registered") {
          setRejected(false);
          setSynced(true);
          setError("");
          setMessage("Your account is registered and synchronized on this node.");
          rememberPendingTransaction(account, "");
        } else {
          setSynced(false);
          if (finality === "unavailable") setMessage("This node is temporarily unavailable. Your request remains tracked; check again later.");
          else setMessage("Registration is being confirmed and synchronized. You do not need to submit it again.");
        }
      } else if (next === "registered") {
        setRejected(false);
        setSynced(true);
        setMessage("Your account is already registered on this node.");
      } else {
        setSynced(false);
      }
    } finally {
      setChecking(false);
    }
  }, [account, base, signer?.secretKeyB64, transactionId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!transactionId || synced || rejected) return;
    const timer = window.setInterval(() => { void refresh(); }, 3_500);
    return () => window.clearInterval(timer);
  }, [transactionId, synced, rejected, refresh]);

  async function clearRejectedTransaction(): Promise<void> {
    if (!rejected || !account || busy || checking) return;
    const latest = await readAccountRegistrationStatus(account, base);
    if (latest !== "not_registered") {
      setError("The node no longer reports a safely unregistered account. Refresh the status before retrying.");
      return;
    }
    rememberPendingTransaction(account, "");
    setTransactionId("");
    setRejected(false);
    setError("");
    setMessage("You may prepare a new registration request. The rejected transaction remains available in your previous logs.");
  }

  async function handleRegister(): Promise<void> {
    if (!account || !signer?.secretKeyB64 || busy || transactionId || synced) return;
    setBusy(true);
    setError("");
    setMessage("Preparing and signing your account registration. This may take a moment.");
    try {
      // Fail closed across crashes or ambiguous network responses: submission may succeed
      // even if the client never receives the transaction ID.
      rememberPendingTransaction(account, "submission_unknown");
      setTransactionId("submission_unknown");
      const txId = await submitBasicAccountRegistration(account, base);
      rememberPendingTransaction(account, txId);
      setTransactionId(txId);
      setMessage("Registration submitted. Waiting for the network to confirm and synchronize it.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Account registration could not be submitted.");
      setMessage("Check your account's registration status before starting another attempt.");
    } finally {
      setBusy(false);
    }
  }

  if (!account || !signer?.secretKeyB64) {
    return (
      <main className="pageStack">
        <section className="card"><div className="cardBody formStack">
          <p className="eyebrow">Account setup</p>
          <h1 className="cardTitle">Restore your account access</h1>
          <p className="cardDesc">WeAll needs a valid account key on this device before it can register an account. Return to sign-in and restore your recovery file.</p>
          <button className="btn btnPrimary" type="button" onClick={() => nav("/login")}>Open sign-in</button>
        </div></section>
      </main>
    );
  }

  const waiting = !!transactionId && !synced && !rejected;

  return (
    <main className="pageStack" data-testid="guided-account-registration">
      <section className="card heroCard">
        <div className="cardBody formStack">
          <p className="eyebrow">Create your account · Step 3 of 3</p>
          <h1 className="heroTitle heroTitleSm">Register your account</h1>
          <p className="heroText">
            Your account key is available on this device. This final step records your
            account on the WeAll network so other people can recognize it.
          </p>
          <div className="statusRowWrap" aria-label="Account setup progress">
            <span className="statusPill ok">1. Account key ready</span>
            <span className="statusPill ok">2. Recovery saved</span>
            <span className={"statusPill " + (synced ? "ok" : "")}>3. Network registration</span>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <h2 className="cardTitle">Your account: {account}</h2>
          <p className="cardDesc">
            Registering is separate from human verification. You can explore WeAll
            after registration; posting and community decision privileges require
            the appropriate human-verification level.
          </p>

          {synced ? (
            <div className="calloutSuccess" data-testid="registration-complete">
              Your basic account is ready. You can begin human verification.
            </div>
          ) : rejected ? (
            <div className="calloutDanger" data-testid="registration-rejected">
              The network rejected this registration. Review the transaction,
              then deliberately choose whether to make a new request.
            </div>
          ) : waiting ? (
            <div className="calloutInfo" data-testid="registration-pending">
              Your registration has been submitted. Please keep this transaction
              for reference; do not submit a second registration while it is pending.
            </div>
          ) : registration === "key_mismatch" ? (
            <div className="calloutDanger" data-testid="registration-key-mismatch">
              This handle already belongs to a different account key. Restore
              the correct recovery file or choose another handle; do not retry
              registration using this key.
            </div>
          ) : registration === "unavailable" ? (
            <div className="calloutInfo">
              We cannot confirm the node's account status yet. Check your connection
              before registering so you do not accidentally submit twice.
            </div>
          ) : (
            <div className="calloutInfo">Your account key is ready. Register it on the network to continue.</div>
          )}

          {message ? <p className="muted" role="status">{message}</p> : null}
          {error ? <p className="error-text" role="alert">{error}</p> : null}

          <div className="buttonRowWide">
            {synced ? (
              <button className="btn btnPrimary" type="button" onClick={() => nav("/verification")}>
                Continue to human verification
              </button>
            ) : (
              <button
                className="btn btnPrimary"
                type="button"
                data-testid="submit-basic-registration"
                disabled={busy || checking || waiting || rejected || registration !== "not_registered"}
                onClick={() => void handleRegister()}
              >
                {busy ? "Registering…" : waiting ? "Registration pending" : "Register my account"}
              </button>
            )}
            {rejected ? (
              <button className="btn" type="button" disabled={checking || busy} onClick={() => void clearRejectedTransaction()}>
                Prepare a new request
              </button>
            ) : null}
            <button className="btn" type="button" disabled={checking || busy} onClick={() => void refresh()}>
              {checking ? "Checking…" : "Check registration status"}
            </button>
          </div>
          {transactionId ? (
            <details className="advancedDetails">
              <summary>Advanced: registration transaction</summary>
              <pre className="jsonBlock">{transactionId}</pre>
            </details>
          ) : null}
        </div>
      </section>
    </main>
  );
}
