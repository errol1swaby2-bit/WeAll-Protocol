import React, { useEffect, useMemo, useState } from "react";

import { weall } from "../api/weall";
import { getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function asBool(value: unknown): boolean {
  return value === true;
}

function asNumber(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function parseWcnToAtomic(input: string, atomicPerCoin: number): number {
  const raw = String(input || "").trim();
  if (!raw) return 0;
  if (!/^\d+(\.\d{0,8})?$/.test(raw)) return 0;

  const [wholeRaw, fracRaw = ""] = raw.split(".");
  const whole = Number(wholeRaw || "0");
  const frac = Number((fracRaw + "00000000").slice(0, 8));

  if (!Number.isFinite(whole) || !Number.isFinite(frac)) return 0;

  const atomic = whole * atomicPerCoin + frac;
  return Number.isSafeInteger(atomic) ? atomic : 0;
}

function formatAtomic(value: unknown, atomicPerCoin: number): string {
  const atomic = asNumber(value, 0);
  if (!Number.isFinite(atomic)) return "0 WCN";

  const whole = Math.floor(atomic / atomicPerCoin);
  const frac = Math.abs(atomic % atomicPerCoin);
  const fracText = String(frac).padStart(8, "0").replace(/0+$/, "");

  return `${whole}${fracText ? `.${fracText}` : ""} WCN`;
}

export default function WalletPanel({
  account,
  base,
  compact = false,
}: {
  account: string;
  base: string;
  compact?: boolean;
}): JSX.Element {
  const normalizedAccount = useMemo(() => normalizeAccount(account), [account]);
  const session = getSession();
  const viewer = session ? normalizeAccount(session.account) : "";
  const isSelf = !!viewer && viewer === normalizedAccount;

  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [toAccount, setToAccount] = useState("");
  const [amountWcn, setAmountWcn] = useState("1");
  const [memo, setMemo] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState<Record<string, any> | null>(null);

  async function load(): Promise<void> {
    if (!normalizedAccount) return;
    setErr("");
    try {
      const res = await weall.economicsStatus({ account: normalizedAccount }, base);
      setStatus(asRecord(res));
    } catch (e: any) {
      setErr(e?.message || "Wallet status failed to load.");
      setStatus(null);
    }
  }

  useEffect(() => {
    void load();
  }, [base, normalizedAccount]);

  const tokenomics = asRecord(status?.tokenomics);
  const precision = asRecord(tokenomics.precision);
  const capabilities = asRecord(status?.capabilities);
  const accountInfo = asRecord(status?.account);
  const atomicPerCoin = Math.max(1, asNumber(precision.atomic_units_per_coin, 100_000_000));
  const balanceAtomic = asNumber(accountInfo.balance, 0);
  const enabled = asBool(status?.enabled) && asBool(capabilities.balance_transfer_enabled);
  const locked = !enabled;
  const atomicAmount = parseWcnToAtomic(amountWcn, atomicPerCoin);

  const disabledReason = !isSelf
    ? "Sign in as this account to send WeCoin."
    : locked
      ? "WeCoin transfers are visible but locked until Genesis economics activation."
      : atomicAmount <= 0
        ? "Enter a positive WCN amount."
        : !toAccount.trim()
          ? "Enter a recipient account."
          : "";

  async function send(): Promise<void> {
    setErr("");
    setResult(null);

    if (disabledReason) {
      setErr(disabledReason);
      return;
    }

    setBusy(true);
    try {
      const res = await submitSignedTx({
        account: normalizedAccount,
        tx_type: "BALANCE_TRANSFER",
        payload: {
          from_account_id: normalizedAccount,
          to_account_id: normalizeAccount(toAccount.trim()),
          amount: atomicAmount,
          memo: String(memo || "").trim() || undefined,
          purpose: "profile_wallet_send",
        },
        base,
      });
      setResult(asRecord(res));
      await load();
    } catch (e: any) {
      setErr(e?.body?.error?.message || e?.body?.detail || e?.message || "WeCoin send failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={`card ${compact ? "walletPanelCompact" : "walletPanel"}`}>
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Wallet</div>
            <h2 className="cardTitle">WeCoin balance</h2>
            <p className="cardDesc">
              WeCoin is visible as protocol state now. Sends and tips remain locked until economics activation.
            </p>
          </div>
          <button className="btn" onClick={() => void load()} disabled={busy}>
            Refresh
          </button>
        </div>

        <div className="statsGrid statsGridCompact">
          <div className="statCard">
            <span className="statLabel">Balance</span>
            <span className="statValue">{formatAtomic(balanceAtomic, atomicPerCoin)}</span>
          </div>
          <div className="statCard">
            <span className="statLabel">Transfer status</span>
            <span className="statValue">{enabled ? "Enabled" : "Locked"}</span>
          </div>
          <div className="statCard">
            <span className="statLabel">Token</span>
            <span className="statValue">{String(tokenomics.symbol || "WCN")}</span>
          </div>
          <div className="statCard">
            <span className="statLabel">Supply cap</span>
            <span className="statValue">{String(asRecord(tokenomics.supply).max_supply_wcn || "21,000,000")} WCN</span>
          </div>
        </div>

        <div className={`calloutInfo ${enabled ? "calloutSuccess" : ""}`}>
          <strong>{enabled ? "WeCoin transfers are active" : "Genesis economics are locked"}</strong>
          <div style={{ marginTop: 6 }}>
            {enabled
              ? "You can submit a signed BALANCE_TRANSFER from this wallet."
              : "This wallet is read-only until the Genesis lock and governance activation path enable economics."}
          </div>
        </div>

        {isSelf ? (
          <div className="formStack">
            <h3 className="sectionTitle">Send WeCoin</h3>
            <label className="fieldLabel">
              Recipient account
              <input
                className="input"
                value={toAccount}
                onChange={(e) => setToAccount(e.target.value)}
                placeholder="@recipient"
              />
            </label>
            <label className="fieldLabel">
              Amount
              <input
                className="input"
                value={amountWcn}
                onChange={(e) => setAmountWcn(e.target.value)}
                placeholder="1.0"
              />
            </label>
            <label className="fieldLabel">
              Note
              <input
                className="input"
                value={memo}
                onChange={(e) => setMemo(e.target.value)}
                placeholder="optional"
              />
            </label>
            <div className="buttonRow buttonRowWide">
              <button className="btn btnPrimary" onClick={() => void send()} disabled={busy || !!disabledReason}>
                {busy ? "Sending…" : "Send WeCoin"}
              </button>
              <span className="cardDesc">
                {disabledReason || `Prepared amount: ${formatAtomic(atomicAmount, atomicPerCoin)}`}
              </span>
            </div>
          </div>
        ) : (
          <p className="cardDesc">Only the signed-in owner can send from this wallet.</p>
        )}

        {err ? <div className="errorBox">{err}</div> : null}
        {result ? (
          <div className="successBox">
            Send transaction submitted. Tx: {String(result.tx_id || result?.result?.tx_id || "pending")}
          </div>
        ) : null}
      </div>
    </section>
  );
}
