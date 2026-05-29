import React, { useEffect, useState } from "react";

import { weall } from "../api/weall";
import { normalizeAccount } from "../auth/keys";
import { getSession, submitSignedTx } from "../auth/session";

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
  if (!raw || !/^\d+(\.\d{0,8})?$/.test(raw)) return 0;
  const [wholeRaw, fracRaw = ""] = raw.split(".");
  const whole = Number(wholeRaw || "0");
  const frac = Number((fracRaw + "00000000").slice(0, 8));
  const atomic = whole * atomicPerCoin + frac;
  return Number.isSafeInteger(atomic) ? atomic : 0;
}

export default function ContentTipButton({
  base,
  targetId,
  author,
}: {
  base: string;
  targetId: string;
  author: string;
}): JSX.Element | null {
  const session = getSession();
  const viewer = session ? normalizeAccount(session.account) : "";
  const recipient = normalizeAccount(author);
  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [amountWcn, setAmountWcn] = useState("1");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    let alive = true;
    async function load(): Promise<void> {
      if (!viewer) return;
      try {
        const res = await weall.economicsStatus({ account: viewer }, base);
        if (alive) setStatus(asRecord(res));
      } catch {
        if (alive) setStatus(null);
      }
    }
    void load();
    return () => {
      alive = false;
    };
  }, [base, viewer]);

  if (!recipient || !targetId) return null;

  const tokenomics = asRecord(status?.tokenomics);
  const atomicPerCoin = Math.max(1, asNumber(asRecord(tokenomics.precision).atomic_units_per_coin, 100_000_000));
  const capabilities = asRecord(status?.capabilities);
  const enabled = asBool(status?.enabled) && asBool(capabilities.balance_transfer_enabled);
  const amount = parseWcnToAtomic(amountWcn, atomicPerCoin);
  const isSelfTip = !!viewer && viewer === recipient;

  const disabledReason = !viewer
    ? "Sign in to tip."
    : isSelfTip
      ? "You cannot tip your own post."
      : !enabled
        ? "Tips are locked until Genesis economics activation."
        : amount <= 0
          ? "Enter a positive amount."
          : "";

  async function tip(): Promise<void> {
    setMsg("");
    if (disabledReason) {
      setMsg(disabledReason);
      return;
    }

    setBusy(true);
    try {
      const res = await submitSignedTx({
        account: viewer,
        tx_type: "BALANCE_TRANSFER",
        payload: {
          from_account_id: viewer,
          to_account_id: recipient,
          amount,
          memo: `Tip for ${targetId}`,
          purpose: "content_tip",
          content_id: targetId,
        },
        base,
      });
      setMsg(`Tip submitted: ${String(res?.tx_id || res?.result?.tx_id || "pending")}`);
    } catch (e: any) {
      setMsg(e?.body?.error?.message || e?.body?.detail || e?.message || "Tip failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="buttonRow buttonRowWide" style={{ marginTop: 8 }}>
      <input
        className="input"
        style={{ maxWidth: 120 }}
        value={amountWcn}
        onChange={(e) => setAmountWcn(e.target.value)}
        aria-label="Tip amount in WCN"
      />
      <button className="btn" onClick={() => void tip()} disabled={busy || !!disabledReason}>
        {busy ? "Tipping…" : "Tip WCN"}
      </button>
      <span className="cardDesc">{disabledReason || msg || "Send a WeCoin tip to the creator."}</span>
    </div>
  );
}
