import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import GateBanner from "../components/GateBanner";
import { nav } from "../lib/router";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

// Gating logic is centralized in src/lib/gates.ts

export default function Thread({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [thread, setThread] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  // Session + gates
  const [acct, setAcct] = useState<string | null>(null);
  const [canSign, setCanSign] = useState(false);
  const [acctState, setAcctState] = useState<any | null>(null);

  // Reply composer
  const [reply, setReply] = useState("");
  const [replying, setReplying] = useState(false);
  const [replyErr, setReplyErr] = useState<{ msg: string; details: any } | null>(null);

  function refreshSession() {
    const s = getSession();
    const a = s ? normalizeAccount(s.account) : null;
    setAcct(a);
    const kp = a ? getKeypair(a) : null;
    setCanSign(!!kp?.secretKeyB64);
  }

  async function refreshAccountState() {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const r = await weall.account(acct, base);
      setAcctState((r as any)?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function load() {
    setErr(null);
    try {
      const r = await weall.thread(id, base);
      setThread(r);
    } catch (e: any) {
      setErr(prettyErr(e));
      setThread(null);
    }
  }

  useEffect(() => {
    refreshSession();
    refreshAccountState();
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => {
    refreshSession();
    refreshAccountState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [acct]);

  const items: any[] = thread?.items || thread?.comments || thread || [];

  const replyGate = checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2, minRep: 1 });

  async function submitReply() {
    setReplyErr(null);
    if (!acct) return setReplyErr({ msg: "not_logged_in", details: null });
    if (!replyGate.ok) return setReplyErr({ msg: replyGate.reason || "gated", details: acctState });

    const b = (reply || "").trim();
    if (!b) return setReplyErr({ msg: "reply body required", details: null });

    setReplying(true);
    try {
      await submitSignedTx({
        account: acct,
        tx_type: "CONTENT_COMMENT_CREATE",
        payload: { post_id: id, body: b },
        parent: null,
        base,
      });
      setReply("");
      await refreshAccountState();
      await load();
    } catch (e: any) {
      setReplyErr(prettyErr(e));
    } finally {
      setReplying(false);
    }
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav(`/content/${encodeURIComponent(id)}`)}>← Content</button>
        <h2 style={{ margin: 0 }}>Thread</h2>
        <button onClick={load}>Refresh</button>
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      </div>

      <div style={{ marginTop: 12 }}>
        <div style={{ opacity: 0.7, fontFamily: "monospace", fontSize: 12, marginBottom: 8 }}>{id}</div>

        {/* Reply composer */}
        <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14, marginBottom: 12 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
            <div style={{ fontWeight: 800 }}>Reply</div>
            <div style={{ opacity: 0.75, fontSize: 13 }}>
              {acct ? (
                <>
                  as <b>{acct}</b>
                  {acctState ? <> — <b>{summarizeAccountState(acctState)}</b></> : null}
                </>
              ) : (
                <>Not logged in</>
              )}
            </div>
            <div style={{ flex: 1 }} />
            {!acct ? (
              <button onClick={() => nav("/poh")} style={{ fontSize: 13 }}>
                Go to PoH
              </button>
            ) : (
              <button onClick={refreshAccountState} style={{ fontSize: 13 }}>
                Refresh gates
              </button>
            )}
          </div>

          <GateBanner gate={replyGate} prefix="Replying disabled" />

          <textarea
            value={reply}
            onChange={(e) => setReply(e.target.value)}
            placeholder="Write a reply…"
            style={{ width: "100%", marginTop: 10, padding: 10, borderRadius: 10, border: "1px solid #ccc", minHeight: 80 }}
          />
          <div style={{ marginTop: 10, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button
              onClick={submitReply}
              disabled={!replyGate.ok || replying}
              style={{
                padding: "10px 12px",
                borderRadius: 10,
                border: "1px solid #111",
                background: replyGate.ok ? "#111" : "#eee",
                color: replyGate.ok ? "white" : "#777",
                cursor: replyGate.ok ? "pointer" : "not-allowed",
              }}
            >
              {replying ? "Posting…" : "Post reply"}
            </button>
          </div>

          <div style={{ marginTop: 10 }}>
            <ErrorBanner message={replyErr?.msg} details={replyErr?.details} onDismiss={() => setReplyErr(null)} />
          </div>
        </div>

        {!items?.length ? (
          <div style={{ opacity: 0.7 }}>(no comments)</div>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {items.map((c, i) => (
              <div
                key={c?.comment_id || c?.id || i}
                style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}
              >
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
                  <span style={{ fontWeight: 800 }}>{String(c?.author || c?.account || "unknown")}</span>
                  <span style={{ opacity: 0.65, fontFamily: "monospace", fontSize: 12 }}>{String(c?.comment_id || c?.id || "")}</span>
                  {c?.ts ? <span style={{ opacity: 0.75 }}>{new Date(Number(c.ts)).toLocaleString()}</span> : null}
                </div>
                <div style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>{String(c?.body || c?.text || c?.comment || "")}</div>
              </div>
            ))}
          </div>
        )}

        <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
          <div style={{ fontWeight: 700, marginBottom: 6 }}>Raw</div>
          <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(thread, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}
